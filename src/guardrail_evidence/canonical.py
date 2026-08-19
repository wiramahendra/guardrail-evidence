"""Canonical, deterministic serialization — with redaction fused into it.

Canonical JSON format
---------------------
* UTF-8 encoding
* keys sorted lexicographically
* compact separators (``,`` and ``:``)
* no NaN / infinity
* ``ensure_ascii=False`` (non-ASCII text is emitted as UTF-8)

Hashes are SHA-256 over the canonical bytes, hex-encoded.

Why redaction lives here
------------------------
Redaction and canonicalization are one traversal, not two passes. Splitting
them is a standing invitation to a specific and serious bug: a redactor that
understands one set of container types, and a canonicalizer that expands a
*wider* set. Any type the canonicalizer expands but the redactor does not
becomes a hole through which named secrets reach persisted evidence.

Dataclasses and named tuples are exactly that shape. Both carry named fields.
A redactor written for mappings does not see those names, but a canonicalizer
must expand them to produce deterministic output — so ``Credentials(api_key=
"sk-live-...")`` canonicalizes to ``{"api_key": "sk-live-..."}`` with the
secret intact. A named tuple is worse, because it is also a ``tuple``: a
sequence-aware redactor flattens it positionally and the field names cease to
exist before anything can match them.

Fusing the two makes the failure unrepresentable. There is one function that
decides how a value expands, and it consults the sensitive-name set at every
point where it produces a name.

Value policy
------------
Deterministically converted: ``None``, ``bool``, ``int``, finite ``float``,
``str``, ``list``, ``tuple``, named tuples (by field name), ``dict`` with
string keys, and dataclass *instances* (by field name).

Anything else becomes a **type marker** of the form
``<unsupported:module.QualifiedTypeName>``, which carries no value data.
This is deliberate: guarded functions routinely receive rich objects (HTTP
clients, ORM rows, ``self``), failing the call for those would make the guard
unusable, and calling ``repr()`` would leak whatever the object holds. The
marker keeps evidence deterministic and leak-free at the cost of not
committing to the object's contents.

Two conditions remain hard failures (:class:`CanonicalizationError`), because
accepting them would make evidence non-deterministic or ambiguous:

* NaN or infinite floats, anywhere in the structure
* cyclic containers, or nesting beyond :data:`MAX_DEPTH`
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
from typing import Any, NamedTuple

from .errors import CanonicalizationError

MAX_DEPTH = 64

REDACTED = "<REDACTED>"

#: Prefix of the marker produced for values that are not canonicalizable.
#: The full marker is ``UNSUPPORTED_MARKER + type_name + ">"``.
UNSUPPORTED_MARKER = "<unsupported:"
_UNSUPPORTED_MARKER = f"{UNSUPPORTED_MARKER}{{type_name}}>"
_NON_STRING_KEY_MARKER = "<unsupported:mapping-with-non-string-keys>"

#: Minimum length for a string to be worth scrubbing out of error text.
#: Shorter values produce too many spurious replacements to be useful.
_MIN_SCRUBBABLE_LENGTH = 4


def type_name(value: Any) -> str:
    """Deterministic dotted name for a value's type."""
    cls = type(value)
    module = getattr(cls, "__module__", "unknown") or "unknown"
    qualname = getattr(cls, "__qualname__", cls.__name__)
    return f"{module}.{qualname}"


def is_named_tuple(value: Any) -> bool:
    """Whether *value* is a named tuple instance.

    There is no ``isinstance`` check for this; the structural test against
    ``_fields`` is the documented approach. It must be applied before any
    generic ``tuple`` branch, or the field names are lost.
    """
    return isinstance(value, tuple) and hasattr(value, "_fields")


def _field_names(value: Any) -> tuple[str, ...] | None:
    """Named fields of *value*, or None if it does not expand by name."""
    if isinstance(value, dict):
        return None  # handled separately: keys may be non-strings
    if is_named_tuple(value):
        fields = value._fields
        if all(isinstance(name, str) for name in fields):
            return tuple(fields)
        return None
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return tuple(field.name for field in dataclasses.fields(value))
    return None


class Canonicalized(NamedTuple):
    """The result of one fused redact-and-canonicalize traversal."""

    #: JSON-safe structure with every sensitive-named value replaced.
    value: Any
    #: Raw string values that were redacted, for scrubbing error text. These
    #: never leave the process and are never persisted.
    redacted_values: tuple[str, ...]


def canonicalize(value: Any, sensitive: frozenset[str] = frozenset()) -> Canonicalized:
    """Redact and canonicalize *value* in a single pass.

    Any position that carries a name — a mapping key, a dataclass field, a
    named-tuple field — is matched case-insensitively against *sensitive*, and
    replaced with :data:`REDACTED` if it matches. The replacement is a fixed
    literal, so no length, prefix, or hash of the raw value survives.

    Raises:
        CanonicalizationError: for NaN/infinity, cycles, or excessive depth.
    """
    collected: list[str] = []
    result = _walk(value, sensitive, collected, _depth=0, _seen=frozenset())
    return Canonicalized(result, tuple(collected))


def _redact(value: Any, collected: list[str]) -> str:
    """Replace a sensitive value, remembering it for later error scrubbing."""
    if isinstance(value, str) and len(value) >= _MIN_SCRUBBABLE_LENGTH:
        collected.append(value)
    return REDACTED


def _walk(
    value: Any,
    sensitive: frozenset[str],
    collected: list[str],
    *,
    _depth: int,
    _seen: frozenset[int],
) -> Any:
    if _depth > MAX_DEPTH:
        raise CanonicalizationError(f"nesting exceeds maximum depth of {MAX_DEPTH}")

    if value is None or isinstance(value, (bool, int, str)):
        return value

    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError(
                "NaN and infinite floats are not permitted in canonical evidence"
            )
        return value

    def descend(item: Any, seen: frozenset[int]) -> Any:
        return _walk(item, sensitive, collected, _depth=_depth + 1, _seen=seen)

    # Named containers: dict, dataclass instance, named tuple. Every one of
    # these produces field names, so every one must consult `sensitive`.
    if isinstance(value, dict):
        if id(value) in _seen:
            raise CanonicalizationError("cyclic container cannot be canonicalized")
        if not all(isinstance(key, str) for key in value):
            return _NON_STRING_KEY_MARKER
        seen = _seen | {id(value)}
        return {
            key: (
                _redact(item, collected)
                if is_sensitive_name(key, sensitive)
                else descend(item, seen)
            )
            for key, item in value.items()
        }

    names = _field_names(value)
    if names is not None:
        if id(value) in _seen:
            raise CanonicalizationError("cyclic container cannot be canonicalized")
        seen = _seen | {id(value)}
        return {
            name: (
                _redact(getattr(value, name), collected)
                if is_sensitive_name(name, sensitive)
                else descend(getattr(value, name), seen)
            )
            for name in names
        }

    # Positional containers carry no names, so nothing here can match; the
    # named-tuple check above must already have run.
    if isinstance(value, (list, tuple)):
        if id(value) in _seen:
            raise CanonicalizationError("cyclic container cannot be canonicalized")
        seen = _seen | {id(value)}
        return [descend(item, seen) for item in value]

    return _UNSUPPORTED_MARKER.format(type_name=type_name(value))


def is_sensitive_name(name: str, sensitive: frozenset[str]) -> bool:
    """Case-insensitive membership test for a field or parameter name."""
    return name.lower() in sensitive


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize an already-canonical structure to canonical JSON bytes."""
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(f"canonical JSON serialization failed: {exc}") from exc
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value: Any, sensitive: frozenset[str] = frozenset()) -> str:
    """SHA-256 hex of the canonical, redacted encoding of *value*."""
    return sha256_hex(canonical_json_bytes(canonicalize(value, sensitive).value))
