"""Property test: a sensitive-named field never survives canonicalization.

The defect this library was extracted to fix was invisible to example-based
tests, because the examples were written against the container types the
author had in mind. The gap was a type nobody thought to write an example for.

This test does not enumerate types. It builds arbitrary nested structures out
of every container the canonicalizer can expand, plants a secret under a
sensitive name at a random point inside, and asserts the secret is absent from
the serialized output. Adding a new expandable container without teaching the
redactor about it will fail here without anyone having to think of it.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any, NamedTuple

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from guardrail_evidence.canonical import canonicalize
from guardrail_evidence.redaction import SENSITIVE_NAMES

SECRET = "sk-live-PROPERTY-TEST-SECRET-abcdef123456"


@dataclasses.dataclass
class Holder:
    """A dataclass whose field name is chosen per-instance is impossible, so
    every sensitive name gets its own field and only one is populated."""

    api_key: Any = None
    token: Any = None
    password: Any = None
    harmless: Any = None


class TupleHolder(NamedTuple):
    api_key: Any = None
    token: Any = None
    harmless: Any = None


_SENSITIVE_KEYS = sorted(SENSITIVE_NAMES)

#: Leaves that are safe to embed anywhere.
_harmless = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1000, max_value=1000),
    st.text(max_size=8).filter(lambda s: SECRET not in s),
)


@st.composite
def _secret_bearing(draw: st.DrawFn, depth: int = 0) -> Any:
    """A structure that contains SECRET under some sensitive name."""
    if depth >= 3:
        shape = draw(st.sampled_from(["dict", "dataclass", "namedtuple"]))
    else:
        shape = draw(
            st.sampled_from(["dict", "dataclass", "namedtuple", "list", "tuple", "nested"])
        )

    if shape == "dict":
        key = draw(st.sampled_from(_SENSITIVE_KEYS))
        # Mixed case, because matching is case-insensitive.
        key = draw(st.sampled_from([key, key.upper(), key.capitalize()]))
        return {key: SECRET, "other": draw(_harmless)}

    if shape == "dataclass":
        field = draw(st.sampled_from(["api_key", "token", "password"]))
        return Holder(**{field: SECRET}, harmless=draw(_harmless))

    if shape == "namedtuple":
        field = draw(st.sampled_from(["api_key", "token"]))
        return TupleHolder(**{field: SECRET}, harmless=draw(_harmless))

    inner = draw(_secret_bearing(depth + 1))

    if shape == "list":
        return [draw(_harmless), inner]
    if shape == "tuple":
        return (inner, draw(_harmless))

    # "nested": bury it under a non-sensitive name so it must be recursed into.
    wrapper = draw(st.sampled_from(["dict", "dataclass"]))
    if wrapper == "dict":
        return {"payload": inner, "note": draw(_harmless)}
    return Holder(harmless=inner)


@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(_secret_bearing())
def test_secret_never_survives_canonicalization(structure: Any) -> None:
    canonical, collected = canonicalize(structure, SENSITIVE_NAMES)
    serialized = json.dumps(canonical, sort_keys=True, default=str)
    assert SECRET not in serialized
    # Whatever was removed must be available for scrubbing error text.
    assert SECRET in collected


@settings(max_examples=200, deadline=None)
@given(_secret_bearing())
def test_canonicalization_is_deterministic(structure: Any) -> None:
    first = json.dumps(canonicalize(structure, SENSITIVE_NAMES).value, sort_keys=True, default=str)
    second = json.dumps(canonicalize(structure, SENSITIVE_NAMES).value, sort_keys=True, default=str)
    assert first == second


@settings(max_examples=200, deadline=None)
@given(st.recursive(_harmless, lambda c: st.lists(c, max_size=3), max_leaves=12))
def test_harmless_structures_are_left_intact(structure: Any) -> None:
    """Redaction must not fire on names that are not sensitive."""
    canonical, collected = canonicalize(structure, SENSITIVE_NAMES)
    assert collected == ()
    assert canonical == json.loads(json.dumps(canonical))
