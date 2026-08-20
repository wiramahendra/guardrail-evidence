"""The ``@guard`` decorator.

Guarding a function makes the code declaration itself the registration — no
registry call, no backend, no account, no network.

The decorator builds a deterministic :class:`ActionContract` from the function
and the ``@guard`` arguments at decoration time, then hands every invocation
to the shared execution engine in :mod:`guardrail_evidence.engine` — the same
engine used by ``wrap_tool``. That engine owns the ordering, fail-closed
semantics, and evidence writes; see its module docstring for the precise flow.

The only thing this module adds on top is decoration-time handling: building
the contract, validating canonical metadata, and rejecting callables that
cannot be guarded safely in this version (async and generator functions).
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar, overload

from .approval import ApprovalProvider
from .canonical import canonicalize
from .contracts import ActionContract, build_contract
from .engine import execute_sync
from .errors import CanonicalizationError, ContractError
from .identity import SigningIdentity
from .journal import JournalStore
from .observer import ActionObserver
from .redaction import build_sensitive_set

F = TypeVar("F", bound=Callable[..., Any])


@overload
def guard(func: F) -> F: ...


@overload
def guard(
    func: None = None,
    *,
    action: str | None = ...,
    risk: str = ...,
    approval: str = ...,
    journal: str | Path | JournalStore | None = ...,
    redact: list[str] | tuple[str, ...] | None = ...,
    metadata: dict[str, Any] | None = ...,
    approval_provider: ApprovalProvider | None = ...,
    identity: SigningIdentity | None = ...,
    observer: ActionObserver | None = ...,
) -> Callable[[F], F]: ...


def guard(
    func: F | None = None,
    *,
    action: str | None = None,
    risk: str = "medium",
    approval: str = "required",
    journal: str | Path | JournalStore | None = None,
    redact: list[str] | tuple[str, ...] | None = None,
    metadata: dict[str, Any] | None = None,
    approval_provider: ApprovalProvider | None = None,
    identity: SigningIdentity | None = None,
    observer: ActionObserver | None = None,
) -> F | Callable[[F], F]:
    """Guard a consequential synchronous function.

    Usable bare (``@guard``) or with arguments (``@guard(...)``).

    Args:
        action: Stable logical action name. Defaults to a deterministic
            identity derived from the module and qualified function name.
        risk: ``low`` | ``medium`` | ``high`` | ``critical``.
        approval: ``required`` (default; fail-safe) or ``never``.
        journal: Journal path override, or a ``JournalStore`` implementation.
        redact: Additional parameter and field names to redact
            (case-insensitive), on top of the built-in set.
        metadata: Small JSON-safe dict recorded on every decision event. Passes
            the same redaction and canonicalization rules as inputs.
        approval_provider: An injectable ``ApprovalProvider``. Defaults to the
            interactive terminal prompt, which fails closed off a TTY.
        identity: An injectable ``SigningIdentity``. Defaults to the local
            Ed25519 key, created on first use.
        observer: An optional ``ActionObserver`` notified once per contract
            version before the first execution. Omitted means no outward
            calls of any kind are possible.
    """

    def decorate(target: F) -> F:
        contract = build_contract(target, action=action, risk=risk, approval=approval)
        sensitive = build_sensitive_set(redact)
        canonical_metadata = _prepare_metadata(metadata, sensitive, contract)
        try:
            signature = inspect.signature(target)
        except (TypeError, ValueError) as exc:
            raise ContractError(f"cannot inspect signature of {target!r}: {exc}") from exc

        @functools.wraps(target)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return execute_sync(
                target=target,
                args=args,
                kwargs=kwargs,
                contract=contract,
                sensitive=sensitive,
                canonical_metadata=canonical_metadata,
                signature=signature,
                journal=journal,
                approval_provider=approval_provider,
                identity=identity,
                observer=observer,
            )

        wrapper.__guardrail_contract__ = contract  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    if func is not None:
        return decorate(func)
    return decorate


def _prepare_metadata(
    metadata: dict[str, Any] | None,
    sensitive: frozenset[str],
    contract: ActionContract,
) -> Any:
    """Validate, redact, and canonicalize decorator metadata at decoration time."""
    if metadata is None:
        return None
    if not isinstance(metadata, dict) or not all(isinstance(k, str) for k in metadata):
        raise ContractError(
            f"metadata for action {contract.action_name!r} must be a dict with string keys"
        )
    try:
        return canonicalize(metadata, sensitive).value
    except CanonicalizationError as exc:
        raise ContractError(
            f"metadata for action {contract.action_name!r} is not canonicalizable: {exc}"
        ) from exc
