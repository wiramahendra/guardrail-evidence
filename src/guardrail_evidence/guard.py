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
cannot be guarded safely in this version (generator and async-generator
functions). Synchronous and asynchronous functions are both supported.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar, overload

from .approval import ApprovalProvider
from .canonical import canonicalize
from .contracts import ActionContract, _build_contract_unchecked, build_contract
from .engine import _make_async_wrapper, _make_sync_wrapper
from .errors import CanonicalizationError, ContractError, UnsupportedFunctionError
from .identity import SigningIdentity
from .journal import JournalStore
from .observer import ActionObserver
from .redaction import build_sensitive_set

F = TypeVar("F", bound=Callable[..., Any])


def _is_async_callable(func: Any) -> bool:
    """True when calling *func* returns a coroutine."""
    if inspect.iscoroutinefunction(func):
        return True
    if isinstance(func, functools.partial):
        return inspect.iscoroutinefunction(func.func)
    call = type(func).__call__
    return inspect.iscoroutinefunction(call)


def _is_generator_callable(func: Any) -> bool:
    """True when calling *func* returns a generator (sync or async)."""
    if inspect.isgeneratorfunction(func):
        return True
    if inspect.isasyncgenfunction(func):
        return True
    if isinstance(func, functools.partial):
        return inspect.isgeneratorfunction(func.func) or inspect.isasyncgenfunction(func.func)
    call = type(func).__call__
    return inspect.isgeneratorfunction(call) or inspect.isasyncgenfunction(call)


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
    """Guard a consequential function (synchronous or asynchronous).

    Usable bare (``@guard``) or with arguments (``@guard(...)``).

    An ``async def`` target is wrapped in an async wrapper that awaits the
    original call, so the guarded callable stays a coroutine function.

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
        if _is_generator_callable(target):
            raise UnsupportedFunctionError(
                f"@guard does not support generator functions; "
                f"{getattr(target, '__qualname__', target)!r} yields instead of returning. "
                "Guarding a generator would record an outcome before any work runs."
            )

        is_async = _is_async_callable(target)
        if is_async:
            contract = _build_contract_unchecked(
                target, action=action, risk=risk, approval=approval
            )
        else:
            contract = build_contract(target, action=action, risk=risk, approval=approval)

        sensitive = build_sensitive_set(redact)
        canonical_metadata = _prepare_metadata(metadata, sensitive, contract)
        try:
            signature = inspect.signature(target)
        except (TypeError, ValueError) as exc:
            raise ContractError(f"cannot inspect signature of {target!r}: {exc}") from exc

        if is_async:
            wrapper = _make_async_wrapper(
                target,
                contract,
                sensitive,
                canonical_metadata,
                signature,
                journal,
                approval_provider,
                identity,
                observer,
            )
        else:
            wrapper = _make_sync_wrapper(
                target,
                contract,
                sensitive,
                canonical_metadata,
                signature,
                journal,
                approval_provider,
                identity,
                observer,
            )

        functools.update_wrapper(wrapper, target)
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
