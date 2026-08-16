"""Framework-neutral wrapping for existing agent tools.

``wrap_tool`` reuses the same guard engine (contract building, redaction,
approval, evidence, Connected synchronization) as ``@guard`` without
requiring source-code edits to the original callable. ``wrap_tools``
applies the same primitive to a sequence or mapping of callables.

The returned callables are ordinary Python functions (or async functions)
that an agent framework can register exactly as it would any other tool.
No framework dependency is introduced, no automatic discovery is performed,
and no network activity occurs without explicit Connected configuration.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, ParamSpec, TypeVar, overload

from .approval import ApprovalProvider, ApprovalRequest
from .canonical import canonical_json_bytes, canonicalize, sha256_hex
from .contracts import ActionContract, _build_contract_unchecked, build_contract
from .errors import ActionDenied, ContractError, ToolWrapError, UnsupportedFunctionError
from .guard import (
    EVENT_TYPE_DECISION,
    STATUS_FAILED,
    STATUS_SUCCEEDED,
    _append_event,
    _evaluate_approval,
    _prepare_metadata,
    _record_outcome_or_raise,
    _resolve_journal,
)
from .identity import LocalSigningIdentity, SigningIdentity
from .journal import JournalStore
from .observer import ActionObserver, notify_once
from .redaction import bounded_summary, build_sensitive_set

P = ParamSpec("P")
R = TypeVar("R")

_CONTRACT_ATTR = "__guardrail_contract__"


# ---------------------------------------------------------------------------
# Callable category detection
# ---------------------------------------------------------------------------


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


def _tool_name(func: Any) -> str | None:
    name = getattr(func, "__name__", None)
    if isinstance(name, str) and name:
        return name
    return None


# ---------------------------------------------------------------------------
# wrap_tool
# ---------------------------------------------------------------------------


@overload
def wrap_tool(
    func: Callable[P, R],
    *,
    action: str,
    risk: str = ...,
    approval: str = ...,
    journal: str | Path | JournalStore | None = ...,
    redact: list[str] | tuple[str, ...] | None = ...,
    metadata: dict[str, Any] | None = ...,
    approval_provider: ApprovalProvider | None = ...,
    identity: SigningIdentity | None = ...,
    observer: ActionObserver | None = ...,
) -> Callable[P, R]: ...


@overload
def wrap_tool(
    func: Callable[..., Any],
    *,
    action: str,
    risk: str = ...,
    approval: str = ...,
    journal: str | Path | JournalStore | None = ...,
    redact: list[str] | tuple[str, ...] | None = ...,
    metadata: dict[str, Any] | None = ...,
    approval_provider: ApprovalProvider | None = ...,
    identity: SigningIdentity | None = ...,
    observer: ActionObserver | None = ...,
) -> Callable[..., Any]: ...


def wrap_tool(
    func: Callable[..., Any],
    *,
    action: str,
    risk: str = "medium",
    approval: str = "required",
    journal: str | Path | JournalStore | None = None,
    redact: list[str] | tuple[str, ...] | None = None,
    metadata: dict[str, Any] | None = None,
    approval_provider: ApprovalProvider | None = None,
    identity: SigningIdentity | None = None,
    observer: ActionObserver | None = None,
) -> Callable[..., Any]:
    """Guard an existing callable without editing its source.

    Returns a new callable that produces the same ActionContract and signed
    evidence as an equivalent ``@guard`` declaration. The original
    callable is never mutated.

    Args:
        func: The existing callable to wrap. Synchronous functions, async
            functions, bound methods, ``functools.partial`` objects, and
            callable objects with a stable ``__call__`` signature are
            supported. Generator functions and async generator functions are
            rejected.
        action: Stable logical action name (required).
        risk: ``low`` | ``medium`` | ``high`` | ``critical``.
        approval: ``required`` (default) or ``never``.
        journal: Journal path override or ``JournalStore`` implementation.
        redact: Additional parameter names to redact (case-insensitive).
        metadata: Small JSON-safe dict recorded on every decision event.
        approval_provider: Injectable ``ApprovalProvider``.
        identity: Injectable ``SigningIdentity``.
        observer: Injectable ``ActionObserver`` for an observer integration.

    Raises:
        ToolWrapError: If *func* is already guarded, not callable, or is a
            generator/async-generator callable.
        ContractError: If the contract cannot be built (invalid action name,
            unresolvable signature, etc.).
    """
    if not callable(func):
        raise ToolWrapError(f"wrap_tool expected a callable, got {type(func).__name__}")
    if hasattr(func, _CONTRACT_ATTR):
        raise ToolWrapError(
            f"cannot wrap {getattr(func, '__qualname__', _tool_name(func) or repr(func))!r}: "
            "it is already guarded by @guard or wrap_tool"
        )
    if _is_generator_callable(func):
        raise ToolWrapError(
            f"cannot wrap {getattr(func, '__qualname__', _tool_name(func) or repr(func))!r}: "
            "generator and async-generator callables are not supported "
            "(guarding a generator would record an outcome before any work runs)"
        )

    is_async = _is_async_callable(func)

    if is_async:
        contract = _build_contract_unchecked(func, action=action, risk=risk, approval=approval)
    else:
        contract = build_contract(func, action=action, risk=risk, approval=approval)

    sensitive = build_sensitive_set(redact)
    canonical_metadata = _prepare_metadata(metadata, sensitive, contract)
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError) as exc:
        raise ToolWrapError(f"cannot inspect signature: {exc}") from exc

    if is_async:
        wrapper = _make_async_wrapper(
            func,
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
            func,
            contract,
            sensitive,
            canonical_metadata,
            signature,
            journal,
            approval_provider,
            identity,
            observer,
        )

    functools.update_wrapper(wrapper, func, updated=())
    setattr(wrapper, _CONTRACT_ATTR, contract)
    return wrapper


def _make_sync_wrapper(
    target: Callable[..., Any],
    contract: ActionContract,
    sensitive: frozenset[str],
    canonical_metadata: Any,
    signature: inspect.Signature,
    journal: str | Path | JournalStore | None,
    approval_provider: ApprovalProvider | None,
    identity: SigningIdentity | None,
    observer: ActionObserver | None,
) -> Callable[..., Any]:
    """Build a synchronous wrapper reusing the guard engine's helpers."""

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()

        notify_once(observer, contract)

        canonical_input, raw_sensitive_values = canonicalize(dict(bound.arguments), sensitive)
        input_hash = sha256_hex(canonical_json_bytes(canonical_input))
        input_summary = bounded_summary(canonical_input)

        active_identity = identity or LocalSigningIdentity.load_or_create()

        request = ApprovalRequest(
            action_name=contract.action_name,
            risk=contract.risk,
            approval_mode=contract.approval_mode,
            redacted_input_summary=input_summary,
            input_hash=input_hash,
            contract_hash=contract.contract_hash,
        )
        decision = _evaluate_approval(request, contract, approval_provider)

        store = _resolve_journal(journal)
        decision_payload_extra: dict[str, Any] = {
            "decision": decision.decision,
            "risk": contract.risk,
            "approval_mode": contract.approval_mode,
            "redacted_input_summary": input_summary,
            "input_hash": input_hash,
        }
        if canonical_metadata is not None:
            decision_payload_extra["metadata"] = canonical_metadata
        decision_event = _append_event(
            store,
            active_identity,
            contract,
            EVENT_TYPE_DECISION,
            decision_payload_extra,
        )

        if not decision.allowed:
            raise ActionDenied(
                contract.action_name,
                f"action denied: {contract.action_name} ({decision.reason})",
            )

        try:
            result = target(*args, **kwargs)
        except Exception as exc:
            _record_outcome_or_raise(
                store,
                active_identity,
                contract,
                decision_event,
                status=STATUS_FAILED,
                result=None,
                exception=exc,
                raw_sensitive_values=raw_sensitive_values,
            )
            raise

        _record_outcome_or_raise(
            store,
            active_identity,
            contract,
            decision_event,
            status=STATUS_SUCCEEDED,
            result=result,
            exception=None,
            raw_sensitive_values=raw_sensitive_values,
        )
        return result

    return wrapper


def _make_async_wrapper(
    target: Callable[..., Any],
    contract: ActionContract,
    sensitive: frozenset[str],
    canonical_metadata: Any,
    signature: inspect.Signature,
    journal: str | Path | JournalStore | None,
    approval_provider: ApprovalProvider | None,
    identity: SigningIdentity | None,
    observer: ActionObserver | None,
) -> Callable[..., Any]:
    """Build an asynchronous wrapper reusing the guard engine's helpers.

    Structurally identical to the sync wrapper except for ``await`` at the
    execution step. All contract, redaction, approval, evidence, and
    Connected logic is shared.
    """

    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()

        notify_once(observer, contract)

        canonical_input, raw_sensitive_values = canonicalize(dict(bound.arguments), sensitive)
        input_hash = sha256_hex(canonical_json_bytes(canonical_input))
        input_summary = bounded_summary(canonical_input)

        active_identity = identity or LocalSigningIdentity.load_or_create()

        request = ApprovalRequest(
            action_name=contract.action_name,
            risk=contract.risk,
            approval_mode=contract.approval_mode,
            redacted_input_summary=input_summary,
            input_hash=input_hash,
            contract_hash=contract.contract_hash,
        )
        decision = _evaluate_approval(request, contract, approval_provider)

        store = _resolve_journal(journal)
        decision_payload_extra: dict[str, Any] = {
            "decision": decision.decision,
            "risk": contract.risk,
            "approval_mode": contract.approval_mode,
            "redacted_input_summary": input_summary,
            "input_hash": input_hash,
        }
        if canonical_metadata is not None:
            decision_payload_extra["metadata"] = canonical_metadata
        decision_event = _append_event(
            store,
            active_identity,
            contract,
            EVENT_TYPE_DECISION,
            decision_payload_extra,
        )

        if not decision.allowed:
            raise ActionDenied(
                contract.action_name,
                f"action denied: {contract.action_name} ({decision.reason})",
            )

        try:
            result = await target(*args, **kwargs)
        except Exception as exc:
            _record_outcome_or_raise(
                store,
                active_identity,
                contract,
                decision_event,
                status=STATUS_FAILED,
                result=None,
                exception=exc,
                raw_sensitive_values=raw_sensitive_values,
            )
            raise

        _record_outcome_or_raise(
            store,
            active_identity,
            contract,
            decision_event,
            status=STATUS_SUCCEEDED,
            result=result,
            exception=None,
            raw_sensitive_values=raw_sensitive_values,
        )
        return result

    return wrapper


# ---------------------------------------------------------------------------
# wrap_tools
# ---------------------------------------------------------------------------


def wrap_tools(
    tools: Sequence[Callable[..., Any]] | Mapping[str, Callable[..., Any]],
    *,
    configuration: Mapping[str, Mapping[str, Any]],
) -> list[Callable[..., Any]] | dict[str, Callable[..., Any]]:
    """Wrap a collection of existing callables.

    Args:
        tools: A sequence or mapping of callables to wrap. For a sequence,
            each callable's ``__name__`` is used as the configuration key.
            For a mapping, the mapping keys are used directly.
        configuration: A mapping from tool name to ``wrap_tool`` keyword
            arguments. Each value must include at least an ``action`` key.
            Action names across all tools must be unique.

    Returns:
        A new list (for sequence input) or dict (for mapping input) of
        wrapped callables. The caller's collection is never mutated.

    Raises:
        ToolWrapError: If a tool name is missing from *configuration*, a
            configuration entry lacks an ``action``, duplicate action names
            are detected, a non-callable entry is found, or any individual
            ``wrap_tool`` call fails.
    """
    if isinstance(tools, Mapping):
        return _wrap_tools_mapping(tools, configuration)
    return _wrap_tools_sequence(tools, configuration)


def _wrap_tools_sequence(
    tools: Sequence[Callable[..., Any]],
    configuration: Mapping[str, Mapping[str, Any]],
) -> list[Callable[..., Any]]:
    wrapped: list[Callable[..., Any]] = []
    seen_actions: set[str] = set()
    for tool in tools:
        if not callable(tool):
            raise ToolWrapError(
                f"wrap_tools encountered a non-callable entry: {type(tool).__name__}"
            )
        name = _tool_name(tool)
        if name is None:
            raise ToolWrapError(
                f"wrap_tools cannot determine a stable name for {tool!r}; "
                "use a mapping or ensure the callable has __name__"
            )
        config = configuration.get(name)
        if config is None:
            raise ToolWrapError(f"wrap_tools: no configuration provided for tool {name!r}")
        result = _wrap_one(tool, config, name, seen_actions)
        wrapped.append(result)
    return wrapped


def _wrap_tools_mapping(
    tools: Mapping[str, Callable[..., Any]],
    configuration: Mapping[str, Mapping[str, Any]],
) -> dict[str, Callable[..., Any]]:
    wrapped: dict[str, Callable[..., Any]] = {}
    seen_actions: set[str] = set()
    for key, tool in tools.items():
        if not callable(tool):
            raise ToolWrapError(
                f"wrap_tools encountered a non-callable entry for key {key!r}: "
                f"{type(tool).__name__}"
            )
        config = configuration.get(key)
        if config is None:
            raise ToolWrapError(f"wrap_tools: no configuration provided for tool {key!r}")
        result = _wrap_one(tool, config, key, seen_actions)
        wrapped[key] = result
    return wrapped


def _wrap_one(
    tool: Callable[..., Any],
    config: Mapping[str, Any],
    display_name: str,
    seen_actions: set[str],
) -> Callable[..., Any]:
    config_dict = dict(config)
    action = config_dict.get("action")
    if not isinstance(action, str) or not action:
        raise ToolWrapError(
            f"wrap_tools: configuration for {display_name!r} must include a "
            "non-empty 'action' string"
        )
    if action in seen_actions:
        raise ToolWrapError(
            f"wrap_tools: duplicate action name {action!r} "
            f"(from tool {display_name!r}); action names must be unique"
        )
    seen_actions.add(action)
    try:
        return wrap_tool(tool, **config_dict)
    except (ToolWrapError, ContractError, UnsupportedFunctionError):
        raise
