"""Exception hierarchy for the Embedded the guard SDK.

Every error raised by the SDK derives from :class:`GuardrailError` so callers can
distinguish guard-layer failures from failures raised by the guarded function
itself (which are always re-raised unwrapped).
"""

from __future__ import annotations


class GuardrailError(Exception):
    """Base class for all errors raised by the the guard SDK."""


class ContractError(GuardrailError):
    """The action contract could not be built or is invalid.

    Raised at decoration time (e.g. invalid explicit action name) so mistakes
    fail at import time, not at call time.
    """


class UnsupportedFunctionError(ContractError):
    """The decorated callable cannot be guarded in this SDK version.

    Embedded the guard v0 supports synchronous callables only. Decorating a
    coroutine function raises this error at decoration time rather than
    silently producing incorrect pre-execution semantics.
    """


class ToolWrapError(ContractError):
    """``wrap_tool`` or ``wrap_tools`` could not wrap the callable safely.

    Raised when a callable is already guarded, is not callable, is an
    unsupported callable category (generator, async generator), or when
    a collection helper receives duplicate action names or missing
    configuration.
    """


class CanonicalizationError(GuardrailError):
    """A value could not be converted to the canonical evidence representation.

    Raised before the guarded function executes (fail closed). Typical causes:
    NaN or infinite floats, cyclic containers, or excessive nesting depth.
    """


class RedactionError(GuardrailError):
    """Input redaction failed. The guarded function is not executed."""


class ApprovalError(GuardrailError):
    """The approval provider failed to produce a decision.

    This is distinct from :class:`ActionDenied`: the provider errored (or was
    unavailable), so the guard fails closed and the guarded function does not run.
    """


class ApprovalUnavailableError(ApprovalError):
    """Approval is required but no interactive terminal (or provider) exists.

    Raised, for example, when ``approval="required"`` and stdin is not a TTY
    and no explicit approval provider was configured. Fails closed.
    """


class ActionDenied(GuardrailError):
    """The approval decision was *denied*; the guarded function did not run.

    A signed ``decision`` event with ``decision="denied"`` has been appended to
    the journal before this exception is raised.
    """

    def __init__(self, action_name: str, message: str | None = None) -> None:
        self.action_name = action_name
        super().__init__(message or f"action denied: {action_name}")


class IdentityError(GuardrailError):
    """The local signing identity could not be created or loaded."""


class SigningError(GuardrailError):
    """Signing an event failed. Pre-execution signing failures fail closed."""


class JournalError(GuardrailError):
    """The journal could not be read or durably appended.

    When raised *before* execution, the guarded function has NOT run.
    Post-execution journal failures are reported as
    :class:`EvidencePersistenceError` instead.
    """


class EvidencePersistenceError(GuardrailError):
    """Base class for evidence persistence failures.

    Not every evidence persistence error means the guarded function ran. Use
    :class:`ExecutionCompletedEvidenceError` for the explicit post-execution
    case. This base class is retained as the stable public name for callers
    that already catch post-execution evidence errors.
    """

    def __init__(
        self,
        message: str,
        *,
        function_outcome: str | None = None,
        result: object = None,
    ) -> None:
        super().__init__(message)
        if function_outcome is not None:
            self.executed = True
            self.function_outcome = function_outcome
            self.result = result


class ExecutionCompletedEvidenceError(EvidencePersistenceError):
    """The guarded function ALREADY EXECUTED but outcome evidence is incomplete.

    This error is deliberately distinct from every pre-execution failure: it
    must never be read as "the action did not run". The external side effect
    (refund, deletion, message, ...) may have occurred. the guard does not retry
    the guarded function.

    Attributes:
        execution_occurred: Always ``True``; the guarded function was invoked.
        executed: Compatibility alias for ``execution_occurred``.
        execution_state: ``"completed"`` when the function returned normally,
            or ``"failed"`` when it raised.
        evidence_state: Always ``"incomplete"``.
        retry_safe: Always ``False``. Automatic retry is unsafe because the
            action may have already produced an external side effect.
        action_id: Stable action identifier when available.
        decision_event_id: Event id of the persisted decision when available.
        function_outcome: Existing structured outcome string:
            ``"succeeded"`` or ``"failed"``.
        result: The guarded function's return value when it succeeded, so a
            caller that chooses to handle this error can still recover the
            result. Not included in ``str(error)``.
    """

    def __init__(
        self,
        message: str,
        *,
        action_id: str | None,
        decision_event_id: str | None,
        function_outcome: str,
        result: object = None,
    ) -> None:
        super().__init__(message)
        self.execution_occurred = True
        self.executed = True
        self.execution_state = "completed" if function_outcome == "succeeded" else "failed"
        self.evidence_state = "incomplete"
        self.retry_safe = False
        self.action_id = action_id
        self.decision_event_id = decision_event_id
        self.function_outcome = function_outcome
        self.result = result


class VerificationError(GuardrailError):
    """A journal failed verification (corruption, tampering, bad signature)."""


class EvidencePrivacyInspectionError(GuardrailError):
    """A local evidence privacy inspection could not be completed safely."""

    execution_occurred = False
    retry_safe = False
    error_code = "evidence_privacy_inspection_failed"
