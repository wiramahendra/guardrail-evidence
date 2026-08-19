"""Approval-gated, tamper-evident evidence for consequential Python calls.

Decorate a function that does something you would not want to happen twice, or
silently, or unapproved:

.. code-block:: python

    from guardrail_evidence import guard

    @guard(action="billing.refund", risk="high")
    def refund(customer_id: str, amount_cents: int, api_key: str) -> dict:
        return payments.refund(customer_id, amount_cents)

Every call now produces two signed, hash-chained journal entries — a
``decision`` recorded *before* execution and an ``outcome`` recorded after —
and prompts for approval unless a provider says otherwise. Sensitive arguments
never reach the journal, the prompt, or any hash.

There is no service behind this. No account, no API key, no network: the
guarantee is a local Ed25519 key and an append-only file you can verify
offline with ``guardrail-evidence verify``.

What the evidence proves, precisely, is in ``docs/THREAT_MODEL.md``. It is
worth reading before relying on it — in particular, truncating the *tail* of a
journal is not detectable from the journal alone.
"""

from __future__ import annotations

from .approval import (
    ApprovalDecision,
    ApprovalProvider,
    ApprovalRequest,
    AutoAllowProvider,
    TerminalApprovalProvider,
)
from .canonical import REDACTED, Canonicalized, canonical_hash, canonicalize
from .contracts import ActionContract, ParameterDescriptor
from .errors import (
    ActionDenied,
    ApprovalError,
    ApprovalUnavailableError,
    CanonicalizationError,
    ContractError,
    EvidencePersistenceError,
    EvidencePrivacyInspectionError,
    ExecutionCompletedEvidenceError,
    GuardrailError,
    IdentityError,
    JournalError,
    RedactionError,
    SigningError,
    ToolWrapError,
    UnsupportedFunctionError,
    VerificationError,
)
from .errors import (
    ExecutionCompletedEvidenceError as EvidenceIncompleteError,
)
from .guard import guard
from .identity import LocalSigningIdentity, SigningIdentity, evidence_home, load_public_key
from .journal import FileJournal, JournalStore
from .observer import ActionObserver
from .privacy import (
    ActionPrivacyInspection,
    EvidencePrivacyReport,
    PrivacyClassification,
    inspect_journal,
)
from .redaction import SENSITIVE_NAMES, build_sensitive_set
from .verification import VerificationIssue, VerificationResult, verify_journal
from .wrap_tool import wrap_tool, wrap_tools

_FALLBACK_VERSION = "0.1.0"


def _package_version() -> str:
    """The installed package version, with a source-tree fallback.

    ``pyproject.toml`` is the single source of truth; this reads the installed
    distribution's metadata so the two cannot drift apart.
    """
    try:
        from importlib.metadata import version

        return version("guardrail-evidence")
    except Exception:  # pragma: no cover - running from a source checkout
        return _FALLBACK_VERSION


__version__ = _package_version()

__all__ = [
    "REDACTED",
    "SENSITIVE_NAMES",
    "ActionContract",
    "ActionDenied",
    "ActionObserver",
    "ActionPrivacyInspection",
    "ApprovalDecision",
    "ApprovalError",
    "ApprovalProvider",
    "ApprovalRequest",
    "ApprovalUnavailableError",
    "AutoAllowProvider",
    "CanonicalizationError",
    "Canonicalized",
    "ContractError",
    "EvidenceIncompleteError",
    "EvidencePersistenceError",
    "EvidencePrivacyInspectionError",
    "EvidencePrivacyReport",
    "ExecutionCompletedEvidenceError",
    "FileJournal",
    "GuardrailError",
    "IdentityError",
    "JournalError",
    "JournalStore",
    "LocalSigningIdentity",
    "ParameterDescriptor",
    "PrivacyClassification",
    "RedactionError",
    "SigningError",
    "SigningIdentity",
    "TerminalApprovalProvider",
    "ToolWrapError",
    "UnsupportedFunctionError",
    "VerificationError",
    "VerificationIssue",
    "VerificationResult",
    "__version__",
    "build_sensitive_set",
    "canonical_hash",
    "canonicalize",
    "evidence_home",
    "guard",
    "inspect_journal",
    "load_public_key",
    "verify_journal",
    "wrap_tool",
    "wrap_tools",
]
