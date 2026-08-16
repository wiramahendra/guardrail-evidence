"""Offline journal verification.

Verification is fully deterministic and needs only the journal file and the
local public verification key. It checks, per event:

* the line parses as a JSON object;
* ``schema_version`` is a known version;
* required fields for the event type are present with sane types;
* ``event_hash`` equals SHA-256 of the canonical unsigned payload
  (everything except ``event_hash`` and ``signature``);
* the Ed25519 ``signature`` verifies over the raw digest bytes;
* ``previous_event_hash`` links to the immediately preceding event
  (JSON ``null`` for the first event).

This detects modified events, reordered events, and deletion from the middle
of the chain. Deleting the final tail of the journal is NOT detectable from
the journal alone; that requires an external checkpoint (a Connected-mode
capability).
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .identity import key_id_for, verify_signature
from .journal import EVENT_SCHEMA_VERSION, event_digest, unsigned_payload

KNOWN_SCHEMA_VERSIONS = frozenset({EVENT_SCHEMA_VERSION})
KNOWN_EVENT_TYPES = frozenset({"decision", "outcome"})

_SHARED_REQUIRED_FIELDS = (
    "schema_version",
    "event_type",
    "event_id",
    "action_id",
    "action_name",
    "contract_hash",
    "timestamp_utc",
    "key_id",
    "event_hash",
    "signature",
)
_DECISION_REQUIRED_FIELDS = (
    "decision",
    "risk",
    "approval_mode",
    "redacted_input_summary",
    "input_hash",
)
_OUTCOME_REQUIRED_FIELDS = (
    "status",
    "decision_event_id",
)


@dataclasses.dataclass(frozen=True)
class VerificationIssue:
    line_number: int  # 1-based journal line; 0 for file-level issues
    code: str
    message: str


@dataclasses.dataclass(frozen=True)
class VerificationResult:
    valid: bool
    events_verified: int
    issues: tuple[VerificationIssue, ...]


@dataclasses.dataclass(frozen=True)
class JournalSnapshot:
    """One immutable read of a journal and its local verification result."""

    verification: VerificationResult
    events: tuple[dict[str, Any], ...]


def verify_journal(path: Path, public_key: Ed25519PublicKey) -> VerificationResult:
    """Verify every event and the hash chain of the journal at *path*."""
    return load_journal_snapshot(path, public_key).verification


def load_journal_snapshot(path: Path, public_key: Ed25519PublicKey) -> JournalSnapshot:
    """Read, parse, and verify a journal once for local consumers.

    Privacy inspection and evidence sync use the returned events so signed
    content cannot change between verification and subsequent local handling.
    """
    issues: list[VerificationIssue] = []

    try:
        raw = path.read_bytes()
    except OSError as exc:
        return JournalSnapshot(
            verification=VerificationResult(
                valid=False,
                events_verified=0,
                issues=(
                    VerificationIssue(
                        0, "unreadable", f"cannot read journal ({type(exc).__name__})"
                    ),
                ),
            ),
            events=(),
        )

    expected_key_id = key_id_for(public_key)
    previous_hash: str | None = None
    events_verified = 0
    events: list[dict[str, Any]] = []

    lines = raw.split(b"\n")
    line_number = 0
    for raw_line in lines:
        line_number += 1
        stripped = raw_line.strip()
        if not stripped:
            continue

        try:
            event = json.loads(stripped.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            issues.append(
                VerificationIssue(line_number, "malformed_json", f"line is not valid JSON: {exc}")
            )
            # The chain cannot be followed past an unparseable line.
            return JournalSnapshot(
                VerificationResult(False, events_verified, tuple(issues)), tuple(events)
            )

        if not isinstance(event, dict):
            issues.append(
                VerificationIssue(line_number, "malformed_event", "line is not a JSON object")
            )
            return JournalSnapshot(
                VerificationResult(False, events_verified, tuple(issues)), tuple(events)
            )

        events.append(event)
        event_issues = _verify_event(event, line_number, previous_hash, public_key, expected_key_id)
        issues.extend(event_issues)
        if not event_issues:
            events_verified += 1

        # Follow the chain using the *stored* hash so a single tampered payload
        # reports one hash/signature issue instead of cascading chain errors on
        # every subsequent line. If the attacker recomputed event_hash instead,
        # the next event's linkage check breaks — either way it is detected.
        stored_hash = event.get("event_hash")
        previous_hash = stored_hash if isinstance(stored_hash, str) else None

    return JournalSnapshot(
        verification=VerificationResult(
            valid=not issues, events_verified=events_verified, issues=tuple(issues)
        ),
        events=tuple(events),
    )


def _verify_event(
    event: dict,
    line_number: int,
    expected_previous_hash: str | None,
    public_key: Ed25519PublicKey,
    expected_key_id: str,
) -> list[VerificationIssue]:
    issues: list[VerificationIssue] = []

    schema_version = event.get("schema_version")
    if schema_version not in KNOWN_SCHEMA_VERSIONS:
        issues.append(
            VerificationIssue(
                line_number,
                "unknown_schema",
                f"unsupported schema_version {schema_version!r}; "
                f"this verifier supports {sorted(KNOWN_SCHEMA_VERSIONS)}",
            )
        )
        return issues  # Field layout of unknown schemas is undefined.

    event_type = event.get("event_type")
    if event_type not in KNOWN_EVENT_TYPES:
        issues.append(
            VerificationIssue(
                line_number, "unknown_event_type", f"unknown event_type {event_type!r}"
            )
        )
        return issues

    required = list(_SHARED_REQUIRED_FIELDS)
    required += (
        list(_DECISION_REQUIRED_FIELDS)
        if event_type == "decision"
        else list(_OUTCOME_REQUIRED_FIELDS)
    )
    missing = [field for field in required if field not in event]
    if "previous_event_hash" not in event:
        missing.append("previous_event_hash")
    if missing:
        issues.append(
            VerificationIssue(
                line_number,
                "missing_fields",
                f"missing required fields: {', '.join(sorted(missing))}",
            )
        )
        return issues

    # Chain linkage.
    if event["previous_event_hash"] != expected_previous_hash:
        issues.append(
            VerificationIssue(
                line_number,
                "chain_break",
                "previous_event_hash does not match the preceding event "
                f"(expected {expected_previous_hash!r}, found {event['previous_event_hash']!r}); "
                "events may have been modified, reordered, or deleted",
            )
        )

    # Hash integrity.
    payload = unsigned_payload(event)
    digest = event_digest(payload)
    if event["event_hash"] != digest.hex():
        issues.append(
            VerificationIssue(
                line_number,
                "hash_mismatch",
                "event_hash does not match the canonical payload; event was modified",
            )
        )

    # Signature over the recomputed digest: a tampered payload fails here even
    # if the attacker also recomputed event_hash.
    if event.get("key_id") != expected_key_id:
        issues.append(
            VerificationIssue(
                line_number,
                "unknown_key",
                f"event key_id {event.get('key_id')!r} does not match the "
                f"verification key ({expected_key_id})",
            )
        )
    elif not verify_signature(public_key, digest, str(event["signature"])):
        issues.append(
            VerificationIssue(line_number, "bad_signature", "Ed25519 signature verification failed")
        )

    return issues
