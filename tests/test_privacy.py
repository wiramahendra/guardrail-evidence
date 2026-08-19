"""Privacy classification of recorded summaries, including the unsupported-type marker.

``privacy._classify_summary`` parses the bounded summary string back into a
structure to decide whether anything an ordinary argument value survived. This
file pins every branch, including the unsupported-type marker, which was dead
code until the canonicalizer and the classifier agreed on one constant.
"""

from __future__ import annotations

import json

import pytest

import guardrail_evidence as ge
from guardrail_evidence.canonical import UNSUPPORTED_MARKER, canonicalize
from guardrail_evidence.privacy import (
    PrivacyClassification,
    _classify_summary,
    inspect_journal,
)
from guardrail_evidence.redaction import SENSITIVE_NAMES, bounded_summary
from helpers import allow


def classify(value, sensitive: frozenset[str] = SENSITIVE_NAMES):
    canonical, _ = canonicalize(value, sensitive)
    return _classify_summary(bounded_summary(canonical))


def test_fully_redacted_every_value_is_the_marker():
    cls, names, _ = classify({"api_key": "sk-secret", "token": "abc"})
    assert cls is PrivacyClassification.FULLY_REDACTED
    assert names == ()


def test_partially_redacted_reports_the_retained_names():
    cls, names, _ = classify({"api_key": "sk-secret", "amount": 5})
    assert cls is PrivacyClassification.PARTIALLY_REDACTED
    assert names == ("amount",)


def test_no_arguments():
    cls, _, _ = _classify_summary("")
    assert cls is PrivacyClassification.NO_ARGUMENTS


def test_malformed_summary_is_unknown():
    cls, _, _ = _classify_summary("this is not name=value syntax")
    assert cls is PrivacyClassification.UNKNOWN


def test_truncated_summary_is_unknown():
    cls, _, _ = _classify_summary("a=1...(truncated)")
    assert cls is PrivacyClassification.UNKNOWN


def test_unsupported_type_is_classified_unknown():
    cls, names, _ = classify({"payload": object()})
    assert cls is PrivacyClassification.UNKNOWN
    assert names == ("payload",)


def test_unsupported_marker_matches_the_canonicalizer_output():
    """The classifier and the canonicalizer must share one marker constant."""
    canonical, _ = canonicalize({"x": object()}, SENSITIVE_NAMES)
    assert canonical["x"].startswith(UNSUPPORTED_MARKER)
    assert canonical["x"].endswith(">")
    cls, _, _ = _classify_summary(bounded_summary(canonical))
    assert cls is PrivacyClassification.UNKNOWN


def test_inspect_flags_unsupported_types_as_not_safe(evidence_home):
    @ge.guard(action="test.unsupported", approval_provider=allow())
    def act(payload):
        return None

    act(object())

    report = inspect_journal(evidence_home / "journal.jsonl")
    assert report.safe_for_upload is False
    assert report.actions[0].classification is PrivacyClassification.UNKNOWN


def test_inspect_marks_fully_redacted_as_safe(evidence_home):
    @ge.guard(action="test.safe", approval_provider=allow())
    def act(api_key: str):
        return None

    act("sk-ONE-TWO-THREE")

    report = inspect_journal(evidence_home / "journal.jsonl")
    assert report.safe_for_upload is True
    assert report.actions[0].classification is PrivacyClassification.FULLY_REDACTED


def test_inspect_refuses_to_classify_a_tampered_journal(evidence_home):
    @ge.guard(action="test.tampered", approval_provider=allow())
    def act(api_key: str):
        return None

    act("sk-ONE-TWO-THREE")
    path = evidence_home / "journal.jsonl"
    lines = path.read_text().splitlines()
    event = json.loads(lines[0])
    event["risk"] = "low"
    lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(ge.EvidencePrivacyInspectionError, match="failed local verification"):
        inspect_journal(path)
