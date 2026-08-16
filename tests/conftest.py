"""Shared fixtures.

The ``_no_network`` fixture is autouse and global: it replaces socket creation
with a hard failure for the entire suite. The library's central claim is that
it does not talk to anything, and the only way to keep that true as the code
changes is to make a socket impossible to open while any test runs.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from guardrail_evidence.approval import ApprovalDecision, ApprovalRequest
from guardrail_evidence.contracts import ActionContract
from guardrail_evidence.observer import reset_notifications


class NetworkAttemptError(RuntimeError):
    """Raised when anything under test tries to open a socket."""


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*args: Any, **kwargs: Any):
        raise NetworkAttemptError("network access attempted")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


@pytest.fixture(autouse=True)
def _reset_observer_state() -> None:
    """Observer notifications are once-per-process; tests need a clean slate."""
    reset_notifications()
    yield
    reset_notifications()


@pytest.fixture
def evidence_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An isolated evidence home, so tests never touch the real one."""
    home = tmp_path / "evidence-home"
    home.mkdir()
    monkeypatch.setenv("GUARDRAIL_EVIDENCE_HOME", str(home))
    return home


@dataclass
class StaticProvider:
    """An approval provider with a fixed answer."""

    decision: str
    reason: str = "test provider"
    seen: list[ApprovalRequest] | None = None

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        if self.seen is None:
            self.seen = []
        self.seen.append(request)
        return ApprovalDecision(self.decision, self.reason)


def allow() -> StaticProvider:
    return StaticProvider("allowed")


def deny() -> StaticProvider:
    return StaticProvider("denied")


class RecordingObserver:
    """Collects the contracts it is told about."""

    def __init__(self, fail_with: Exception | None = None) -> None:
        self.contracts: list[ActionContract] = []
        self.calls = 0
        self._fail_with = fail_with

    def contract_declared(self, contract: ActionContract) -> None:
        self.calls += 1
        if self._fail_with is not None:
            raise self._fail_with
        self.contracts.append(contract)
