"""``guardrail-evidence`` — offline inspection of a local evidence journal.

Every subcommand is read-only and works without a network. That is the point:
evidence you can only check by asking a service is evidence you are trusting
the service about.

    guardrail-evidence verify [--journal PATH] [--public-key PATH] [--json]
    guardrail-evidence key-info [--json]
    guardrail-evidence inspect [--journal PATH] [--json]

Exit codes: ``0`` success, ``1`` verification or inspection failure, ``2``
usage error (argparse exits ``2`` itself on a malformed command).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .errors import GuardrailError
from .identity import (
    PUBLIC_KEY_FILENAME,
    LocalSigningIdentity,
    default_journal_path,
    evidence_home,
    load_public_key,
    public_key_fingerprint,
)
from .privacy import inspect_journal
from .verification import verify_journal

EXIT_OK = 0
EXIT_FAILURE = 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrail-evidence",
        description="Verify and inspect a local evidence journal, offline.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify", help="verify a journal's signatures and hash chain")
    verify.add_argument("--journal", type=Path, default=None, help="journal path")
    verify.add_argument("--public-key", type=Path, default=None, help="verifying key path")
    verify.add_argument("--json", action="store_true", help="emit JSON")

    key_info = subparsers.add_parser("key-info", help="print the local signing identity")
    key_info.add_argument("--json", action="store_true", help="emit JSON")

    inspect = subparsers.add_parser(
        "inspect", help="report what a journal would disclose if shared"
    )
    inspect.add_argument("--journal", type=Path, default=None, help="journal path")
    inspect.add_argument("--json", action="store_true", help="emit JSON")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            return _cmd_verify(args)
        if args.command == "key-info":
            return _cmd_key_info(args)
        if args.command == "inspect":
            return _cmd_inspect(args)
    except GuardrailError as exc:
        _fail(f"{type(exc).__name__}: {exc}", as_json=getattr(args, "json", False))
        return EXIT_FAILURE
    parser.error(f"unknown command {args.command!r}")  # exits with code 2
    return EXIT_FAILURE  # pragma: no cover - parser.error raises SystemExit


def _cmd_verify(args: argparse.Namespace) -> int:
    journal_path = args.journal or default_journal_path()
    key_path = args.public_key or (evidence_home() / PUBLIC_KEY_FILENAME)

    if not journal_path.exists():
        _fail(f"no journal at {journal_path}", as_json=args.json)
        return EXIT_FAILURE

    result = verify_journal(journal_path, load_public_key(key_path))
    payload: dict[str, Any] = {
        "journal": str(journal_path),
        "valid": result.valid,
        "events_verified": result.events_verified,
        "issues": [
            {"line_number": issue.line_number, "code": issue.code, "message": issue.message}
            for issue in result.issues
        ],
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif result.valid:
        print(f"OK  {journal_path}")
        print(f"    {result.events_verified} events, signatures and hash chain intact")
        print("    note: truncation of the journal tail is not detectable offline")
    else:
        print(f"FAIL  {journal_path}")
        print(f"      {result.events_verified} events verified before the first problem")
        for issue in result.issues:
            location = f"line {issue.line_number}" if issue.line_number else "file"
            print(f"      {location}: [{issue.code}] {issue.message}")

    return EXIT_OK if result.valid else EXIT_FAILURE


def _cmd_key_info(args: argparse.Namespace) -> int:
    identity = LocalSigningIdentity.load_or_create()
    public_path = identity.public_key_path
    payload = {
        "home": str(identity.home),
        "key_id": identity.key_id,
        "fingerprint": public_key_fingerprint(identity.public_key()),
        "public_key_path": str(public_path),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for label, value in payload.items():
            print(f"{label:20} {value}")
    return EXIT_OK


def _cmd_inspect(args: argparse.Namespace) -> int:
    journal_path = args.journal or default_journal_path()

    if not journal_path.exists():
        _fail(f"no journal at {journal_path}", as_json=args.json)
        return EXIT_FAILURE

    report = inspect_journal(journal_path)
    payload = {
        "journal": str(journal_path),
        "event_count": report.event_count,
        "decision_count": report.decision_count,
        "outcome_count": report.outcome_count,
        "safe_for_upload": report.safe_for_upload,
        "actions": [
            {
                "action_name": action.action_name,
                "classification": action.classification.value,
                "retained_parameter_names": list(action.retained_parameter_names),
                "explanation": action.explanation,
            }
            for action in report.actions
        ],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return EXIT_OK

    print(f"{journal_path}")
    print(
        f"  {report.event_count} events ({report.decision_count} decisions, "
        f"{report.outcome_count} outcomes)\n"
    )
    if not report.actions:
        print("  (no actions recorded)")
    for action in report.actions:
        print(f"  {action.action_name}")
        print(f"    classification: {action.classification.value}")
        if action.retained_parameter_names:
            print(f"    discloses:      {', '.join(action.retained_parameter_names)}")
        print(f"    {action.explanation}")
    print()
    if report.safe_for_upload:
        print("  Every recorded argument is redacted.")
    else:
        print("  Some arguments are recorded in the clear. Review before sharing.")
    return EXIT_OK


def _fail(message: str, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"error": message}, indent=2), file=sys.stderr)
    else:
        print(f"error: {message}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
