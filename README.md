# guardrail-evidence

Approval-gated, tamper-evident evidence for consequential Python function
calls — the ones you would not want to happen twice, silently, or unapproved.

```python
from guardrail_evidence import guard


@guard(action="billing.refund", risk="high")
def refund(customer_id: str, amount_cents: int, api_key: str) -> dict:
    return payments.refund(customer_id, amount_cents)
```

That decorator does four things on every call:

1. asks for approval, and **denies by default** if nobody can answer;
2. writes a signed `decision` record **before** the function runs;
3. runs the function exactly once;
4. writes a signed `outcome` record after.

The records form a hash chain in an append-only file, signed with a local
Ed25519 key. `api_key` never appears in the file, in the approval prompt, or in
any hash.

There is no service behind this. No account, no API key, no network — the
whole guarantee is a local key and a file you can verify offline:

```console
$ guardrail-evidence verify
OK  ~/.guardrail_evidence/journal.jsonl
    2 events, signatures and hash chain intact
    note: truncation of the journal tail is not detectable offline
```

## Install

```sh
pip install guardrail-evidence
```

One runtime dependency: `cryptography`, for Ed25519. Everything else is the
standard library.

## What problem this solves

An agent that can issue refunds, delete infrastructure, or send email needs two
things that are usually bolted on afterwards and separately: someone to say yes
before the irreversible part, and a record afterwards that survives the
argument about what happened.

Logging is not that record. A log line is written by the same process that
performed the action, in the same trust domain, with nothing preventing its
later edit. It answers "what did we print" rather than "what did we do."

This library aims at the narrow, checkable version: a signed statement that a
specific declared action, with a specific redacted input hash, was approved at
a specific point in a chain, and that the chain has not been reordered or
edited since. That is less than "proof the refund happened" and the difference
matters — [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) is explicit about
where the line falls.

## Redaction is fused into canonicalization

This is the design decision most worth explaining, because getting it wrong is
subtle and the failure is silent.

Evidence needs a deterministic serialization to hash. Secrets need removing
before that serialization. The obvious structure is two passes — redact, then
canonicalize — and it has a hole: any container type the canonicalizer expands
but the redactor does not becomes a route for named secrets into evidence.

Dataclasses are exactly that shape. A redactor written for mappings does not
recognise `Credentials(api_key="sk-live-...")` as having named fields, so it
passes it through untouched. The canonicalizer must expand it to produce
deterministic output, so it becomes `{"api_key": "sk-live-..."}` — with the
secret intact, in the input hash, in the journal, and in the text shown to
whoever is being asked to approve the call.

Named tuples are worse, because a named tuple *is* a `tuple`: a sequence-aware
redactor flattens it positionally and the field names cease to exist before
anything can match against them.

Here they are one traversal. A single function decides how a value expands, and
it consults the sensitive-name set at every point where it produces a name, so
expansion without redaction is unrepresentable rather than merely discouraged.
`tests/test_redaction_property.py` asserts the property over generated nested
structures rather than over a list of types someone thought of.

## Usage

### Approval

The default provider prompts on the controlling terminal and denies on anything
that is not an explicit yes. Off a TTY — CI, cron, a daemon — it raises rather
than assuming consent.

```python
from guardrail_evidence import ApprovalDecision, guard


class PolicyProvider:
    def decide(self, request):
        if request.risk in ("low", "medium"):
            return ApprovalDecision("allowed", "auto-approved by policy")
        return ApprovalDecision("denied", "high risk needs a human")


@guard(action="deploy.staging", approval_provider=PolicyProvider())
def deploy(ref: str): ...
```

The provider sees the action name, declared risk, input hash, contract hash,
and a bounded **redacted** summary. It never sees raw arguments.

### Redaction

Built-in names (`api_key`, `password`, `token`, `secret`, `authorization`, and
others) are matched at any depth, case-insensitively and confusable-insensitively
(NFKC, accent stripping, and common Cyrillic/Greek lookalikes fold to ASCII, so
`api_kеy` with a Cyrillic е is redacted like `api_key`). Add your own:

```python
@guard(action="user.verify", redact=["pin", "ssn"])
def verify(user_id: str, pin: str): ...
```

### Wrapping tools you did not write

```python
from guardrail_evidence import wrap_tools

safe_tools = wrap_tools(existing_tools, risk="high")
```

### Async functions

`@guard` and `wrap_tool` accept `async def` functions too — the guarded
callable stays a coroutine function, with the same decision/outcome evidence:

```python
@guard(action="billing.refund", risk="high")
async def refund(customer_id: str, amount_cents: int) -> dict:
    return await payments.refund(customer_id, amount_cents)
```

Generator and async-generator functions are rejected: guarding a generator
would record an outcome before any work runs.

### Verifying

```sh
guardrail-evidence verify --journal ./journal.jsonl --public-key ./verify_key.pem
guardrail-evidence audit --journal ./journal.jsonl --public-key ./verify_key.pem
guardrail-evidence inspect          # what would this journal disclose if shared?
guardrail-evidence key-info
```

`verify` checks signatures and the hash chain. `audit` then pairs every decision
with its outcome and gives an operational status: `denied`, `succeeded`,
`failed`, or `needs_reconciliation`. Failed calls and allowed decisions with no
outcome make the command exit non-zero: an external side effect may have
completed before an exception or process death, so the operator must check the
external system before any retry. It also rejects duplicate outcomes, orphan
outcomes, outcomes for denied decisions, and identity mismatches between a
decision and its outcome.

```console
$ guardrail-evidence audit
~/.guardrail_evidence/journal.jsonl
  needs_reconciliation     billing.refund
    decision: 4f6a...
  ATTENTION: one or more allowed actions failed or have no outcome.
  Check the external system before retrying; the side effect may have occurred.
```

This is a reconciliation queue, not proof of the external-world result. A
recorded `succeeded` status still means only that the Python function returned
without raising.

`inspect` exists because the journal is designed to be shareable, and "designed
to be" is not the same as "is". It classifies each action by whether its
recorded inputs are fully redacted, so you can check before sending one to an
auditor.

### Reaching outward, if you must

The library makes no network calls and has no configuration that would cause
one. If you need a central registry of declared actions, that is a single
explicit seam:

```python
class Registry:
    def contract_declared(self, contract):
        requests.post(URL, json={"action": contract.action_name,
                                 "hash": contract.contract_hash})

@guard(action="billing.refund", observer=Registry())
def refund(...): ...
```

Called once per contract version, before approval and before execution, with
the contract only — never arguments, results, events, or keys. If it raises,
the function does not run. There is no silent fallback, because a recorder that
quietly stops recording is worse than one that stops.

## What the evidence does and does not establish

**Does**, given the verifying key and the journal file:

- an action with this declared contract was approved before execution;
- the recorded inputs hash to this value, after redaction;
- events have not been edited, reordered, or removed from the middle;
- every event was signed by the holder of this key.

**Does not**:

- prove the external side effect occurred. The record says the function was
  called and what it returned, not what the payment processor did;
- detect deletion of the journal's **tail**. Truncation needs an external
  witness — a checkpoint, a counter-signature, an append-only remote;
- protect against an attacker who holds the signing key. It is a local file;
  anyone who can read it can forge a chain;
- make anything idempotent. Calls are not deduplicated and failures are not
  retried, deliberately: retrying a consequential action is the caller's
  decision.

`ExecutionCompletedEvidenceError` names the one genuinely awkward state — the
function ran, the outcome could not be recorded — as its own exception type, so
callers can distinguish it from "did not run" instead of guessing.

## Development

```sh
pip install -e ".[dev]"
pytest
ruff check .
```

The suite runs under an autouse fixture that makes socket creation raise, so a
network call introduced anywhere fails the tests rather than the audit.

## Provenance and license

Extracted from an internal agent-action layer and reworked: the fused
redaction traversal, the observer seam, the tail-read rewrite, and the private
key permission check are new here. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
and [`docs/EVIDENCE_FORMAT.md`](docs/EVIDENCE_FORMAT.md).

MIT.
