# Threat model

Read this before relying on the evidence for anything that matters. Most of it
is about what the journal *cannot* tell you, because that is the part people
get wrong.

## What is being protected

A record that a consequential action was declared, approved, and executed —
one that stays meaningful when the person reading it does not trust the person
who produced it.

## Trust assumptions

The guarantees hold only while all of these do:

1. **The signing key is secret.** It lives at
   `~/.guardrail_evidence/signing_key.pem`, mode `0600`, unencrypted. Anyone
   who can read that file can forge an entire journal that verifies.
2. **The verifier has an authentic public key.** Verification proves a chain
   was signed by whoever holds the private half of the key you supply. If the
   attacker also supplies the public key, it proves nothing. Distribute the
   fingerprint out of band.
3. **The Python process is not compromised.** This is an in-process library.
   Code running in the same interpreter can monkey-patch the guard, call the
   underlying function directly, or read arguments before redaction.
4. **The clock is roughly right.** Timestamps come from the local clock and are
   signed, so they cannot be edited afterwards — but a wrong clock signs a
   wrong time, and nothing here detects that.

## What the evidence establishes

Given the journal file and an authentic verifying key:

| Claim | Established | How |
|---|---|---|
| An action with this contract was approved before it ran | Yes | The `decision` event is written and fsynced before the call |
| The declared code matches what was recorded | Yes, weakly | `code_fingerprint` hashes the function source when available |
| Recorded inputs hash to this value | Yes | `input_hash` over the redacted canonical form |
| Events have not been edited | Yes | Each event's signature covers its own content |
| Events have not been reordered or removed from the middle | Yes | `previous_event_hash` chains each to its predecessor |
| Every event came from one key | Yes | Ed25519 signature per event, `key_id` recorded |

## What the evidence does not establish

### The side effect happened

This is the most important limit and the easiest to overstate. The journal
records that a Python function was called and what it returned. It does not
record what the payment processor, the cloud API, or the mail server did. A
successful `outcome` event means the function returned without raising — which
is evidence about your process, not about the world.

Anyone describing this as proof that a refund occurred is describing something
this library does not do.

### Tail truncation

Deleting entries from the **end** of the journal is undetectable from the
journal alone. Every remaining event still chains correctly, because a chain
has no idea how long it was supposed to be.

`tests/test_evidence.py::test_truncated_tail_is_not_detectable` asserts this
deliberately, so the limitation cannot quietly stop being true without someone
noticing.

Closing it requires an external witness: periodic checkpoints of `(length,
last_event_hash)` somewhere the attacker does not control, counter-signatures
from a second party, or shipping events to an append-only remote as they are
written. The `ActionObserver` hook is not that — it sees contracts, not events.

### A dishonest process

Nothing prevents code in the same process from calling the unguarded function.
The decorator is a convention enforced at the call site, not a sandbox. Evidence
shows what went *through* the guard, and cannot show what went around it.

### Content of unsupported objects

Values that are not JSON-native, dataclasses, or named tuples are recorded as
`<unsupported:module.TypeName>`. This is deliberate — calling `repr()` would
leak whatever the object holds — but it means the evidence does not commit to
those arguments' contents. An action whose meaningful input is a rich object is
weakly evidenced.

### Secrets you did not name

Redaction is name-based. A secret passed as `data` or `payload` is not
redacted, because nothing marks it as sensitive. Use `redact=[...]`, and use
`guardrail-evidence inspect` to see what a journal would actually disclose
before sharing it.

Name-based redaction also cannot help with a secret embedded inside a larger
string — a connection string in a `url` parameter, a token inside a JSON blob
passed as text. Those pass through.

## Residual risks worth stating plainly

**Low-entropy values are recoverable from hashes.** `input_hash` is over the
redacted structure, so redacted values are gone. But a *non*-redacted argument
with a small domain — a four-digit PIN, a boolean, an account from a known
list — can be recovered by hashing every candidate. Redaction replaces values
with a fixed literal precisely so this does not apply to them; it does apply to
everything you did not redact.

**Key compromise is retroactive and total.** There is no forward secrecy and no
key rotation. An attacker who obtains the key can rewrite the entire history,
not just future entries, and the result verifies.

**Concurrent writers on exotic platforms.** Appends take an in-process lock plus
an OS file lock (`fcntl` on Unix, `msvcrt` on Windows). On a platform with
neither, two processes writing the same journal can interleave. Verification
detects the result as a chain error rather than accepting it silently, so this
degrades to a false alarm rather than a false negative.

**`ExecutionCompletedEvidenceError` is a real state, not a theoretical one.**
The function ran and the outcome could not be persisted. The side effect may
have happened. It is a distinct exception type because the caller must decide
what to do, and automatic retry is unsafe.

## What would strengthen it

In rough order of value per unit of work:

1. **Checkpoint the tail.** Periodically record `(length, last_event_hash)`
   somewhere separate. Closes the largest gap.
2. **Counter-sign.** A second party signing periodic checkpoints turns a
   self-attestation into something closer to a witnessed one.
3. **Hardware-backed keys.** A key in a TPM, Secure Enclave, or HSM cannot be
   copied out of the file, which addresses trust assumption 1 directly.
4. **Key rotation with a signed rotation record**, so a compromise has a
   bounded blast radius instead of an unbounded one.

None of these are implemented.
