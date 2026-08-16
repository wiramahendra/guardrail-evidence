# Evidence format v1

The journal is newline-delimited JSON: one event per line, append-only. This
document specifies it completely enough to write an independent verifier in
another language, which is the point — evidence you can only check with the
library that produced it is a weaker claim than it appears.

## Canonical JSON

Every hash and signature is computed over the same encoding:

- UTF-8
- object keys sorted lexicographically by code point
- separators `,` and `:` with no whitespace
- `NaN`, `Infinity`, `-Infinity` rejected
- non-ASCII emitted as UTF-8, **not** `\u` escaped

In Python:

```python
json.dumps(
    value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
).encode("utf-8")
```

## Value canonicalization

Before hashing, argument structures are converted to JSON-safe values and
redacted in the same traversal:

| Python value | Canonical form |
|---|---|
| `None`, `bool`, `int`, `str` | unchanged |
| `float` | unchanged if finite; otherwise an error |
| `list`, `tuple` | JSON array |
| named tuple | JSON object keyed by field name |
| dataclass instance | JSON object keyed by field name |
| `dict` with all-string keys | JSON object |
| `dict` with any non-string key | `"<unsupported:mapping-with-non-string-keys>"` |
| anything else | `"<unsupported:module.QualifiedTypeName>"` |

At every point that produces a **name** — a mapping key, a dataclass field, a
named-tuple field — the name is lowercased and matched against the sensitive
set. A match replaces the value with the literal string `"<REDACTED>"`.

Named tuples must be checked before the generic tuple branch. A named tuple is
a `tuple`, and treating it as a sequence discards the field names, which is
both a fidelity loss and a redaction bypass.

Cycles and nesting deeper than 64 are errors.

## Event structure

Every event carries:

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | `"1"` |
| `event_type` | string | `"decision"` or `"outcome"` |
| `event_id` | string | UUIDv4 |
| `action_id` | string | `module.qualified_name` |
| `action_name` | string | declared logical name |
| `contract_hash` | string | SHA-256 hex of the contract |
| `timestamp_utc` | string | RFC 3339 UTC, microseconds, `Z` suffix |
| `key_id` | string | `ed25519:` + first 16 hex of SHA-256 of the raw public key |
| `previous_event_hash` | string \| null | previous line's `event_hash`; `null` for the first |
| `event_hash` | string | see below |
| `signature` | string | see below |

`decision` events add:

| Field | Type |
|---|---|
| `decision` | `"allowed"` \| `"denied"` |
| `risk` | `"low"` \| `"medium"` \| `"high"` \| `"critical"` |
| `approval_mode` | `"required"` \| `"never"` |
| `redacted_input_summary` | string, bounded |
| `input_hash` | SHA-256 hex over the redacted canonical arguments |
| `metadata` | object, optional |

`outcome` events add:

| Field | Type |
|---|---|
| `status` | `"succeeded"` \| `"failed"` |
| `decision_event_id` | the authorizing decision's `event_id` |
| `observed_result_type` | dotted type name, or `null` on failure |
| `redacted_output_hash` | optional; absent when the result must not be hashed |
| `exception_type` | on failure |
| `sanitized_error_summary` | on failure, bounded and scrubbed |

`redacted_output_hash` is absent when the result is itself one of the redacted
input values — hashing a low-entropy secret commits something confirmable by
guessing — or when the result is not canonicalizable.

## Hashing and signing

1. **Unsigned payload**: the event object minus `event_hash` and `signature`.
   `previous_event_hash` *is* included.
2. `event_hash = SHA-256(canonical_json(unsigned_payload))`, hex.
3. `signature = base64(Ed25519_sign(raw_32_byte_digest))`.

Note step 3 signs the **raw digest bytes**, not the canonical JSON. Ed25519
hashes internally, so this is a hash of a hash; it is safe under SHA-256
collision resistance and it is what a verifier must reproduce exactly.

## Contract hash

```
contract_hash = SHA-256(canonical_json({
    schema_version, action_name, module, qualified_name, risk,
    approval_mode, execution_mode, parameter_descriptors, code_fingerprint
}))
```

`parameter_descriptors` is an array of `{name, kind, has_default, annotation}`
in declaration order. `kind` is the `inspect.Parameter.kind` name, for example
`POSITIONAL_OR_KEYWORD`. `annotation` is a stable string or `null`.
`code_fingerprint` is SHA-256 of the dedented function source, or `null` when
source is unavailable — a missing source never invents a fingerprint.

The contract contains no timestamps, absolute paths, memory addresses, or
interpreter-specific values, so the same declaration hashes identically across
machines and runs.

## Verification algorithm

```
previous = null
for each non-empty line, in order:
    event = parse_json(line)
    payload = event without {event_hash, signature}

    assert event.schema_version == "1"
    assert payload.previous_event_hash == previous

    digest = SHA-256(canonical_json(payload))
    assert digest.hex() == event.event_hash
    assert ed25519_verify(public_key, base64_decode(event.signature), digest)
    assert key_id_for(public_key) == event.key_id

    previous = event.event_hash
```

A verifier that stops at the first failure and reports the index is sufficient;
this implementation collects issues so it can report more than one.

Note what the algorithm cannot check: that the chain is *complete*. Any prefix
of a valid chain is itself a valid chain. See
[`THREAT_MODEL.md`](THREAT_MODEL.md).

## Compatibility

`schema_version` is `"1"`. A verifier encountering a different value should
refuse rather than guess. New optional fields within version 1 will not change
existing field semantics, but note that any added field changes `event_hash`
for events that carry it — which is correct, since the signature must cover
everything recorded.
