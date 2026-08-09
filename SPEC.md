# OpenSlay verifiable randomness v2

English | [简体中文](SPEC.zh-CN.md)

This document specifies the public computation performed by
`openslay-rng-verifier`. It deliberately does not specify or expose the game
engine.

## Binary encoding

- Text is strict UTF-8 prefixed by its unsigned 32-bit big-endian byte length.
- A training seed is a signed 64-bit big-endian integer.
- A seat and HMAC block index are unsigned 32-bit big-endian integers.
- A `purpose_counter` is a non-negative canonical-JSON integer in the
  JSON-safe range `0..2^53-1`; it has no separate binary encoding.
- Digests are 32 bytes internally and 64 lowercase hexadecimal characters in
  JSON.

Public randomness input removes only leading and trailing U+0020 SPACE, rejects
Unicode control characters, and is limited to 64 UTF-8 bytes. It is not Unicode
normalized.

## Match seed derivation

The server publishes this commitment before accepting human contributions:

```text
SHA256(
  "OpenSlay/server-commitment/v1"
  || text(match_id)
  || text(ruleset_hash)
  || server_secret
)
```

A human contribution is:

```text
SHA256(
  "OpenSlay/player-contribution/v1"
  || text(match_id)
  || uint32_be(seat_id)
  || text(public_input)
  || client_nonce
)
```

The online master seed uses human contributions in ascending seat order:

```text
SHA256(
  "OpenSlay/online-master-seed/v1"
  || text(match_id)
  || text(ruleset_hash)
  || server_secret
  || contribution_0 || contribution_1 || ...
)
```

The deterministic training seed is:

```text
SHA256(
  "OpenSlay/training-master-seed/v1"
  || int64_be(numeric_seed)
  || text(public_input)
)
```

## State-bound operation streams

The first use of a purpose has `purpose_counter = 0`, the second has counter 1,
and so forth. The counter is independent for every purpose. Before an operation,
the engine records a canonical authoritative state object with
`state_version = 1` and a non-empty `kind`. It includes hidden card zones and
the active resolution state; it is not a viewer-redacted UI snapshot.

The state and operation context are bound as follows:

```text
state_digest = SHA256(
  "OpenSlay/random-state/v1"
  || canonical_json(authoritative_pre_operation_state)
)

context_digest = SHA256(
  "OpenSlay/random-context/v1"
  || canonical_json({
       format_version, algorithm, operation_sequence,
       operation, purpose, purpose_counter, scope, inputs,
       state_digest, previous_audit_hash
     })
)
```

One semantic operation then obtains 256-bit blocks from:

```text
HMAC-SHA256(
  key=master_seed,
  message="OpenSlay/random-stream/v2"
          || bytes.fromhex(context_digest)
          || uint32_be(block_index)
)
```

`block_index` begins at zero inside each operation. Bounded integers use
rejection sampling: accept a 256-bit value only when it is below
`2^256 - (2^256 mod bound)`, then return `value mod bound`.

- `probability`: draw in `[0, denominator)` and test `draw < numerator`.
- `choice`: draw an index into the recorded candidate list.
- `sample`: repeatedly draw and remove an index from the remaining indices.
- `shuffle`: perform descending Fisher–Yates swaps.

For the current prototype ruleset, an authoritative deck epoch must contain
144 cards. After replacing its contiguous runtime `card_id` values with
`1..144`, the candidates' canonical JSON SHA-256 must equal
`8f4503267ca0c9d2fe0a8835121ab2cc9c4b79165ea64641f562f15a8c6ffc39`.
The complete public candidate list ships in `data/prototype-deck-v1.json`.

## Transcript chain

Canonical JSON uses UTF-8, sorted object keys, no insignificant whitespace, no
floating-point numbers, and integers restricted to the JSON-safe range.
The standalone Python JSONL loader rejects duplicate object keys while parsing.
Floating-point values are rejected when canonical verification traverses
covered randomness content, not by a loader-wide pre-pass. The Godot UI first
passes raw JSON through the engine parser, which can collapse duplicate keys and
integral-valued floating-point lexemes before its verifier sees them. Untrusted
raw transcripts therefore require the strict standalone CLI; the client-side
result is not equivalent at this raw-syntax boundary.

Every typed record extends the previous hash:

```text
SHA256(
  "OpenSlay/random-audit-chain/v1"
  || bytes.fromhex(previous_hash)
  || utf8(canonical_json({"record_type": type, "context": context}))
)
```

The manifest begins at 32 zero bytes. An operation excludes its
`previous_audit_hash` and `audit_hash` fields from the context passed to this
formula. The reveal excludes `final_audit_hash`.

Each operation record contains the full canonical `state`, `state_digest`, and
`context_digest`. Verification recomputes both digests before recomputing the
HMAC result. Live checkpoints contain no raw hidden-state fields, but their
heads digest records containing state; semantic concealment against inference
from those heads is not proved.

## Action-tree property

State binding removes the fixed schedule in which the Nth use of one purpose
always consumes the same random value. When accepted actions produce distinct
recorded pre-operation states or contexts, their descendants use different
streams; actions that converge to the same bound record need not diverge.
If decision point `t` has `b_t` legal continuations, a depth-`T` action tree can
contain approximately `b_1 * b_2 * ... * b_T` leaves. Drawing two cards per turn
continually changes the hand, timing, target, response, and combination choices,
so human-controlled branches commonly grow exponentially.

This is a computational obstacle to pre-game seed searching, not a proof that
the authoritative server can never predict a result. A server that knows the
master seed can evaluate any fully specified hypothetical state and may search
or prune the tree. Bot seats are not independent entropy when the server knows
their policy and policy RNG. The protocol therefore also requires pre-game
commitment, human contributions, monotonic action/operation order, no rollback
or reroll after action acceptance, and a terminal reveal.

The standalone cryptographic verifier proves that a result follows from the
recorded state and master seed. Proving that consecutive states are legal game
transitions additionally requires deterministic engine replay of the accepted
action log. Live checkpoint heads let a client detect replacement of its
retained prefix; they do not prevent alternative unseen suffixes or split views.

## Local witness

The client writes an opening `witness_header`, then flushes one
`randomness_checkpoint` for every operation before displaying state that claims
that checkpoint head. Format version 1 rejects missing or extra fields. The
header contains exactly `record_type`, `format_version`, `match_id`, and `mode`,
plus `numeric_seed` and `public_randomness_input` in training mode, or
`ruleset_hash`, `server_commitment`, `seat_id`, `public_randomness_input`,
`client_nonce`, and `contribution` in online mode. Each checkpoint contains
exactly:

- `record_type`
- `format_version`
- `match_id`
- JSONL `log_sequence`
- `operation_sequence`
- `previous_audit_hash`
- `audit_hash`

Terminal verification requires every checkpoint to equal the corresponding
terminal transcript operation. This establishes equality with the supplied
checkpoints only. Treating them as stored during play requires trusted,
non-rewritable local provenance; they are not a third-party timestamp or public
notary.

## Public rules

The cryptographic verifier proves that reported results follow from recorded
inputs. An optional JSON rule descriptor can additionally constrain those
inputs using public card and skill descriptions. The descriptor is data, not
engine source. Its reproducible hash is:

```text
SHA256("OpenSlay/public-rules/v1" || canonical_json(descriptor_without_hash))
```

Version-2 game transcripts do not yet require a `public_rules_hash`. When a
descriptor is supplied, its rules check passes, and the manifest contains the
matching field, that field computationally binds the parsed canonical descriptor
payload excluding `public_rules_hash` within the supplied transcript under
SHA-256 collision resistance. A
descriptor's self-hash alone provides no transcript or pre-receipt binding;
`compatible_ruleset_hashes` is merely a descriptor-side compatibility claim
unless the descriptor is authenticated externally.
