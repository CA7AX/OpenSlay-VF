# OpenSlay verifiable randomness v2

English | [简体中文](SPEC.zh-CN.md)

This document specifies the public computation and wire validation performed by
`openslay-rng-verify` for format version 2 and algorithm
`openslay-hmac-sha256-state-v2`. It deliberately does not specify or expose the
game engine. “Must” below describes a transcript that can receive a verified
status; explicitly documented extension fields remain permitted.

## Canonical values and binary encoding

### Canonical JSON

All contexts, states, inputs, results, proofs, receipt summaries, and descriptor
payloads covered by a digest use the following canonical JSON profile:

- The value domain is JSON `null`, booleans, strings, integers, arrays, and
  objects. Floating-point values and binary values are not permitted.
- Integers are restricted to the interoperable range
  `-(2^53-1)..2^53-1`. A boolean is not an integer.
- Strings contain Unicode scalar values, are encoded as strict UTF-8 without a
  byte-order mark, and are not Unicode-normalized.
- Object keys on the wire are strings. Canonical serialization sorts them
  lexicographically by Unicode code point; the parsed wire object need not
  already use that order. Implementations adapting integer map keys first
  convert them to ordinary base-10 strings and must reject collisions after
  conversion.
- Serialization uses no insignificant whitespace: commas and colons are the
  single-byte separators `,` and `:` with no adjacent spaces.
- Integers use their shortest decimal spelling. Strings escape quotation mark,
  reverse solidus, and U+0000 through U+001F as required by JSON; the short
  escapes `\b`, `\t`, `\n`, `\f`, and `\r` are used where applicable, and the
  remaining control characters use lowercase `\u00xx`. Solidus and all other
  Unicode scalar values are emitted unescaped as UTF-8.

Equivalently, for values already in this JSON subset, the reference
serialization is Python `json.dumps(value, ensure_ascii=False,
allow_nan=False, separators=(",", ":"), sort_keys=True)` after the validation
above. Hashing always canonicalizes the parsed value; the outer JSONL line need
not itself have sorted keys or minimal whitespace.

The standalone loaders reject duplicate object keys and non-finite JSON numeric
tokens while parsing both JSONL and compact JSON. Finite floating-point values
are rejected when canonical verification traverses covered randomness content,
not by a loader-wide pre-pass. The in-memory Godot verifier receives already
parsed values, cannot recover duplicate-key or numeric-lexeme distinctions, and
accepts integral-valued floats in that representation. The standard Godot
replay loader compensates for raw JSONL by preflighting duplicate keys and
canonical number tokens on claimed-randomness lines before invoking the
verifier. Callers that bypass that loader with parsed dictionaries do not gain
the same raw-syntax guarantee; the strict standalone CLI remains the independent
boundary for untrusted JSONL or compact JSON.

### Binary primitives

- `||` denotes raw byte concatenation. Quoted domain-separation strings in
  formulas are exactly the displayed ASCII bytes, with no length prefix or
  terminator. `utf8(value)` is strict UTF-8 with no length prefix.
- `text(value)` is strict UTF-8 prefixed by its unsigned 32-bit big-endian byte
  length.
- `uint32_be(value)` is an unsigned 32-bit big-endian integer.
- `int64_be(value)` is a signed 64-bit two's-complement big-endian integer.
- SHA-256 and HMAC-SHA256 outputs are raw 32-byte strings inside formulas and
  lowercase 64-character hexadecimal strings in JSON. Decoding hexadecimal
  precedes any binary concatenation.
- `server_secret` and every human `client_nonce` are exactly 32 bytes. Their
  JSON representations are lowercase 64-character hexadecimal strings, as are
  `server_commitment` and `contribution`.
- A seat and an HMAC block index are in `0..2^32-1` and use `uint32_be` when a
  formula encodes them.
- A `purpose_counter` is a non-negative canonical-JSON integer in
  `0..2^53-1`; it has no separate binary encoding.

Public randomness input removes only leading and trailing U+0020 SPACE, rejects
characters in Unicode general category `Cc`, and is limited to 64 UTF-8 bytes.
It is not Unicode-normalized. A transcript stores the already-normalized value.

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

`match_id` is a non-empty string. `ruleset_hash` is 64-character lowercase
SHA-256 hexadecimal text. The verifier checks the transcript's declared receipt
ordering; establishing that publication really occurred at that time requires
a retained client receipt and trusted provenance.

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

The online master seed uses human contributions in ascending `seat_id` order;
non-human seats contribute no bytes:

```text
SHA256(
  "OpenSlay/online-master-seed/v1"
  || text(match_id)
  || text(ruleset_hash)
  || server_secret
  || contribution_0 || contribution_1 || ...
)
```

The deterministic training master seed is:

```text
SHA256(
  "OpenSlay/training-master-seed/v1"
  || int64_be(numeric_seed)
  || text(public_input)
)
```

`numeric_seed` is in `-2^63..2^63-1`. In the training reveal it is encoded as a
JSON **string** containing its canonical decimal spelling: `0`, a positive
decimal without a sign or leading zero, or `-` followed by a non-zero decimal
without a leading zero. This preserves the complete signed-64-bit domain across
JSON implementations.

## Transcript record envelope

A full game JSONL may interleave unrelated records. A randomness record is an
outer JSON object with these validation rules:

| Field | Requirement |
| --- | --- |
| `sequence` | Required positive JSON-safe integer; randomness-record values strictly increase in file order, but need not be consecutive. |
| `record_type` | `randomness_manifest`, `randomness`, or `randomness_reveal`; at least this field or `category` must identify the record. |
| `category` | Optional alias for `record_type`; if present on a randomness record it must equal `record_type`/the identified type. |
| `format_version` | Optional at the outer level; if present it must be JSON integer `2`. |
| `context` | Required object containing the enclosed record specified below. |

Other outer fields such as `created_at` and `message` are permitted, ignored by
cryptographic verification, and not included in the audit hash. A conforming
producer should emit both `record_type` and `category` with the same value plus
outer `format_version = 2`. An unknown string beginning with `randomness` in
either type field is invalid rather than ignored.

Once any recognized v2 randomness record is present, there must be exactly one
manifest; it must precede every operation and reveal, and there may be at most
one reveal. Operation order is the file order of `randomness` records. The
reveal's outer `sequence` must follow the manifest and all operations. Absence
of a reveal is `Incomplete`; randomness operations or a reveal without a
manifest are `Invalid`. An otherwise valid input containing no recognized v2
randomness record is treated as a legacy seed-only log and returns `Unverified`.

## Manifest context

The `randomness_manifest` context contains the following common fields. Common
and mode-specific fields listed as required must be present. Other canonical
extension fields are allowed and are included in the manifest audit hash.

| Field | Requirement |
| --- | --- |
| `format_version` | JSON integer `2` |
| `algorithm` | `openslay-hmac-sha256-state-v2` |
| `mode` | `training`, `online`, or the explicitly unverified compatibility value `unverified` |
| `ruleset_hash` | 64-character lowercase hexadecimal digest |
| `match_id` | Non-empty string for `training` and `online` |
| `commitment_published_order` | `null` in training; non-negative JSON-safe integer online |
| `participants` | Empty array in training; ascending-seat receipt array online |
| `server_commitment` | `null` in training; 64-character lowercase hexadecimal digest online |
| `deck_source` | Must be `oracle` for a verified result; a missing or different value yields `Unverified` after all otherwise applicable checks. |
| `deck_ledger_version` | JSON integer `1` declares the [deck ledger](#deck-ledger). With `deck_source = oracle`, a missing or different value yields `Unverified` after all otherwise applicable checks. |

`public_rules_hash` may be present as an extension; its separate rules-layer
semantics are defined under [Public rules](#public-rules).

In compatibility mode `unverified`, only `format_version`, `algorithm`, `mode`,
and `ruleset_hash` are required by the verifier; the other manifest fields are
canonical extensions without verified derivation semantics.

### Online participant receipt

A conforming producer emits exactly these seven fields for every participant.
The angle-bracket strings below are schema metavariables, not literal wire
values:

```json
{
  "seat_id": 1,
  "driver_kind": "human",
  "public_randomness_input": "42",
  "client_nonce": "<64 lowercase hex>",
  "contribution": "<64 lowercase hex>",
  "commitment_received_order": 1,
  "accepted_order": 2
}
```

`seat_id` values are unique uint32 integers and the participant array is sorted
ascending by seat. `driver_kind` is a non-empty string. For
`driver_kind = "human"`, the remaining five fields are required: the public
input is normalized, nonce and contribution are lowercase 32-byte hexadecimal
values, both order fields are positive JSON-safe integers,
`commitment_received_order < accepted_order`, and both are greater than the
manifest's `commitment_published_order`. All receipt and accepted order values
across all humans are globally unique. The verifier recomputes each human
contribution.

For any other `driver_kind`, the seat is non-human and all five optional fields
must be JSON `null` (the verifier also accepts their omission as the equivalent
compact form). Non-human seats do not enter master-seed derivation.

## Operation context and state binding

Every `randomness` context has **exactly** these fields; missing or additional
fields are invalid:

```text
format_version, algorithm, operation_sequence, operation, purpose,
purpose_counter, scope, inputs, state, state_digest, context_digest,
result, proof, previous_audit_hash, audit_hash
```

Common constraints are:

- `format_version` is JSON integer `2`, and `algorithm` is
  `openslay-hmac-sha256-state-v2`.
- `operation_sequence` is the positive, gapless global operation index starting
  at 1. `purpose_counter` starts at 0 independently for each purpose and is
  gapless in file order.
- `purpose` is 2–128 ASCII characters matching
  `[a-z0-9][a-z0-9._:/-]{1,127}`.
- `previous_audit_hash`, `state_digest`, `context_digest`, and `audit_hash` are
  lowercase 64-character hexadecimal strings.
- `operation` is `probability`, `choice`, `sample`, or `shuffle`; its `inputs`,
  `result`, and `proof` must match the exact semantics below.

`scope` contains exactly these fields:

| Field | Type and constraint |
| --- | --- |
| `scope_id` | Non-empty string |
| `parent_scope_id`, `event_id`, `event`, `phase`, `skill` | String or `null` |
| `round` | Non-negative JSON-safe integer |
| `owner`, `actor` | JSON-safe integer or `null` |
| `targets` | Array of JSON-safe integers |

Before an operation, the engine records a canonical authoritative `state`
object. A conforming state has JSON integer `state_version = 1` and a non-empty
string `kind`; other canonical fields are permitted. OpenSlay engine states
include hidden card zones and active resolution state and are not viewer-redacted
UI snapshots. The verifier validates canonical form, `state_version`, `kind`,
and the digest; it does not prove completeness or legal transition from the
preceding state. When the manifest declares the [deck ledger](#deck-ledger),
the state field `deck_ledger` is reserved for it, and the verifier also replays
that field and checks an `engine` state's `zones.draw_pile`.

The state and operation context are bound as follows:

```text
state_digest = SHA256(
  "OpenSlay/random-state/v1"
  || utf8(canonical_json(authoritative_pre_operation_state))
)

context_digest = SHA256(
  "OpenSlay/random-context/v1"
  || utf8(canonical_json({
       format_version, algorithm, operation_sequence,
       operation, purpose, purpose_counter, scope, inputs,
       state_digest, previous_audit_hash
     }))
)
```

## HMAC stream and bounded draws

One semantic operation obtains 256-bit blocks from:

```text
HMAC-SHA256(
  key=master_seed,
  message="OpenSlay/random-stream/v2"
          || bytes.fromhex(context_digest)
          || uint32_be(block_index)
)
```

`block_index` begins at zero inside each operation and increments after every
attempt, including rejected values; it never wraps. Interpret the 32 HMAC bytes
as one unsigned **big-endian** integer `value`. For bound `b`, where
`1 <= b <= 2^256`, set:

```text
limit = 2^256 - (2^256 mod b)
```

Reject values `>= limit`; accept the first value below `limit` and return
`value mod b`. Every bounded draw has this exact proof object:

```json
{
  "upper_bound": 7,
  "block_index": 1,
  "raw_value": "0000000000000000000000000000000000000000000000000000000000000002",
  "rejected": [
    {"block_index": 0, "raw_value": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
  ]
}
```

The example field values are illustrative: `block_index` identifies the
accepted block, while `rejected` contains every preceding rejected block for
that draw in order and therefore cannot also contain the accepted index.
`raw_value` is the 32 HMAC bytes rendered directly as lowercase hexadecimal.
All bounds occurring in a valid semantic-operation transcript must themselves
fit canonical JSON.

## Semantic operations and proof layouts

Candidate values may be any canonical JSON values and may repeat. Every proof
object has exactly the fields shown; `blocks_used` is the operation stream's
next block index after all draws, i.e. the total number of accepted and rejected
blocks consumed by the operation. The examples below are schematic layouts:
their hexadecimal values illustrate the required structure and arithmetic but
are not claimed to be HMAC outputs for an unstated seed and context.

### `probability`

Inputs contain exactly `numerator` and `denominator`, both JSON integers, with
`0 <= numerator <= denominator <= 2^53-1` and `denominator > 0`. Draw
`d` in `[0, denominator)` and return `d < numerator`.

For schematic inputs `{"numerator":3,"denominator":7}`:

```json
{
  "result": true,
  "proof": {
    "draw": 2,
    "draws": [{"upper_bound": 7, "block_index": 0, "raw_value": "0000000000000000000000000000000000000000000000000000000000000002", "rejected": []}],
    "blocks_used": 1
  }
}
```

### `choice`

Inputs contain exactly non-empty array `candidates`. Draw one index in
`[0, len(candidates))`; the result is the candidate at that index.

For schematic inputs `{"candidates":["first","second","third"]}`:

```json
{
  "result": "second",
  "proof": {
    "selected_index": 1,
    "draws": [{"upper_bound": 3, "block_index": 0, "raw_value": "0000000000000000000000000000000000000000000000000000000000000001", "rejected": []}],
    "blocks_used": 1
  }
}
```

### `sample`

Inputs contain exactly array `candidates` and JSON integer `count`, with
`0 <= count <= len(candidates)`. Start with the remaining original indices
`[0, ..., n-1]`; repeatedly draw a relative index into that remaining list,
remove it, and append the removed original index to `selected_indices`. The
result is the candidates at those original indices in selection order.

For schematic inputs
`{"candidates":["first","second","third"],"count":2}`:

```json
{
  "result": ["third", "first"],
  "proof": {
    "selected_indices": [2, 0],
    "draws": [
      {"upper_bound": 3, "block_index": 0, "raw_value": "0000000000000000000000000000000000000000000000000000000000000002", "rejected": []},
      {"upper_bound": 2, "block_index": 1, "raw_value": "0000000000000000000000000000000000000000000000000000000000000000", "rejected": []}
    ],
    "blocks_used": 2
  }
}
```

For `count = 0`, all three arrays are empty and `blocks_used = 0`.

### `shuffle`

Inputs contain `candidates` and optionally object `metadata`, with no other
fields. An empty candidate array is permitted. Initialize
`permutation = [0, ..., n-1]`. For `i` descending from `n-1` through `1`, draw
`j` in `[0, i]`, swap `permutation[i]` and `permutation[j]`, and append `[i,j]`
to `swaps`. The result is the original candidates in final permutation order.

For schematic inputs `{"candidates":["first","second","third"]}`:

```json
{
  "result": ["third", "first", "second"],
  "proof": {
    "permutation": [2, 0, 1],
    "swaps": [[2, 1], [1, 0]],
    "draws": [
      {"upper_bound": 3, "block_index": 0, "raw_value": "0000000000000000000000000000000000000000000000000000000000000001", "rejected": []},
      {"upper_bound": 2, "block_index": 1, "raw_value": "0000000000000000000000000000000000000000000000000000000000000000", "rejected": []}
    ],
    "blocks_used": 2
  }
}
```

For zero or one candidate, `swaps` and `draws` are empty,
`permutation` is the identity list, and `blocks_used = 0`.

### Prototype deck epochs

A record claims a deck epoch when its purpose begins `deck.epoch.` or its
shuffle metadata contains `deck_epoch`; both claims must then be present and
agree. It must be a `shuffle` whose purpose is exactly `deck.epoch.N`, where
`N` starts at 1 and increments by one. Metadata contains exactly:

```json
{"deck_epoch": 1, "start_card_id": 1, "card_count": 144}
```

`start_card_id` starts at 1 and advances by 144 each epoch; `card_count` equals
the candidate count. Every epoch contains the bundled 144-card prototype in
its authoritative pre-shuffle order with contiguous runtime `card_id` values.
After replacing those IDs with `1..144`,
`SHA256(utf8(canonical_json(candidates)))` is
`8f4503267ca0c9d2fe0a8835121ab2cc9c4b79165ea64641f562f15a8c6ffc39`.
The complete public candidate list ships in `data/prototype-deck-v1.json`.

### Deck ledger

A manifest with JSON integer `deck_ledger_version = 1` declares that every card
leaving or returning to the draw pile is recorded. Every operation `state` then
contains `deck_ledger`, an array of the moves since the previous operation (or
since the manifest, for the first operation), and the reveal contains
`deck_ledger_tail`, an array of the moves after the last operation. Existing
digests bind both: the state digest binds an operation's moves into its HMAC
context and audit hash, and the reveal binds the tail into `final_audit_hash`.
Each move has exactly one of these forms:

```json
{"move": "draw", "card_id": 17, "player_id": 2}
{"move": "take", "card_id": 18, "player_id": 1}
{"move": "restore", "card_ids": [19, 18], "player_id": 1}
```

Card ids are positive JSON-safe integers, `card_ids` contains no duplicates, and
`player_id` is a uint32 or `null`. `draw` moves a card into a hand; `take`
removes it for a skill inspection; `restore` returns inspected cards.

The verifier replays one draw pile across all epochs. The pile is ordered bottom
first, so its last element is drawn next, which is also the order of a shuffle
`result`:

1. Before each operation, apply its `deck_ledger` in order. `draw` and `take`
   require `card_id` to equal the top card's `card_id` and remove that card.
   `take` adds the card to the open inspection, and every take in one
   inspection names the same `player_id`. `draw` closes any open inspection.
2. `restore` requires an open inspection with the same `player_id`, and every
   id must name a card taken during that inspection. The cards are placed on
   top so that `card_ids[0]` is drawn next, and the inspection closes. Taken
   cards that are not restored stay out of the pile.
3. If the operation's `state.kind` is `engine`, `state.zones.draw_pile` must be
   present and equal the replayed pile exactly, card objects included.
4. A deck-epoch shuffle requires the replayed pile to be empty; its `result`
   becomes the new pile.
5. After the last operation, apply `deck_ledger_tail`.

Any violation is `Invalid`. A successful replay proves that every draw took the
top card of a verified shuffle, that no epoch was reshuffled early, and that each
recorded engine draw pile changed only through declared moves. It does not
prove that an inspection was triggered legally, that a restore order was the
inspecting player's choice, or that a drawn card reached the named hand; those
require engine replay of the accepted-action log. Moves after the last
operation are bound only by the terminal reveal, not by any live checkpoint.

## Transcript hash chain

Every randomness record extends the previous hash:

```text
SHA256(
  "OpenSlay/random-audit-chain/v1"
  || bytes.fromhex(previous_hash)
  || utf8(canonical_json({"record_type": type, "context": context}))
)
```

The manifest begins at 32 zero bytes. Its complete context, including extension
fields, is hashed. For an operation, remove `previous_audit_hash` and
`audit_hash` from its context before applying the formula; the first formula
argument is its declared previous head. Store the result as `audit_hash`. For
the reveal, remove only `final_audit_hash`; store the result as
`final_audit_hash`. The full reveal context therefore binds the revealed seed
material, outcome, receipt summary, operation count, and extensions.

Each operation stores the full canonical `state`, `state_digest`, and
`context_digest`. Verification recomputes both digests, every HMAC block,
result, complete proof object, and every audit-chain head. Live checkpoints
contain no raw hidden-state fields, but their heads digest records containing
state; semantic concealment against inference from those heads is not proved.

## Reveal contexts and readiness receipts

Every `randomness_reveal` context uses these common fields, required except where
the table says optional. Other canonical extension fields are allowed and
included in `final_audit_hash`.

| Field | Requirement |
| --- | --- |
| `format_version` | JSON integer `2` |
| `algorithm` | `openslay-hmac-sha256-state-v2` |
| `mode` | Exactly the manifest mode |
| `outcome` | `completed` or `aborted` |
| `reason` | Optional; if present, string or `null` |
| `operation_count` | Non-negative JSON-safe integer equal to the number of operation records |
| `receipt_summary` | Object; mode-specific requirements below |
| `deck_ledger_tail` | Required array when the manifest declares deck ledger version 1; see [Deck ledger](#deck-ledger) |
| `final_audit_hash` | Lowercase 64-character hexadecimal reveal-chain head |

### Training reveal

The reveal additionally requires `numeric_seed` as canonical signed-64-bit
decimal **string** and normalized string `public_randomness_input`.
`server_secret` must be absent. `receipt_summary` is required to be an object,
but version 2 imposes no required training-summary keys; `{}` is valid and any
canonical extension fields are hash-bound.

### Online reveal

The reveal additionally requires `server_secret` as lowercase hexadecimal for
exactly 32 bytes. `numeric_seed` and `public_randomness_input` must both be
absent. `receipt_summary` requires at least these fields; additional canonical
fields are allowed and hash-bound:

| Field | Requirement |
| --- | --- |
| `match_id` | Exactly the manifest `match_id` |
| `winner_ids` | Array whose elements are uint32 player IDs; version 2 does not require sorting or uniqueness |
| `required_seats` | Sorted, unique array of uint32 human seats required before start |
| `accepted_seats` | Sorted, unique subset of `required_seats` |
| `start_delivered_seats` | Sorted, unique subset of both `required_seats` and `accepted_seats` |
| `contributions_complete` | Boolean equal to `(accepted_seats == required_seats)` |

The sorted human seats in the manifest participant receipts must equal
`accepted_seats`. Readiness is complete exactly when
`contributions_complete` is true and
`start_delivered_seats == required_seats`.

If readiness is incomplete, `outcome` must be `aborted`. Such a transcript is
`Incomplete` only when it contains zero random operations and declares
`operation_count = 0`; an incomplete-readiness transcript containing an
operation is `Invalid`. Complete readiness permits either terminal outcome—the
randomness verifier does not certify match completion.

### Unverified compatibility reveal

Mode `unverified` adds no derivation-specific reveal fields. The common fields,
canonical form, record ordering, and audit chain remain required; other
canonical fields are extensions. As detailed below, the verifier returns before
receipt, seed, HMAC-result, or deck-epoch recomputation.

## Verification completion semantics

Verification completion follows these branches:

- Mode `unverified` yields `Unverified` after canonical structure, ordering,
  digest, audit-chain, and reveal checks; the verifier does not reconstruct a
  receipt or seed and does not recompute HMAC results or deck epochs on this
  compatibility branch.
- In `training` or `online` mode, after receipt, seed, and operation
  recomputation, a manifest `deck_source` other than `oracle` or a canonical
  field named `unverified_adapter` anywhere in the manifest, an operation
  context, or the reveal context yields `Unverified` rather than a verified
  claim.
- With `deck_source = oracle`, a manifest whose `deck_ledger_version` is missing
  or is not JSON integer `1` yields `Unverified`: the deck order may be proved,
  but dealing is not. With version 1, the [deck ledger](#deck-ledger) replay
  must succeed; a failure is `Invalid` regardless of `deck_source`.
- A verified transcript must contain at least one valid prototype deck epoch.
  An aborted transcript with no epoch is `Incomplete`; a completed oracle-deck
  transcript with no epoch is `Invalid`.
- A successful online transcript is `Verified fair`; a successful training
  transcript is `Verified deterministic`. These names establish the internal
  protocol consistency described here, not entropy quality, server honesty,
  legal game-state transitions, or match completion.

## Action-tree property

State binding removes the fixed schedule in which the Nth use of one purpose
always consumes the same random value. Assuming no SHA-256 collision, when
accepted actions produce distinct recorded pre-operation states or contexts,
their descendants use distinct HMAC messages; actions that converge to the same
recorded binding need not diverge. If decision point `t` has `b_t` legal
continuations, a depth-`T` action tree can contain approximately
`b_1 * b_2 * ... * b_T` leaves. Drawing two cards per turn continually changes
the hand, timing, target, response, and combination choices, so human-controlled
branches commonly grow exponentially.

This is a computational obstacle to pre-game seed searching, not a proof that
the authoritative server can never predict a result. A server that knows the
master seed can evaluate any fully specified hypothetical state and may search
or prune the tree. Bot seats are not independent entropy when the server knows
their policy and policy RNG. Online derivation therefore requires the pre-game
server commitment and a contribution for every human seat; an all-bot online
match relies solely on the committed server secret, while training is
deterministic. The transcript enforces gapless random-operation order and a
terminal reveal. Preventing action grinding additionally requires the game
integration to maintain monotonic accepted-action order and prohibit rollback
or reroll after acceptance; this standalone verifier cannot certify those
requirements because it has no accepted-action log.

The standalone cryptographic verifier proves that a result follows from the
recorded state and master seed. Proving that consecutive states are legal game
transitions additionally requires deterministic engine replay of the accepted
action log. Live checkpoint heads let a client detect replacement of its
retained prefix; they do not prevent alternative unseen suffixes or split
views. Declared receipt order numbers likewise are not timestamps or signed
third-party receipts.

## Local witness

The client writes an opening `witness_header`, then flushes one
`randomness_checkpoint` for every operation before displaying state that claims
that checkpoint head. Witness format version 1 rejects missing or extra fields.
The header has `record_type = "witness_header"`, JSON integer
`format_version = 1`, the verified manifest's non-empty `match_id`, and mode
`training` or `online`. It contains exactly those four fields plus
`numeric_seed` and `public_randomness_input` in training mode, or `ruleset_hash`,
`server_commitment`, `seat_id`, `public_randomness_input`, `client_nonce`, and
`contribution` in online mode. The training seed and public input are strings
equal to the verified reveal; the seed is therefore the same canonical decimal
string. Online `ruleset_hash` and `server_commitment` equal the verified
manifest, `seat_id` is uint32 and identifies its human participant, and the
three participant strings equal that receipt. Each checkpoint contains exactly:

- `record_type` = `randomness_checkpoint`
- `format_version` = 1
- `match_id`
- JSONL `log_sequence`
- `operation_sequence`
- `previous_audit_hash`
- `audit_hash`

Operation sequence starts at 1 and is gapless; log sequence is positive,
JSON-safe, and strictly increasing. Hashes are lowercase 64-character
hexadecimal strings, and each checkpoint after the first names the preceding
checkpoint's `audit_hash`.

A `Complete` witness result requires the terminal transcript itself to be
verified and checkpoints to match its operations one-for-one in order.
The header is also cross-checked against the verified manifest, reveal, and
participant receipt. Per-checkpoint equality covers `match_id`, outer
`log_sequence`, `operation_sequence`, `previous_audit_hash`, and `audit_hash`.
This establishes equality with the supplied checkpoints only. Treating them as
stored during play requires trusted, non-rewritable local provenance; they are
not a third-party timestamp or public notary. A sidecar reconstructed after the
match can satisfy the data checks but does not establish live observation. The
displayed five-group short fingerprint is only the first 80 bits of the 256-bit
final audit hash: it is a manual mismatch aid, and equality of short
fingerprints does not establish equality of the full hashes.

## Public rules

The cryptographic verifier proves that reported results follow from recorded
inputs. An optional JSON rule descriptor can additionally constrain those
inputs using public card and skill descriptions. The descriptor is data, not
engine source. Its reproducible hash is:

```text
SHA256("OpenSlay/public-rules/v1" || utf8(canonical_json(descriptor_without_hash)))
```

Version-2 game transcripts do not require a `public_rules_hash`. When a
descriptor is supplied, its rules check passes, and the manifest contains the
matching field, that field computationally binds the parsed canonical
descriptor payload excluding `public_rules_hash` within the supplied
transcript under SHA-256 collision resistance. A descriptor's self-hash alone
provides no transcript or pre-receipt binding; `compatible_ruleset_hashes` is
merely a descriptor-side compatibility claim unless the descriptor is
authenticated externally.

### Public descriptor format 2 (package 0.3.0)

Descriptor formats 1 and 2 use the unchanged `OpenSlay/public-rules/v1` self-hash formula. This is a descriptor extension, not a transcript protocol change; format-1 descriptors remain supported. Format 2 requires each selector to carry nonempty input, deck, candidate, or state constraints. Unknown rule fields and state kinds are rejected.

`candidate_constraints: {"ordered_subset_of": ["id", ...]}` requires a nonempty, duplicate-free subsequence of the public universe in the declared order. `state_constraints` declares one finite `kind`; it requires an engine snapshot (`state_version: 1`, `kind: "engine"`). Supported kinds are:

| Kind | Checked input |
| --- | --- |
| `owned_card_pool` | Complete sorted hand/horse keys, including player, zone, and index; player must occur in scope targets |
| `hand_pool` | Exact complete hand of one recorded player; discard count is positive and bounded by hand size |
| `horse_pool` | Complete sorted horse keys of the first scope target |
| `debuff_pool` | Complete sorted control/environment keys of the scope actor |
| `neighbor_hand_pool` | Complete sorted hand keys of the living upper/lower neighbor of the scope actor; requires `direction` |
| `redirect_targets` | Unique sorted living player IDs excluding scope actor and owner; distance and subset completeness are not checked |
| `horse_probability` | Numerator `min(4, 1 + horse count)` of scope owner, falling back to actor |
| `environment_counter` | Numerator `min(8, active_count)` for the first scope target; requires `effect` (`洪水` or `山火`) |

Malformed engine evidence or inconsistent inputs are `Invalid`. Unavailable engine state or required scope bindings are `Partial`, listed separately as `incomplete_purposes`; such operations do not increment `checked_operation_count`. Unknown purposes remain `Partial` when allowed by the descriptor. `Verified` means all supplied operations passed the declared finite input constraints. It does not authenticate snapshots, prove trigger/transition legality, or prove every candidate pool is complete where a rule checks membership only.
