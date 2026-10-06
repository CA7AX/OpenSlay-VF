# Changelog

All notable changes to the public verifier are recorded here. Package releases
follow semantic versioning independently from transcript protocol versions.

## Unreleased

- Add the deck ledger (`deck_ledger_version` 1). An oracle deck now records every draw, skill inspection, and restore; each operation state carries the moves since the previous operation, and the reveal carries `deck_ledger_tail`.
- Replay those moves on one draw pile across epochs: every draw must take the top card, restores must return only cards under the same player's open inspection, an epoch may only be shuffled once the pile is empty, and every `engine` state's `zones.draw_pile` must equal the replayed pile.
- Report `deck_moves_verified` in JSON, the CLI, and the verified summary.
- Breaking for verdicts: an oracle-deck transcript without a supported deck ledger declaration is now `Unverified`, because its deck order is proved but its dealing is not. The transcript wire format remains protocol v2.

## 0.3.1 - 2026-10-05

- Describe the 5p/8p hidden identity deal (`setup.identity`): only the two public role lists, in fixed order, with the lord excluded from the shuffle.
- Reject reordered roles, incorrect counts, lord-containing or empty lists, and non-shuffle identity operations without changing the transcript format or verifier code.

## 0.3.0 - 2026-10-02

- Cover all 73 current random purposes with a new bundled format-2 public rules descriptor; retain the immutable historical v1 partial descriptor.
- Check fixed probabilities and choice pools, roster candidates/counts, complete recorded hand/equipment/debuff/neighbor pools, living redirect membership, and state-dependent horse/environment numerators.
- Keep unknown purposes and unavailable required pre-operation state Partial; report missing-state purposes separately and reject malformed or inconsistent evidence.
- Add cryptographically consistent wrong-input tests without changing protocol-v2 encodings, seed derivation, streams, or transcript verification.

- Adopt the water-ink OpenSlay emblem and a new verifier README hero.
- Reorganize the English and Chinese project guides around verification scope,
  protocol flow, result semantics, and public code ownership.
- Extend the source boundary gate with strict, exact-path PNG validation for
  the two public brand assets.
- Complete the normative protocol wire schemas and bounded-draw proof format so
  independent implementations do not depend on unstated Python behavior, and
  require `state_version` to use the exact JSON integer type.
- Correct nonce disclosure, witness provenance, audit-hash scope, CLI exit-code,
  directory discovery, truncation, and example-output documentation.
- Prevent decoded transcripts from spoofing loader-only truncation markers, and
  make complete-witness report text state only the equality actually checked.
- Require private vulnerability reporting to remain available at release time.

## 0.2.1 - 2026-08-09

- Bootstrap the verifier as an independently maintained public repository.
- Keep bilingual CLI output UTF-8 on legacy Windows console code pages.
- Add standalone CI, distribution auditing, reproducible-build checks, and
  guarded GitHub release automation.
- Clarify that the bundled rules descriptor is partial and that protocol test
  secrets are synthetic public fixtures.

## 0.2.0 - 2026-08-03

- Internal evaluated snapshot of the protocol-v2 standalone verifier.
