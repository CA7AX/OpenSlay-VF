# Changelog

All notable changes to the public verifier are recorded here. Package releases
follow semantic versioning independently from transcript protocol versions.

## 0.6.0 - 2026-11-02

- Add the bundled `openslay-prototype-v4` descriptor (104 purposes) for the 2026-11 character balance pass and make it what `bundled` loads. `skill.wu.sun-ce.active.damage` moves from 3/4 to 1/2 and `skill.wei.cao-cao.active.lose-rage` from 1/2 to 1/4. New fixed odds are `skill.wei.yue-jin.active.draw-on-damage` (1/4) and `skill.wei.xun-you.control-card-resolved.recover-hp` (3/4). `skill.qun.hua-xiong.active.lose-rage` is removed. Its `public_rules_hash` is `33f4ff27895380ec7671cef35f01b8204a323e1a55d69707e3f1f9e0132fcd1d`.
- Keep `openslay-prototype-v3` unchanged. `load_ruleset` and `--rules` now also accept `openslay-prototype-v4`, so transcripts recorded before this balance pass still verify with `--rules openslay-prototype-v3`.
- Breaking for verdicts: against `bundled`, transcripts recorded under the v3 odds now return `Invalid` for the changed purposes. The transcript wire format remains protocol v2.
- Add [`examples/`](examples/README.md): a synthetic 2v2 training transcript (seed `42`, input `雪`) that verifies as `Verified deterministic` against the bundled rules, a forgery of it, and an English and Chinese guide to verifying both, including recomputing the flipped roll by hand. The forgery flips the last roll, which does not change the match result, and repairs its proof, the deck ledger tail, and both hashes. It passes every check that does not need the seed and fails as `Invalid` at sequence 582 when the roll is recomputed. None of its rolls changed between v3 and v4.

## 0.5.0 - 2026-10-24

- Add the bundled `openslay-prototype-v3` descriptor (103 purposes) for the 2026-10 character balance pass and make it what `bundled` loads. Twenty fixed skill odds move one 25% step (for example `skill.wu.sun-shang-xiang.active.damage` 3/4 → 1/2 and `skill.shu.fa-zheng.skill-card-target.cancel-card` 1/4 → 1/2), and 26 new fixed-odds purposes describe the new skill rolls, such as `skill.wei.yue-jin.active.gain-rage` (1/2) and `skill.qun.chen-gong.enter-dying.recover-hp` (3/4). Its `public_rules_hash` is `233f269af3013c53f8032356097afe20cb0cb2204cda9d634d3afb2236e04dae`.
- Keep `openslay-prototype-v2` unchanged. `load_ruleset` and `--rules` now also accept a bundled ruleset ID (`openslay-prototype-v1.partial`, `openslay-prototype-v2`, `openslay-prototype-v3`), so transcripts recorded before the balance pass still verify with `--rules openslay-prototype-v2`.
- Breaking for verdicts: against `bundled`, transcripts recorded under the v2 odds now return `Invalid` for the changed purposes. The transcript wire format remains protocol v2.

## 0.4.0 - 2026-10-20

- Describe the 5p/8p identity draft in the bundled v2 descriptor (77 purposes): `setup.seat` samples 1 to 8 entries from an ordered subset of `[0, ..., 7]` (lobby slots for an oversubscribed role, or free seats for a random slot), `setup.draft.lord-hand` samples two generals from exactly the roster without its 8 lord generals, and `setup.draft.hand` samples one to three generals from an ordered subset of the full roster, possibly more than once per seat. The descriptor's `public_rules_hash` becomes `14024aa1ef63e486531c1deb2e5d1dc4fd40f98e025131f71562ee00a67ba540`.
- Let `candidate_constraints.ordered_subset_of` hold JSON integers as well as strings. A universe must use one exact type and candidates must match it, so booleans and numeric strings are rejected. Older verifiers reject descriptors with integer universes as invalid.
- Rename the basic healing card 桃 to 杏 in the public prototype deck (8 cards). The deck digest changes to `5e928eaaf2112d84e92763ca467a38d37ffcb642d484c37bbe650980fad85b8f` and the bundled v2 descriptor's `public_rules_hash` to `af7614cc1f63122efc9e32ba3815e78b36c0c0f35b9c9d621a76e8f9c0146af9`. Breaking for verdicts: transcripts recorded with the old 桃 deck no longer match the bundled deck. The immutable historical v1 partial descriptor is unchanged.
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
