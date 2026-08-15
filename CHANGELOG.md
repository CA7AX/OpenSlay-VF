# Changelog

All notable changes to the public verifier are recorded here. Package releases
follow semantic versioning independently from transcript protocol versions.

## Unreleased

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
