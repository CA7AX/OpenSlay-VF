# openslay-rng-verifier

English | [简体中文](README.zh-CN.md)

A standalone, engine-separated, standard-library-only generator and verifier
for OpenSlay randomness transcripts.

The library contains no game engine, character implementation, server,
matchmaking, UI, or private build source. It verifies the public protocol:

1. the pre-game commitment and player contributions;
2. every state-bound HMAC-SHA256 random operation and its proof;
3. canonical pre-operation state/context digests, per-purpose counters, global operation order, and the transcript hash chain;
4. the terminal reveal and final audit hash;
5. optionally, the local `randomness_witness` sidecar;
6. optionally, RNG inputs against a public data-only rules descriptor.

The protocol is documented in [SPEC.md](SPEC.md).

The package owns the protocol encodings, bounded HMAC stream, semantic random
operations, generic oracle, transcript verifier, witness checks, CLI, and
public data. It never imports the OpenSlay engine. Applications must pass an
explicit ruleset hash when constructing the generic oracle.

## Install and run from this repository

The repository root is also the Python package directory. Install it in
editable mode before invoking the module or console entry point:

```bash
python -m pip install -e .
openslay-rng-verify --version
```

```bash
python -m openslay_rng_verifier /path/to/match.jsonl
python -m openslay_rng_verifier /path/to/transcript.json --json
python -m openslay_rng_verifier /path/to/match.jsonl \
  --witness /path/to/randomness_witness/<match-hash>.jsonl
python -m openslay_rng_verifier /path/to/match.jsonl --rules bundled
python -m openslay_rng_verifier /path/to/match.jsonl --language zh
python -m openslay_rng_verifier /path/to/match.jsonl --language en
```

The `openslay-rng-verify` console command accepts the same arguments.

Human-readable CLI output is bilingual by default. Use
`--language bilingual`, `--language zh`, or `--language en` to select the
presentation language. `--json` remains language-neutral and retains its stable
machine-readable field names and status values.

Exit codes are `0` for a complete requested verification, `1` for invalid or
conflicting data, and `2` for incomplete, unverified, partial, or missing data.

The transcript argument may be:

- a full game JSONL replay;
- a compact JSON object containing `records`;
- a JSON list of transcript records;
- a directory, in which case the newest recognizable transcript is selected.

## Python API

```python
from openslay_rng_verifier import load_transcript, verify_records

records, resolved_path = load_transcript("match.jsonl")
report = verify_records(records)
print(report.status, report.final_audit_hash)
```

Human-facing Python integrations can use the same bilingual formatter without
changing the underlying report:

```python
from openslay_rng_verifier import format_human_report

print(format_human_report(report, language="bilingual"))
```

For the local witness:

```python
from openslay_rng_verifier import load_witness, verify_witness

header, checkpoints = load_witness("witness.jsonl")
witness = verify_witness(header, checkpoints, records)
print(witness.status, witness.short_fingerprint)
```

## What the result means

- `Verified fair`: online commitment, contributions, reveal, and operations all
  verify.
- `Verified deterministic`: a training match reproduces exactly from its
  declared seed and public input.
- `Complete` local witness: the terminal transcript also agrees with every
  checkpoint this client persisted during play.
- `Partial` public rules: described operations match, but the supplied public
  descriptor intentionally allows purposes it does not yet describe.

The local witness proves consistency with what one client received. It does not
prove that all clients received the same live history. Players can compare the
full final audit hash, or the five-group short seal, to detect divergent
terminal histories.

## Game rules without engine disclosure

A human can compare the transcript's purpose and inputs with the public card or
skill description. Programs can do the same with `operation_rules` in a public
descriptor. For example:

```json
{
  "operation": "probability",
  "purpose": "environment.thunder.self-damage",
  "input_constraints": {
    "numerator": {"equals": 1},
    "denominator": {"equals": 4}
  },
  "rule_reference": "环境牌 · 引雷"
}
```

This publishes the rule and probability, not the event engine that implements
them. The included prototype descriptor is explicitly partial until every
random purpose has a stable public description.

## Standalone distribution

This directory is a complete Python project with its own package metadata, MIT
license, specification, tests, public data, and console entry point. A wheel can
be built from this directory alone and installed without any OpenSlay package.
The `server_secret`, nonce, and ruleset hash in `test-vectors/` are synthetic,
public fixtures rather than deployed credentials.

All `0.x` releases are development prereleases. Before a stable `1.0` release,
publish the complete rules descriptor and bind its hash in the game transcript.
