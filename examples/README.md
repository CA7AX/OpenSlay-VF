# Example trajectories: one honest, one forged

[简体中文](README.zh-CN.md)

This folder holds two randomness transcripts from the same OpenSlay match. One
is exactly what the game wrote. The other is a careful forgery: it flips a roll
that leaves the match result unchanged, then repairs everything it can without
the seed. This guide shows how to verify both and why the verifier still
catches the forgery.

| File | What it is | Expected status | Exit code |
| --- | --- | --- | ---: |
| [`training-2v2-seed42.valid.json`](training-2v2-seed42.valid.json) | The transcript as recorded | `Verified deterministic` | `0` |
| [`training-2v2-seed42.tampered-careful.json`](training-2v2-seed42.tampered-careful.json) | The last roll flipped, with its proof, the deck ledger, and the hashes repaired to match | `Invalid` at sequence `582` | `1` |

## Where the match came from

The match is synthetic. Four rule-based bots played a 2v2 training match
(貂蝉 and 太史慈 against 庞统 and 孙权) with numeric seed `42` and public
randomness input `雪`. No person played it. Blue (庞统 and 孙权) won.

The files are compact transcripts: a JSON object whose `records` list holds
only the randomness records from the game log. These are one
`randomness_manifest`, 22 `randomness` operations, and one `randomness_reveal`.
Each `sequence` is the record's line number in the original game log, so the
numbers have gaps. Every operation keeps the engine state it was bound to,
which is why the files are large (about 740 KB each). The records were made
under the 2026-10 balance odds. None of their rolls changed in the 2026-11
pass, so they still check against the bundled rules. A transcript that uses a
changed roll needs `--rules openslay-prototype-v3`.

A training transcript discloses its seed. Anyone can recompute every roll, so
the transcript proves it is internally consistent and reproducible. It does not
prove the server was honest; the online protocol adds the commitment and player
nonces for that. See [what verification does not prove](../README.md#-what-it-verifies).

## The forgery

The forgery flips one roll. The roll is chosen so that the rest of the
transcript still tells a consistent story, and every value the flip touches is
repaired. Flipping a result alone would break that record's audit hash, which
anyone can check without the seed.

**Why the last roll.** Each roll draws its HMAC block from a context digest,
and that digest covers the previous record's audit hash. Changing any roll
therefore changes the block of every roll after it. Record `582` is the last
of the 22 rolls, so only the reveal comes after it.

**Why this roll.** In round 22, 孙权's skill 江左雄略 rolled a 1-in-2 chance
to draw an extra card. It succeeded, and he drew card 100 (摧锋♣), which he
never played. He killed 貂蝉 with the 杀♦ he had drawn just before the roll,
and that ended the match. Had the roll failed, Blue would still have won on the
same turn with the same 杀. We checked this by rerunning the match with the
roll forced to fail. The battle log lost one line, `[孙权] 摸了1张牌`, and
nothing else changed.

**What it changes.** Seven values differ from the honest file:

| Field | Honest | Forgery | Why |
| --- | --- | --- | --- |
| Roll `result` | `true` | `false` | The flip |
| Roll `proof.draw` | `0` | `1` | Agrees with the new result |
| Roll `proof.draws[0].raw_value` | `…4228ee` | `…4228ef` | An odd block gives draw `1` |
| Roll `audit_hash` | `5fb9d140…` | `25c5f087…` | Recomputed |
| Reveal `sequence` | `596` | `593` | The draw's three log lines are gone |
| Reveal `deck_ledger_tail` | 孙权 draws card 100 | empty | A failed roll draws no card |
| Reveal `final_audit_hash` | `09bee980…` | `31390c5c…` | Recomputed |

The hash function is public, so anyone can recompute the two hashes. The
forced-failure rerun produced this exact file, byte for byte. It is what the
game would have recorded if that one HMAC block had been odd.
[`tests/test_examples.py`](../tests/test_examples.py) rebuilds it from the
honest file with the edits above.

The forger left the roll's state and scope alone, so its context digest is
unchanged. That is what gives it away (step 5).

## Verify them yourself

### 1. Install

You need Python 3.10 or newer. There are no other dependencies.

```bash
git clone https://github.com/CA7AX/OpenSlay-VF.git
cd OpenSlay-VF
python -m pip install -e .
```

Run every command below from the repository root.

### 2. See what changed

```bash
diff examples/training-2v2-seed42.valid.json examples/training-2v2-seed42.tampered-careful.json
```

The diff prints the seven changes in the table above. On Windows, use `fc`
instead of `diff`.

### 3. Verify the honest transcript

```bash
openslay-rng-verify examples/training-2v2-seed42.valid.json --rules bundled --language en
```

```text
Verification status: Verified deterministic
Summary: Verified deterministic: 22 random operations, 1 deck epoch(s), and 59 deck move(s) verified.
Random operations: 22
Deck epochs verified: 1
Deck moves verified: 59
Final audit hash: 09bee98039744b8a1d4a3c4dbf146a88e5f86818428e86d64e7a2eb0017ed5a9

Public rules: Verified
Summary: All 22 random operation(s) match the public rules descriptor.
```

The sample outputs in this guide leave out the report header, the transcript
path, and the rules detail lines.

The exit code is `0`. The verifier rebuilt the training master seed from `42`
and `雪`. It then recomputed all 22 operations, including the 144-card deck
shuffle, and replayed all 59 draws against that shuffle. It also rebuilt the
hash chain up to the final audit hash and checked every operation's inputs
against the public rules.

### 4. Verify the forgery

```bash
openslay-rng-verify examples/training-2v2-seed42.tampered-careful.json --rules bundled --language en
```

```text
Verification status: Invalid
Summary: Invalid randomness transcript at JSONL sequence 582 (skill.wu.sun-quan.draw-phase.flood-extra-card): result does not match the HMAC-derived operation
Random operations: 21
Deck epochs verified: 1
Deck moves verified: 56
Failure record sequence: 582
Failure operation: 22
Failure purpose: skill.wu.sun-quan.draw-phase.flood-extra-card
Final audit hash: 31390c5cb0828586d2dca21f268a18875fe3ac1a8ec9b1307ceff97e35eb051a

Public rules: Invalid
Summary: Rule inputs cannot be trusted because transcript verification failed.
```

The exit code is `1`. The report names the exact record, operation, and
purpose that were changed. The file passes every check that does not need the
seed: each record's structure and digests, the audit chain, and the reveal's
final hash. The verifier then derives the seed and recomputes the rolls in
order. The first 21 rolls and 56 deck moves match. The 22nd does not, because
the seed gives a different HMAC block for this context than the one the forger
stored. The rules check also fails, because rule inputs from a broken
transcript cannot be trusted.

The `Final audit hash` line shows the hash the forged reveal claims. It
differs from the honest `09bee980…`, so anyone who kept the hash shown at the
end of the match can spot the change without running the verifier.

Leave out `--language en` for the default Chinese and English report. Add
`--json` for a stable, machine-readable report.

```bash
openslay-rng-verify examples/training-2v2-seed42.tampered-careful.json --json
```

The JSON report has `"status": "Invalid"`, `"failure_sequence": 582`, and
`"exit_code": 1` under `verification`.

### 5. Recompute the roll by hand

You do not have to take the verifier's word for it. This script recomputes
record 582 from the disclosed seed, using only the public protocol primitives:

```python
import json
from openslay_rng_verifier.protocol import HMACStream, derive_training_master_seed

with open("examples/training-2v2-seed42.tampered-careful.json", encoding="utf-8") as handle:
    records = json.load(handle)["records"]
reveal = records[-1]["context"]
roll = next(r["context"] for r in records if r["sequence"] == 582)

seed = derive_training_master_seed(
    int(reveal["numeric_seed"]), reveal["public_randomness_input"]
)
stream = HMACStream(seed, context_digest=bytes.fromhex(roll["context_digest"]))
draw, proof = stream.bounded(roll["inputs"]["denominator"])

print("recorded:", roll["result"])                        # False (forged)
print("recomputed:", draw < roll["inputs"]["numerator"])  # True
print("same HMAC block:", proof["raw_value"] == roll["proof"]["draws"][0]["raw_value"])  # False
```

The recorded result agrees with the stored block, but the stored block is not
the one the seed gives for this context. The honest block ends in `…ee`. It is
even, so the draw is `0`. The roll succeeds when the draw is below
`numerator = 1`, so it succeeded.

The full verifier also recomputes `context_digest` from the canonical scope,
state, inputs, and previous audit hash, so the forger cannot pick a different
context to get a lucky block.

## What it would take to repair the forgery

- **Rewrite the hashes and the stored block.** This forgery does both, and the
  recomputed roll still exposes it.
- **Change the seed.** Every operation, the deck order, and all 59 deck moves
  change with it. That is a different match, not a small edit to this one.
- **Change the recorded state or scope until the HMAC block gives the result
  you want.** The roll is bound to its state, so this needs a different state.
  The verifier checks the draw pile in every state against the deck replay,
  but it does not check that other state, such as hands or rage, follows the
  game rules. Such a forgery can pass this verifier on its own. It still
  changes the final audit hash. Anyone who kept the hash shown at the end of
  the match, or a local witness sidecar, sees the mismatch.

In an online match the seed comes from a server secret committed before play,
mixed with each human's nonce. The server cannot pick a convenient seed after
the commitment is published. See [SPEC.md](../SPEC.md) for the exact
derivation.

## Make your own forgery

[`trial_tamper`](../witness.py) changes one operation's result in an in-memory
copy and returns the failed report. It reseals nothing, so it fails on the
audit hash before the verifier uses the seed:

```python
from openslay_rng_verifier import load_transcript, trial_tamper

records, _ = load_transcript("examples/training-2v2-seed42.valid.json")
_forged, report = trial_tamper(records, preferred_operation=5)
print(report.status, report.failure_sequence)  # Invalid 93
```

You can also edit a copy of the honest file by hand. Change a card in the
deck shuffle, a counter, or a hash, then run the verifier again.
