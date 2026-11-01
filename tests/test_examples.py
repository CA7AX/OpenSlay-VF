from __future__ import annotations

from pathlib import Path

from openslay_rng_verifier import (
    load_ruleset,
    load_transcript,
    verify_declared_rules,
    verify_records,
)
from openslay_rng_verifier.protocol import transcript_record_hash


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
VALID = EXAMPLES / "training-2v2-seed42.valid.json"
TAMPERED = EXAMPLES / "training-2v2-seed42.tampered-careful.json"
TAMPERED_SEQUENCE = 582


def _flip_last_roll_and_reseal(records: list[dict]) -> list[dict]:
    roll, reveal = records[-2]["context"], records[-1]["context"]
    roll["result"] = False
    roll["proof"]["draw"] = 1
    block = roll["proof"]["draws"][0]
    block["raw_value"] = f"{int(block['raw_value'], 16) ^ 1:064x}"
    # A failed roll draws no extra card, and the log loses that draw's lines.
    reveal["deck_ledger_tail"] = []
    records[-1]["sequence"] -= 3
    roll["audit_hash"] = transcript_record_hash(
        roll["previous_audit_hash"],
        "randomness",
        {k: v for k, v in roll.items() if k not in {"audit_hash", "previous_audit_hash"}},
    )
    reveal["final_audit_hash"] = transcript_record_hash(
        roll["audit_hash"],
        "randomness_reveal",
        {k: v for k, v in reveal.items() if k != "final_audit_hash"},
    )
    return records


def test_valid_example_verifies_against_bundled_rules() -> None:
    records, _ = load_transcript(VALID)
    report = verify_records(records)

    assert report.status == "Verified deterministic"
    assert report.operation_count == 22
    assert report.deck_moves_verified == 59
    assert report.final_audit_hash == (
        "09bee98039744b8a1d4a3c4dbf146a88e5f86818428e86d64e7a2eb0017ed5a9"
    )
    assert verify_declared_rules(report, load_ruleset("bundled")).status == "Verified"


def test_tampered_example_is_the_valid_file_with_its_last_roll_resealed() -> None:
    valid, _ = load_transcript(VALID)
    assert valid[-2]["context"]["result"] is True
    assert valid[-1]["context"]["deck_ledger_tail"] == [
        {"card_id": 100, "move": "draw", "player_id": 2}
    ]

    tampered, _ = load_transcript(TAMPERED)
    assert tampered == _flip_last_roll_and_reseal(valid)


def test_tampered_example_passes_seedless_checks_and_fails_on_the_roll() -> None:
    records, _ = load_transcript(TAMPERED)
    report = verify_records(records)

    assert report.status == "Invalid"
    assert report.exit_code == 1
    assert report.failure_sequence == TAMPERED_SEQUENCE
    assert report.failure_operation_sequence == 22
    assert report.summary.endswith("result does not match the HMAC-derived operation")
    # The chain and reveal hash held, so every earlier roll was recomputed.
    assert report.operation_count == 21
    assert report.deck_moves_verified == 56
