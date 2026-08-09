from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from openslay_rng_verifier import (
    VerificationReport,
    format_human_report,
    load_ruleset,
    localized_status,
    trial_tamper,
    verify_declared_rules,
    verify_records,
    verify_witness,
)
from openslay_rng_verifier.protocol import (
    HMACStream,
    MAX_SAFE_JSON_INTEGER,
    RANDOMNESS_ALGORITHM,
    RANDOMNESS_FORMAT_VERSION,
    ZERO_AUDIT_HASH,
    derive_online_master_seed,
    derive_player_contribution,
    derive_server_commitment,
    derive_training_master_seed,
    random_context_digest,
    random_state_digest,
    transcript_record_hash,
)
from openslay_rng_verifier.verifier import recompute_operation


ROOT = Path(__file__).resolve().parents[1]
RULESET_HASH = "11" * 32


def _scope() -> dict[str, Any]:
    return {
        "scope_id": "test:scope",
        "parent_scope_id": None,
        "event_id": None,
        "event": "test",
        "round": 0,
        "phase": None,
        "skill": None,
        "owner": None,
        "actor": None,
        "targets": [],
    }


def _training_records() -> list[dict[str, Any]]:
    public_deck = json.loads(
        (
            ROOT / "data" / "prototype-deck-v1.json"
        ).read_text(encoding="utf-8")
    )
    deck_candidates = public_deck["candidates"]
    manifest = {
        "format_version": RANDOMNESS_FORMAT_VERSION,
        "algorithm": RANDOMNESS_ALGORITHM,
        "mode": "training",
        "ruleset_hash": RULESET_HASH,
        "match_id": "training:standalone-test",
        "server_commitment": None,
        "commitment_published_order": None,
        "participants": [],
        "deck_source": "oracle",
    }
    master_seed = derive_training_master_seed(42, "test")
    previous = transcript_record_hash(
        ZERO_AUDIT_HASH, "randomness_manifest", manifest
    )
    records = [
        {
            "sequence": 1,
            "category": "randomness_manifest",
            "record_type": "randomness_manifest",
            "format_version": RANDOMNESS_FORMAT_VERSION,
            "context": manifest,
        }
    ]
    operation_specs = [
        (
            "shuffle",
            "deck.epoch.1",
            {
                "candidates": deck_candidates,
                "metadata": {
                    "deck_epoch": 1,
                    "start_card_id": 1,
                    "card_count": len(deck_candidates),
                },
            },
        ),
        ("probability", "environment.thunder.self-damage", {"numerator": 1, "denominator": 4}),
    ]
    for index, (operation, purpose, inputs) in enumerate(operation_specs, start=1):
        context = {
            "format_version": RANDOMNESS_FORMAT_VERSION,
            "algorithm": RANDOMNESS_ALGORITHM,
            "operation_sequence": index,
            "operation": operation,
            "purpose": purpose,
            "purpose_counter": 0,
            "scope": _scope(),
            "inputs": inputs,
            "state": {"state_version": 1, "kind": "test", "step": index},
            "result": None,
            "proof": {},
            "previous_audit_hash": previous,
            "audit_hash": ZERO_AUDIT_HASH,
        }
        context["state_digest"] = random_state_digest(context["state"])
        context["context_digest"] = random_context_digest(
            operation_sequence=index,
            operation=operation,
            purpose=purpose,
            purpose_counter=0,
            scope=context["scope"],
            inputs=inputs,
            state_digest=context["state_digest"],
            previous_audit_hash=previous,
        )
        expected = recompute_operation(master_seed, context)
        context.update(expected)
        chain_payload = dict(context)
        chain_payload.pop("previous_audit_hash")
        chain_payload.pop("audit_hash")
        context["audit_hash"] = transcript_record_hash(
            previous, "randomness", chain_payload
        )
        previous = context["audit_hash"]
        records.append(
            {
                "sequence": index + 1,
                "category": "randomness",
                "record_type": "randomness",
                "format_version": RANDOMNESS_FORMAT_VERSION,
                "context": context,
            }
        )
    reveal = {
        "format_version": RANDOMNESS_FORMAT_VERSION,
        "algorithm": RANDOMNESS_ALGORITHM,
        "mode": "training",
        "numeric_seed": "42",
        "public_randomness_input": "test",
        "outcome": "completed",
        "reason": None,
        "operation_count": 2,
        "receipt_summary": {"winner_ids": [0]},
    }
    reveal["final_audit_hash"] = transcript_record_hash(
        previous, "randomness_reveal", reveal
    )
    records.append(
        {
            "sequence": 4,
            "category": "randomness_reveal",
            "record_type": "randomness_reveal",
            "format_version": RANDOMNESS_FORMAT_VERSION,
            "context": reveal,
        }
    )
    return records


def _witness(records: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    header = {
        "record_type": "witness_header",
        "format_version": 1,
        "mode": "training",
        "match_id": "training:standalone-test",
        "numeric_seed": "42",
        "public_randomness_input": "test",
    }
    operations = [item for item in records if item["record_type"] == "randomness"]
    checkpoints = [
        {
            "record_type": "randomness_checkpoint",
            "format_version": 1,
            "match_id": "training:standalone-test",
            "log_sequence": record["sequence"],
            "operation_sequence": index,
            "previous_audit_hash": record["context"]["previous_audit_hash"],
            "audit_hash": record["context"]["audit_hash"],
        }
        for index, record in enumerate(operations, start=1)
    ]
    return header, checkpoints


def test_fixed_protocol_vectors() -> None:
    vectors = json.loads(
        (ROOT / "test-vectors" / "protocol-v2.json").read_text(encoding="utf-8")
    )
    value = vectors["derivation"]
    secret = bytes.fromhex(value["server_secret"])
    nonce = bytes.fromhex(value["client_nonce"])
    contribution = derive_player_contribution(
        value["match_id"], value["seat_id"], value["public_randomness_input"], nonce
    )
    assert contribution.hex() == value["player_contribution"]
    assert derive_server_commitment(
        value["match_id"], value["ruleset_hash"], secret
    ).hex() == value["server_commitment"]
    assert derive_online_master_seed(
        value["match_id"], value["ruleset_hash"], secret, [contribution]
    ).hex() == value["online_master_seed"]
    assert derive_training_master_seed(
        int(value["training_numeric_seed"]), value["training_public_randomness_input"]
    ).hex() == value["training_master_seed"]
    stream_value = vectors["hmac_stream"]
    stream = HMACStream(
        bytes.fromhex(stream_value["master_seed"]),
        context_digest=bytes.fromhex(stream_value["context_digest"]),
    )
    block, block_index = stream.next_uint256()
    assert block_index == stream_value["block_index"]
    assert f"{block:064x}" == stream_value["block_hex"]


def test_training_transcript_tamper_and_witness() -> None:
    records = _training_records()
    verification = verify_records(records)
    assert verification.status == "Verified deterministic"
    assert verification.operation_count == 2

    header, checkpoints = _witness(records)
    witness = verify_witness(header, checkpoints, records)
    assert witness.status == "Complete"
    assert witness.short_fingerprint != "—"

    oversized_sequences = copy.deepcopy(records)
    for offset, record in enumerate(oversized_sequences, start=1):
        record["sequence"] = MAX_SAFE_JSON_INTEGER + offset
    oversized_report = verify_records(oversized_sequences)
    assert oversized_report.status == "Invalid"
    assert "sequence must be a positive JSON-safe integer" in oversized_report.summary

    malformed_header = dict(header)
    malformed_header["record_type"] = "future_witness_header"
    assert verify_witness(malformed_header, checkpoints, records).status == "Invalid"
    malformed_header = dict(header)
    malformed_header["format_version"] = 999
    assert verify_witness(malformed_header, checkpoints, records).status == "Invalid"
    malformed_header = dict(header)
    malformed_header["format_version"] = 1.0
    assert verify_witness(malformed_header, checkpoints, records).status == "Invalid"
    malformed_header = dict(header)
    malformed_header["numeric_seed"] = 42
    assert verify_witness(malformed_header, checkpoints, records).status == "Invalid"
    malformed_header = dict(header)
    malformed_header["extension"] = "not permitted in witness format v1"
    assert verify_witness(malformed_header, checkpoints, records).status == "Invalid"
    malformed_header = dict(header)
    del malformed_header["public_randomness_input"]
    assert verify_witness(malformed_header, checkpoints, records).status == "Invalid"

    malformed_checkpoints = [dict(checkpoint) for checkpoint in checkpoints]
    malformed_checkpoints[0]["record_type"] = "future_randomness_checkpoint"
    assert verify_witness(header, malformed_checkpoints, records).status == "Invalid"
    malformed_checkpoints = [dict(checkpoint) for checkpoint in checkpoints]
    malformed_checkpoints[0]["format_version"] = 999
    assert verify_witness(header, malformed_checkpoints, records).status == "Invalid"
    malformed_checkpoints = [dict(checkpoint) for checkpoint in checkpoints]
    malformed_checkpoints[0]["format_version"] = 1.0
    assert verify_witness(header, malformed_checkpoints, records).status == "Invalid"
    malformed_checkpoints = [dict(checkpoint) for checkpoint in checkpoints]
    malformed_checkpoints[0]["operation_sequence"] = 1.0
    assert verify_witness(header, malformed_checkpoints, records).status == "Invalid"
    malformed_checkpoints = [dict(checkpoint) for checkpoint in checkpoints]
    malformed_checkpoints[0]["operation_sequence"] = 1.000001
    assert verify_witness(header, malformed_checkpoints, records).status == "Invalid"
    malformed_checkpoints = [dict(checkpoint) for checkpoint in checkpoints]
    malformed_checkpoints[0]["log_sequence"] = float(
        malformed_checkpoints[0]["log_sequence"]
    )
    assert verify_witness(header, malformed_checkpoints, records).status == "Invalid"
    malformed_checkpoints = [dict(checkpoint) for checkpoint in checkpoints]
    malformed_checkpoints[0]["log_sequence"] = MAX_SAFE_JSON_INTEGER + 1
    oversized_witness = verify_witness(header, malformed_checkpoints, records)
    assert oversized_witness.status == "Invalid"
    assert "invalid log sequence" in oversized_witness.summary
    malformed_checkpoints = [dict(checkpoint) for checkpoint in checkpoints]
    malformed_checkpoints[0]["extension"] = "not permitted in witness format v1"
    assert verify_witness(header, malformed_checkpoints, records).status == "Invalid"
    malformed_checkpoints = [dict(checkpoint) for checkpoint in checkpoints]
    del malformed_checkpoints[0]["audit_hash"]
    assert verify_witness(header, malformed_checkpoints, records).status == "Invalid"

    incomplete_records = records[:-1]
    malformed_header = dict(header)
    malformed_header["extension"] = "not permitted in witness format v1"
    assert (
        verify_witness(malformed_header, checkpoints, incomplete_records).status
        == "Invalid"
    )
    malformed_header = dict(header)
    del malformed_header["public_randomness_input"]
    assert (
        verify_witness(malformed_header, checkpoints, incomplete_records).status
        == "Invalid"
    )
    malformed_checkpoints = [dict(checkpoint) for checkpoint in checkpoints]
    malformed_checkpoints[0]["extension"] = "not permitted in witness format v1"
    assert (
        verify_witness(header, malformed_checkpoints, incomplete_records).status
        == "Invalid"
    )
    malformed_checkpoints = [dict(checkpoint) for checkpoint in checkpoints]
    del malformed_checkpoints[0]["audit_hash"]
    assert (
        verify_witness(header, malformed_checkpoints, incomplete_records).status
        == "Invalid"
    )

    interrupted_records = [
        *records,
        {
            "sequence": records[-1]["sequence"] + 1,
            "category": "randomness_truncated",
            "context": {"detail": "recognized interrupted JSONL tail"},
        },
    ]
    assert verify_witness(header, checkpoints, interrupted_records).status == "Incomplete"

    incomplete = verify_witness(header, checkpoints[:-1], records)
    assert incomplete.status == "Incomplete"
    assert incomplete.failure_operation_sequence == 2

    _copy, tampered = trial_tamper(records, 2)
    assert tampered.status == "Invalid"
    assert tampered.failure_operation_sequence == 2
    assert records == _training_records()


def test_public_rules_are_data_only_and_partial_descriptor_is_honest() -> None:
    verification = verify_records(_training_records())
    descriptor = load_ruleset("bundled")
    rules = verify_declared_rules(verification, descriptor)
    assert rules.status == "Verified"

    exact = {
        "format_version": 1,
        "ruleset_id": "test",
        "allow_unlisted_purposes": False,
        "operation_rules": [
            {
                "purpose": "deck.epoch.1",
                "operation": "shuffle",
            },
            {
                "purpose": "environment.thunder.self-damage",
                "operation": "probability",
                "input_constraints": {
                    "numerator": {"equals": 1},
                    "denominator": {"equals": 4},
                },
            },
        ],
    }
    assert verify_declared_rules(verification, exact).status == "Verified"

    partial = {
        "format_version": 1,
        "ruleset_id": "partial-test",
        "allow_unlisted_purposes": True,
        "operation_rules": [
            {"purpose": "deck.epoch.1", "operation": "shuffle"},
        ],
    }
    partial_report = verify_declared_rules(verification, partial)
    assert partial_report.status == "Partial"
    assert partial_report.unlisted_purposes == (
        "environment.thunder.self-damage",
    )


def test_source_checkout_cli(tmp_path: Path) -> None:
    transcript = tmp_path / "transcript.json"
    transcript.write_text(
        json.dumps({"records": _training_records()}, ensure_ascii=False),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-m", "openslay_rng_verifier", str(transcript), "--json"],
        cwd=ROOT.parent,
        text=True,
        encoding="utf-8",
        errors="strict",
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["verification"]["status"] == "Verified deterministic"

    bilingual = subprocess.run(
        [sys.executable, "-m", "openslay_rng_verifier", str(transcript)],
        cwd=ROOT.parent,
        text=True,
        encoding="utf-8",
        errors="strict",
        capture_output=True,
        check=False,
    )
    assert bilingual.returncode == 0, bilingual.stderr
    assert "验证状态 / Verification status" in bilingual.stdout
    assert "定策可验 / Verified deterministic" in bilingual.stdout

    chinese = subprocess.run(
        [
            sys.executable,
            "-m",
            "openslay_rng_verifier",
            str(transcript),
            "--language",
            "zh",
        ],
        cwd=ROOT.parent,
        text=True,
        encoding="utf-8",
        errors="strict",
        capture_output=True,
        check=False,
    )
    assert chinese.returncode == 0, chinese.stderr
    assert "验证状态: 定策可验" in chinese.stdout
    assert "Verification status" not in chinese.stdout
    assert report["verification"]["reveal"]["final_audit_hash"] in chinese.stdout


def test_human_report_supports_bilingual_chinese_and_english() -> None:
    records = _training_records()
    verification = verify_records(records)
    header, checkpoints = _witness(records)
    witness = verify_witness(header, checkpoints, records)
    rules = verify_declared_rules(verification, load_ruleset("bundled"))

    bilingual = format_human_report(
        verification,
        transcript_path="match.jsonl",
        witness=witness,
        rules=rules,
    )
    assert "OpenSlay 随机性验证报告 / OpenSlay Randomness Verification Report" in bilingual
    assert "验证状态 / Verification status: 定策可验 / Verified deterministic" in bilingual
    assert "已核验 2 次随机操作和 1 个牌堆纪元" in bilingual
    assert "Verified deterministic: 2 random operations and 1 deck epoch(s) verified." in bilingual
    assert verification.final_audit_hash in bilingual
    assert "本机见证 / Local witness: 完整 / Complete" in bilingual
    assert "公开规则 / Public rules: 已验证 / Verified" in bilingual

    chinese = format_human_report(verification, language="zh")
    assert "验证状态: 定策可验" in chinese
    assert "随机操作数: 2" in chinese
    assert "Verification status" not in chinese

    english = format_human_report(verification, language="en")
    assert "Verification status: Verified deterministic" in english
    assert "Random operations: 2" in english
    assert "验证状态" not in english


def test_verified_fair_uses_player_facing_chinese_without_changing_protocol() -> None:
    report = VerificationReport(
        status="Verified fair",
        summary="Verified fair: 2 random operations and 1 deck epoch(s) verified.",
        exit_code=0,
        operation_count=2,
        deck_epochs_verified=1,
    )

    assert localized_status(report.status) == "验策相合 / Verified fair"
    assert localized_status(report.status, "zh") == "验策相合"
    assert localized_status(report.status, "en") == "Verified fair"
    bilingual = format_human_report(report)
    assert "验证状态 / Verification status: 验策相合 / Verified fair" in bilingual
    assert "验策相合：已核验 2 次随机操作和 1 个牌堆纪元" in bilingual
    assert "公平性已验证" not in bilingual


def test_cli_help_is_bilingual() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "openslay_rng_verifier", "--help"],
        cwd=ROOT.parent,
        text=True,
        encoding="utf-8",
        errors="strict",
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "独立验证 OpenSlay 随机性策牒" in completed.stdout
    assert "Independently verify an OpenSlay randomness" in completed.stdout
    assert "transcript and optional local witness sidecar" in completed.stdout
    assert "--language {bilingual,zh,en}" in completed.stdout


def test_trial_tamper_never_mutates_input() -> None:
    records = _training_records()
    original = copy.deepcopy(records)
    trial_tamper(records)
    assert records == original
