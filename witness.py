"""Verification of the append-only local witness sidecar."""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from .protocol import DIGEST_RE, MAX_SAFE_JSON_INTEGER
from .verifier import VerificationReport, read_jsonl_records, verify_records


WitnessStatus = Literal["Complete", "Missing", "Incomplete", "Invalid"]

_WITNESS_HEADER_COMMON_FIELDS = frozenset(
    {"record_type", "format_version", "match_id", "mode"}
)
_WITNESS_HEADER_TRAINING_FIELDS = _WITNESS_HEADER_COMMON_FIELDS | {
    "numeric_seed",
    "public_randomness_input",
}
_WITNESS_HEADER_ONLINE_FIELDS = _WITNESS_HEADER_COMMON_FIELDS | {
    "ruleset_hash",
    "server_commitment",
    "seat_id",
    "public_randomness_input",
    "client_nonce",
    "contribution",
}
_WITNESS_CHECKPOINT_FIELDS = frozenset(
    {
        "record_type",
        "format_version",
        "match_id",
        "operation_sequence",
        "log_sequence",
        "previous_audit_hash",
        "audit_hash",
    }
)


@dataclass(frozen=True)
class WitnessReport:
    status: WitnessStatus
    summary: str
    exit_code: int
    failure_operation_sequence: int | None = None
    checkpoint_count: int = 0
    operation_count: int = 0
    final_audit_hash: str = ""
    short_fingerprint: str = "—"
    transcript_verification: VerificationReport | None = None

    @property
    def complete(self) -> bool:
        return self.status == "Complete"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def short_fingerprint(final_hash: str) -> str:
    if not isinstance(final_hash, str) or len(final_hash) < 20:
        return "—"
    return " · ".join(final_hash[index : index + 4].upper() for index in range(0, 20, 4))


def load_witness(path: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load and structurally validate a Godot ``randomness_witness`` JSONL file."""

    candidate = Path(path).expanduser()
    if not candidate.is_file():
        raise ValueError(f"witness sidecar does not exist: {candidate}")
    records = read_jsonl_records(candidate)
    if not records:
        raise ValueError("witness sidecar is empty")
    if any(
        record.get("category") in {"randomness_parse_error", "randomness_truncated"}
        for record in records
    ):
        detail = records[-1].get("context", {}).get("detail", "malformed witness JSONL")
        raise ValueError(str(detail))
    header = records[0]
    _validate_header_schema(header)
    checkpoints: list[dict[str, Any]] = []
    for record in records[1:]:
        if record.get("record_type") != "randomness_checkpoint":
            raise ValueError("witness sidecar contains an unknown record type")
        checkpoints.append(record)
    _validate_checkpoint_sequence(header, checkpoints)
    return dict(header), checkpoints


def verify_witness_path(
    transcript_path: str | Path,
    witness_path: str | Path,
) -> WitnessReport:
    from .verifier import load_transcript

    records, _resolved = load_transcript(transcript_path)
    try:
        header, checkpoints = load_witness(witness_path)
    except ValueError as exc:
        verification = verify_records(records)
        return _report(
            "Invalid",
            str(exc),
            verification=verification,
            operation_count=verification.operation_count,
        )
    return verify_witness(header, checkpoints, records)


def verify_witness(
    header: dict[str, Any] | None,
    checkpoints: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> WitnessReport:
    """Cross-check a live local sidecar against the terminal transcript."""

    verification = verify_records(records)
    if not header:
        return _report(
            "Missing",
            "This replay was not witnessed by this local client.",
            verification=verification,
            operation_count=verification.operation_count,
        )
    if verification.status == "Invalid":
        return _report(
            "Invalid",
            verification.summary,
            failure=verification.failure_operation_sequence,
            checkpoints=len(checkpoints),
            operation_count=verification.operation_count,
            verification=verification,
        )
    try:
        _validate_header_schema(header)
        _validate_checkpoint_sequence(header, checkpoints)
    except ValueError as exc:
        return _report(
            "Invalid",
            str(exc),
            failure=1 if checkpoints else None,
            checkpoints=len(checkpoints),
            operation_count=verification.operation_count,
            verification=verification,
        )
    if verification.status == "Incomplete":
        return _report(
            "Incomplete",
            "The terminal transcript is incomplete; retained checkpoints cannot all be matched.",
            checkpoints=len(checkpoints),
            operation_count=verification.operation_count,
            verification=verification,
        )
    if not verification.verified:
        return _report(
            "Missing",
            "The transcript can be inspected but cannot claim a complete local witness.",
            checkpoints=len(checkpoints),
            operation_count=verification.operation_count,
            verification=verification,
        )
    try:
        _validate_header_against_receipt(header, verification)
    except ValueError as exc:
        return _report(
            "Invalid",
            str(exc),
            failure=1 if verification.operation_count else None,
            checkpoints=len(checkpoints),
            operation_count=verification.operation_count,
            verification=verification,
        )
    operations = [
        record
        for record in records
        if record.get("record_type", record.get("category")) == "randomness"
    ]
    for index, (checkpoint, operation_record) in enumerate(
        zip(checkpoints, operations), start=1
    ):
        context = operation_record.get("context", {})
        expected = {
            "match_id": verification.manifest.get("match_id") if verification.manifest else None,
            "log_sequence": operation_record.get("sequence"),
            "operation_sequence": index,
            "previous_audit_hash": context.get("previous_audit_hash"),
            "audit_hash": context.get("audit_hash"),
        }
        actual = {field: checkpoint.get(field) for field in expected}
        if actual != expected:
            return _report(
                "Invalid",
                f"Local checkpoint {index} differs from the terminal transcript.",
                failure=index,
                checkpoints=len(checkpoints),
                operation_count=len(operations),
                verification=verification,
            )
    if len(checkpoints) > len(operations):
        return _report(
            "Invalid",
            "The local sidecar contains more checkpoints than the transcript.",
            failure=len(operations) + 1,
            checkpoints=len(checkpoints),
            operation_count=len(operations),
            verification=verification,
        )
    if len(checkpoints) < len(operations):
        return _report(
            "Incomplete",
            f"The local sidecar is missing checkpoint {len(checkpoints) + 1} and later.",
            failure=len(checkpoints) + 1,
            checkpoints=len(checkpoints),
            operation_count=len(operations),
            verification=verification,
        )
    return _report(
        "Complete",
        "All supplied checkpoints match the terminal transcript.",
        checkpoints=len(checkpoints),
        operation_count=len(operations),
        verification=verification,
    )


def trial_tamper(
    records: list[dict[str, Any]], preferred_operation: int = 1
) -> tuple[list[dict[str, Any]], VerificationReport]:
    """Mutate an in-memory copy and return the expected failing verification."""

    copied = copy.deepcopy(records)
    operations = [
        record
        for record in copied
        if record.get("record_type", record.get("category")) == "randomness"
    ]
    if not operations:
        raise ValueError("transcript has no random operation to mutate")
    selected = min(max(preferred_operation, 1), len(operations))
    context = operations[selected - 1].get("context", {})
    context["result"] = _mutated_value(context.get("result"))
    return copied, verify_records(copied)


def _validate_checkpoint_sequence(
    header: dict[str, Any], checkpoints: list[dict[str, Any]]
) -> None:
    match_id = header.get("match_id")
    if not isinstance(match_id, str) or not match_id:
        raise ValueError("witness header has no match_id")
    previous_hash = ""
    previous_log_sequence = 0
    for expected_sequence, checkpoint in enumerate(checkpoints, start=1):
        if not isinstance(checkpoint, dict):
            raise ValueError(f"checkpoint {expected_sequence} must be an object")
        _require_exact_fields(
            checkpoint,
            _WITNESS_CHECKPOINT_FIELDS,
            f"checkpoint {expected_sequence}",
        )
        if checkpoint.get("record_type") != "randomness_checkpoint":
            raise ValueError(f"checkpoint {expected_sequence} has invalid record type")
        if (
            type(checkpoint.get("format_version")) is not int
            or checkpoint.get("format_version") != 1
        ):
            raise ValueError(f"checkpoint {expected_sequence} has invalid format version")
        if checkpoint.get("match_id") != match_id:
            raise ValueError(f"checkpoint {expected_sequence} has wrong match_id")
        if (
            type(checkpoint.get("operation_sequence")) is not int
            or checkpoint.get("operation_sequence") != expected_sequence
            or checkpoint.get("operation_sequence") > MAX_SAFE_JSON_INTEGER
        ):
            raise ValueError(f"checkpoint sequence breaks at operation {expected_sequence}")
        log_sequence = checkpoint.get("log_sequence")
        if (
            type(log_sequence) is not int
            or log_sequence <= previous_log_sequence
            or log_sequence > MAX_SAFE_JSON_INTEGER
        ):
            raise ValueError(f"checkpoint {expected_sequence} has invalid log sequence")
        previous = checkpoint.get("previous_audit_hash")
        current = checkpoint.get("audit_hash")
        if not isinstance(previous, str) or not DIGEST_RE.fullmatch(previous):
            raise ValueError(f"checkpoint {expected_sequence} has malformed previous hash")
        if not isinstance(current, str) or not DIGEST_RE.fullmatch(current):
            raise ValueError(f"checkpoint {expected_sequence} has malformed audit hash")
        if expected_sequence > 1 and previous != previous_hash:
            raise ValueError(f"checkpoint chain breaks at operation {expected_sequence}")
        previous_hash = current
        previous_log_sequence = log_sequence


def _validate_header_against_receipt(
    header: dict[str, Any], verification: VerificationReport
) -> None:
    _validate_header_schema(header)
    manifest = verification.manifest or {}
    reveal = verification.reveal or {}
    if type(header.get("match_id")) is not str:
        raise ValueError("witness header match_id must be a string")
    if header.get("match_id") != manifest.get("match_id"):
        raise ValueError("witness header match_id differs from transcript")
    mode = header.get("mode")
    if type(mode) is not str:
        raise ValueError("witness header mode must be a string")
    if mode != manifest.get("mode"):
        raise ValueError("witness header mode differs from transcript")
    if mode == "training":
        if type(header.get("numeric_seed")) is not str:
            raise ValueError("training witness numeric_seed must be a string")
        if header.get("numeric_seed") != reveal.get("numeric_seed"):
            raise ValueError("training seed differs from the opening witness")
        if type(header.get("public_randomness_input")) is not str:
            raise ValueError("training witness public input must be a string")
        if header.get("public_randomness_input", "") != reveal.get(
            "public_randomness_input", ""
        ):
            raise ValueError("training public input differs from opening witness")
        return
    if mode != "online":
        raise ValueError("witness header has unsupported mode")
    for field in ("ruleset_hash", "server_commitment"):
        if type(header.get(field)) is not str:
            raise ValueError(f"witness header {field} must be a string")
        if header.get(field) != manifest.get(field):
            raise ValueError(f"witness header {field} differs from transcript")
    seat_id = header.get("seat_id")
    if type(seat_id) is not int or not 0 <= seat_id <= 0xFFFFFFFF:
        raise ValueError("witness header seat_id must be a uint32 integer")
    participants = manifest.get("participants", [])
    participant = next(
        (
            item
            for item in participants
            if isinstance(item, dict) and item.get("seat_id") == seat_id
        ),
        None,
    )
    if participant is None:
        raise ValueError("transcript does not contain the witnessing participant")
    for field in ("public_randomness_input", "client_nonce", "contribution"):
        if type(header.get(field)) is not str:
            raise ValueError(f"witness participant field {field} must be a string")
        if header.get(field) != participant.get(field):
            raise ValueError(f"witness participant field {field} differs from transcript")


def _validate_header_schema(header: dict[str, Any]) -> None:
    if header.get("record_type") != "witness_header":
        raise ValueError("witness header has invalid record type")
    if (
        type(header.get("format_version")) is not int
        or header.get("format_version") != 1
    ):
        raise ValueError("witness header has invalid format version")
    mode = header.get("mode")
    if type(mode) is not str:
        raise ValueError("witness header mode must be a string")
    if mode == "training":
        expected_fields = _WITNESS_HEADER_TRAINING_FIELDS
    elif mode == "online":
        expected_fields = _WITNESS_HEADER_ONLINE_FIELDS
    else:
        raise ValueError("witness header has unsupported mode")
    _require_exact_fields(header, expected_fields, f"{mode} witness header")


def _require_exact_fields(
    record: dict[str, Any], expected_fields: frozenset[str], label: str
) -> None:
    actual_fields = frozenset(record)
    if actual_fields == expected_fields:
        return
    missing = sorted(expected_fields - actual_fields)
    extra = sorted(actual_fields - expected_fields)
    details: list[str] = []
    if missing:
        details.append("missing " + ", ".join(missing))
    if extra:
        details.append("extra " + ", ".join(extra))
    raise ValueError(f"{label} has invalid field set ({'; '.join(details)})")


def _mutated_value(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, list):
        copied = copy.deepcopy(value)
        if len(copied) >= 2:
            copied[0], copied[1] = copied[1], copied[0]
        elif copied:
            copied[0] = _mutated_value(copied[0])
        else:
            copied.append("tampered")
        return copied
    if isinstance(value, str):
        return value + ":tampered"
    return "tampered"


def _report(
    status: WitnessStatus,
    summary: str,
    *,
    failure: int | None = None,
    checkpoints: int = 0,
    operation_count: int = 0,
    verification: VerificationReport | None = None,
) -> WitnessReport:
    final_hash = verification.final_audit_hash if verification else ""
    exit_code = 0 if status == "Complete" else (1 if status == "Invalid" else 2)
    return WitnessReport(
        status=status,
        summary=summary,
        exit_code=exit_code,
        failure_operation_sequence=failure,
        checkpoint_count=checkpoints,
        operation_count=operation_count,
        final_audit_hash=final_hash,
        short_fingerprint=short_fingerprint(final_hash),
        transcript_verification=verification,
    )


__all__ = [
    "WitnessReport",
    "WitnessStatus",
    "load_witness",
    "short_fingerprint",
    "trial_tamper",
    "verify_witness",
    "verify_witness_path",
]
