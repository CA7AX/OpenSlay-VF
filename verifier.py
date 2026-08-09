"""Standalone post-game verification for OpenSlay randomness transcripts."""

from __future__ import annotations

import hmac
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from .operations import execute_operation

from .protocol import (
    MAX_SAFE_JSON_INTEGER,
    RANDOMNESS_ALGORITHM,
    RANDOMNESS_FORMAT_VERSION,
    ZERO_AUDIT_HASH,
    ParticipantContribution,
    PublicRandomnessInputError,
    RandomnessError,
    _HMACStream,
    _parse_digest_hex,
    canonical_json,
    canonicalize,
    derive_online_master_seed,
    derive_server_commitment,
    derive_training_master_seed,
    normalize_public_randomness_input,
    random_context_digest,
    random_state_digest,
    transcript_record_hash,
    validate_participant_contributions,
    validate_random_scope,
    validate_random_state,
    validate_ruleset_hash,
)


VerificationStatus = Literal[
    "Verified fair",
    "Verified deterministic",
    "Unverified",
    "Incomplete",
    "Invalid",
]

_RANDOMNESS_RECORD_TYPES = {
    "randomness_manifest",
    "randomness",
    "randomness_reveal",
}
_OPERATION_CONTEXT_FIELDS = {
    "format_version",
    "algorithm",
    "operation_sequence",
    "operation",
    "purpose",
    "purpose_counter",
    "scope",
    "inputs",
    "state",
    "state_digest",
    "context_digest",
    "result",
    "proof",
    "previous_audit_hash",
    "audit_hash",
}
_PURPOSE_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{1,127}$")
_PARTIAL_JSON_LITERALS = {
    "t",
    "tr",
    "tru",
    "f",
    "fa",
    "fal",
    "fals",
    "n",
    "nu",
    "nul",
}
_PROTOTYPE_DECK_PATH = Path(__file__).with_name("data") / "prototype-deck-v1.json"
_PROTOTYPE_DECK_SIZE = 144


class _DuplicateJSONKey(ValueError):
    pass


class _IncompleteReceipt(RandomnessError):
    pass


@dataclass(frozen=True)
class VerificationReport:
    status: VerificationStatus
    summary: str
    exit_code: int
    manifest: dict[str, Any] | None = None
    reveal: dict[str, Any] | None = None
    operation_count: int = 0
    deck_epochs_verified: int = 0
    failure_sequence: int | None = None
    failure_operation_sequence: int | None = None
    failure_purpose: str | None = None
    random_events: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @property
    def verified(self) -> bool:
        return self.status in {"Verified fair", "Verified deterministic"}

    @property
    def final_audit_hash(self) -> str:
        if not self.reveal:
            return ""
        value = self.reveal.get("final_audit_hash", "")
        return value if isinstance(value, str) else ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is not allowed")


def _parse_marker(category: str, line_number: int, detail: str) -> dict[str, Any]:
    return {
        "category": category,
        "sequence": line_number,
        "context": {"detail": detail, "line_number": line_number},
    }


def _looks_like_truncated_json(line: str, error: json.JSONDecodeError) -> bool:
    """Return whether an unterminated final buffer is a plausible JSON prefix.

    Merely being the final line is not enough: ``{not json`` is corruption,
    while ``{"type":"randomness_reveal"`` is a writer interrupted mid-record.
    """

    candidate = line.rstrip(" \t\r\n")
    if not candidate.lstrip().startswith("{"):
        return False
    if error.msg.startswith("Unterminated string"):
        return True
    if error.pos >= len(candidate):
        return True
    tail = candidate[error.pos:]
    if error.msg == "Expecting value" and tail in _PARTIAL_JSON_LITERALS:
        return True
    if re.search(r"(?:[eE][+-]?|\.)$", candidate):
        return True
    return False


def read_jsonl_records(path: str | Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    raw_lines = Path(path).read_bytes().splitlines(keepends=True)
    for index, raw_line in enumerate(raw_lines):
        line_number = index + 1
        terminated = raw_line.endswith((b"\n", b"\r"))
        is_final_physical_line = index == len(raw_lines) - 1
        try:
            decoded = raw_line.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            truncated = (
                is_final_physical_line
                and not terminated
                and raw_line.lstrip(b" \t").startswith(b"{")
                and exc.reason == "unexpected end of data"
                and exc.end == len(raw_line)
            )
            category = (
                "randomness_truncated" if truncated else "randomness_parse_error"
            )
            detail = (
                f"truncated UTF-8 on line {line_number}"
                if truncated
                else f"invalid UTF-8 on line {line_number}"
            )
            records.append(_parse_marker(category, line_number, detail))
            return records
        line = decoded.strip(" \t\r\n")
        if not line:
            continue
        try:
            record = json.loads(
                line,
                object_pairs_hook=_json_object,
                parse_constant=_reject_json_constant,
            )
        except json.JSONDecodeError as exc:
            truncated = (
                is_final_physical_line
                and not terminated
                and _looks_like_truncated_json(line, exc)
            )
            category = (
                "randomness_truncated" if truncated else "randomness_parse_error"
            )
            detail = (
                f"truncated JSON on line {line_number}"
                if truncated
                else f"invalid JSON on line {line_number}: {exc.msg}"
            )
            records.append(_parse_marker(category, line_number, detail))
            return records
        except (_DuplicateJSONKey, ValueError) as exc:
            records.append(
                _parse_marker(
                    "randomness_parse_error",
                    line_number,
                    f"invalid JSON on line {line_number}: {exc}",
                )
            )
            return records
        except RecursionError:
            records.append(
                _parse_marker(
                    "randomness_parse_error",
                    line_number,
                    f"JSON nesting is too deep on line {line_number}",
                )
            )
            return records
        if not isinstance(record, dict):
            records.append(
                _parse_marker(
                    "randomness_parse_error",
                    line_number,
                    f"JSONL line {line_number} must contain an object",
                )
            )
            return records
        records.append(record)
    return records


def verify_replay(path: str | Path) -> VerificationReport:
    resolved = resolve_verification_path(path)
    return verify_records(read_jsonl_records(resolved))


def _strict_json_loads(value: str) -> Any:
    return json.loads(
        value,
        object_pairs_hook=_json_object,
        parse_constant=_reject_json_constant,
    )


def load_transcript(path: str | Path) -> tuple[list[dict[str, Any]], Path]:
    """Load a replay JSONL, compact JSON transcript, or replay directory."""

    candidate = Path(path).expanduser()
    if candidate.is_dir() or candidate.suffix.lower() in {".jsonl", ".log"}:
        resolved = resolve_verification_path(candidate)
        return read_jsonl_records(resolved), resolved
    if not candidate.is_file():
        raise ValueError(f"transcript path does not exist: {candidate}")
    try:
        parsed = _strict_json_loads(candidate.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, _DuplicateJSONKey, ValueError) as exc:
        raise ValueError(f"invalid transcript JSON: {exc}") from exc
    if isinstance(parsed, dict) and isinstance(parsed.get("records"), list):
        records = parsed["records"]
    elif isinstance(parsed, list):
        records = parsed
    else:
        raise ValueError("transcript JSON must be a record list or contain 'records'")
    if any(not isinstance(record, dict) for record in records):
        raise ValueError("transcript records must be JSON objects")
    return list(records), candidate.resolve()


def verify_path(path: str | Path) -> VerificationReport:
    records, _resolved = load_transcript(path)
    return verify_records(records)


def resolve_verification_path(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_file():
        if candidate.suffix == ".log":
            sibling = candidate.with_suffix(".jsonl")
            if sibling.is_file():
                return sibling.resolve()
        return candidate.resolve()
    if candidate.is_dir():
        logs = sorted(
            candidate.rglob("*.jsonl"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        for log in logs:
            if log.name.endswith(".llm.jsonl"):
                continue
            try:
                parsed = read_jsonl_records(log)
                if any(
                    record.get("category") in {"randomness_manifest", "engine_init"}
                    for record in parsed
                ):
                    return log.resolve()
                has_parse_marker = any(
                    record.get("category")
                    in {"randomness_truncated", "randomness_parse_error"}
                    for record in parsed
                )
                if has_parse_marker:
                    raw = log.read_bytes()
                    if b"randomness" in raw or b"engine_init" in raw:
                        return log.resolve()
            except OSError:
                continue
        raise ValueError(f"{candidate} does not contain a game JSONL log")
    raise ValueError(f"replay path does not exist: {candidate}")


def verify_records(records: list[dict[str, Any]]) -> VerificationReport:
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            return _invalid(
                "verification input contains a non-object record", sequence=index
            )
    parse_error = next(
        (record for record in records if record.get("category") == "randomness_parse_error"),
        None,
    )
    if parse_error is not None:
        return _invalid(
            str((parse_error.get("context") or {}).get("detail", "invalid JSON")),
            sequence=_sequence(parse_error),
        )

    truncated = next(
        (record for record in records if record.get("category") == "randomness_truncated"),
        None,
    )
    if truncated is not None:
        prefix_report = verify_records(
            [
                record
                for record in records
                if record.get("category") != "randomness_truncated"
            ]
        )
        if prefix_report.status == "Invalid":
            return prefix_report
        manifest_hint = next(
            (
                _context(record)
                for record in records
                if _record_type(record) == "randomness_manifest"
            ),
            None,
        )
        return VerificationReport(
            status="Incomplete",
            summary=str(
                (_context(truncated)).get(
                    "detail", "The JSONL writer stopped during its final record."
                )
            ),
            exit_code=2,
            manifest=manifest_hint,
            failure_sequence=_sequence(truncated),
        )

    envelope_report = _validate_randomness_envelopes(records)
    if envelope_report is not None:
        return envelope_report

    manifests = [record for record in records if _record_type(record) == "randomness_manifest"]
    random_records = [record for record in records if _record_type(record) == "randomness"]
    reveals = [record for record in records if _record_type(record) == "randomness_reveal"]

    if not manifests:
        if random_records or reveals:
            offending = random_records[0] if random_records else reveals[0]
            return _invalid(
                "versioned randomness records require a randomness manifest",
                sequence=_sequence(offending),
            )
        return VerificationReport(
            status="Unverified",
            summary="Legacy seed-only log: no randomness manifest is present.",
            exit_code=2,
            operation_count=len(random_records),
        )
    if len(manifests) != 1:
        return _invalid("transcript must contain exactly one randomness manifest")

    manifest_record = manifests[0]
    manifest = _context(manifest_record)
    manifest_sequence = _sequence(manifest_record)
    try:
        _require_canonical_context(manifest, "manifest")
        _validate_common_header(manifest, "manifest")
        validate_ruleset_hash(manifest.get("ruleset_hash"))
    except RandomnessError as exc:
        return _invalid(str(exc), sequence=manifest_sequence, manifest=manifest)

    mode = manifest.get("mode")
    if mode not in {"training", "online", "unverified"}:
        return _invalid(
            f"unsupported randomness mode: {mode!r}",
            sequence=manifest_sequence,
            manifest=manifest,
        )

    later_records = [*random_records, *reveals]
    if any(_sequence(record) < manifest_sequence for record in later_records):
        offending = next(
            record for record in later_records if _sequence(record) < manifest_sequence
        )
        return _invalid(
            "randomness record appears before the manifest",
            sequence=_sequence(offending),
            manifest=manifest,
        )

    if len(reveals) > 1:
        return _invalid("transcript must contain at most one randomness reveal", manifest=manifest)

    try:
        manifest_hash = transcript_record_hash(
            ZERO_AUDIT_HASH,
            "randomness_manifest",
            manifest,
        )
    except RandomnessError as exc:
        return _invalid(str(exc), sequence=manifest_sequence, manifest=manifest)

    chain_report, operation_chain_hash = _validate_chain_without_seed(
        random_records,
        manifest,
        initial_hash=manifest_hash,
    )
    if chain_report is not None:
        return chain_report

    if not reveals:
        return VerificationReport(
            status="Incomplete",
            summary="The server or training derivation has not been revealed yet.",
            exit_code=2,
            manifest=manifest,
            operation_count=len(random_records),
            random_events=tuple(_context(record) for record in random_records),
        )

    reveal_record = reveals[0]
    reveal = _context(reveal_record)
    reveal_sequence = _sequence(reveal_record)
    if reveal_sequence < max((manifest_sequence, *(_sequence(item) for item in random_records))):
        return _invalid(
            "randomness reveal appears before the end of the transcript",
            sequence=reveal_sequence,
            manifest=manifest,
            reveal=reveal,
        )
    try:
        _require_canonical_context(reveal, "reveal")
        _validate_common_header(reveal, "reveal")
        if reveal.get("mode") != mode:
            raise RandomnessError("manifest and reveal modes differ")
        _validate_reveal_fields(reveal)
        if (
            type(reveal.get("operation_count")) is not int
            or reveal.get("operation_count") != len(random_records)
        ):
            raise RandomnessError("reveal operation count does not match transcript")
        actual_final_hash = reveal.get("final_audit_hash")
        reveal_chain_context = dict(reveal)
        reveal_chain_context.pop("final_audit_hash", None)
        expected_final_hash = transcript_record_hash(
            operation_chain_hash,
            "randomness_reveal",
            reveal_chain_context,
        )
        _parse_digest_hex(actual_final_hash, "final_audit_hash")
        if not hmac.compare_digest(actual_final_hash, expected_final_hash):
            raise RandomnessError("reveal final audit hash does not match transcript")
    except RandomnessError as exc:
        return _invalid(
            str(exc),
            sequence=reveal_sequence,
            manifest=manifest,
            reveal=reveal,
        )

    if mode == "unverified":
        return VerificationReport(
            status="Unverified",
            summary="Transcript used the deprecated unverified RNG adapter.",
            exit_code=2,
            manifest=manifest,
            reveal=reveal,
            operation_count=len(random_records),
            random_events=tuple(_context(record) for record in random_records),
        )

    try:
        master_seed = _master_seed_from_receipt(manifest, reveal)
    except _IncompleteReceipt as exc:
        if random_records:
            return _invalid(
                "pre-start abort contains random operations",
                sequence=_sequence(random_records[0]),
                manifest=manifest,
                reveal=reveal,
            )
        if reveal.get("operation_count") != 0:
            return _invalid(
                "pre-start abort must reveal zero operations",
                sequence=reveal_sequence,
                manifest=manifest,
                reveal=reveal,
            )
        return VerificationReport(
            status="Incomplete",
            summary=f"Incomplete randomness transcript: {exc}",
            exit_code=2,
            manifest=manifest,
            reveal=reveal,
        )
    except RandomnessError as exc:
        return _invalid(
            str(exc),
            sequence=reveal_sequence,
            manifest=manifest,
            reveal=reveal,
        )

    counters: dict[str, int] = defaultdict(int)
    previous_hash = manifest_hash
    deck_epoch = 0
    next_deck_card_id = 1
    verified_events: list[dict[str, Any]] = []
    for expected_sequence, record in enumerate(random_records, start=1):
        context = _context(record)
        record_sequence = _sequence(record)
        purpose = context.get("purpose")
        try:
            _require_canonical_context(context, "random operation")
            _validate_common_header(context, "random operation")
            if type(context.get("operation_sequence")) is not int or context.get(
                "operation_sequence"
            ) != expected_sequence:
                raise RandomnessError(
                    f"operation sequence must be {expected_sequence}, got "
                    f"{context.get('operation_sequence')!r}"
                )
            if not isinstance(purpose, str) or not _PURPOSE_RE.fullmatch(purpose):
                raise RandomnessError("random operation is missing its purpose")
            expected_counter = counters[purpose]
            if type(context.get("purpose_counter")) is not int or context.get(
                "purpose_counter"
            ) != expected_counter:
                raise RandomnessError(
                    f"purpose counter for {purpose!r} must be {expected_counter}"
                )
            counters[purpose] += 1
            if context.get("previous_audit_hash") != previous_hash:
                raise RandomnessError("audit chain previous hash does not match")
            expected = _recompute_operation(master_seed, context)
            for field_name in ("result", "proof"):
                if canonical_json(context.get(field_name)) != canonical_json(
                    expected[field_name]
                ):
                    raise RandomnessError(
                        f"{field_name} does not match the HMAC-derived operation"
                    )
            chain_payload = dict(context)
            actual_hash = chain_payload.pop("audit_hash", None)
            chain_payload.pop("previous_audit_hash", None)
            expected_hash = transcript_record_hash(
                previous_hash,
                "randomness",
                chain_payload,
            )
            _parse_digest_hex(actual_hash, "audit_hash")
            if not hmac.compare_digest(actual_hash, expected_hash):
                raise RandomnessError("audit hash does not match the operation record")
            previous_hash = expected_hash

            deck_update = _validate_deck_record(
                context,
                expected_epoch=deck_epoch + 1,
                expected_start_card_id=next_deck_card_id,
            )
            if deck_update is not None:
                deck_epoch, next_deck_card_id = deck_update
            verified_events.append(context)
        except (RandomnessError, TypeError, ValueError) as exc:
            return _invalid(
                str(exc),
                sequence=record_sequence,
                operation_sequence=expected_sequence,
                purpose=purpose if isinstance(purpose, str) else None,
                manifest=manifest,
                reveal=reveal,
                operation_count=expected_sequence - 1,
                deck_epochs=deck_epoch,
                random_events=tuple(verified_events),
            )

    unverified_reason = _unverified_source_reason(
        manifest,
        random_records,
        reveals,
    )
    if unverified_reason is not None:
        return VerificationReport(
            status="Unverified",
            summary=unverified_reason,
            exit_code=2,
            manifest=manifest,
            reveal=reveal,
            operation_count=len(random_records),
            deck_epochs_verified=deck_epoch,
            random_events=tuple(verified_events),
        )

    if deck_epoch == 0:
        if reveal.get("outcome") == "aborted":
            return VerificationReport(
                status="Incomplete",
                summary=(
                    "The match aborted before an authoritative deck epoch was "
                    "recorded."
                ),
                exit_code=2,
                manifest=manifest,
                reveal=reveal,
                operation_count=len(random_records),
                random_events=tuple(verified_events),
            )
        return _invalid(
            "completed transcript claims an oracle deck but contains no deck epoch",
            sequence=reveal_sequence,
            manifest=manifest,
            reveal=reveal,
            operation_count=len(random_records),
            random_events=tuple(verified_events),
        )

    status: VerificationStatus = (
        "Verified fair" if mode == "online" else "Verified deterministic"
    )
    return VerificationReport(
        status=status,
        summary=(
            f"{status}: {len(random_records)} random operations and "
            f"{deck_epoch} deck epoch(s) verified."
        ),
        exit_code=0,
        manifest=manifest,
        reveal=reveal,
        operation_count=len(random_records),
        deck_epochs_verified=deck_epoch,
        random_events=tuple(verified_events),
    )


def _master_seed_from_receipt(
    manifest: dict[str, Any],
    reveal: dict[str, Any],
) -> bytes:
    mode = manifest.get("mode")
    if mode == "training":
        numeric_seed_text = reveal.get("numeric_seed")
        public_input = reveal.get("public_randomness_input")
        match_id = manifest.get("match_id")
        if not isinstance(match_id, str) or not match_id:
            raise RandomnessError("training manifest is missing match identity")
        if "server_commitment" not in manifest or manifest["server_commitment"] is not None:
            raise RandomnessError("training manifest cannot contain a server commitment")
        if (
            "commitment_published_order" not in manifest
            or manifest["commitment_published_order"] is not None
        ):
            raise RandomnessError(
                "training manifest cannot contain a commitment publication order"
            )
        if manifest.get("participants") != []:
            raise RandomnessError("training manifest cannot contain participants")
        if "server_secret" in reveal:
            raise RandomnessError("training reveal cannot contain a server secret")
        if not isinstance(numeric_seed_text, str) or not isinstance(public_input, str):
            raise RandomnessError("training reveal is missing derivation data")
        try:
            numeric_seed = int(numeric_seed_text, 10)
        except ValueError as exc:
            raise RandomnessError("training numeric seed is not canonical decimal text") from exc
        if str(numeric_seed) != numeric_seed_text:
            raise RandomnessError("training numeric seed is not canonical decimal text")
        try:
            normalized = normalize_public_randomness_input(public_input)
        except PublicRandomnessInputError as exc:
            raise RandomnessError(str(exc)) from exc
        if normalized != public_input:
            raise RandomnessError(
                "training public randomness input is not canonically normalized"
            )
        return derive_training_master_seed(numeric_seed, public_input)

    if "numeric_seed" in reveal or "public_randomness_input" in reveal:
        raise RandomnessError("online reveal contains training derivation data")
    match_id = manifest.get("match_id")
    ruleset_hash = manifest.get("ruleset_hash")
    commitment_hex = manifest.get("server_commitment")
    secret_hex = reveal.get("server_secret")
    participants_raw = manifest.get("participants")
    commitment_order = manifest.get("commitment_published_order")
    if not isinstance(match_id, str) or not match_id or not isinstance(ruleset_hash, str):
        raise RandomnessError("online manifest is missing match or ruleset identity")
    validate_ruleset_hash(ruleset_hash)
    if type(commitment_order) is not int or commitment_order < 0:
        raise RandomnessError("online manifest is missing commitment publication order")
    server_secret = _parse_digest_hex(secret_hex, "server_secret")
    expected_commitment = derive_server_commitment(match_id, ruleset_hash, server_secret)
    actual_commitment = _parse_digest_hex(commitment_hex, "server_commitment")
    if not hmac.compare_digest(expected_commitment, actual_commitment):
        raise RandomnessError("server secret does not match the pre-game commitment")
    if not isinstance(participants_raw, list):
        raise RandomnessError("online manifest participant list is missing")
    try:
        participants = tuple(
            ParticipantContribution(**participant)
            for participant in participants_raw
            if isinstance(participant, dict)
        )
    except TypeError as exc:
        raise RandomnessError("online participant receipt has invalid fields") from exc
    if len(participants) != len(participants_raw):
        raise RandomnessError("online participant receipt is malformed")
    ordered = validate_participant_contributions(match_id, participants)
    if [item.seat_id for item in participants] != [
        item.seat_id for item in ordered
    ]:
        raise RandomnessError("online participants are not ordered by seat id")
    for participant in ordered:
        if (
                participant.driver_kind == "human"
                and (
                participant.commitment_received_order <= commitment_order
                or (participant.accepted_order or 0) <= commitment_order
            )
        ):
            raise RandomnessError("a contribution was accepted before commitment publication")
    contributions: list[bytes] = []
    for participant in ordered:
        if participant.driver_kind != "human":
            continue
        contributions.append(
            _parse_digest_hex(participant.contribution or "", "player_contribution")
        )

    _validate_online_receipt_summary(manifest, reveal, ordered)
    return derive_online_master_seed(
        match_id,
        ruleset_hash,
        server_secret,
        contributions,
    )


def _validate_online_receipt_summary(
    manifest: dict[str, Any],
    reveal: dict[str, Any],
    participants: tuple[ParticipantContribution, ...],
) -> None:
    summary = reveal.get("receipt_summary")
    if not isinstance(summary, dict):
        raise RandomnessError("online reveal receipt_summary must be an object")
    required_fields = {
        "match_id",
        "winner_ids",
        "required_seats",
        "accepted_seats",
        "start_delivered_seats",
        "contributions_complete",
    }
    if not required_fields.issubset(summary):
        raise RandomnessError("online receipt summary is missing required readiness fields")

    required = _canonical_seat_list(summary.get("required_seats"), "required_seats")
    accepted = _canonical_seat_list(summary.get("accepted_seats"), "accepted_seats")
    delivered = _canonical_seat_list(
        summary.get("start_delivered_seats"), "start_delivered_seats"
    )
    complete = summary.get("contributions_complete")
    if type(complete) is not bool:
        raise RandomnessError("contributions_complete must be a boolean")
    if not set(accepted).issubset(required):
        raise RandomnessError("accepted seats must be a subset of required seats")
    if not set(delivered).issubset(required):
        raise RandomnessError("start-delivered seats must be a subset of required seats")
    if not set(delivered).issubset(accepted):
        raise RandomnessError("start-delivered seats must be a subset of accepted seats")
    expected_complete = accepted == required
    if complete != expected_complete:
        raise RandomnessError("contributions_complete contradicts accepted seats")
    participant_humans = sorted(
        participant.seat_id
        for participant in participants
        if participant.driver_kind == "human"
    )
    if participant_humans != accepted:
        raise RandomnessError("participant receipts do not match accepted seats")

    match_id = summary.get("match_id")
    if match_id != manifest.get("match_id"):
        raise RandomnessError("receipt summary match_id differs from the manifest")
    winner_ids = summary.get("winner_ids")
    if not isinstance(winner_ids, list) or any(
        type(player_id) is not int or player_id < 0 or player_id > 0xFFFFFFFF
        for player_id in winner_ids
    ):
        raise RandomnessError("winner_ids must contain uint32 player ids")
    outcome = reveal.get("outcome")
    ready_to_start = complete and delivered == required
    if not ready_to_start:
        if outcome != "aborted":
            raise RandomnessError(
                "an incomplete online readiness receipt must have aborted outcome"
            )
        raise _IncompleteReceipt(
            "online match aborted before every contribution and start receipt was complete"
        )


def _canonical_seat_list(value: Any, field: str) -> list[int]:
    if not isinstance(value, list):
        raise RandomnessError(f"{field} must be a list")
    if any(type(item) is not int or item < 0 or item > 0xFFFFFFFF for item in value):
        raise RandomnessError(f"{field} must contain uint32 seat ids")
    if value != sorted(set(value)):
        raise RandomnessError(f"{field} must be sorted and unique")
    return value


def _validate_randomness_envelopes(
    records: list[dict[str, Any]],
) -> VerificationReport | None:
    previous_sequence = 0
    for record in records:
        category = record.get("category")
        has_explicit_type = "record_type" in record
        has_category = "category" in record
        explicit_type = record.get("record_type")
        category_type = category if category in _RANDOMNESS_RECORD_TYPES else None
        record_type = (
            explicit_type if explicit_type in _RANDOMNESS_RECORD_TYPES else None
        )
        if category_type is not None and record_type is not None and category_type != record_type:
            return _invalid("record_type and category identify different randomness records")
        claimed_type = record_type or category_type
        if claimed_type is None:
            if any(
                isinstance(value, str) and value.startswith("randomness")
                for value in (explicit_type, category)
            ):
                return _invalid("record claims an unsupported randomness record type")
            continue
        if has_explicit_type and explicit_type != claimed_type:
            return _invalid("randomness record has an invalid record_type")
        if has_category and category != claimed_type:
            return _invalid("randomness record has an invalid category")
        sequence = record.get("sequence")
        if (
            type(sequence) is not int
            or sequence <= 0
            or sequence > MAX_SAFE_JSON_INTEGER
        ):
            return _invalid(
                "randomness record sequence must be a positive JSON-safe integer"
            )
        if sequence <= previous_sequence:
            return _invalid(
                "randomness record sequences must increase in file order",
                sequence=sequence,
            )
        previous_sequence = sequence
        context = record.get("context")
        if not isinstance(context, dict):
            return _invalid(
                "randomness record context must be an object", sequence=sequence
            )
        try:
            _require_canonical_context(context, claimed_type)
        except RandomnessError as exc:
            return _invalid(str(exc), sequence=sequence)
        top_version = record.get("format_version")
        if "format_version" in record and (
            type(top_version) is not int
            or top_version != RANDOMNESS_FORMAT_VERSION
        ):
            return _invalid(
                "randomness record envelope has an unsupported format version",
                sequence=sequence,
            )
    return None


def _require_canonical_context(context: Any, label: str) -> None:
    if not isinstance(context, dict):
        raise RandomnessError(f"{label} must be an object")
    try:
        canonical = canonicalize(context)
    except RecursionError as exc:
        raise RandomnessError(f"{label} nesting is too deep") from exc
    if canonical != context:
        raise RandomnessError(f"{label} is not in canonical JSON form")


def _unverified_source_reason(
    manifest: dict[str, Any],
    random_records: list[dict[str, Any]],
    reveals: list[dict[str, Any]],
) -> str | None:
    deck_source = manifest.get("deck_source")
    if deck_source != "oracle":
        rendered = "missing" if deck_source is None else repr(deck_source)
        return (
            "Authoritative deck order is unverified because deck_source is "
            f"{rendered}, not 'oracle'."
        )
    if (
        _contains_unverified_adapter(manifest)
        or any(
            _contains_unverified_adapter(_context(record))
            for record in [*random_records, *reveals]
        )
    ):
        return "Transcript contains values produced by the unverified RNG adapter."
    return None


def _contains_unverified_adapter(value: Any) -> bool:
    if isinstance(value, dict):
        if "unverified_adapter" in value:
            return True
        return any(_contains_unverified_adapter(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_unverified_adapter(item) for item in value)
    return False


def _validate_reveal_fields(reveal: dict[str, Any]) -> None:
    outcome = reveal.get("outcome")
    if outcome not in {"completed", "aborted"}:
        raise RandomnessError("reveal outcome must be 'completed' or 'aborted'")
    reason = reveal.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise RandomnessError("reveal reason must be a string or null")
    operation_count = reveal.get("operation_count")
    if type(operation_count) is not int or operation_count < 0:
        raise RandomnessError("reveal operation_count must be a non-negative integer")
    _parse_digest_hex(reveal.get("final_audit_hash"), "final_audit_hash")
    if not isinstance(reveal.get("receipt_summary"), dict):
        raise RandomnessError("reveal receipt_summary must be an object")


def _validate_chain_without_seed(
    random_records: list[dict[str, Any]],
    manifest: dict[str, Any],
    *,
    initial_hash: str,
) -> tuple[VerificationReport | None, str]:
    previous_hash = initial_hash
    counters: dict[str, int] = defaultdict(int)
    for expected_sequence, record in enumerate(random_records, start=1):
        context = _context(record)
        purpose = context.get("purpose")
        try:
            _require_canonical_context(context, "random operation")
            _validate_operation_structure(context)
        except RandomnessError as exc:
            return (
                _invalid(
                    str(exc),
                    sequence=_sequence(record),
                    operation_sequence=expected_sequence,
                    purpose=purpose if isinstance(purpose, str) else None,
                    manifest=manifest,
                ),
                previous_hash,
            )
        if (
            type(context.get("operation_sequence")) is not int
            or context.get("operation_sequence") != expected_sequence
        ):
            return (
                _invalid(
                    f"operation sequence must be {expected_sequence}",
                    sequence=_sequence(record),
                    operation_sequence=expected_sequence,
                    purpose=purpose if isinstance(purpose, str) else None,
                    manifest=manifest,
                ),
                previous_hash,
            )
        if not isinstance(purpose, str) or not _PURPOSE_RE.fullmatch(purpose):
            return (
                _invalid(
                    "random operation purpose is malformed",
                    sequence=_sequence(record),
                    operation_sequence=expected_sequence,
                    manifest=manifest,
                ),
                previous_hash,
            )
        expected_counter = counters[purpose]
        if (
            type(context.get("purpose_counter")) is not int
            or context.get("purpose_counter") != expected_counter
        ):
            return (
                _invalid(
                    f"purpose counter for {purpose!r} must be {expected_counter}",
                    sequence=_sequence(record),
                    operation_sequence=expected_sequence,
                    purpose=purpose,
                    manifest=manifest,
                ),
                previous_hash,
            )
        counters[purpose] += 1
        if context.get("previous_audit_hash") != previous_hash:
            return (
                _invalid(
                    "audit chain previous hash does not match",
                    sequence=_sequence(record),
                    operation_sequence=expected_sequence,
                    purpose=purpose if isinstance(purpose, str) else None,
                    manifest=manifest,
                ),
                previous_hash,
            )
        chain_payload = dict(context)
        actual_hash = chain_payload.pop("audit_hash", None)
        chain_payload.pop("previous_audit_hash", None)
        try:
            expected_hash = transcript_record_hash(
                previous_hash,
                "randomness",
                chain_payload,
            )
        except RandomnessError as exc:
            return (
                _invalid(
                    str(exc),
                    sequence=_sequence(record),
                    operation_sequence=expected_sequence,
                    purpose=purpose if isinstance(purpose, str) else None,
                    manifest=manifest,
                ),
                previous_hash,
            )
        try:
            _parse_digest_hex(actual_hash, "audit_hash")
        except RandomnessError as exc:
            return (
                _invalid(
                    str(exc),
                    sequence=_sequence(record),
                    operation_sequence=expected_sequence,
                    purpose=purpose if isinstance(purpose, str) else None,
                    manifest=manifest,
                ),
                previous_hash,
            )
        if not hmac.compare_digest(actual_hash, expected_hash):
            return (
                _invalid(
                    "audit hash does not match the operation record",
                    sequence=_sequence(record),
                    operation_sequence=expected_sequence,
                    purpose=purpose if isinstance(purpose, str) else None,
                    manifest=manifest,
                ),
                previous_hash,
            )
        previous_hash = expected_hash
    return None, previous_hash


def _validate_operation_structure(context: dict[str, Any]) -> None:
    if set(context) != _OPERATION_CONTEXT_FIELDS:
        raise RandomnessError("random operation has missing or unexpected fields")
    _validate_common_header(context, "random operation")
    validate_random_scope(context.get("scope"))
    validate_random_state(context.get("state"))
    operation = context.get("operation")
    purpose = context.get("purpose")
    counter = context.get("purpose_counter")
    if (
        not isinstance(operation, str)
        or not isinstance(purpose, str)
        or not _PURPOSE_RE.fullmatch(purpose)
        or type(counter) is not int
        or counter < 0
    ):
        raise RandomnessError("random operation identity is malformed")
    inputs = context.get("inputs")
    if not isinstance(inputs, dict):
        raise RandomnessError("random operation inputs are malformed")
    if not isinstance(context.get("proof"), dict):
        raise RandomnessError("random operation proof must be an object")
    expected_state_digest = random_state_digest(context["state"])
    if context.get("state_digest") != expected_state_digest:
        raise RandomnessError("random operation state digest does not match its snapshot")
    expected_context_digest = random_context_digest(
        operation_sequence=context.get("operation_sequence"),
        operation=operation,
        purpose=purpose,
        purpose_counter=counter,
        scope=context["scope"],
        inputs=inputs,
        state_digest=expected_state_digest,
        previous_audit_hash=context.get("previous_audit_hash"),
    )
    if context.get("context_digest") != expected_context_digest:
        raise RandomnessError("random operation context digest does not match")
    if operation == "probability":
        if set(inputs) != {"numerator", "denominator"}:
            raise RandomnessError("probability inputs have unexpected fields")
        numerator = inputs.get("numerator")
        denominator = inputs.get("denominator")
        if type(numerator) is not int or type(denominator) is not int:
            raise RandomnessError("probability inputs are malformed")
        if (
            denominator <= 0
            or denominator > MAX_SAFE_JSON_INTEGER
            or numerator < 0
            or numerator > MAX_SAFE_JSON_INTEGER
            or numerator > denominator
        ):
            raise RandomnessError("probability fraction is out of range")
        return
    candidates = inputs.get("candidates")
    if not isinstance(candidates, list):
        raise RandomnessError(f"{operation} candidates are malformed")
    if operation == "choice":
        if set(inputs) != {"candidates"}:
            raise RandomnessError("choice inputs have unexpected fields")
        if not candidates:
            raise RandomnessError("choice candidates are empty")
        return
    if operation == "sample":
        if set(inputs) != {"candidates", "count"}:
            raise RandomnessError("sample inputs have unexpected fields")
        count = inputs.get("count")
        if type(count) is not int or count < 0 or count > len(candidates):
            raise RandomnessError("sample count is malformed")
        return
    if operation == "shuffle":
        if not set(inputs).issubset({"candidates", "metadata"}):
            raise RandomnessError("shuffle inputs have unexpected fields")
        if "metadata" in inputs and not isinstance(inputs["metadata"], dict):
            raise RandomnessError("shuffle metadata must be an object")
        return
    raise RandomnessError(f"unsupported random operation: {operation!r}")


def _recompute_operation(master_seed: bytes, context: dict[str, Any]) -> dict[str, Any]:
    _validate_operation_structure(context)
    stream = _HMACStream(
        master_seed,
        context_digest=_parse_digest_hex(
            context.get("context_digest"), "context_digest"
        ),
    )
    return execute_operation(context["operation"], context["inputs"], stream)


recompute_operation = _recompute_operation


def _validate_deck_record(
    context: dict[str, Any],
    *,
    expected_epoch: int,
    expected_start_card_id: int,
) -> tuple[int, int] | None:
    purpose = context.get("purpose")
    inputs = context.get("inputs")
    if not isinstance(inputs, dict) or not isinstance(purpose, str):
        return None
    metadata = inputs.get("metadata")
    purpose_claims_deck = purpose.startswith("deck.epoch.")
    metadata_claims_deck = isinstance(metadata, dict) and "deck_epoch" in metadata
    if not purpose_claims_deck and not metadata_claims_deck:
        return None
    if not purpose_claims_deck or not metadata_claims_deck:
        raise RandomnessError(
            "deck shuffle must include matching purpose and epoch metadata"
        )
    if context.get("operation") != "shuffle":
        raise RandomnessError("deck epoch record must be a shuffle")
    if set(metadata) != {"deck_epoch", "start_card_id", "card_count"}:
        raise RandomnessError("deck epoch metadata has missing or unexpected fields")
    epoch = metadata.get("deck_epoch")
    start_card_id = metadata.get("start_card_id")
    card_count = metadata.get("card_count")
    if type(epoch) is not int or epoch != expected_epoch:
        raise RandomnessError(
            f"deck epoch must be {expected_epoch}, got {epoch!r}"
        )
    if purpose != f"deck.epoch.{epoch}":
        raise RandomnessError("deck epoch purpose does not match its epoch")
    if type(start_card_id) is not int or start_card_id <= 0:
        raise RandomnessError("deck start_card_id must be a positive integer")
    if start_card_id != expected_start_card_id:
        raise RandomnessError(
            f"deck epoch {epoch} must start at card id {expected_start_card_id}"
        )
    candidates = inputs.get("candidates")
    if not isinstance(candidates, list):
        raise RandomnessError("deck epoch candidates must be a list")
    if type(card_count) is not int or card_count != len(candidates) or card_count <= 0:
        raise RandomnessError("deck epoch card_count does not match its candidates")
    if card_count != _PROTOTYPE_DECK_SIZE:
        raise RandomnessError(
            f"deck epoch must contain the {_PROTOTYPE_DECK_SIZE}-card prototype"
        )
    public_deck = json.loads(_PROTOTYPE_DECK_PATH.read_text(encoding="utf-8"))
    public_candidates = public_deck.get("candidates")
    if not isinstance(public_candidates, list) or len(public_candidates) != _PROTOTYPE_DECK_SIZE:
        raise RandomnessError("bundled public prototype deck manifest is malformed")
    expected_candidates = [
        {**candidate, "card_id": start_card_id + offset}
        for offset, candidate in enumerate(public_candidates)
        if isinstance(candidate, dict)
    ]
    if len(expected_candidates) != _PROTOTYPE_DECK_SIZE:
        raise RandomnessError("bundled public prototype deck manifest is malformed")
    if canonical_json(candidates) != canonical_json(expected_candidates):
        raise RandomnessError(
            "deck epoch candidates do not match the authoritative prototype sequence"
        )
    return epoch, start_card_id + card_count


def _validate_common_header(context: dict[str, Any], label: str) -> None:
    if (
        type(context.get("format_version")) is not int
        or context.get("format_version") != RANDOMNESS_FORMAT_VERSION
    ):
        raise RandomnessError(f"{label} has an unsupported format version")
    if context.get("algorithm") != RANDOMNESS_ALGORITHM:
        raise RandomnessError(f"{label} has an unsupported algorithm")


def _record_type(record: dict[str, Any]) -> str:
    value = record.get("record_type", record.get("category", ""))
    return value if isinstance(value, str) else ""


def _context(record: dict[str, Any]) -> dict[str, Any]:
    context = record.get("context")
    return dict(context) if isinstance(context, dict) else {}


def _sequence(record: dict[str, Any]) -> int:
    value = record.get("sequence")
    return value if type(value) is int else 0


def _invalid(
    summary: str,
    *,
    sequence: int | None = None,
    operation_sequence: int | None = None,
    purpose: str | None = None,
    manifest: dict[str, Any] | None = None,
    reveal: dict[str, Any] | None = None,
    operation_count: int = 0,
    deck_epochs: int = 0,
    random_events: tuple[dict[str, Any], ...] = (),
) -> VerificationReport:
    location = ""
    if sequence is not None:
        location += f" at JSONL sequence {sequence}"
    if purpose:
        location += f" ({purpose})"
    return VerificationReport(
        status="Invalid",
        summary=f"Invalid randomness transcript{location}: {summary}",
        exit_code=1,
        manifest=manifest,
        reveal=reveal,
        operation_count=operation_count,
        deck_epochs_verified=deck_epochs,
        failure_sequence=sequence,
        failure_operation_sequence=operation_sequence,
        failure_purpose=purpose,
        random_events=random_events,
    )


__all__ = [
    "VerificationReport",
    "VerificationStatus",
    "load_transcript",
    "read_jsonl_records",
    "recompute_operation",
    "resolve_verification_path",
    "verify_path",
    "verify_records",
    "verify_replay",
]
