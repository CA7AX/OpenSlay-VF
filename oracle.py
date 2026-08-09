"""Generic verifiable, domain-separated randomness oracle.

This independently publishable, standard-library-only implementation turns a
256-bit master seed into semantic operations and records enough information to
reproduce every result after the seed is revealed.  Applications provide an
explicit ruleset hash and may adapt the oracle without becoming dependencies of
this package.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import random
import re
import struct
import unicodedata
import warnings
from collections import defaultdict
from collections.abc import Callable, Mapping, MutableSequence, Sequence
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Protocol, TypeVar

from .operations import execute_operation


RANDOMNESS_FORMAT_VERSION = 2
RANDOMNESS_ALGORITHM = "openslay-hmac-sha256-state-v2"
RANDOM_STATE_VERSION = 1
MAX_SAFE_JSON_INTEGER = (1 << 53) - 1

SERVER_COMMITMENT_TAG = b"OpenSlay/server-commitment/v1"
PLAYER_CONTRIBUTION_TAG = b"OpenSlay/player-contribution/v1"
ONLINE_MASTER_TAG = b"OpenSlay/online-master-seed/v1"
TRAINING_MASTER_TAG = b"OpenSlay/training-master-seed/v1"
HMAC_STREAM_TAG = b"OpenSlay/random-stream/v2"
RANDOM_STATE_TAG = b"OpenSlay/random-state/v1"
RANDOM_CONTEXT_TAG = b"OpenSlay/random-context/v1"
AUDIT_CHAIN_TAG = b"OpenSlay/random-audit-chain/v1"

ZERO_AUDIT_HASH = "00" * 32
_UINT256_SIZE = 1 << 256
_PURPOSE_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{1,127}$")
_RULESET_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_RANDOMNESS_RECORD_TYPES = {
    "randomness_manifest",
    "randomness",
    "randomness_reveal",
}
RANDOM_SCOPE_FIELDS = frozenset(
    {
        "scope_id",
        "parent_scope_id",
        "event_id",
        "event",
        "round",
        "phase",
        "skill",
        "owner",
        "actor",
        "targets",
    }
)

RandomnessMode = Literal["training", "online", "unverified"]
T = TypeVar("T")


class RandomnessError(ValueError):
    """Base class for invalid randomness inputs or transcripts."""


class PublicRandomnessInputError(RandomnessError):
    """Raised when a public phrase cannot be accepted safely."""


class RandomnessLogger(Protocol):
    def audit_event(self, category: str, message: str, **context: Any) -> Any: ...


class _FrozenManifestDict(dict[str, Any]):
    def _immutable(self, *_args: Any, **_kwargs: Any) -> None:
        raise RandomnessError("randomness manifest is frozen after transcript commitment")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable
    __ior__ = _immutable

    def __deepcopy__(self, memo: dict[int, Any]) -> dict[str, Any]:
        return {key: copy.deepcopy(value, memo) for key, value in self.items()}


class _FrozenManifestList(list[Any]):
    def _immutable(self, *_args: Any, **_kwargs: Any) -> None:
        raise RandomnessError("randomness manifest is frozen after transcript commitment")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __iadd__ = _immutable
    __imul__ = _immutable
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable

    def __deepcopy__(self, memo: dict[int, Any]) -> list[Any]:
        return [copy.deepcopy(value, memo) for value in self]


def _freeze_manifest_value(value: Any) -> Any:
    if isinstance(value, dict):
        return _FrozenManifestDict(
            {key: _freeze_manifest_value(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return _FrozenManifestList(_freeze_manifest_value(item) for item in value)
    return value


def uint32_be(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise RandomnessError("uint32 value is out of range")
    return struct.pack(">I", value)


def uint64_be(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise RandomnessError("uint64 value is out of range")
    return struct.pack(">Q", value)


def int64_be(value: int) -> bytes:
    if type(value) is not int or not -(1 << 63) <= value < (1 << 63):
        raise RandomnessError("numeric seed must fit in a signed 64-bit integer")
    return struct.pack(">q", value)


def encode_bytes(value: bytes) -> bytes:
    """Encode a variable-length field with an explicit uint32 length prefix."""

    if type(value) is not bytes:
        raise RandomnessError("length-prefixed binary fields must be bytes")
    return uint32_be(len(value)) + value


def encode_text(value: str) -> bytes:
    if not isinstance(value, str):
        raise RandomnessError("length-prefixed text fields must be strings")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise RandomnessError("text contains a code point that cannot be UTF-8 encoded") from exc
    return encode_bytes(encoded)


def normalize_public_randomness_input(value: str) -> str:
    """Validate a replay-visible input while preserving intentional Unicode.

    Only leading and trailing U+0020 characters are removed.  In particular,
    no Unicode normalization or generic whitespace stripping is performed.
    """

    if not isinstance(value, str):
        raise PublicRandomnessInputError("public randomness input must be a string")
    normalized = value.strip(" ")
    for character in normalized:
        if unicodedata.category(character) == "Cc":
            raise PublicRandomnessInputError("public randomness input contains a control character")
    try:
        encoded = normalized.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise PublicRandomnessInputError(
            "public randomness input contains a code point that cannot be UTF-8 encoded"
        ) from exc
    if len(encoded) > 64:
        raise PublicRandomnessInputError(
            "public randomness input exceeds 64 UTF-8 bytes"
        )
    return normalized


def _require_digest(value: bytes, field: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise RandomnessError(f"{field} must contain exactly 32 bytes")
    return value


def _parse_digest_hex(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not _DIGEST_HEX_RE.fullmatch(value):
        raise RandomnessError(
            f"{field} must be a 64-character lowercase hexadecimal digest"
        )
    parsed = bytes.fromhex(value)
    return _require_digest(parsed, field)


def derive_server_commitment(
    match_id: str,
    ruleset_hash: str,
    server_secret: bytes,
) -> bytes:
    _validate_match_id(match_id)
    validate_ruleset_hash(ruleset_hash)
    _require_digest(server_secret, "server_secret")
    return hashlib.sha256(
        SERVER_COMMITMENT_TAG
        + encode_text(match_id)
        + encode_text(ruleset_hash)
        + server_secret
    ).digest()


def derive_player_contribution(
    match_id: str,
    seat_id: int,
    public_randomness_input: str,
    client_nonce: bytes,
) -> bytes:
    _validate_match_id(match_id)
    normalized = normalize_public_randomness_input(public_randomness_input)
    _require_digest(client_nonce, "client_nonce")
    return hashlib.sha256(
        PLAYER_CONTRIBUTION_TAG
        + encode_text(match_id)
        + uint32_be(seat_id)
        + encode_text(normalized)
        + client_nonce
    ).digest()


def derive_online_master_seed(
    match_id: str,
    ruleset_hash: str,
    server_secret: bytes,
    ordered_player_contributions: Sequence[bytes],
) -> bytes:
    _validate_match_id(match_id)
    validate_ruleset_hash(ruleset_hash)
    _require_digest(server_secret, "server_secret")
    contributions = b"".join(
        _require_digest(value, "player_contribution")
        for value in ordered_player_contributions
    )
    return hashlib.sha256(
        ONLINE_MASTER_TAG
        + encode_text(match_id)
        + encode_text(ruleset_hash)
        + server_secret
        + contributions
    ).digest()


def derive_training_master_seed(
    numeric_seed: int,
    public_randomness_input: str = "",
) -> bytes:
    normalized = normalize_public_randomness_input(public_randomness_input)
    return hashlib.sha256(
        TRAINING_MASTER_TAG + int64_be(numeric_seed) + encode_text(normalized)
    ).digest()


@dataclass(frozen=True)
class ParticipantContribution:
    seat_id: int
    driver_kind: str
    public_randomness_input: str | None = None
    client_nonce: str | None = None
    contribution: str | None = None
    commitment_received_order: int | None = None
    accepted_order: int | None = None

    @classmethod
    def human(
        cls,
        *,
        seat_id: int,
        public_randomness_input: str,
        client_nonce: bytes,
        contribution: bytes,
        commitment_received_order: int,
        accepted_order: int,
    ) -> "ParticipantContribution":
        return cls(
            seat_id=seat_id,
            driver_kind="human",
            public_randomness_input=normalize_public_randomness_input(public_randomness_input),
            client_nonce=_require_digest(client_nonce, "client_nonce").hex(),
            contribution=_require_digest(contribution, "player_contribution").hex(),
            commitment_received_order=commitment_received_order,
            accepted_order=accepted_order,
        )

    @classmethod
    def bot(cls, *, seat_id: int, driver_kind: str = "random_bot") -> "ParticipantContribution":
        return cls(seat_id=seat_id, driver_kind=driver_kind)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_participant_contributions(
    match_id: str,
    participants: Sequence[ParticipantContribution],
) -> tuple[ParticipantContribution, ...]:
    _validate_match_id(match_id)
    try:
        materialized = tuple(participants)
    except TypeError as exc:
        raise RandomnessError("participants must be an iterable of receipts") from exc
    for participant in materialized:
        if not isinstance(participant, ParticipantContribution):
            raise RandomnessError(
                "participants must contain ParticipantContribution receipts"
            )
        uint32_be(participant.seat_id)
    ordered = tuple(sorted(materialized, key=lambda item: item.seat_id))
    seat_ids = [participant.seat_id for participant in ordered]
    if len(seat_ids) != len(set(seat_ids)):
        raise RandomnessError("participant seat ids must be unique")
    human_orders: set[int] = set()
    for participant in ordered:
        if not isinstance(participant.driver_kind, str) or not participant.driver_kind:
            raise RandomnessError("participant driver_kind must be a non-empty string")
        if participant.driver_kind != "human":
            if any(
                value is not None
                for value in (
                    participant.public_randomness_input,
                    participant.client_nonce,
                    participant.contribution,
                    participant.commitment_received_order,
                    participant.accepted_order,
                )
            ):
                raise RandomnessError("bot seats cannot supply player contributions")
            continue
        if participant.public_randomness_input is None:
            raise RandomnessError("human participant is missing public randomness input")
        normalized = normalize_public_randomness_input(
            participant.public_randomness_input
        )
        if normalized != participant.public_randomness_input:
            raise RandomnessError(
                "human participant public randomness input is not canonically normalized"
            )
        nonce = _parse_digest_hex(participant.client_nonce or "", "client_nonce")
        contribution = _parse_digest_hex(
            participant.contribution or "", "player_contribution"
        )
        expected = derive_player_contribution(
            match_id,
            participant.seat_id,
            normalized,
            nonce,
        )
        if not hmac.compare_digest(expected, contribution):
            raise RandomnessError(
                f"participant contribution for seat {participant.seat_id} does not match"
            )
        if (
            type(participant.accepted_order) is not int
            or participant.accepted_order <= 0
        ):
            raise RandomnessError("human participant is missing a valid accepted order")
        if (
            type(participant.commitment_received_order) is not int
            or participant.commitment_received_order <= 0
            or participant.commitment_received_order >= participant.accepted_order
        ):
            raise RandomnessError(
                "human contribution was not accepted after its commitment receipt"
            )
        for order in (
            participant.commitment_received_order,
            participant.accepted_order,
        ):
            if order in human_orders:
                raise RandomnessError(
                    "human participant receipt and accepted orders must be globally unique"
                )
            human_orders.add(order)
    return ordered


def canonicalize(value: Any) -> Any:
    """Convert values into the JSON subset used by transcript hashing."""

    if is_dataclass(value):
        return canonicalize(asdict(value))
    if isinstance(value, Enum):
        return canonicalize(value.value)
    if isinstance(value, Path):
        return canonicalize(str(value))
    if isinstance(value, bytes):
        raise RandomnessError(
            "binary values are not canonical semantic randomness values; use explicit hexadecimal text"
        )
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        normalized_items: list[tuple[str, Any]] = []
        for key, item in value.items():
            if isinstance(key, bool) or not isinstance(key, (str, int)):
                raise RandomnessError("canonical mapping keys must be strings or integers")
            if isinstance(key, int) and abs(key) > MAX_SAFE_JSON_INTEGER:
                raise RandomnessError(
                    "canonical integers must be within the JSON-safe range "
                    f"[-{MAX_SAFE_JSON_INTEGER}, {MAX_SAFE_JSON_INTEGER}]"
                )
            serialized_key = str(key)
            canonicalize(serialized_key)
            normalized_items.append((serialized_key, item))
        for serialized_key, item in sorted(normalized_items, key=lambda pair: pair[0]):
            if serialized_key in result:
                raise RandomnessError("canonical mapping contains colliding string keys")
            result[serialized_key] = canonicalize(item)
        return result
    if isinstance(value, (list, tuple)):
        return [canonicalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [canonicalize(item) for item in value]
        return sorted(items, key=canonical_json)
    if isinstance(value, float):
        raise RandomnessError("floating-point values are not canonical randomness inputs")
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise RandomnessError(
                "canonical strings must contain valid Unicode scalar values"
            ) from exc
        return value
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_JSON_INTEGER:
            raise RandomnessError(
                "canonical integers must be within the JSON-safe range "
                f"[-{MAX_SAFE_JSON_INTEGER}, {MAX_SAFE_JSON_INTEGER}]"
            )
        return value
    raise RandomnessError(
        f"unsupported canonical randomness value: {type(value).__name__}"
    )


def validate_ruleset_hash(value: str) -> str:
    if not isinstance(value, str) or not _RULESET_HASH_RE.fullmatch(value):
        raise RandomnessError("ruleset_hash must be a lowercase SHA-256 hexadecimal digest")
    return value


def _validate_match_id(value: str) -> None:
    if not isinstance(value, str) or not value:
        raise RandomnessError("match_id must be a non-empty string")


def canonical_json(value: Any) -> str:
    return json.dumps(
        canonicalize(value),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def validate_random_scope(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical, complete semantic scope for an oracle operation."""

    if not isinstance(value, Mapping):
        raise RandomnessError("random operation scope must be an object")
    canonical = canonicalize(dict(value))
    if not isinstance(canonical, dict) or set(canonical) != RANDOM_SCOPE_FIELDS:
        raise RandomnessError(
            "random operation scope must contain exactly the required semantic fields"
        )
    if not isinstance(canonical["scope_id"], str) or not canonical["scope_id"]:
        raise RandomnessError("random operation scope_id must be a non-empty string")
    for field in ("parent_scope_id", "event_id", "event", "phase", "skill"):
        if canonical[field] is not None and not isinstance(canonical[field], str):
            raise RandomnessError(f"random operation {field} must be a string or null")
    if type(canonical["round"]) is not int or canonical["round"] < 0:
        raise RandomnessError("random operation round must be a non-negative integer")
    for field in ("owner", "actor"):
        if canonical[field] is not None and type(canonical[field]) is not int:
            raise RandomnessError(f"random operation {field} must be an integer or null")
    targets = canonical["targets"]
    if not isinstance(targets, list) or any(type(target) is not int for target in targets):
        raise RandomnessError("random operation targets must be a list of integers")
    return canonical


def validate_random_state(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return a canonical authoritative pre-operation state snapshot."""

    if not isinstance(value, Mapping):
        raise RandomnessError("random operation state must be an object")
    canonical = canonicalize(dict(value))
    if not isinstance(canonical, dict):  # pragma: no cover - mapping invariant
        raise RandomnessError("random operation state must be an object")
    if canonical.get("state_version") != RANDOM_STATE_VERSION:
        raise RandomnessError("random operation state has an unsupported version")
    kind = canonical.get("kind")
    if not isinstance(kind, str) or not kind:
        raise RandomnessError("random operation state kind must be a non-empty string")
    return canonical


def random_state_digest(value: Mapping[str, Any]) -> str:
    """Hash one canonical state without exposing it to the HMAC key schedule."""

    state = validate_random_state(value)
    return hashlib.sha256(
        RANDOM_STATE_TAG + canonical_json(state).encode("utf-8")
    ).hexdigest()


def random_context_digest(
    *,
    operation_sequence: int,
    operation: str,
    purpose: str,
    purpose_counter: int,
    scope: Mapping[str, Any],
    inputs: Mapping[str, Any],
    state_digest: str,
    previous_audit_hash: str,
) -> str:
    """Bind an RNG stream to its exact state, action context, and history."""

    if type(operation_sequence) is not int or operation_sequence <= 0:
        raise RandomnessError("operation sequence must be a positive integer")
    if not isinstance(operation, str) or not operation:
        raise RandomnessError("operation must be a non-empty string")
    if not isinstance(purpose, str) or not _PURPOSE_RE.fullmatch(purpose):
        raise RandomnessError("purpose is malformed")
    if type(purpose_counter) is not int or purpose_counter < 0:
        raise RandomnessError("purpose counter must be non-negative")
    canonical_scope = validate_random_scope(scope)
    canonical_inputs = canonicalize(dict(inputs))
    _parse_digest_hex(state_digest, "state_digest")
    _parse_digest_hex(previous_audit_hash, "previous_audit_hash")
    payload = {
        "format_version": RANDOMNESS_FORMAT_VERSION,
        "algorithm": RANDOMNESS_ALGORITHM,
        "operation_sequence": operation_sequence,
        "operation": operation,
        "purpose": purpose,
        "purpose_counter": purpose_counter,
        "scope": canonical_scope,
        "inputs": canonical_inputs,
        "state_digest": state_digest,
        "previous_audit_hash": previous_audit_hash,
    }
    return hashlib.sha256(
        RANDOM_CONTEXT_TAG + canonical_json(payload).encode("utf-8")
    ).hexdigest()


def transcript_record_hash(
    previous_hash: str,
    record_type: str,
    context: Mapping[str, Any],
) -> str:
    """Extend the transcript chain with a typed canonical record context."""

    previous = _parse_digest_hex(previous_hash, "previous_audit_hash")
    if record_type not in _RANDOMNESS_RECORD_TYPES:
        raise RandomnessError("unsupported randomness transcript record type")
    if not isinstance(context, Mapping):
        raise RandomnessError("randomness transcript context must be an object")
    wrapper = {
        "record_type": record_type,
        "context": canonicalize(dict(context)),
    }
    return hashlib.sha256(
        AUDIT_CHAIN_TAG + previous + canonical_json(wrapper).encode("utf-8")
    ).hexdigest()


def audit_hash(previous_hash: str, payload: Mapping[str, Any]) -> str:
    """Compatibility name for extending the chain with an operation record."""

    return transcript_record_hash(previous_hash, "randomness", payload)


@dataclass(frozen=True)
class _PreparedOperation:
    operation_sequence: int
    counter: int
    inputs: dict[str, Any]
    scope: dict[str, Any]
    state: dict[str, Any]
    state_digest: str
    context_digest: str
    previous_audit_hash: str


class _HMACStream:
    def __init__(
        self,
        master_seed: bytes,
        *,
        context_digest: bytes,
    ) -> None:
        self._master_seed = _require_digest(master_seed, "master_seed")
        self._prefix = HMAC_STREAM_TAG + _require_digest(
            context_digest, "context_digest"
        )
        self.block_index = 0

    def next_uint256(self) -> tuple[int, int]:
        block_index = self.block_index
        digest = hmac.new(
            self._master_seed,
            self._prefix + uint32_be(block_index),
            hashlib.sha256,
        ).digest()
        self.block_index += 1
        return int.from_bytes(digest, "big"), block_index

    def bounded(self, upper_bound: int) -> tuple[int, dict[str, Any]]:
        if (
            type(upper_bound) is not int
            or upper_bound <= 0
            or upper_bound > _UINT256_SIZE
        ):
            raise RandomnessError("random bound must be an integer in [1, 2**256]")
        limit = _UINT256_SIZE - (_UINT256_SIZE % upper_bound)
        rejected: list[dict[str, Any]] = []
        while True:
            raw_value, block_index = self.next_uint256()
            if raw_value < limit:
                return raw_value % upper_bound, {
                    "upper_bound": upper_bound,
                    "block_index": block_index,
                    "raw_value": f"{raw_value:064x}",
                    "rejected": rejected,
                }
            rejected.append(
                {"block_index": block_index, "raw_value": f"{raw_value:064x}"}
            )


# Public name used by the verifier and third-party vector checks.
HMACStream = _HMACStream


class _OperationStream:
    """Apply an oracle's verified or compatibility bounded-draw policy."""

    def __init__(self, oracle: "RandomOracle", stream: _HMACStream) -> None:
        self._oracle = oracle
        self._stream = stream

    @property
    def block_index(self) -> int:
        return self._stream.block_index

    def bounded(self, upper_bound: int) -> tuple[int, dict[str, Any]]:
        return self._oracle._bounded(self._stream, upper_bound)


class RandomOracle:
    """Semantic authoritative randomness backed by a 256-bit HMAC stream."""

    def __init__(
        self,
        master_seed: bytes,
        *,
        mode: RandomnessMode,
        ruleset_hash: str,
        manifest: Mapping[str, Any] | None = None,
        reveal: Mapping[str, Any] | None = None,
        logger: RandomnessLogger | None = None,
    ) -> None:
        if mode not in {"training", "online"}:
            raise RandomnessError("verified RandomOracle mode must be training or online")
        self._master_seed = _require_digest(master_seed, "master_seed")
        self.mode: RandomnessMode = mode
        self.ruleset_hash = validate_ruleset_hash(ruleset_hash)
        self._purpose_counters: dict[str, int] = defaultdict(int)
        self._operation_sequence = 0
        self._previous_audit_hash = ZERO_AUDIT_HASH
        self._logger = logger
        self._scope_provider: Callable[[], Mapping[str, Any]] | None = None
        self._state_provider: Callable[[], Mapping[str, Any]] | None = None
        self._manifest_committed = False
        self._committed_manifest_json: str | None = None
        self._finalized = False
        self._records: list[dict[str, Any]] = []
        self._pending_records: list[tuple[str, str, dict[str, Any]]] = []
        base_manifest: dict[str, Any] = {
            "format_version": RANDOMNESS_FORMAT_VERSION,
            "algorithm": RANDOMNESS_ALGORITHM,
            "mode": mode,
            "ruleset_hash": self.ruleset_hash,
            "commitment_published_order": None,
            "participants": [],
        }
        if manifest:
            manifest_fields = canonicalize(dict(manifest))
            for reserved in ("format_version", "algorithm", "mode", "ruleset_hash"):
                if (
                    reserved in manifest_fields
                    and canonical_json(manifest_fields[reserved])
                    != canonical_json(base_manifest[reserved])
                ):
                    raise RandomnessError(
                        f"manifest cannot override reserved field {reserved!r}"
                    )
            base_manifest.update(manifest_fields)
        self.manifest = base_manifest
        self._reveal_template = canonicalize(dict(reveal or {}))
        reserved_reveal_fields = {
            "format_version",
            "algorithm",
            "mode",
            "outcome",
            "reason",
            "operation_count",
            "final_audit_hash",
            "receipt_summary",
        }
        conflicting_reveal_fields = reserved_reveal_fields.intersection(
            self._reveal_template
        )
        if conflicting_reveal_fields:
            rendered = ", ".join(sorted(conflicting_reveal_fields))
            raise RandomnessError(
                f"reveal template cannot override generated fields: {rendered}"
            )

    @classmethod
    def for_training(
        cls,
        numeric_seed: int,
        public_randomness_input: str = "",
        *,
        ruleset_hash: str,
        logger: RandomnessLogger | None = None,
        match_id: str | None = None,
    ) -> "RandomOracle":
        normalized = normalize_public_randomness_input(public_randomness_input)
        return cls(
            derive_training_master_seed(numeric_seed, normalized),
            mode="training",
            ruleset_hash=ruleset_hash,
            manifest={
                "match_id": match_id or f"training:{numeric_seed}",
                "server_commitment": None,
            },
            reveal={
                # Decimal text preserves the full signed-int64 domain in
                # Godot, whose JSON parser represents numbers as floats.
                "numeric_seed": str(numeric_seed),
                "public_randomness_input": normalized,
            },
            logger=logger,
        )

    @classmethod
    def for_online(
        cls,
        *,
        match_id: str,
        ruleset_hash: str,
        server_secret: bytes,
        participants: Sequence[ParticipantContribution],
        commitment_published_order: int,
        logger: RandomnessLogger | None = None,
    ) -> "RandomOracle":
        if type(commitment_published_order) is not int or commitment_published_order < 0:
            raise RandomnessError("commitment publication order must be non-negative")
        ordered = validate_participant_contributions(match_id, participants)
        for participant in ordered:
            if (
                participant.driver_kind == "human"
                and (
                    (participant.commitment_received_order or 0) <= commitment_published_order
                    or (participant.accepted_order or 0) <= commitment_published_order
                )
            ):
                raise RandomnessError("a contribution was accepted before the server commitment")
        contributions = [
            _parse_digest_hex(participant.contribution or "", "player_contribution")
            for participant in ordered
            if participant.driver_kind == "human"
        ]
        commitment = derive_server_commitment(match_id, ruleset_hash, server_secret)
        return cls(
            derive_online_master_seed(
                match_id,
                ruleset_hash,
                server_secret,
                contributions,
            ),
            mode="online",
            ruleset_hash=ruleset_hash,
            manifest={
                "match_id": match_id,
                "server_commitment": commitment.hex(),
                "commitment_published_order": commitment_published_order,
                "participants": [participant.to_dict() for participant in ordered],
            },
            reveal={"server_secret": _require_digest(server_secret, "server_secret").hex()},
            logger=logger,
        )

    @property
    def final_audit_hash(self) -> str:
        self._assert_manifest_unchanged()
        return self._previous_audit_hash

    @property
    def operation_count(self) -> int:
        return self._operation_sequence

    @property
    def records(self) -> tuple[dict[str, Any], ...]:
        self._assert_manifest_unchanged()
        return tuple(self._records)

    @property
    def finalized(self) -> bool:
        return self._finalized

    def bind_logger(self, logger: RandomnessLogger | None) -> None:
        self._assert_manifest_unchanged()
        self._logger = logger
        if logger is not None:
            self._flush_pending()

    def set_deck_source(self, deck_source: str) -> None:
        """Set or idempotently confirm the authoritative deck source."""

        if not isinstance(deck_source, str) or not deck_source:
            raise RandomnessError("deck_source must be a non-empty string")
        existing = self.manifest.get("deck_source")
        if existing is not None and existing != deck_source:
            raise RandomnessError(
                f"randomness manifest deck_source is already {existing!r}, not {deck_source!r}"
            )
        if self._manifest_committed:
            self._assert_manifest_unchanged()
            if existing != deck_source:
                raise RandomnessError(
                    "cannot add deck_source after the randomness manifest is committed"
                )
            return
        self.manifest["deck_source"] = deck_source

    def set_scope_provider(
        self,
        provider: Callable[[], Mapping[str, Any]] | None,
    ) -> None:
        self._scope_provider = provider

    def set_state_provider(
        self,
        provider: Callable[[], Mapping[str, Any]] | None,
    ) -> None:
        """Set the authoritative state captured immediately before each operation."""

        self._state_provider = provider

    def probability(
        self,
        purpose: str,
        numerator: int,
        denominator: int,
        *,
        scope: Mapping[str, Any] | None = None,
    ) -> bool:
        self._validate_probability(numerator, denominator)
        return self._perform_operation(
            "probability",
            purpose,
            {"numerator": numerator, "denominator": denominator},
            scope,
        )

    def choice(
        self,
        purpose: str,
        candidates: Sequence[T],
        *,
        scope: Mapping[str, Any] | None = None,
    ) -> T:
        materialized = list(candidates)
        if not materialized:
            raise RandomnessError("choice requires at least one candidate")
        return self._perform_operation(
            "choice",
            purpose,
            {"candidates": materialized},
            scope,
        )

    def sample(
        self,
        purpose: str,
        population: Sequence[T],
        count: int,
        *,
        scope: Mapping[str, Any] | None = None,
    ) -> list[T]:
        materialized = list(population)
        if type(count) is not int or count < 0 or count > len(materialized):
            raise RandomnessError("sample count must be between zero and population size")
        return self._perform_operation(
            "sample",
            purpose,
            {"candidates": materialized, "count": count},
            scope,
        )

    def shuffle(
        self,
        purpose: str,
        items: MutableSequence[T],
        *,
        scope: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        before = list(items)
        inputs: dict[str, Any] = {"candidates": before}
        if metadata is not None:
            inputs["metadata"] = dict(metadata)
        result = self._perform_operation("shuffle", purpose, inputs, scope)
        items[:] = result

    def _perform_operation(
        self,
        operation: str,
        purpose: str,
        inputs: Mapping[str, Any],
        scope: Mapping[str, Any] | None,
    ) -> Any:
        """Execute and record one operation through the shared semantic kernel."""

        prepared = self._preflight_operation(operation, purpose, inputs, scope)
        stream = self._stream(purpose, prepared)
        executed = execute_operation(
            operation,
            dict(inputs),
            _OperationStream(self, stream),
        )
        self._record_operation(
            operation=operation,
            purpose=purpose,
            prepared=prepared,
            result=executed["result"],
            proof=executed["proof"],
        )
        return executed["result"]

    def finalize(
        self,
        *,
        outcome: str = "completed",
        reason: str | None = None,
        receipt_summary: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._assert_manifest_unchanged()
        if self._finalized:
            return self.reveal_payload
        if outcome not in {"completed", "aborted"}:
            raise RandomnessError("randomness outcome must be 'completed' or 'aborted'")
        if reason is not None and not isinstance(reason, str):
            raise RandomnessError("randomness reveal reason must be a string or null")
        payload_without_hash = canonicalize(
            {
                "format_version": RANDOMNESS_FORMAT_VERSION,
                "algorithm": RANDOMNESS_ALGORITHM,
                "mode": self.mode,
                **self._reveal_template,
                "outcome": outcome,
                "reason": reason,
                "operation_count": self._operation_sequence,
                "receipt_summary": canonicalize(dict(receipt_summary or {})),
            }
        )
        self._commit_manifest()
        final_hash = transcript_record_hash(
            self._previous_audit_hash,
            "randomness_reveal",
            payload_without_hash,
        )
        self.reveal_payload = {
            **payload_without_hash,
            "final_audit_hash": final_hash,
        }
        self._previous_audit_hash = final_hash
        self._emit(
            "randomness_reveal",
            "Randomness derivation material revealed",
            self.reveal_payload,
        )
        self._finalized = True
        return dict(self.reveal_payload)

    def _preflight_operation(
        self,
        operation: str,
        purpose: str,
        inputs: Mapping[str, Any],
        scope: Mapping[str, Any] | None,
    ) -> _PreparedOperation:
        self._validate_purpose(purpose)
        if self._finalized:
            raise RandomnessError("randomness oracle has already been finalized")
        counter = self._purpose_counters.get(purpose, 0)
        canonical_inputs = canonicalize(dict(inputs))
        if not isinstance(canonical_inputs, dict):  # pragma: no cover - dict input invariant
            raise RandomnessError("random operation inputs must be an object")
        resolved_scope: dict[str, Any] = {
            "scope_id": f"oracle:{operation}:{purpose}:{counter}",
            "parent_scope_id": None,
            "event_id": None,
            "event": operation,
            "round": 0,
            "phase": None,
            "skill": None,
            "owner": None,
            "actor": None,
            "targets": [],
        }
        if self._scope_provider is not None:
            provided = self._scope_provider()
            if not isinstance(provided, Mapping):
                raise RandomnessError("random scope provider must return an object")
            resolved_scope = validate_random_scope(provided)
        if scope is not None:
            if not isinstance(scope, Mapping):
                raise RandomnessError("random operation scope must be an object")
            resolved_scope = validate_random_scope(scope)
        canonical_scope = validate_random_scope(resolved_scope)
        if self._state_provider is None:
            resolved_state: Mapping[str, Any] = {
                "state_version": RANDOM_STATE_VERSION,
                "kind": "oracle-bootstrap",
                "match_id": self.manifest.get("match_id"),
                "ruleset_hash": self.ruleset_hash,
            }
        else:
            resolved_state = self._state_provider()
            if not isinstance(resolved_state, Mapping):
                raise RandomnessError("random state provider must return an object")
        canonical_state = validate_random_state(resolved_state)
        state_hash = random_state_digest(canonical_state)

        # The manifest is the first audit-chain record.  It must be committed
        # before deriving the first operation context so the stream also binds
        # to the exact pre-game commitment and participant receipt.
        self._commit_manifest()
        previous_hash = self._previous_audit_hash
        operation_sequence = self._operation_sequence + 1
        context_hash = random_context_digest(
            operation_sequence=operation_sequence,
            operation=operation,
            purpose=purpose,
            purpose_counter=counter,
            scope=canonical_scope,
            inputs=canonical_inputs,
            state_digest=state_hash,
            previous_audit_hash=previous_hash,
        )
        return _PreparedOperation(
            operation_sequence=operation_sequence,
            counter=counter,
            inputs=canonical_inputs,
            scope=canonical_scope,
            state=canonical_state,
            state_digest=state_hash,
            context_digest=context_hash,
            previous_audit_hash=previous_hash,
        )

    def _stream(self, purpose: str, prepared: _PreparedOperation) -> _HMACStream:
        self._assert_manifest_unchanged()
        if prepared.counter != self._purpose_counters[purpose]:
            raise RandomnessError("random operation purpose counter changed during preflight")
        if prepared.operation_sequence != self._operation_sequence + 1:
            raise RandomnessError("random operation sequence changed during preflight")
        if prepared.previous_audit_hash != self._previous_audit_hash:
            raise RandomnessError("random audit chain changed during preflight")
        self._purpose_counters[purpose] += 1
        return _HMACStream(
            self._master_seed,
            context_digest=bytes.fromhex(prepared.context_digest),
        )

    def _bounded(self, stream: _HMACStream, upper_bound: int) -> tuple[int, dict[str, Any]]:
        return stream.bounded(upper_bound)

    def _record_operation(
        self,
        *,
        operation: str,
        purpose: str,
        prepared: _PreparedOperation,
        result: Any,
        proof: Mapping[str, Any],
    ) -> None:
        self._operation_sequence += 1
        if self._operation_sequence != prepared.operation_sequence:
            raise RandomnessError("recorded operation sequence differs from its context")
        payload = canonicalize(
            {
                "format_version": RANDOMNESS_FORMAT_VERSION,
                "algorithm": RANDOMNESS_ALGORITHM,
                "operation_sequence": self._operation_sequence,
                "operation": operation,
                "purpose": purpose,
                "purpose_counter": prepared.counter,
                "scope": prepared.scope,
                "inputs": prepared.inputs,
                "state": prepared.state,
                "state_digest": prepared.state_digest,
                "context_digest": prepared.context_digest,
                "result": result,
                "proof": proof,
                "previous_audit_hash": prepared.previous_audit_hash,
            }
        )
        chain_payload = dict(payload)
        chain_payload.pop("previous_audit_hash", None)
        payload["audit_hash"] = transcript_record_hash(
            self._previous_audit_hash,
            "randomness",
            chain_payload,
        )
        self._previous_audit_hash = payload["audit_hash"]
        self._records.append(payload)
        self._emit("randomness", "Authoritative random operation", payload)

    def _commit_manifest(self) -> None:
        if self._manifest_committed:
            self._assert_manifest_unchanged()
            return
        committed = canonicalize(self.manifest)
        if not isinstance(committed, dict):  # pragma: no cover - manifest invariant
            raise RandomnessError("randomness manifest must be an object")
        self._committed_manifest_json = canonical_json(committed)
        self.manifest = _freeze_manifest_value(committed)
        self._manifest_committed = True
        self._previous_audit_hash = transcript_record_hash(
            ZERO_AUDIT_HASH,
            "randomness_manifest",
            committed,
        )
        self._emit(
            "randomness_manifest",
            "Randomness transcript manifest",
            committed,
        )

    def _assert_manifest_unchanged(self) -> None:
        if not self._manifest_committed:
            return
        try:
            current = canonical_json(self.manifest)
        except RandomnessError as exc:
            raise RandomnessError(
                "randomness manifest changed after transcript commitment"
            ) from exc
        if current != self._committed_manifest_json:
            raise RandomnessError(
                "randomness manifest changed after transcript commitment"
            )

    def _flush_pending(self) -> None:
        if self._logger is None:
            return
        while self._pending_records:
            category, message, payload = self._pending_records[0]
            self._write_logger(category, message, payload)
            self._pending_records.pop(0)

    def _emit(self, category: str, message: str, payload: Mapping[str, Any]) -> None:
        serialized = canonicalize(dict(payload))
        self._pending_records.append((category, message, serialized))
        self._flush_pending()

    def _write_logger(
        self,
        category: str,
        message: str,
        payload: Mapping[str, Any],
    ) -> None:
        if self._logger is None:
            return
        writer = getattr(self._logger, "audit_event", None)
        if not callable(writer):
            writer = getattr(self._logger, "event", None)
        if callable(writer):
            writer(category, message, **payload)

    @staticmethod
    def _validate_purpose(purpose: str) -> None:
        if not isinstance(purpose, str) or not _PURPOSE_RE.fullmatch(purpose):
            raise RandomnessError(
                "purpose must be a stable 2-128 character lowercase identifier"
            )

    @staticmethod
    def _validate_probability(numerator: int, denominator: int) -> None:
        if type(numerator) is not int or type(denominator) is not int:
            raise RandomnessError("probability must use exact integer fractions")
        if (
            denominator <= 0
            or denominator > MAX_SAFE_JSON_INTEGER
            or numerator < 0
            or numerator > MAX_SAFE_JSON_INTEGER
            or numerator > denominator
        ):
            raise RandomnessError(
                "probability fraction must use JSON-safe integers and satisfy "
                f"0 <= numerator <= denominator <= {MAX_SAFE_JSON_INTEGER}"
            )


class UnverifiedRandomOracle(RandomOracle):
    """Deprecated adapter for callers that still inject ``random.Random``."""

    def __init__(
        self,
        rng: random.Random,
        *,
        ruleset_hash: str,
        logger: RandomnessLogger | None = None,
    ) -> None:
        if not isinstance(rng, random.Random):
            raise RandomnessError("rng must be an instance of random.Random")
        warnings.warn(
            "rng= is deprecated for authoritative state; pass random_oracle= instead",
            DeprecationWarning,
            stacklevel=2,
        )
        self._adapter_rng = rng
        super().__init__(
            b"\x00" * 32,
            mode="training",
            ruleset_hash=ruleset_hash,
            manifest={"server_commitment": None},
            reveal={},
            logger=None,
        )
        self.mode = "unverified"
        self.manifest["mode"] = "unverified"
        if logger is not None:
            self.bind_logger(logger)

    def _bounded(self, stream: _HMACStream, upper_bound: int) -> tuple[int, dict[str, Any]]:
        if (
            type(upper_bound) is not int
            or upper_bound <= 0
            or upper_bound > _UINT256_SIZE
        ):
            raise RandomnessError("random bound must be an integer in [1, 2**256]")
        selected = self._adapter_rng.randrange(upper_bound)
        stream.block_index += 1
        return selected, {
            "upper_bound": upper_bound,
            "adapter_value": selected,
            "unverified_adapter": "python-random",
            "rejected": [],
        }

__all__ = [
    "AUDIT_CHAIN_TAG",
    "HMAC_STREAM_TAG",
    "MAX_SAFE_JSON_INTEGER",
    "ONLINE_MASTER_TAG",
    "PLAYER_CONTRIBUTION_TAG",
    "RANDOM_CONTEXT_TAG",
    "RANDOM_SCOPE_FIELDS",
    "RANDOM_STATE_TAG",
    "RANDOM_STATE_VERSION",
    "RANDOMNESS_ALGORITHM",
    "RANDOMNESS_FORMAT_VERSION",
    "SERVER_COMMITMENT_TAG",
    "TRAINING_MASTER_TAG",
    "ZERO_AUDIT_HASH",
    "ParticipantContribution",
    "PublicRandomnessInputError",
    "RandomOracle",
    "RandomnessError",
    "UnverifiedRandomOracle",
    "audit_hash",
    "canonical_json",
    "canonicalize",
    "derive_online_master_seed",
    "derive_player_contribution",
    "derive_server_commitment",
    "derive_training_master_seed",
    "encode_bytes",
    "encode_text",
    "int64_be",
    "normalize_public_randomness_input",
    "random_context_digest",
    "random_state_digest",
    "transcript_record_hash",
    "uint32_be",
    "uint64_be",
    "validate_participant_contributions",
    "validate_random_scope",
    "validate_random_state",
    "validate_ruleset_hash",
]
