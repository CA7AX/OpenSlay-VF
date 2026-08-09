"""Public protocol facade for the standalone randomness implementation.

The generator and verifier intentionally consume these same wire primitives.
This module contains no OpenSlay engine imports and is safe to publish as part
of the standalone package.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .oracle import (
    AUDIT_CHAIN_TAG,
    HMAC_STREAM_TAG,
    MAX_SAFE_JSON_INTEGER,
    ONLINE_MASTER_TAG,
    PLAYER_CONTRIBUTION_TAG,
    RANDOM_CONTEXT_TAG,
    RANDOM_SCOPE_FIELDS,
    RANDOM_STATE_TAG,
    RANDOM_STATE_VERSION,
    RANDOMNESS_ALGORITHM,
    RANDOMNESS_FORMAT_VERSION,
    SERVER_COMMITMENT_TAG,
    TRAINING_MASTER_TAG,
    ZERO_AUDIT_HASH,
    HMACStream,
    ParticipantContribution,
    PublicRandomnessInputError,
    RandomnessError,
    _DIGEST_HEX_RE,
    _PURPOSE_RE,
    _RANDOMNESS_RECORD_TYPES,
    _parse_digest_hex as _oracle_parse_digest_hex,
    _validate_match_id,
    audit_hash,
    canonical_json,
    canonicalize,
    derive_online_master_seed,
    derive_player_contribution,
    derive_server_commitment,
    derive_training_master_seed,
    encode_bytes,
    encode_text,
    int64_be,
    normalize_public_randomness_input,
    random_context_digest,
    random_state_digest,
    transcript_record_hash,
    uint32_be,
    uint64_be,
    validate_participant_contributions,
    validate_random_scope,
    validate_random_state,
    validate_ruleset_hash,
)


VerificationError = RandomnessError
PURPOSE_RE = _PURPOSE_RE
DIGEST_RE = _DIGEST_HEX_RE
RANDOMNESS_RECORD_TYPES = frozenset(_RANDOMNESS_RECORD_TYPES)
_HMACStream = HMACStream


class IncompleteReceipt(RandomnessError):
    """Raised when an online match lacks a fully witnessed start receipt."""


def parse_digest(value: Any, field: str) -> bytes:
    return _oracle_parse_digest_hex(value, field)


_parse_digest_hex = parse_digest


def validate_match_id(value: Any) -> str:
    _validate_match_id(value)
    return value


def validate_participants(
    match_id: str,
    participants: Sequence[ParticipantContribution],
) -> tuple[ParticipantContribution, ...]:
    return validate_participant_contributions(match_id, participants)


__all__ = [
    "AUDIT_CHAIN_TAG",
    "DIGEST_RE",
    "HMAC_STREAM_TAG",
    "HMACStream",
    "IncompleteReceipt",
    "MAX_SAFE_JSON_INTEGER",
    "ONLINE_MASTER_TAG",
    "PLAYER_CONTRIBUTION_TAG",
    "PURPOSE_RE",
    "ParticipantContribution",
    "PublicRandomnessInputError",
    "RANDOMNESS_ALGORITHM",
    "RANDOMNESS_FORMAT_VERSION",
    "RANDOMNESS_RECORD_TYPES",
    "RANDOM_CONTEXT_TAG",
    "RANDOM_SCOPE_FIELDS",
    "RANDOM_STATE_TAG",
    "RANDOM_STATE_VERSION",
    "RandomnessError",
    "SERVER_COMMITMENT_TAG",
    "TRAINING_MASTER_TAG",
    "VerificationError",
    "ZERO_AUDIT_HASH",
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
    "parse_digest",
    "random_context_digest",
    "random_state_digest",
    "transcript_record_hash",
    "uint32_be",
    "uint64_be",
    "validate_match_id",
    "validate_participant_contributions",
    "validate_participants",
    "validate_random_scope",
    "validate_random_state",
    "validate_ruleset_hash",
]
