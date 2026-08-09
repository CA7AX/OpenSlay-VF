"""Standalone verifier for OpenSlay randomness transcripts."""

from .localization import (
    HumanLanguage,
    bilingual_label,
    format_human_report,
    format_input_error,
    localized_status,
)
from .oracle import RandomOracle
from .protocol import (
    RANDOMNESS_ALGORITHM,
    RANDOMNESS_FORMAT_VERSION,
    ParticipantContribution,
    PublicRandomnessInputError,
    RandomnessError,
    derive_online_master_seed,
    derive_player_contribution,
    derive_server_commitment,
    derive_training_master_seed,
)
from .rules import (
    RuleVerificationReport,
    descriptor_hash,
    load_ruleset,
    verify_declared_rules,
)
from .verifier import (
    VerificationReport,
    load_transcript,
    read_jsonl_records,
    recompute_operation,
    verify_path,
    verify_records,
)
from .witness import (
    WitnessReport,
    load_witness,
    short_fingerprint,
    trial_tamper,
    verify_witness,
    verify_witness_path,
)

__version__ = "0.2.1"

__all__ = [
    "RANDOMNESS_ALGORITHM",
    "RANDOMNESS_FORMAT_VERSION",
    "ParticipantContribution",
    "PublicRandomnessInputError",
    "RandomOracle",
    "RandomnessError",
    "HumanLanguage",
    "RuleVerificationReport",
    "VerificationReport",
    "WitnessReport",
    "descriptor_hash",
    "derive_online_master_seed",
    "derive_player_contribution",
    "derive_server_commitment",
    "derive_training_master_seed",
    "bilingual_label",
    "format_human_report",
    "format_input_error",
    "load_ruleset",
    "load_transcript",
    "load_witness",
    "localized_status",
    "read_jsonl_records",
    "recompute_operation",
    "short_fingerprint",
    "trial_tamper",
    "verify_declared_rules",
    "verify_path",
    "verify_records",
    "verify_witness",
    "verify_witness_path",
]
