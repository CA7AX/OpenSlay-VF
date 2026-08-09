"""Optional validation against public, data-only game-rule descriptors."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

from .protocol import DIGEST_RE, VerificationError, canonical_json, canonicalize
from .verifier import VerificationReport


RuleStatus = Literal["Verified", "Partial", "Not checked", "Invalid"]


@dataclass(frozen=True)
class RuleVerificationReport:
    status: RuleStatus
    summary: str
    exit_code: int
    checked_operation_count: int = 0
    unlisted_purposes: tuple[str, ...] = ()
    failure_operation_sequence: int | None = None
    failure_purpose: str | None = None
    descriptor_hash: str = ""

    @property
    def verified(self) -> bool:
        return self.status == "Verified"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_ruleset(path: str | Path) -> dict[str, Any]:
    try:
        if str(path) == "bundled":
            raw = (
                files("openslay_rng_verifier")
                .joinpath("data/openslay-prototype-v1.partial.json")
                .read_text(encoding="utf-8")
            )
        else:
            raw = Path(path).expanduser().read_text(encoding="utf-8")
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load public ruleset descriptor: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("public ruleset descriptor must be a JSON object")
    try:
        canonical = canonicalize(value)
    except VerificationError as exc:
        raise ValueError(str(exc)) from exc
    if canonical != value:
        raise ValueError("public ruleset descriptor is not canonical")
    return value


def descriptor_hash(descriptor: dict[str, Any]) -> str:
    """Return the reproducible public-rules hash for a descriptor."""

    payload = dict(descriptor)
    payload.pop("public_rules_hash", None)
    return hashlib.sha256(
        b"OpenSlay/public-rules/v1" + canonical_json(payload).encode("utf-8")
    ).hexdigest()


def verify_declared_rules(
    verification: VerificationReport,
    descriptor: dict[str, Any] | None,
) -> RuleVerificationReport:
    """Check transcript inputs against rules data without loading game code."""

    if descriptor is None:
        return RuleVerificationReport(
            status="Not checked",
            summary="No public ruleset descriptor was supplied.",
            exit_code=2,
        )
    digest = descriptor_hash(descriptor)
    try:
        _validate_descriptor(descriptor, digest)
    except ValueError as exc:
        return RuleVerificationReport(
            status="Invalid",
            summary=f"Invalid public ruleset descriptor: {exc}",
            exit_code=1,
            descriptor_hash=digest,
        )
    if not verification.verified:
        return RuleVerificationReport(
            status="Invalid",
            summary="Rule inputs cannot be trusted because transcript verification failed.",
            exit_code=1,
            descriptor_hash=digest,
        )
    committed_hash = (verification.manifest or {}).get("public_rules_hash")
    if committed_hash is not None and committed_hash != digest:
        return RuleVerificationReport(
            status="Invalid",
            summary="Public rules descriptor hash differs from the committed transcript hash.",
            exit_code=1,
            descriptor_hash=digest,
        )
    accepted_private_hashes = descriptor.get("compatible_ruleset_hashes", [])
    transcript_ruleset_hash = (verification.manifest or {}).get("ruleset_hash")
    if accepted_private_hashes and transcript_ruleset_hash not in accepted_private_hashes:
        return RuleVerificationReport(
            status="Invalid",
            summary="Descriptor is not declared compatible with this transcript ruleset.",
            exit_code=1,
            descriptor_hash=digest,
        )

    raw_rules = descriptor.get("operation_rules", [])
    allow_unlisted = descriptor.get("allow_unlisted_purposes", False)
    unlisted: set[str] = set()
    checked = 0
    for sequence, event in enumerate(verification.random_events, start=1):
        purpose = event.get("purpose")
        matching = [rule for rule in raw_rules if _rule_matches(rule, purpose)]
        if not matching:
            unlisted.add(str(purpose))
            if not allow_unlisted:
                return RuleVerificationReport(
                    status="Invalid",
                    summary=f"No public rule covers operation {sequence} ({purpose}).",
                    exit_code=1,
                    checked_operation_count=checked,
                    unlisted_purposes=tuple(sorted(unlisted)),
                    failure_operation_sequence=sequence,
                    failure_purpose=str(purpose),
                    descriptor_hash=digest,
                )
            continue
        if len(matching) > 1:
            return RuleVerificationReport(
                status="Invalid",
                summary=f"Multiple public rules match operation {sequence} ({purpose}).",
                exit_code=1,
                checked_operation_count=checked,
                failure_operation_sequence=sequence,
                failure_purpose=str(purpose),
                descriptor_hash=digest,
            )
        error = _operation_rule_error(event, matching[0])
        if error:
            return RuleVerificationReport(
                status="Invalid",
                summary=f"Operation {sequence} ({purpose}) violates public rule: {error}",
                exit_code=1,
                checked_operation_count=checked,
                failure_operation_sequence=sequence,
                failure_purpose=str(purpose),
                descriptor_hash=digest,
            )
        checked += 1

    if unlisted:
        return RuleVerificationReport(
            status="Partial",
            summary=(
                f"{checked} operation(s) match public rules; "
                f"{len(unlisted)} purpose(s) are not yet described."
            ),
            exit_code=2,
            checked_operation_count=checked,
            unlisted_purposes=tuple(sorted(unlisted)),
            descriptor_hash=digest,
        )
    return RuleVerificationReport(
        status="Verified",
        summary=f"All {checked} random operation(s) match the public rules descriptor.",
        exit_code=0,
        checked_operation_count=checked,
        descriptor_hash=digest,
    )


def _validate_descriptor(descriptor: dict[str, Any], actual_hash: str) -> None:
    if descriptor.get("format_version") != 1:
        raise ValueError("unsupported descriptor format_version")
    if not isinstance(descriptor.get("ruleset_id"), str) or not descriptor["ruleset_id"]:
        raise ValueError("ruleset_id must be a non-empty string")
    claimed_hash = descriptor.get("public_rules_hash")
    if claimed_hash is not None:
        if not isinstance(claimed_hash, str) or not DIGEST_RE.fullmatch(claimed_hash):
            raise ValueError("public_rules_hash must be a lowercase SHA-256 digest")
        if claimed_hash != actual_hash:
            raise ValueError("public_rules_hash does not match descriptor contents")
    compatible = descriptor.get("compatible_ruleset_hashes", [])
    if not isinstance(compatible, list) or any(
        not isinstance(value, str) or not DIGEST_RE.fullmatch(value)
        for value in compatible
    ):
        raise ValueError("compatible_ruleset_hashes must contain SHA-256 digests")
    if type(descriptor.get("allow_unlisted_purposes", False)) is not bool:
        raise ValueError("allow_unlisted_purposes must be boolean")
    rules = descriptor.get("operation_rules")
    if not isinstance(rules, list):
        raise ValueError("operation_rules must be a list")
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            raise ValueError(f"operation rule {index} must be an object")
        exact = rule.get("purpose")
        pattern = rule.get("purpose_pattern")
        if (isinstance(exact, str)) == (isinstance(pattern, str)):
            raise ValueError(f"operation rule {index} needs exactly one purpose selector")
        if isinstance(pattern, str):
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"operation rule {index} has invalid regex: {exc}") from exc
        if rule.get("operation") not in {"probability", "choice", "sample", "shuffle"}:
            raise ValueError(f"operation rule {index} has unsupported operation")
        constraints = rule.get("input_constraints", {})
        if not isinstance(constraints, dict):
            raise ValueError(f"operation rule {index} constraints must be an object")
        for field, constraint in constraints.items():
            if not isinstance(field, str) or not isinstance(constraint, dict):
                raise ValueError(f"operation rule {index} has malformed constraint")
            if not set(constraint).issubset({"equals", "one_of", "minimum", "maximum"}):
                raise ValueError(f"operation rule {index} has unknown constraint operator")
            if "one_of" in constraint and not isinstance(constraint["one_of"], list):
                raise ValueError(f"operation rule {index} one_of must be a list")
            for bound in ("minimum", "maximum"):
                if bound in constraint and type(constraint[bound]) is not int:
                    raise ValueError(f"operation rule {index} {bound} must be an integer")
        deck = rule.get("deck_candidates")
        if deck is not None:
            if not isinstance(deck, dict) or set(deck) != {
                "card_count",
                "normalized_candidates_sha256",
            }:
                raise ValueError(f"operation rule {index} has malformed deck manifest")
            if type(deck["card_count"]) is not int or deck["card_count"] <= 0:
                raise ValueError(f"operation rule {index} has invalid deck card count")
            digest = deck["normalized_candidates_sha256"]
            if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
                raise ValueError(f"operation rule {index} has invalid deck digest")


def _rule_matches(rule: dict[str, Any], purpose: Any) -> bool:
    if not isinstance(purpose, str):
        return False
    if isinstance(rule.get("purpose"), str):
        return purpose == rule["purpose"]
    pattern = rule.get("purpose_pattern")
    return isinstance(pattern, str) and re.fullmatch(pattern, purpose) is not None


def _operation_rule_error(event: dict[str, Any], rule: dict[str, Any]) -> str:
    if event.get("operation") != rule.get("operation"):
        return f"expected operation {rule.get('operation')!r}"
    inputs = event.get("inputs")
    if not isinstance(inputs, dict):
        return "inputs are not an object"
    constraints = rule.get("input_constraints", {})
    for field, constraint in constraints.items():
        if field not in inputs:
            return f"input {field!r} is missing"
        if not isinstance(constraint, dict):
            return f"constraint for {field!r} is malformed"
        value = inputs[field]
        if "equals" in constraint and canonical_json(value) != canonical_json(
            constraint["equals"]
        ):
            return f"input {field!r} does not equal the public value"
        if "one_of" in constraint:
            options = constraint["one_of"]
            if not isinstance(options, list) or all(
                canonical_json(value) != canonical_json(option) for option in options
            ):
                return f"input {field!r} is outside the public alternatives"
        if "minimum" in constraint and (
            type(value) is not int or value < constraint["minimum"]
        ):
            return f"input {field!r} is below the public minimum"
        if "maximum" in constraint and (
            type(value) is not int or value > constraint["maximum"]
        ):
            return f"input {field!r} exceeds the public maximum"
    deck = rule.get("deck_candidates")
    if deck is not None:
        if not isinstance(deck, dict):
            return "deck_candidates rule is malformed"
        candidates = inputs.get("candidates")
        if not isinstance(candidates, list):
            return "deck candidates are missing"
        expected_count = deck.get("card_count")
        if type(expected_count) is int and len(candidates) != expected_count:
            return f"deck has {len(candidates)} cards, expected {expected_count}"
        normalized = []
        for index, candidate in enumerate(candidates, start=1):
            if not isinstance(candidate, dict):
                return "deck candidate is not an object"
            item = dict(candidate)
            item["card_id"] = index
            normalized.append(item)
        actual = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
        if actual != deck.get("normalized_candidates_sha256"):
            return "deck candidates differ from the public deck manifest"
    return ""


__all__ = [
    "RuleVerificationReport",
    "RuleStatus",
    "descriptor_hash",
    "load_ruleset",
    "verify_declared_rules",
]
