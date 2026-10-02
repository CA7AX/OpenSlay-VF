from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from openslay_rng_verifier import RandomOracle, load_ruleset, verify_declared_rules, verify_records
from openslay_rng_verifier.rules import descriptor_hash, _validate_descriptor


ROOT = Path(__file__).resolve().parents[1]
DESCRIPTOR = load_ruleset("bundled")
RULES = {rule["purpose"]: rule for rule in DESCRIPTOR["operation_rules"] if "purpose" in rule}
DECK = json.loads((ROOT / "data/prototype-deck-v1.json").read_text(encoding="utf-8"))["candidates"]


class CaptureLogger:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def audit_event(self, category: str, message: str, **context: Any) -> None:
        self.records.append({"sequence": len(self.records) + 1, "record_type": category, "category": category, "format_version": context["format_version"], "context": copy.deepcopy(context)})


def _report(purpose: str, operation: str, inputs: dict[str, Any], *, state: dict[str, Any] | None = None, actor: int = 0, owner: int | None = None, targets: tuple[int, ...] = (1,)):
    logger = CaptureLogger()
    random_oracle = RandomOracle.for_training(42, ruleset_hash="11" * 32, logger=logger)
    random_oracle.set_deck_source("oracle")
    cards = copy.deepcopy(DECK)
    random_oracle.shuffle("deck.epoch.1", cards, metadata={"deck_epoch": 1, "start_card_id": 1, "card_count": 144})
    if state is not None:
        random_oracle.set_state_provider(lambda: state)
    scope = {"scope_id": "test", "parent_scope_id": None, "event_id": None, "event": "test", "round": 0, "phase": "play", "skill": None, "owner": owner, "actor": actor, "targets": list(targets)}
    if operation == "probability":
        random_oracle.probability(purpose, inputs["numerator"], inputs["denominator"], scope=scope)
    elif operation == "choice":
        random_oracle.choice(purpose, inputs["candidates"], scope=scope)
    else:
        random_oracle.sample(purpose, inputs["candidates"], inputs["count"], scope=scope)
    random_oracle.finalize(outcome="completed", receipt_summary={"winner_ids": [0]})
    verification = verify_records(logger.records)
    assert verification.status == "Verified deterministic", verification.summary
    return verify_declared_rules(verification, DESCRIPTOR)


def _state() -> dict[str, Any]:
    players = []
    for identity in range(3):
        players.append({"player_id": identity, "alive": True, "hand": copy.deepcopy(DECK[identity * 2:identity * 2 + 2]), "horses_plus": [], "horses_minus": [], "controls": [], "environments": []})
    players[0]["controls"] = ["闭穴"]
    players[0]["environments"] = [{"effect": "山火", "state": {"active_count": 2}}]
    players[1]["environments"] = [{"effect": "洪水", "state": {"active_count": 2}}]
    players[1]["horses_minus"] = [copy.deepcopy(DECK[-1])]
    return {"state_version": 1, "kind": "engine", "players": players}


FIXED = [(purpose, rule["input_constraints"]["numerator"]["equals"], rule["input_constraints"]["denominator"]["equals"]) for purpose, rule in RULES.items() if rule["operation"] == "probability" and "equals" in rule["input_constraints"]["numerator"]]


@pytest.mark.parametrize("purpose,numerator,denominator", FIXED)
def test_fixed_probabilities_reject_cryptographically_consistent_wrong_odds(purpose: str, numerator: int, denominator: int) -> None:
    assert _report(purpose, "probability", {"numerator": numerator, "denominator": denominator}).status == "Verified"
    bad = _report(purpose, "probability", {"numerator": (numerator + 1) % denominator, "denominator": denominator})
    assert bad.status == "Invalid"
    assert bad.failure_purpose == purpose


def test_roster_pool_and_selection_count() -> None:
    roster = RULES["setup.roster"]["input_constraints"]["candidates"]["equals"]
    for count in (4, 5, 8):
        assert _report("setup.roster", "sample", {"candidates": roster, "count": count}).status == "Verified"
    for candidates, count in ((roster[:-1], 4), (list(reversed(roster)), 4), (roster, 3)):
        assert _report("setup.roster", "sample", {"candidates": candidates, "count": count}).status == "Invalid"
    assert _report("setup.roster.fill", "sample", {"candidates": roster[2:], "count": 2}).status == "Verified"
    for candidates, count in ((roster[:2] * 2, 2), (["not-a-character"], 1), (list(reversed(roster)), 1), (roster, 4)):
        assert _report("setup.roster.fill", "sample", {"candidates": candidates, "count": count}).status == "Invalid"


@pytest.mark.parametrize("purpose", ["virtual-card.suit", "skill.random-control-card.name"])
def test_fixed_choice_pools_reject_subsets_and_reordering(purpose: str) -> None:
    candidates = RULES[purpose]["input_constraints"]["candidates"]["equals"]
    assert _report(purpose, "choice", {"candidates": candidates}).status == "Verified"
    for changed in (candidates[:-1], list(reversed(candidates))):
        assert _report(purpose, "choice", {"candidates": changed}).status == "Invalid"


def test_hand_discard_checks_the_complete_hand() -> None:
    state = _state()
    hand = state["players"][1]["hand"]
    assert _report("rules.random-hand-discard", "sample", {"candidates": hand, "count": 2}, state=state).status == "Verified"
    for candidates in (hand[:1], list(reversed(hand)), [*hand, state["players"][0]["hand"][0]]):
        assert _report("rules.random-hand-discard", "sample", {"candidates": candidates, "count": 1}, state=state).status == "Invalid"


@pytest.mark.parametrize("purpose", ["card.steal.target-card", "card.destroy.target-card"])
def test_owned_cards_check_hand_equipment_zone_and_index(purpose: str) -> None:
    state = _state()
    player = state["players"][1]
    candidates = sorted([[1, card["card_id"], card["name"], card["suit"], zone, index] for zone, cards in (("hand", player["hand"]), ("horse_minus", player["horses_minus"])) for index, card in enumerate(cards)])
    assert _report(purpose, "choice", {"candidates": candidates}, state=state).status == "Verified"
    for changed in (candidates[:-1], [[*candidates[0][:-1], 99]], list(reversed(candidates))):
        assert _report(purpose, "choice", {"candidates": changed}, state=state).status == "Invalid"
    assert _report(purpose, "choice", {"candidates": candidates}, state=state, targets=(0,)).status == "Invalid"


def test_debuff_and_horse_choices_use_recorded_state() -> None:
    state = _state()
    purpose = "card.heal-cleanse.remove-debuff"
    candidates = [["control", "闭穴"], ["environment", "山火"]]
    assert _report(purpose, "choice", {"candidates": candidates}, state=state).status == "Verified"
    assert _report(purpose, "choice", {"candidates": candidates[:1]}, state=state).status == "Invalid"
    card = state["players"][1]["horses_minus"][0]
    candidates = [["horse-minus", card["card_id"], card["name"], card["suit"]]]
    purpose = "skill.wei.xia-hou-yuan.failed-disarm.steal-horse"
    assert _report(purpose, "choice", {"candidates": candidates}, state=state).status == "Verified"
    candidates[0][0] = "horse-plus"
    assert _report(purpose, "choice", {"candidates": candidates}, state=state).status == "Invalid"


@pytest.mark.parametrize("direction,identity", [("upper", 2), ("lower", 1)])
def test_neighbor_hand_uses_living_seat_order(direction: str, identity: int) -> None:
    state = _state()
    purpose = f"skill.shu.fei-yi.{direction}-neighbor.steal-hand-card"
    candidates = sorted([[identity, card["card_id"], card["name"], card["suit"]] for card in state["players"][identity]["hand"]])
    assert _report(purpose, "choice", {"candidates": candidates}, state=state).status == "Verified"
    assert _report(purpose, "choice", {"candidates": candidates[:1]}, state=state).status == "Invalid"
    state["players"][identity]["alive"] = False
    assert _report(purpose, "choice", {"candidates": candidates}, state=state).status == "Invalid"


def test_redirect_targets_exclude_dead_source_and_owner() -> None:
    state = _state()
    purpose = "skill.qun.zou-shi.slash-target.redirect-target"
    assert _report(purpose, "choice", {"candidates": [2]}, state=state, owner=1).status == "Verified"
    for candidates in ([0], [1], [2, 2], [7]):
        assert _report(purpose, "choice", {"candidates": candidates}, state=state, owner=1).status == "Invalid"
    state["players"][2]["alive"] = False
    assert _report(purpose, "choice", {"candidates": [2]}, state=state, owner=1).status == "Invalid"


@pytest.mark.parametrize("purpose,numerator,actor,owner,targets", [("environment.flood.expire-before-bonus", 2, 0, None, (1,)), ("environment.wildfire.expire-before-bonus", 2, 1, None, (0,)), ("skill.wei.xia-hou-yuan.slash.damage-plus-one", 2, 1, 1, ())])
def test_state_dependent_probabilities_reject_wrong_numerators(purpose: str, numerator: int, actor: int, owner: int | None, targets: tuple[int, ...]) -> None:
    state = _state()
    denominator = RULES[purpose]["input_constraints"]["denominator"]["equals"]
    options = {"state": state, "actor": actor, "owner": owner, "targets": targets}
    assert _report(purpose, "probability", {"numerator": numerator, "denominator": denominator}, **options).status == "Verified"
    assert _report(purpose, "probability", {"numerator": numerator - 1, "denominator": denominator}, **options).status == "Invalid"
    missing = _report(purpose, "probability", {"numerator": numerator, "denominator": denominator})
    assert missing.status == "Partial"
    assert missing.incomplete_purposes == (purpose,)
    assert missing.checked_operation_count == 1


def test_unknown_future_purposes_stay_partial() -> None:
    result = _report("future.proc", "probability", {"numerator": 1, "denominator": 2})
    assert result.status == "Partial"
    assert result.unlisted_purposes == ("future.proc",)


def test_descriptor_is_self_hashed_and_has_no_catch_all() -> None:
    assert DESCRIPTOR["public_rules_hash"] == descriptor_hash(DESCRIPTOR)
    patterns = [rule["purpose_pattern"] for rule in DESCRIPTOR["operation_rules"] if "purpose_pattern" in rule]
    assert patterns == [r"deck\.epoch\.[1-9][0-9]*"]
    assert len(DESCRIPTOR["operation_rules"]) == 73


@pytest.mark.parametrize("change", ["unknown_field", "unknown_state_kind", "wrong_operation", "missing_direction", "empty_constraints", "duplicate_universe", "floating_version"])
def test_format_two_rejects_unsupported_or_empty_constraints(change: str) -> None:
    descriptor = copy.deepcopy(DESCRIPTOR)
    rule = next(rule for rule in descriptor["operation_rules"] if rule.get("purpose") == "skill.shu.fei-yi.upper-neighbor.steal-hand-card")
    if change == "unknown_field":
        rule["ignored_constraint"] = True
    elif change == "unknown_state_kind":
        rule["state_constraints"]["kind"] = "run_python"
    elif change == "wrong_operation":
        rule["operation"] = "sample"
    elif change == "missing_direction":
        del rule["state_constraints"]["direction"]
    elif change == "empty_constraints":
        rule["state_constraints"] = {}
    elif change == "duplicate_universe":
        rule["candidate_constraints"] = {"ordered_subset_of": ["same", "same"]}
    else:
        descriptor["format_version"] = 2.0
    with pytest.raises(ValueError):
        descriptor["public_rules_hash"] = descriptor_hash(descriptor)
        _validate_descriptor(descriptor, descriptor["public_rules_hash"])


def test_missing_binding_is_partial_and_malformed_state_is_invalid() -> None:
    state = _state()
    purpose = "environment.flood.expire-before-bonus"
    inputs = {"numerator": 2, "denominator": 8}
    result = _report(purpose, "probability", inputs, state=state, targets=())
    assert result.status == "Partial"
    assert result.incomplete_purposes == (purpose,)
    from openslay_rng_verifier.localization import _format_rules
    for language in ("zh", "en", "bilingual"):
        assert purpose in "\n".join(_format_rules(result, language))
    assert "缺少必要的状态" in "\n".join(_format_rules(result, "zh"))
    state["players"] = None
    assert _report(purpose, "probability", inputs, state=state).status == "Invalid"


def test_historical_format_one_descriptor_is_unchanged_and_supported() -> None:
    descriptor = load_ruleset(ROOT / "data/openslay-prototype-v1.partial.json")
    assert descriptor["public_rules_hash"] == "51425268c309a0f6247ffdbabe3104d9734a77a3bec7eee4c4d439f3c94c3f45"
    _validate_descriptor(descriptor, descriptor_hash(descriptor))
