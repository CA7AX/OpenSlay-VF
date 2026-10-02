"""Finite, data-only checks against recorded pre-operation state.

These checks do not authenticate the snapshot or replay state transitions.
Missing state is incomplete evidence, never a successful rule check.
"""

from __future__ import annotations

from typing import Any

from .protocol import canonical_json


_OPERATIONS = {
    "owned_card_pool": "choice",
    "hand_pool": "sample",
    "horse_pool": "choice",
    "debuff_pool": "choice",
    "neighbor_hand_pool": "choice",
    "redirect_targets": "choice",
    "horse_probability": "probability",
    "environment_counter": "probability",
}


def validate_state_rule(rule: Any, operation: str) -> None:
    if not isinstance(rule, dict) or not isinstance(rule.get("kind"), str):
        raise ValueError("state_constraints must declare a supported kind")
    kind = rule["kind"]
    if _OPERATIONS.get(kind) != operation:
        raise ValueError("state constraint kind is unsupported for this operation")
    keys = {"kind"}
    if kind == "environment_counter":
        keys.add("effect")
        if rule.get("effect") not in {"洪水", "山火"}:
            raise ValueError("environment counter requires a public environment")
    if kind == "neighbor_hand_pool":
        keys.add("direction")
        if rule.get("direction") not in {"upper", "lower"}:
            raise ValueError("neighbor hand pool requires upper/lower direction")
    if set(rule) != keys:
        raise ValueError("state constraint has missing or unknown fields")


def _same(first: Any, second: Any) -> bool:
    return canonical_json(first) == canonical_json(second)


def _players(state: dict[str, Any]) -> list[dict[str, Any]]:
    players = state.get("players")
    if not isinstance(players, list) or not players:
        raise ValueError("pre-operation players are missing")
    ids: set[int] = set()
    for player in players:
        if not isinstance(player, dict) or type(player.get("player_id")) is not int:
            raise ValueError("pre-operation player IDs are malformed")
        if player["player_id"] in ids:
            raise ValueError("pre-operation player IDs are duplicated")
        ids.add(player["player_id"])
    return players


def _player(players: list[dict[str, Any]], identity: Any) -> dict[str, Any]:
    if type(identity) is int:
        for player in players:
            if player["player_id"] == identity:
                return player
    raise ValueError("required player is absent from pre-operation state")


def _zone(player: dict[str, Any], name: str) -> list[dict[str, Any]]:
    zone = player.get(name)
    if not isinstance(zone, list):
        raise ValueError(f"pre-operation {name} is missing")
    for card in zone:
        if not isinstance(card, dict) or type(card.get("card_id")) is not int:
            raise ValueError(f"pre-operation {name} has malformed cards")
        if any(not isinstance(card.get(key), str) for key in ("name", "suit", "category")):
            raise ValueError(f"pre-operation {name} has malformed card labels")
    return zone


def _first_target(scope: dict[str, Any]) -> Any:
    targets = scope.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("operation target is missing")
    return targets[0]


def _candidate_player(candidates: Any, players: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(candidates, list) or not candidates or not isinstance(candidates[0], list) or not candidates[0]:
        raise ValueError("candidate player keys are malformed")
    return _player(players, candidates[0][0])


def _check(event: dict[str, Any], rule: dict[str, Any]) -> str:
    state, scope, inputs = event["state"], event["scope"], event["inputs"]
    players = _players(state)
    kind = rule["kind"]
    candidates = inputs.get("candidates")
    expected: Any
    if kind == "hand_pool":
        if not isinstance(candidates, list) or not candidates:
            return "random discard requires a non-empty hand"
        # Card IDs identify the hand without relying on a passive's actor/owner,
        # which can differ from the player losing cards.
        hands = [_zone(player, "hand") for player in players]
        if not any(_same(candidates, hand) for hand in hands):
            return "discard candidates differ from every complete recorded hand"
        if type(inputs.get("count")) is not int or not 1 <= inputs["count"] <= len(candidates):
            return "discard count is outside the recorded hand"
        return ""
    if kind == "owned_card_pool":
        target = _candidate_player(candidates, players)
        if target["player_id"] not in scope.get("targets", []):
            return "owned-card candidate player differs from the operation targets"
        expected = []
        for label, zone in (("hand", "hand"), ("horse_plus", "horses_plus"), ("horse_minus", "horses_minus")):
            for index, card in enumerate(_zone(target, zone)):
                expected.append([target["player_id"], card["card_id"], card["name"], card["suit"], label, index])
        expected.sort()
    elif kind == "horse_pool":
        target = _player(players, _first_target(scope))
        expected = []
        for label, zone in (("horse-minus", "horses_minus"), ("horse-plus", "horses_plus")):
            for card in _zone(target, zone):
                expected.append([label, card["card_id"], card["name"], card["suit"]])
        expected.sort()
    elif kind == "debuff_pool":
        actor = _player(players, scope.get("actor"))
        controls, environments = actor.get("controls"), actor.get("environments")
        if not isinstance(controls, list) or any(not isinstance(value, str) for value in controls):
            raise ValueError("pre-operation controls are malformed")
        if not isinstance(environments, list) or any(not isinstance(value, dict) or not isinstance(value.get("effect"), str) for value in environments):
            raise ValueError("pre-operation environments are malformed")
        expected = sorted([["control", value] for value in controls] + [["environment", value["effect"]] for value in environments])
    elif kind == "neighbor_hand_pool":
        living = [player for player in players if player.get("alive") is True]
        actor = _player(living, scope.get("actor"))
        if len(living) < 2:
            return "neighbor choice requires another living player"
        step = -1 if rule["direction"] == "upper" else 1
        neighbor = living[(living.index(actor) + step) % len(living)]
        expected = sorted([[neighbor["player_id"], card["card_id"], card["name"], card["suit"]] for card in _zone(neighbor, "hand")])
    elif kind == "redirect_targets":
        if not isinstance(candidates, list) or not candidates or any(type(value) is not int for value in candidates):
            return "redirect candidates must be player IDs"
        eligible = {player["player_id"] for player in players if player.get("alive") is True}
        eligible.difference_update((scope.get("actor"), scope.get("owner")))
        if candidates != sorted(set(candidates)) or not set(candidates).issubset(eligible):
            return "redirect candidates must be unique living players other than source and owner"
        # Distance/attackability and completeness of this subset require legal
        # engine transitions; this finite check establishes membership only.
        return ""
    elif kind == "horse_probability":
        owner_id = scope.get("owner")
        owner = _player(players, owner_id if owner_id is not None else scope.get("actor"))
        numerator = min(4, 1 + len(_zone(owner, "horses_plus")) + len(_zone(owner, "horses_minus")))
        return "" if inputs.get("numerator") == numerator else "probability numerator differs from the recorded horse count"
    elif kind == "environment_counter":
        target = _player(players, _first_target(scope))
        environments = target.get("environments")
        if not isinstance(environments, list):
            raise ValueError("pre-operation environments are missing")
        matching = [item for item in environments if isinstance(item, dict) and item.get("effect") == rule["effect"]]
        if len(matching) != 1:
            return "required environment is absent or duplicated in pre-operation state"
        count = matching[0].get("state", {}).get("active_count")
        if type(count) is not int or count < 0:
            return "environment active count is malformed"
        return "" if inputs.get("numerator") == min(8, count) else "probability numerator differs from the recorded environment counter"
    else:  # Descriptor validation rejects unknown kinds before evaluation.
        raise ValueError("unsupported state constraint")
    return "" if expected and _same(candidates, expected) else "candidates differ from the complete pre-operation state pool"


def state_rule_error(event: dict[str, Any], rule: dict[str, Any]) -> tuple[str, bool]:
    state = event.get("state")
    if not isinstance(state, dict) or state.get("kind") != "engine":
        return "required engine pre-operation state is unavailable", True
    scope = event.get("scope", {})
    kind = rule["kind"]
    if kind in {"owned_card_pool", "horse_pool", "environment_counter"} and not scope.get("targets"):
        return "required operation target binding is unavailable", True
    if kind in {"debuff_pool", "neighbor_hand_pool"} and scope.get("actor") is None:
        return "required operation actor binding is unavailable", True
    if kind == "horse_probability" and scope.get("owner") is None and scope.get("actor") is None:
        return "required horse owner binding is unavailable", True
    if kind == "redirect_targets" and (scope.get("actor") is None or scope.get("owner") is None):
        return "required redirect source/owner binding is unavailable", True
    try:
        return _check(event, rule), False
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return f"invalid pre-operation rule evidence: {exc}", False
