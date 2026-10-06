from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from openslay_rng_verifier import RandomOracle, verify_records
from openslay_rng_verifier.protocol import (
    RandomnessError,
    ZERO_AUDIT_HASH,
    derive_training_master_seed,
    random_context_digest,
    random_state_digest,
    transcript_record_hash,
)
from openslay_rng_verifier.verifier import recompute_operation


ROOT = Path(__file__).resolve().parents[1]
DECK = json.loads((ROOT / "data" / "prototype-deck-v1.json").read_text(encoding="utf-8"))["candidates"]
MASTER_SEED = derive_training_master_seed(7, "")


class CaptureLogger:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def audit_event(self, category: str, message: str, **context: Any) -> None:
        self.records.append(
            {
                "sequence": len(self.records) + 1,
                "record_type": category,
                "category": category,
                "format_version": 2,
                "context": copy.deepcopy(context),
            }
        )


class LedgerDeck:
    """Minimal oracle-backed draw pile following the engine Deck contract."""

    def __init__(self, oracle: RandomOracle) -> None:
        self.random_oracle = oracle
        self.cards: list[dict[str, Any]] = []
        self.epoch = 0
        oracle.set_deck_source("oracle")
        oracle.set_state_provider(
            lambda: {
                "state_version": 1,
                "kind": "engine",
                "zones": {"draw_pile": copy.deepcopy(self.cards)},
            }
        )

    def _refill(self) -> None:
        if self.cards:
            return
        start_card_id = self.epoch * len(DECK) + 1
        self.epoch += 1
        cards = [
            {**card, "card_id": start_card_id + offset}
            for offset, card in enumerate(DECK)
        ]
        self.random_oracle.shuffle(
            f"deck.epoch.{self.epoch}",
            cards,
            metadata={
                "deck_epoch": self.epoch,
                "start_card_id": start_card_id,
                "card_count": len(cards),
            },
        )
        self.cards = cards

    def draw(self, player_id: int, count: int = 1) -> list[dict[str, Any]]:
        drawn = []
        for _ in range(count):
            self._refill()
            card = self.cards.pop()
            self.random_oracle.record_deck_draw(card["card_id"], player_id=player_id)
            drawn.append(card)
        return drawn

    def take(self, player_id: int, count: int) -> list[dict[str, Any]]:
        taken = []
        for _ in range(count):
            self._refill()
            card = self.cards.pop()
            self.random_oracle.record_deck_take(card["card_id"], player_id=player_id)
            taken.append(card)
        return taken

    def restore(self, player_id: int, cards: list[dict[str, Any]]) -> None:
        self.cards.extend(reversed(cards))
        self.random_oracle.record_deck_restore(
            [card["card_id"] for card in cards], player_id=player_id
        )


def _match() -> list[dict[str, Any]]:
    logger = CaptureLogger()
    oracle = RandomOracle.for_training(7, ruleset_hash="11" * 32, logger=logger)
    deck = LedgerDeck(oracle)
    deck.draw(0, 4)
    # Inspect three, keep the middle card, and return the rest reordered.
    inspected = deck.take(1, 3)
    deck.restore(1, [inspected[2], inspected[0]])
    oracle.probability("environment.thunder.self-damage", 1, 4)
    deck.draw(2, len(deck.cards) - 2)
    # This inspection spans the epoch boundary: two old cards, one new card.
    inspected = deck.take(3, 3)
    deck.restore(3, inspected)
    oracle.probability("environment.thunder.self-damage", 1, 4)
    deck.draw(0, 5)
    oracle.finalize(outcome="completed", receipt_summary={"winner_ids": [0]})
    return logger.records


def _rechain(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Recompute every digest so a tamper is cryptographically consistent."""

    previous = ZERO_AUDIT_HASH
    for record in records:
        context = record["context"]
        if record["record_type"] == "randomness_manifest":
            previous = transcript_record_hash(previous, "randomness_manifest", context)
        elif record["record_type"] == "randomness":
            context["previous_audit_hash"] = previous
            context["state_digest"] = random_state_digest(context["state"])
            context["context_digest"] = random_context_digest(
                operation_sequence=context["operation_sequence"],
                operation=context["operation"],
                purpose=context["purpose"],
                purpose_counter=context["purpose_counter"],
                scope=context["scope"],
                inputs=context["inputs"],
                state_digest=context["state_digest"],
                previous_audit_hash=previous,
            )
            context.update(recompute_operation(MASTER_SEED, context))
            chain_payload = dict(context)
            chain_payload.pop("previous_audit_hash")
            chain_payload.pop("audit_hash")
            context["audit_hash"] = transcript_record_hash(previous, "randomness", chain_payload)
            previous = context["audit_hash"]
        else:
            chain_payload = dict(context)
            chain_payload.pop("final_audit_hash")
            context["final_audit_hash"] = transcript_record_hash(
                previous, "randomness_reveal", chain_payload
            )
    return records


def _tampered(mutate: Callable[[list[dict[str, Any]]], None]) -> Any:
    records = _match()
    mutate(records)
    return verify_records(_rechain(records))


def _operation(records: list[dict[str, Any]], purpose: str, index: int = 0) -> dict[str, Any]:
    matches = [
        record["context"]
        for record in records
        if record["record_type"] == "randomness" and record["context"]["purpose"] == purpose
    ]
    return matches[index]


def _reveal(records: list[dict[str, Any]]) -> dict[str, Any]:
    return records[-1]["context"]


def test_ledger_replays_draws_inspections_and_epochs() -> None:
    records = _match()
    report = verify_records(records)
    assert report.status == "Verified deterministic", report.summary
    assert report.deck_epochs_verified == 2
    # 4 + 137 + 5 draws, and two 3-card inspections with their restores.
    assert report.deck_moves_verified == (4 + 137 + 5) + 2 * (3 + 1)
    assert report.manifest["deck_ledger_version"] == 1
    assert [move["move"] for move in _reveal(records)["deck_ledger_tail"]] == ["draw"] * 5
    # A recomputed but untouched transcript still verifies.
    assert verify_records(_rechain(copy.deepcopy(records))).status == "Verified deterministic"


def test_drawing_below_the_top_card_is_invalid() -> None:
    def deal_from_the_middle(records: list[dict[str, Any]]) -> None:
        state = _operation(records, "environment.thunder.self-damage")["state"]
        first_draw = state["deck_ledger"][0]
        pile = _operation(records, "deck.epoch.1")["result"]
        first_draw["card_id"] = pile[0]["card_id"]

    report = _tampered(deal_from_the_middle)
    assert report.status == "Invalid"
    assert "is on top" in report.summary


def test_engine_draw_pile_must_match_the_replayed_ledger() -> None:
    def hide_a_card(records: list[dict[str, Any]]) -> None:
        state = _operation(records, "environment.thunder.self-damage")["state"]
        del state["zones"]["draw_pile"][0]

    report = _tampered(hide_a_card)
    assert report.status == "Invalid"
    assert "engine draw pile differs" in report.summary


def test_restore_must_return_cards_under_inspection() -> None:
    def restore_a_foreign_card(records: list[dict[str, Any]]) -> None:
        state = _operation(records, "environment.thunder.self-damage")["state"]
        restore = next(move for move in state["deck_ledger"] if move["move"] == "restore")
        restore["card_ids"][0] = 9_999

    report = _tampered(restore_a_foreign_card)
    assert report.status == "Invalid"
    assert "not under inspection" in report.summary


def test_restore_requires_an_open_inspection_by_the_same_player() -> None:
    def other_player_restores(records: list[dict[str, Any]]) -> None:
        state = _operation(records, "environment.thunder.self-damage")["state"]
        restore = next(move for move in state["deck_ledger"] if move["move"] == "restore")
        restore["player_id"] = 0

    report = _tampered(other_player_restores)
    assert report.status == "Invalid"
    assert "differs from the inspection" in report.summary

    def restore_after_a_draw(records: list[dict[str, Any]]) -> None:
        tail = _reveal(records)["deck_ledger_tail"]
        tail.append({"move": "restore", "card_ids": [tail[-1]["card_id"]], "player_id": 0})

    report = _tampered(restore_after_a_draw)
    assert report.status == "Invalid"
    assert "no open inspection" in report.summary


def test_epoch_reshuffle_requires_an_exhausted_pile() -> None:
    def reshuffle_early(records: list[dict[str, Any]]) -> None:
        # Leave the last old card in both the ledger replay and the engine
        # pile, so only the early reshuffle itself is wrong.
        state = _operation(records, "deck.epoch.2")["state"]
        last_take = state["deck_ledger"].pop()
        pile = _operation(records, "deck.epoch.1")["result"]
        state["zones"]["draw_pile"] = [
            card for card in pile if card["card_id"] == last_take["card_id"]
        ]

    report = _tampered(reshuffle_early)
    assert report.status == "Invalid"
    assert "remained in the draw pile" in report.summary


def test_tail_moves_are_replayed_after_the_last_operation() -> None:
    def tail_skips_a_card(records: list[dict[str, Any]]) -> None:
        del _reveal(records)["deck_ledger_tail"][0]

    report = _tampered(tail_skips_a_card)
    assert report.status == "Invalid"
    assert "is on top" in report.summary
    assert report.failure_sequence == _match()[-1]["sequence"]


@pytest.mark.parametrize(
    ("mutate", "detail"),
    [
        (
            lambda records: _operation(records, "deck.epoch.1")["state"].pop("deck_ledger"),
            "missing its deck ledger",
        ),
        (
            lambda records: _reveal(records).pop("deck_ledger_tail"),
            "missing its deck ledger tail",
        ),
        (
            lambda records: _reveal(records)["deck_ledger_tail"][0].update(extra=True),
            "unexpected fields",
        ),
        (
            lambda records: _reveal(records)["deck_ledger_tail"][0].update(move="burn"),
            "unsupported deck move",
        ),
    ],
)
def test_declared_ledger_must_be_complete_and_well_formed(
    mutate: Callable[[list[dict[str, Any]]], Any],
    detail: str,
) -> None:
    report = _tampered(mutate)
    assert report.status == "Invalid"
    assert detail in report.summary


def test_missing_or_unknown_ledger_declaration_is_unverified() -> None:
    report = _tampered(lambda records: records[0]["context"].pop("deck_ledger_version"))
    assert report.status == "Unverified"
    assert report.summary == (
        "Deck dealing is unverified because the manifest declares no deck ledger."
    )

    report = _tampered(lambda records: records[0]["context"].update(deck_ledger_version=2))
    assert report.status == "Unverified"
    assert "deck_ledger_version 2 is not supported" in report.summary


def test_oracle_binds_moves_to_the_next_operation_and_reveal() -> None:
    logger = CaptureLogger()
    oracle = RandomOracle.for_training(7, ruleset_hash="11" * 32, logger=logger)
    with pytest.raises(RandomnessError, match="oracle deck ledger"):
        oracle.record_deck_draw(1, player_id=0)
    deck = LedgerDeck(oracle)
    assert oracle.manifest["deck_ledger_version"] == 1
    deck.draw(0, 2)
    oracle.probability("environment.thunder.self-damage", 1, 4)
    oracle.probability("environment.thunder.self-damage", 1, 4)
    deck.draw(1)
    reveal = oracle.finalize(outcome="completed", receipt_summary={})
    operations = [record["context"] for record in logger.records if record["record_type"] == "randomness"]
    assert [len(context["state"]["deck_ledger"]) for context in operations] == [0, 2, 0]
    assert [move["player_id"] for move in reveal["deck_ledger_tail"]] == [1]
    with pytest.raises(RandomnessError, match="finalized"):
        oracle.record_deck_draw(1, player_id=0)
    other = RandomOracle.for_training(7, ruleset_hash="11" * 32)
    other.set_deck_source("oracle")
    with pytest.raises(RandomnessError, match="player_id"):
        other.record_deck_draw(1, player_id=-1)


def test_state_provider_cannot_supply_the_reserved_ledger_field() -> None:
    oracle = RandomOracle.for_training(7, ruleset_hash="11" * 32)
    oracle.set_deck_source("oracle")
    oracle.set_state_provider(lambda: {"state_version": 1, "kind": "test", "deck_ledger": []})
    with pytest.raises(RandomnessError, match="reserved"):
        oracle.probability("environment.thunder.self-damage", 1, 4)
