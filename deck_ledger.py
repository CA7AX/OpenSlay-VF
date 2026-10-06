"""Replay of the deck ledger bound into OpenSlay randomness transcripts.

A manifest declaring ``deck_ledger_version`` 1 commits the transcript to
recording every card that leaves or returns to the draw pile.  Replaying those
moves on top of the verified epoch shuffles proves that each draw took the
card that was on top of the pile, and that the recorded engine draw pile at
every operation is exactly what the shuffles and moves leave behind.
"""

from __future__ import annotations

from typing import Any

from .oracle import (
    DECK_LEDGER_STATE_FIELD,
    RandomnessError,
    canonical_json,
    validate_deck_move,
)


class DeckLedgerReplay:
    """One continuous draw pile spanning every deck epoch."""

    def __init__(self) -> None:
        # Bottom first: the last card is the next one drawn, matching the
        # engine's draw-pile list and the oracle shuffle result.
        self._pile: list[Any] = []
        # Cards taken for the open skill inspection, keyed by card id.
        self._inspection: dict[int, Any] = {}
        self._inspection_open = False
        self._inspector: int | None = None
        self.moves_verified = 0

    def apply_state(self, state: dict[str, Any]) -> None:
        """Apply the moves bound into one operation's pre-operation state."""

        if DECK_LEDGER_STATE_FIELD not in state:
            raise RandomnessError("random operation state is missing its deck ledger")
        self.apply_moves(state[DECK_LEDGER_STATE_FIELD], "operation deck ledger")
        if state.get("kind") == "engine":
            self._check_engine_draw_pile(state)

    def apply_moves(self, moves: Any, label: str) -> None:
        if not isinstance(moves, list):
            raise RandomnessError(f"{label} must be a list")
        for move in moves:
            self._apply(validate_deck_move(move))
            self.moves_verified += 1

    def begin_epoch(self, shuffled: Any) -> None:
        """Replace the exhausted pile with one verified epoch shuffle."""

        if self._pile:
            raise RandomnessError(
                f"deck epoch was shuffled while {len(self._pile)} card(s) "
                "remained in the draw pile"
            )
        if not isinstance(shuffled, list):
            raise RandomnessError("deck epoch result must be a list")
        self._pile = list(shuffled)

    def _apply(self, entry: dict[str, Any]) -> None:
        move = entry["move"]
        player_id = entry["player_id"]
        if move == "draw":
            self._pop(entry["card_id"])
            # A draw ends any inspection; cards it kept stay out of the pile.
            self._close_inspection()
            return
        if move == "take":
            if self._inspection_open and player_id != self._inspector:
                raise RandomnessError(
                    "deck inspection mixes cards taken for different players"
                )
            card = self._pop(entry["card_id"])
            self._inspection[entry["card_id"]] = card
            self._inspection_open = True
            self._inspector = player_id
            return
        if not self._inspection_open:
            raise RandomnessError("deck restore has no open inspection")
        if player_id != self._inspector:
            raise RandomnessError("deck restore player differs from the inspection")
        card_ids = entry["card_ids"]
        for card_id in card_ids:
            if card_id not in self._inspection:
                raise RandomnessError(
                    f"deck restore returns card {card_id}, which is not under inspection"
                )
        self._pile.extend(self._inspection[card_id] for card_id in reversed(card_ids))
        self._close_inspection()

    def _pop(self, card_id: int) -> Any:
        if not self._pile:
            raise RandomnessError(
                f"deck move takes card {card_id} from an empty draw pile"
            )
        top = self._pile[-1]
        top_id = top.get("card_id") if isinstance(top, dict) else None
        if top_id != card_id:
            raise RandomnessError(
                f"deck move takes card {card_id}, but card {top_id} is on top"
            )
        return self._pile.pop()

    def _close_inspection(self) -> None:
        self._inspection.clear()
        self._inspection_open = False
        self._inspector = None

    def _check_engine_draw_pile(self, state: dict[str, Any]) -> None:
        zones = state.get("zones")
        draw_pile = zones.get("draw_pile") if isinstance(zones, dict) else None
        if not isinstance(draw_pile, list):
            raise RandomnessError("engine state is missing its draw pile")
        if canonical_json(draw_pile) != canonical_json(self._pile):
            raise RandomnessError(
                "engine draw pile differs from the replayed deck ledger"
            )


__all__ = ["DeckLedgerReplay"]
