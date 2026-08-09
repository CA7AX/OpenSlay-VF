"""Pure semantic operations shared by transcript generation and verification."""

from __future__ import annotations

from typing import Any, Protocol


class BoundedStream(Protocol):
    block_index: int

    def bounded(self, upper_bound: int) -> tuple[int, dict[str, Any]]: ...


def execute_operation(
    operation: str,
    inputs: dict[str, Any],
    stream: BoundedStream,
) -> dict[str, Any]:
    """Return the canonical result and proof for one validated operation."""

    if operation == "probability":
        numerator = inputs["numerator"]
        draw, proof = stream.bounded(inputs["denominator"])
        return {
            "result": draw < numerator,
            "proof": {
                "draw": draw,
                "draws": [proof],
                "blocks_used": stream.block_index,
            },
        }

    candidates = inputs["candidates"]
    if operation == "choice":
        selected, proof = stream.bounded(len(candidates))
        return {
            "result": candidates[selected],
            "proof": {
                "selected_index": selected,
                "draws": [proof],
                "blocks_used": stream.block_index,
            },
        }
    if operation == "sample":
        remaining = list(range(len(candidates)))
        selected_indices: list[int] = []
        proofs: list[dict[str, Any]] = []
        for _ in range(inputs["count"]):
            relative, proof = stream.bounded(len(remaining))
            selected_indices.append(remaining.pop(relative))
            proofs.append(proof)
        return {
            "result": [candidates[index] for index in selected_indices],
            "proof": {
                "selected_indices": selected_indices,
                "draws": proofs,
                "blocks_used": stream.block_index,
            },
        }
    if operation == "shuffle":
        order = list(range(len(candidates)))
        swaps: list[list[int]] = []
        proofs: list[dict[str, Any]] = []
        for index in range(len(order) - 1, 0, -1):
            selected, proof = stream.bounded(index + 1)
            order[index], order[selected] = order[selected], order[index]
            swaps.append([index, selected])
            proofs.append(proof)
        return {
            "result": [candidates[index] for index in order],
            "proof": {
                "permutation": order,
                "swaps": swaps,
                "draws": proofs,
                "blocks_used": stream.block_index,
            },
        }
    raise ValueError(f"unsupported random operation: {operation!r}")


__all__ = ["BoundedStream", "execute_operation"]
