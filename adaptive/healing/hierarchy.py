"""Self-healing hierarchy selection (directive §7).

Repairs are attempted from the narrowest, least-disruptive layer upward:

  1 process replacement · 2 workload rescheduling · 3 bounded scaling · 4 config rollback ·
  5 artifact rollback · 6 feature isolation · 7 credential isolation · 8 network isolation ·
  9 cluster evacuation · 10 regional recovery

Guardian must select the *lowest* layer capable of restoring safety and must not jump to a
broader repair while a narrower one remains viable. This module turns a set of
viable :class:`RepairAction`s into that selection, deterministically.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .contracts import REPAIR_LAYER, RepairAction

LAYER_NAMES: dict[int, str] = {
    1: "process replacement",
    2: "workload rescheduling",
    3: "bounded scaling",
    4: "configuration rollback",
    5: "artifact rollback",
    6: "feature isolation",
    7: "credential isolation",
    8: "network isolation",
    9: "cluster evacuation",
    10: "regional recovery",
}


class HierarchyError(RuntimeError):
    """Raised when no viable repair exists, or a broader repair would skip a narrower one."""


class RepairSelection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: RepairAction
    layer: int = Field(ge=1, le=10)
    layer_name: str
    rationale: str


def select_repair(viable: set[RepairAction] | frozenset[RepairAction]) -> RepairSelection:
    """Pick the lowest-layer viable repair (§7). Fail closed on an empty set."""
    if not viable:
        raise HierarchyError("no viable repair available — cannot select a healing action")
    chosen = min(viable, key=lambda a: REPAIR_LAYER[a])
    layer = REPAIR_LAYER[chosen]
    return RepairSelection(
        action=chosen,
        layer=layer,
        layer_name=LAYER_NAMES[layer],
        rationale=(
            f"lowest viable layer {layer} ({LAYER_NAMES[layer]}); "
            f"{len(viable)} candidate(s) considered"
        ),
    )


def assert_no_layer_jump(
    selected: RepairAction, viable: set[RepairAction] | frozenset[RepairAction]
) -> None:
    """Refuse a selection that skips a viable narrower repair (§7). Fail closed."""
    if selected not in viable:
        raise HierarchyError(f"selected action {selected.value} is not in the viable set")
    lowest = min(REPAIR_LAYER[a] for a in viable)
    if REPAIR_LAYER[selected] > lowest:
        narrower = LAYER_NAMES[lowest]
        raise HierarchyError(
            f"selected layer {REPAIR_LAYER[selected]} jumps over a viable narrower repair "
            f"at layer {lowest} ({narrower})"
        )


__all__ = [
    "LAYER_NAMES",
    "HierarchyError",
    "RepairSelection",
    "select_repair",
    "assert_no_layer_jump",
]
