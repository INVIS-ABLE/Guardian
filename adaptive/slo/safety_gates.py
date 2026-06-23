"""The availability-vs-privacy safety gate (directive §9).

"An action that improves availability but weakens privacy must be rejected." This gate
takes a repair's *predicted* effect on each SLO kind and refuses the repair if it would
regress any privacy-critical invariant — no matter how much availability it would buy.

It is advisory-to-deterministic: it produces a typed verdict that the runbook compiler /
healing engine treats as a hard gate. It never *grants* anything; it can only reject.
"""

from __future__ import annotations

from enum import Enum
from typing import Mapping

from pydantic import BaseModel, ConfigDict

from .definitions import PRIVACY_CRITICAL_KINDS, SLOKind


class EffectDirection(str, Enum):
    IMPROVE = "improve"
    NEUTRAL = "neutral"
    REGRESS = "regress"


class SafetyVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    weakened_invariants: tuple[SLOKind, ...] = ()
    improves: tuple[SLOKind, ...] = ()
    reason: str = ""


def evaluate_repair_safety(
    predicted_effects: Mapping[SLOKind, EffectDirection],
) -> SafetyVerdict:
    """Reject a repair that regresses any privacy-critical SLO. Fail closed.

    A repair with no declared effects, or one that only improves/holds invariants, is
    allowed by this gate (other gates still apply). A repair that regresses a
    privacy-critical invariant is rejected even if it improves availability.
    """
    weakened = tuple(
        kind
        for kind, effect in predicted_effects.items()
        if kind in PRIVACY_CRITICAL_KINDS and effect is EffectDirection.REGRESS
    )
    improves = tuple(
        kind for kind, effect in predicted_effects.items() if effect is EffectDirection.IMPROVE
    )
    if weakened:
        names = ", ".join(k.value for k in weakened)
        return SafetyVerdict(
            allowed=False,
            weakened_invariants=weakened,
            improves=improves,
            reason=(
                f"repair would weaken privacy-critical invariant(s): {names} — rejected "
                "regardless of availability benefit (§9)"
            ),
        )
    return SafetyVerdict(
        allowed=True,
        improves=improves,
        reason="no privacy-critical invariant regressed",
    )


__all__ = ["EffectDirection", "SafetyVerdict", "evaluate_repair_safety"]
