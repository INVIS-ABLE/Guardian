"""Progressive-delivery health evaluation (directive §4, §10).

Argo Rollouts drives progressive delivery; Keptn supplies pre/post-deployment health
evidence. Neither grants production authority. The promotion rule is strict and fail-closed:

* a **failed** safety signal triggers automatic rollback;
* a **missing** safety signal also prevents promotion (silence is not success).

Only when every required signal is present and passing may a rollout be recommended for
promotion — and even then the existing authority gates still apply.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class SignalStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    MISSING = "missing"


class SafetySignal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    status: SignalStatus
    source: str = "keptn"  # Keptn provides health evidence; it grants no authority


class RolloutAction(str, Enum):
    PROMOTE = "promote"
    HOLD = "hold"
    ROLLBACK = "rollback"


class RolloutDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: RolloutAction
    reason: str
    failing: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()


def evaluate_rollout(
    signals: tuple[SafetySignal, ...], *, required: tuple[str, ...] = ()
) -> RolloutDecision:
    """Decide a rollout's fate from its safety signals. Fail closed (§10).

    Any failing signal → ROLLBACK. Otherwise any missing/required-but-absent signal →
    HOLD (no promotion). Only all-present-and-passing → PROMOTE.
    """
    by_name = {s.name: s for s in signals}
    failing = tuple(s.name for s in signals if s.status is SignalStatus.FAIL)
    if failing:
        return RolloutDecision(
            action=RolloutAction.ROLLBACK,
            reason="failed safety signal(s) — automatic rollback (§10)",
            failing=failing,
        )

    missing = [s.name for s in signals if s.status is SignalStatus.MISSING]
    missing += [name for name in required if name not in by_name]
    if missing:
        return RolloutDecision(
            action=RolloutAction.HOLD,
            reason="missing safety signal prevents promotion (§10)",
            missing=tuple(sorted(set(missing))),
        )

    if not signals:
        return RolloutDecision(
            action=RolloutAction.HOLD,
            reason="no safety signals — silence is not success (§13)",
        )

    return RolloutDecision(action=RolloutAction.PROMOTE, reason="all safety signals passing")


__all__ = [
    "SignalStatus",
    "SafetySignal",
    "RolloutAction",
    "RolloutDecision",
    "evaluate_rollout",
]
