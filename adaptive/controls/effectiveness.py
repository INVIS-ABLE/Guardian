"""Control-effectiveness scoring (directive §30).

For every security control Guardian tracks what it is *supposed* to do and whether it is
actually doing it. The point is to surface the dangerous quiet failures: a control that is
installed but not functioning, produces no telemetry, runs stale rules, or is the *only*
thing protecting an asset. Pure, deterministic assessment — it raises no alarms and takes
no action, it produces typed findings other parts of Guardian act on.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from ..autonomy.degradation import SignalState

# A control whose rules/validation are older than this is considered stale.
STALE_VALIDATION_DAYS = 30.0


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ControlIssue(str, Enum):
    INSTALLED_NOT_FUNCTIONING = "installed_not_functioning"
    NO_TELEMETRY = "no_telemetry"
    STALE_RULES = "stale_rules"
    ASSUMPTIONS_INVALID = "assumptions_invalid"
    NEVER_OBSERVED_WORKING = "never_observed_working"


class SecurityControl(BaseModel):
    """A tracked control with its expected coverage and observed activity (§30)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    version: str = ""
    expected_prevention_coverage: float = Field(ge=0.0, le=1.0, default=0.0)
    expected_detection_coverage: float = Field(ge=0.0, le=1.0, default=0.0)
    telemetry_health: SignalState = SignalState.HEALTHY
    last_validation_at: datetime | None = None
    last_block_at: datetime | None = None
    last_detection_at: datetime | None = None
    false_positive_rate: float = Field(ge=0.0, le=1.0, default=0.0)
    has_false_negative_evidence: bool = False
    assumptions_hold: bool = True
    dependencies: tuple[str, ...] = ()
    protected_assets: tuple[str, ...] = ()


class ControlAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    control: str
    effective: bool
    issues: tuple[ControlIssue, ...] = ()
    detail: tuple[str, ...] = ()


def assess_control(
    control: SecurityControl, *, now: datetime | None = None
) -> ControlAssessment:
    """Assess one control. A control with any blocking issue is *not* effective."""
    now = now or _utcnow()
    issues: list[ControlIssue] = []
    detail: list[str] = []

    if control.telemetry_health is SignalState.MISSING:
        issues.append(ControlIssue.NO_TELEMETRY)
        detail.append("control emits no telemetry — its state is unknown")

    if not control.assumptions_hold:
        issues.append(ControlIssue.ASSUMPTIONS_INVALID)
        detail.append("control's protective assumptions no longer hold")

    if control.last_validation_at is None:
        issues.append(ControlIssue.NEVER_OBSERVED_WORKING)
        detail.append("control has never been validated")
    elif now - control.last_validation_at > timedelta(days=STALE_VALIDATION_DAYS):
        issues.append(ControlIssue.STALE_RULES)
        detail.append(f"control not validated in over {STALE_VALIDATION_DAYS:.0f} days")

    # Expected to prevent/detect but has never been observed doing either.
    expects_action = (
        control.expected_prevention_coverage > 0 or control.expected_detection_coverage > 0
    )
    never_acted = control.last_block_at is None and control.last_detection_at is None
    if expects_action and never_acted and control.telemetry_health is not SignalState.HEALTHY:
        issues.append(ControlIssue.INSTALLED_NOT_FUNCTIONING)
        detail.append("expected to act but never observed acting, with degraded telemetry")

    effective = not issues
    return ControlAssessment(
        control=control.name, effective=effective,
        issues=tuple(issues), detail=tuple(detail),
    )


class SystemicGaps(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ineffective_controls: tuple[str, ...] = ()
    controls_without_telemetry: tuple[str, ...] = ()
    singly_protected_assets: tuple[str, ...] = ()
    multiple_failing_together: bool = False


def find_systemic_gaps(
    controls: list[SecurityControl], *, now: datetime | None = None
) -> SystemicGaps:
    """Cross-control analysis: single points of protection and correlated failure (§30)."""
    now = now or _utcnow()
    assessments = [assess_control(c, now=now) for c in controls]
    ineffective = tuple(a.control for a in assessments if not a.effective)
    no_telemetry = tuple(
        c.name for c in controls if c.telemetry_health is SignalState.MISSING
    )

    # Assets defended by exactly one control.
    asset_count: dict[str, int] = {}
    for c in controls:
        for asset in c.protected_assets:
            asset_count[asset] = asset_count.get(asset, 0) + 1
    singly = tuple(sorted(a for a, n in asset_count.items() if n == 1))

    return SystemicGaps(
        ineffective_controls=ineffective,
        controls_without_telemetry=no_telemetry,
        singly_protected_assets=singly,
        multiple_failing_together=len(ineffective) >= 2,
    )


__all__ = [
    "STALE_VALIDATION_DAYS",
    "ControlIssue",
    "SecurityControl",
    "ControlAssessment",
    "assess_control",
    "SystemicGaps",
    "find_systemic_gaps",
]
