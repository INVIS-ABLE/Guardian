"""Error-budget burn-rate calculation (directive §9).

Error-budget burn is a core decision input: how fast a service is consuming its allowed
failure budget. ``burn_rate`` is the ratio of the observed bad fraction to the allowed bad
fraction — a burn rate of 1.0 means "spending budget exactly as fast as allowed", >1.0
means "faster than sustainable". The severity bands follow standard multi-window SRE
practice (a 14.4x burn exhausts a 30-day budget in ~2 days).

Pure functions; no I/O. The measured ``achieved_ratio`` comes from the telemetry layer.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from .definitions import SLO

# Burn-rate severity bands (multiples of the sustainable rate).
_CRITICAL_BURN = 14.4
_HIGH_BURN = 6.0
_MEDIUM_BURN = 3.0
_ELEVATED_BURN = 1.0


class BurnSeverity(str, Enum):
    OK = "ok"
    ELEVATED = "elevated"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BurnResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    slo_name: str
    achieved_ratio: float = Field(ge=0.0, le=1.0)
    burn_rate: float = Field(ge=0.0)
    budget_remaining_fraction: float = Field(ge=0.0, le=1.0)
    exhausted: bool
    severity: BurnSeverity


def _severity(burn_rate: float, exhausted: bool) -> BurnSeverity:
    if exhausted or burn_rate >= _CRITICAL_BURN:
        return BurnSeverity.CRITICAL
    if burn_rate >= _HIGH_BURN:
        return BurnSeverity.HIGH
    if burn_rate >= _MEDIUM_BURN:
        return BurnSeverity.MEDIUM
    if burn_rate >= _ELEVATED_BURN:
        return BurnSeverity.ELEVATED
    return BurnSeverity.OK


def compute_burn(slo: SLO, achieved_ratio: float) -> BurnResult:
    """Compute the burn rate and remaining budget for one SLO measurement."""
    achieved = max(0.0, min(1.0, achieved_ratio))
    bad = 1.0 - achieved
    budget = slo.error_budget

    if budget <= 0.0:
        # A zero-tolerance objective (objective == 1.0): any bad event exhausts it.
        burn_rate = float("inf") if bad > 0.0 else 0.0
        remaining = 0.0 if bad > 0.0 else 1.0
        exhausted = bad > 0.0
    else:
        burn_rate = bad / budget
        remaining = max(0.0, 1.0 - burn_rate)
        exhausted = bad >= budget

    # inf is not representable in a bounded float field; cap for the record.
    recorded_burn = burn_rate if burn_rate != float("inf") else 1e9
    return BurnResult(
        slo_name=slo.name,
        achieved_ratio=achieved,
        burn_rate=recorded_burn,
        budget_remaining_fraction=remaining,
        exhausted=exhausted,
        severity=_severity(burn_rate, exhausted),
    )


__all__ = ["BurnSeverity", "BurnResult", "compute_burn"]
