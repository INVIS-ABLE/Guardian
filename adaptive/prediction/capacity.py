"""Capacity / resource-exhaustion prediction (directive §29).

A simple, explainable linear projection: given current usage and a per-second growth rate
against a capacity ceiling, estimate time-to-exhaustion and a risk band. Advisory only —
any preventive scaling stays within approved envelopes elsewhere.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .base import Prediction, RiskLevel

# Time-to-exhaustion (seconds) → risk bands.
_CRITICAL_S = 3600.0          # < 1h
_HIGH_S = 6.0 * 3600.0        # < 6h
_MEDIUM_S = 24.0 * 3600.0     # < 1d
_LOW_S = 3.0 * 24.0 * 3600.0  # < 3d


class CapacitySample(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    resource: str = Field(min_length=1)
    current: float = Field(ge=0.0)
    capacity: float = Field(gt=0.0)
    growth_per_second: float = Field(default=0.0)  # may be negative (draining)

    @property
    def utilisation(self) -> float:
        return min(1.0, self.current / self.capacity)


def project_exhaustion(sample: CapacitySample) -> Prediction:
    headroom = sample.capacity - sample.current

    if headroom <= 0:
        return Prediction(
            subject=sample.resource, kind="capacity_exhaustion", risk=RiskLevel.CRITICAL,
            horizon_seconds=0.0, detail=f"{sample.resource} already at/over capacity",
            recommendation=f"expand {sample.resource} within approved envelope now",
        )
    if sample.growth_per_second <= 0:
        return Prediction(
            subject=sample.resource, kind="capacity_exhaustion", risk=RiskLevel.NONE,
            detail=f"{sample.resource} stable or draining "
                   f"({sample.utilisation*100:.0f}% used)",
        )

    ttl = headroom / sample.growth_per_second
    if ttl <= _CRITICAL_S:
        risk = RiskLevel.CRITICAL
    elif ttl <= _HIGH_S:
        risk = RiskLevel.HIGH
    elif ttl <= _MEDIUM_S:
        risk = RiskLevel.MEDIUM
    elif ttl <= _LOW_S:
        risk = RiskLevel.LOW
    else:
        risk = RiskLevel.NONE

    recommendation = (
        f"pre-scale {sample.resource} within approved envelope"
        if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM)
        else ""
    )
    return Prediction(
        subject=sample.resource, kind="capacity_exhaustion", risk=risk,
        horizon_seconds=ttl,
        detail=f"{sample.resource} exhausts in ~{ttl/3600.0:.1f}h "
               f"({sample.utilisation*100:.0f}% used)",
        recommendation=recommendation,
    )


__all__ = ["CapacitySample", "project_exhaustion"]
