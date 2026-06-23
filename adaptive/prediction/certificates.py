"""Certificate / key-rotation expiry prediction (directive §29).

Fully deterministic: time to expiry against escalating risk bands. Advisory only.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from .base import Prediction, RiskLevel

# Days-remaining → risk bands.
_CRITICAL_DAYS = 3.0
_HIGH_DAYS = 7.0
_MEDIUM_DAYS = 21.0
_LOW_DAYS = 45.0


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CertInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    not_after: datetime
    auto_rotates: bool = False


def predict_cert_expiry(cert: CertInfo, *, now: datetime | None = None) -> Prediction:
    now = now or _utcnow()
    seconds = (cert.not_after - now).total_seconds()
    days = seconds / 86_400.0

    if days <= 0:
        risk = RiskLevel.CRITICAL
        detail = f"{cert.name} has EXPIRED ({-days:.1f} days ago)"
    elif days <= _CRITICAL_DAYS:
        risk = RiskLevel.CRITICAL
        detail = f"{cert.name} expires in {days:.1f} days"
    elif days <= _HIGH_DAYS:
        risk = RiskLevel.HIGH
        detail = f"{cert.name} expires in {days:.1f} days"
    elif days <= _MEDIUM_DAYS:
        risk = RiskLevel.MEDIUM
        detail = f"{cert.name} expires in {days:.1f} days"
    elif days <= _LOW_DAYS:
        risk = RiskLevel.LOW
        detail = f"{cert.name} expires in {days:.1f} days"
    else:
        risk = RiskLevel.NONE
        detail = f"{cert.name} valid for {days:.0f} days"

    if risk in (RiskLevel.NONE, RiskLevel.LOW) or cert.auto_rotates:
        recommendation = "" if risk is RiskLevel.NONE else "monitor; auto-rotation expected"
    else:
        recommendation = f"schedule rotation of {cert.name} before expiry"

    return Prediction(
        subject=cert.name, kind="certificate_expiry", risk=risk,
        horizon_seconds=max(0.0, seconds), detail=detail, recommendation=recommendation,
    )


__all__ = ["CertInfo", "predict_cert_expiry"]
