"""Recovery-readiness prediction (directive §29).

How confident is Guardian that it could actually recover right now? Driven by backup
freshness and — decisively — whether a *restoration* was recently tested. A fresh backup
that has never been restored does not make recovery ready (see §26). Advisory only.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from .base import Prediction, RiskLevel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RecoverySignals(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    service: str = Field(min_length=1)
    last_backup_at: datetime | None = None
    last_successful_restore_test_at: datetime | None = None
    backup_max_age_seconds: float = Field(gt=0.0, default=86_400.0)
    restore_test_max_age_seconds: float = Field(gt=0.0, default=30 * 86_400.0)


def assess_recovery_readiness(
    signals: RecoverySignals, *, now: datetime | None = None
) -> Prediction:
    now = now or _utcnow()

    if signals.last_backup_at is None:
        return Prediction(
            subject=signals.service, kind="recovery_readiness", risk=RiskLevel.CRITICAL,
            detail="no backup recorded", recommendation="run and verify a backup now",
        )
    backup_age = (now - signals.last_backup_at).total_seconds()

    # A backup never proven by restoration is not proven recovery (§26).
    if signals.last_successful_restore_test_at is None:
        return Prediction(
            subject=signals.service, kind="recovery_readiness", risk=RiskLevel.HIGH,
            detail="backups exist but restoration has never been tested",
            recommendation="schedule a restoration test into an isolated environment",
        )
    restore_age = (now - signals.last_successful_restore_test_at).total_seconds()

    stale_backup = backup_age > signals.backup_max_age_seconds
    stale_restore = restore_age > signals.restore_test_max_age_seconds

    if stale_backup and stale_restore:
        risk = RiskLevel.HIGH
        detail = "backup and restoration test both stale"
        rec = "refresh backup and re-run restoration test"
    elif stale_backup:
        risk = RiskLevel.MEDIUM
        detail = f"backup stale ({backup_age/3600.0:.1f}h old)"
        rec = "refresh backup"
    elif stale_restore:
        risk = RiskLevel.MEDIUM
        detail = f"restoration test stale ({restore_age/86_400.0:.0f}d old)"
        rec = "re-run restoration test"
    else:
        risk = RiskLevel.NONE
        detail = "fresh backup with a recent successful restoration test"
        rec = ""

    return Prediction(
        subject=signals.service, kind="recovery_readiness", risk=risk,
        detail=detail, recommendation=rec,
    )


__all__ = ["RecoverySignals", "assess_recovery_readiness"]
