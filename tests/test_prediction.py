"""Level 6 §29: advisory predictors (certificates, capacity, recovery)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from adaptive.prediction import (
    CapacitySample,
    CertInfo,
    RecoverySignals,
    RiskLevel,
    assess_recovery_readiness,
    predict_cert_expiry,
    project_exhaustion,
)

NOW = datetime(2026, 6, 23, 12, 0, 0, tzinfo=timezone.utc)


# --- certificates --------------------------------------------------------------
def test_cert_far_off_is_no_risk():
    p = predict_cert_expiry(CertInfo(name="tls", not_after=NOW + timedelta(days=200)), now=NOW)
    assert p.risk is RiskLevel.NONE


def test_cert_soon_is_critical_and_recommends_rotation():
    p = predict_cert_expiry(CertInfo(name="tls", not_after=NOW + timedelta(days=2)), now=NOW)
    assert p.risk is RiskLevel.CRITICAL
    assert "rotation" in p.recommendation


def test_expired_cert_is_critical():
    p = predict_cert_expiry(CertInfo(name="tls", not_after=NOW - timedelta(days=1)), now=NOW)
    assert p.risk is RiskLevel.CRITICAL
    assert "EXPIRED" in p.detail


# --- capacity ------------------------------------------------------------------
def test_capacity_stable_is_no_risk():
    p = project_exhaustion(CapacitySample(resource="disk", current=50, capacity=100,
                                          growth_per_second=0.0))
    assert p.risk is RiskLevel.NONE


def test_capacity_fast_growth_is_critical():
    # 1 unit headroom, 1/sec growth -> ~1s to exhaustion
    p = project_exhaustion(CapacitySample(resource="disk", current=99, capacity=100,
                                          growth_per_second=1.0))
    assert p.risk is RiskLevel.CRITICAL
    assert "approved envelope" in p.recommendation


def test_capacity_already_full_is_critical():
    p = project_exhaustion(CapacitySample(resource="disk", current=100, capacity=100,
                                          growth_per_second=0.5))
    assert p.risk is RiskLevel.CRITICAL


# --- recovery ------------------------------------------------------------------
def test_no_backup_is_critical():
    p = assess_recovery_readiness(RecoverySignals(service="relay"), now=NOW)
    assert p.risk is RiskLevel.CRITICAL


def test_backup_without_restore_test_is_not_ready():
    p = assess_recovery_readiness(
        RecoverySignals(service="relay", last_backup_at=NOW - timedelta(hours=1)), now=NOW)
    assert p.risk is RiskLevel.HIGH
    assert "never been tested" in p.detail


def test_fresh_backup_and_recent_restore_is_ready():
    p = assess_recovery_readiness(RecoverySignals(
        service="relay", last_backup_at=NOW - timedelta(hours=1),
        last_successful_restore_test_at=NOW - timedelta(days=2)), now=NOW)
    assert p.risk is RiskLevel.NONE
