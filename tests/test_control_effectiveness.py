"""Level 6 §30: control-effectiveness scoring."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from adaptive.autonomy.degradation import SignalState
from adaptive.controls import (
    ControlIssue,
    SecurityControl,
    assess_control,
    find_systemic_gaps,
)

NOW = datetime(2026, 6, 23, 12, 0, 0, tzinfo=timezone.utc)


def _control(**kw) -> SecurityControl:
    base = dict(
        name="waf", owner="platform", expected_detection_coverage=0.8,
        telemetry_health=SignalState.HEALTHY,
        last_validation_at=NOW - timedelta(days=1),
        last_detection_at=NOW - timedelta(hours=1),
    )
    base.update(kw)
    return SecurityControl(**base)


def test_healthy_control_is_effective():
    a = assess_control(_control(), now=NOW)
    assert a.effective is True
    assert a.issues == ()


def test_no_telemetry_is_flagged():
    a = assess_control(_control(telemetry_health=SignalState.MISSING), now=NOW)
    assert ControlIssue.NO_TELEMETRY in a.issues
    assert a.effective is False


def test_stale_rules_flagged():
    a = assess_control(_control(last_validation_at=NOW - timedelta(days=90)), now=NOW)
    assert ControlIssue.STALE_RULES in a.issues


def test_never_validated_flagged():
    a = assess_control(_control(last_validation_at=None), now=NOW)
    assert ControlIssue.NEVER_OBSERVED_WORKING in a.issues


def test_invalid_assumptions_flagged():
    a = assess_control(_control(assumptions_hold=False), now=NOW)
    assert ControlIssue.ASSUMPTIONS_INVALID in a.issues


def test_systemic_gaps_single_point_and_correlated_failure():
    controls = [
        _control(name="waf", telemetry_health=SignalState.MISSING, protected_assets=("api",)),
        _control(name="ids", assumptions_hold=False, protected_assets=("api", "db")),
        _control(name="rbac", protected_assets=("admin",)),  # healthy, sole protector
    ]
    gaps = find_systemic_gaps(controls, now=NOW)
    assert "waf" in gaps.ineffective_controls and "ids" in gaps.ineffective_controls
    assert gaps.multiple_failing_together is True
    assert "waf" in gaps.controls_without_telemetry
    # admin is protected by exactly one control
    assert "admin" in gaps.singly_protected_assets
