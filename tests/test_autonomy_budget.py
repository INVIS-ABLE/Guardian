"""Level 6 §34: autonomy decreases as uncertainty increases."""

from __future__ import annotations

from adaptive.autonomy.budgets import compute_autonomy_budget
from adaptive.autonomy.degradation import EnvironmentHealth, IncidentSeverity, SignalState
from adaptive.autonomy.states import AutonomyClass, ControlState


def _healthy() -> EnvironmentHealth:
    return EnvironmentHealth()  # all defaults are healthy / full completeness


def test_full_health_permits_through_class_d():
    b = compute_autonomy_budget(ControlState.NORMAL, _healthy())
    assert b.allows(AutonomyClass.OBSERVE)
    assert b.allows(AutonomyClass.INVESTIGATE)
    assert b.allows(AutonomyClass.ENGINEER)
    assert b.allows(AutonomyClass.HEAL)
    assert b.model_driven_healing_allowed is True
    assert b.requires_independent_verification is False
    # E is never autonomous.
    assert not b.allows(AutonomyClass.PRODUCTION)


def test_missing_evidence_stops_all_execution():
    h = _healthy().model_copy(update={"evidence_authority": SignalState.MISSING})
    b = compute_autonomy_budget(ControlState.NORMAL, h)
    assert not b.allows(AutonomyClass.HEAL)
    assert not b.allows(AutonomyClass.ENGINEER)
    # observation/investigation still allowed
    assert b.allows(AutonomyClass.OBSERVE)
    assert b.allows(AutonomyClass.INVESTIGATE)


def test_missing_opa_disables_healing():
    h = _healthy().model_copy(update={"policy_authority": SignalState.MISSING})
    b = compute_autonomy_budget(ControlState.NORMAL, h)
    assert not b.allows(AutonomyClass.HEAL)
    # engineering (draft PRs, no production) is still allowed
    assert b.allows(AutonomyClass.ENGINEER)


def test_stale_twin_disables_target_changing_healing():
    h = _healthy().model_copy(update={"digital_twin": SignalState.DEGRADED})
    b = compute_autonomy_budget(ControlState.NORMAL, h)
    assert not b.allows(AutonomyClass.HEAL)


def test_missing_shadow_guardian_disables_high_risk():
    h = _healthy().model_copy(update={"shadow_guardian": SignalState.MISSING})
    b = compute_autonomy_budget(ControlState.NORMAL, h)
    assert not b.allows(AutonomyClass.HEAL)


def test_missing_model_monitoring_disables_model_driven_healing_only():
    h = _healthy().model_copy(update={"model_monitoring": SignalState.MISSING})
    b = compute_autonomy_budget(ControlState.NORMAL, h)
    # deterministic healing still allowed...
    assert b.allows(AutonomyClass.HEAL)
    # ...but not model-driven
    assert b.model_driven_healing_allowed is False


def test_degraded_model_health_raises_verification_and_drops_model_driven():
    h = _healthy().model_copy(update={"model_health": SignalState.DEGRADED})
    b = compute_autonomy_budget(ControlState.NORMAL, h)
    assert b.model_driven_healing_allowed is False
    assert b.requires_independent_verification is True


def test_low_telemetry_completeness_blocks_healing():
    h = _healthy().model_copy(update={"telemetry_completeness": 0.3})
    b = compute_autonomy_budget(ControlState.NORMAL, h)
    assert not b.allows(AutonomyClass.HEAL)


def test_mid_telemetry_completeness_forces_deterministic_healing():
    h = _healthy().model_copy(update={"telemetry_completeness": 0.7})
    b = compute_autonomy_budget(ControlState.NORMAL, h)
    assert b.allows(AutonomyClass.HEAL)
    assert b.model_driven_healing_allowed is False


def test_repeated_repair_failure_freezes_healing():
    h = _healthy().model_copy(update={"recent_repair_success_rate": 0.2})
    b = compute_autonomy_budget(ControlState.NORMAL, h)
    assert not b.allows(AutonomyClass.HEAL)


def test_high_severity_requires_independent_verification():
    h = _healthy().model_copy(update={"incident_severity": IncidentSeverity.CRITICAL})
    b = compute_autonomy_budget(ControlState.NORMAL, h)
    assert b.requires_independent_verification is True


def test_control_state_ceiling_is_respected():
    # Even in perfect health, FROZEN permits only observation.
    b = compute_autonomy_budget(ControlState.FROZEN, _healthy())
    assert b.permitted == frozenset({AutonomyClass.OBSERVE})


def test_reasons_are_recorded_for_every_removal():
    h = _healthy().model_copy(update={"policy_authority": SignalState.MISSING})
    b = compute_autonomy_budget(ControlState.NORMAL, h)
    assert any("OPA" in r or "policy authority" in r for r in b.reasons)
