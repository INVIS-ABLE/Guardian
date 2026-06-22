"""Level 6 §2–3: the autonomic control-state machine and the five autonomy classes."""

from __future__ import annotations

import pytest

from adaptive.autonomy.states import (
    AuthorityGrant,
    AutonomyClass,
    ControlState,
    StateTransitionError,
    apply_transition,
    permitted_classes,
    propose_transition,
)


def test_production_class_is_never_structurally_permitted():
    # Class E is approval-bound; no control state grants it autonomously.
    for state in ControlState.__members__.values():
        assert AutonomyClass.PRODUCTION not in permitted_classes(state)


def test_normal_permits_through_healing():
    perms = permitted_classes(ControlState.NORMAL)
    assert AutonomyClass.OBSERVE in perms
    assert AutonomyClass.HEAL in perms


def test_frozen_permits_only_observation():
    assert permitted_classes(ControlState.FROZEN) == frozenset({AutonomyClass.OBSERVE})


def test_degraded_drops_to_read_and_analysis():
    assert permitted_classes(ControlState.DEGRADED) == frozenset(
        {AutonomyClass.OBSERVE, AutonomyClass.INVESTIGATE}
    )


def test_watch_adds_no_operational_power_over_normal():
    # WATCH must not grant healing as a side effect of escalation (§3).
    assert AutonomyClass.HEAL not in permitted_classes(ControlState.WATCH)


def test_brain_may_de_escalate_to_safer_state_without_authority():
    # NORMAL -> DEGRADED and NORMAL -> FROZEN are de-escalations: always allowed.
    assert apply_transition(ControlState.NORMAL, ControlState.DEGRADED, reason="dep lost") is (
        ControlState.DEGRADED
    )
    assert apply_transition(ControlState.NORMAL, ControlState.FROZEN, reason="emergency") is (
        ControlState.FROZEN
    )


def test_brain_may_not_force_escalation_to_higher_authority_state():
    p = propose_transition(ControlState.WATCH, ControlState.DEFENSIVE, reason="threat")
    assert p.valid is True
    assert p.requires_external_authority is True
    with pytest.raises(StateTransitionError):
        apply_transition(ControlState.WATCH, ControlState.DEFENSIVE, reason="threat")


def test_escalation_succeeds_with_valid_authority():
    grant = AuthorityGrant(granted_by="oncall@invisable", role="human_approver")
    assert (
        apply_transition(
            ControlState.WATCH, ControlState.DEFENSIVE, reason="threat", authority=grant
        )
        is ControlState.DEFENSIVE
    )


def test_escalation_rejected_with_unknown_authority_role():
    grant = AuthorityGrant(granted_by="some-model", role="model")
    with pytest.raises(StateTransitionError):
        apply_transition(
            ControlState.WATCH, ControlState.DEFENSIVE, reason="threat", authority=grant
        )


def test_invalid_transition_is_refused():
    # NORMAL cannot jump straight to CONTAINMENT (single-step ladder only).
    p = propose_transition(ControlState.NORMAL, ControlState.CONTAINMENT, reason="x")
    assert p.valid is False
    with pytest.raises(StateTransitionError):
        apply_transition(ControlState.NORMAL, ControlState.CONTAINMENT, reason="x")


def test_any_state_may_drop_to_frozen_or_degraded():
    for state in ControlState.__members__.values():
        if state is ControlState.FROZEN:
            continue
        assert propose_transition(state, ControlState.FROZEN, reason="safe").valid
    for state in ControlState.__members__.values():
        if state is ControlState.DEGRADED:
            continue
        assert propose_transition(state, ControlState.DEGRADED, reason="safe").valid


def test_restoring_power_from_degraded_requires_authority():
    p = propose_transition(ControlState.DEGRADED, ControlState.NORMAL, reason="recovered")
    assert p.valid is True
    assert p.requires_external_authority is True
