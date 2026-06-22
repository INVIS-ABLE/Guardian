"""Fail-closed proofs for control-plane outages (Phase 6 / area 23).

When a required control-plane dependency (OPA, OpenBao, immudb, Temporal) is unavailable,
sensitive actions must STOP and the refusal must be audited — Guardian never proceeds blind.
"""

from __future__ import annotations

import pytest

from resilience import (
    ControlPlane,
    DependencyState,
    SensitiveActionBlocked,
    guard_sensitive_action,
    is_safe_to_proceed,
)


class _RecordingAudit:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    def record(self, action, *, actor, decision="allowed", detail=None, **_):
        self.entries.append(
            {"action": action, "actor": actor, "decision": decision, "detail": detail or {}}
        )


def test_all_up_permits_sensitive_action():
    cp = ControlPlane.all_up()
    assert is_safe_to_proceed(cp)
    assert cp.unavailable_required() == []
    # Should not raise.
    guard_sensitive_action(cp, action="deploy_patch")


@pytest.mark.parametrize("dep", ["opa", "openbao", "immudb", "temporal"])
def test_each_required_dependency_down_blocks(dep):
    cp = ControlPlane.all_up()
    cp.set_state(dep, DependencyState.DOWN)
    assert not is_safe_to_proceed(cp)
    assert dep in cp.unavailable_required()
    with pytest.raises(SensitiveActionBlocked):
        guard_sensitive_action(cp, action="deploy_patch")


def test_degraded_dependency_also_blocks():
    cp = ControlPlane.all_up()
    cp.set_state("temporal", DependencyState.DEGRADED)
    with pytest.raises(SensitiveActionBlocked):
        guard_sensitive_action(cp, action="run_containment")


def test_block_is_audited_as_denied():
    cp = ControlPlane.all_up()
    cp.set_state("openbao", DependencyState.DOWN)
    audit = _RecordingAudit()
    with pytest.raises(SensitiveActionBlocked):
        guard_sensitive_action(cp, action="issue_credential", audit=audit, actor="guardian")
    assert len(audit.entries) == 1
    entry = audit.entries[0]
    assert entry["decision"] == "denied"
    assert "openbao" in entry["detail"]["unavailable"]


def test_auditing_failure_does_not_break_enforcement():
    class _BrokenAudit:
        def record(self, *_, **__):
            raise RuntimeError("audit sink down")

    cp = ControlPlane.all_up()
    cp.set_state("immudb", DependencyState.DOWN)
    # Even if the audit sink throws, the action must still be refused.
    with pytest.raises(SensitiveActionBlocked):
        guard_sensitive_action(cp, action="record_evidence", audit=_BrokenAudit())


def test_multiple_down_reported_sorted():
    cp = ControlPlane.all_up()
    cp.set_state("opa", DependencyState.DOWN)
    cp.set_state("immudb", DependencyState.DOWN)
    assert cp.unavailable_required() == ["immudb", "opa"]
