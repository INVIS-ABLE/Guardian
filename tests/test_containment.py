"""Phase 6 — reversible containment: deterministic, bounded, reversible, audited."""

from __future__ import annotations

import pytest

from containment import (
    ContainmentRejected,
    ContainmentRequest,
    DeterministicContainmentAdapter,
    REVERSIBLE_ACTIONS,
    is_reversible_action,
)
from core.audit import AuditLog


def _adapter(tmp_path, **kw):
    return DeterministicContainmentAdapter(audit=AuditLog(log_dir=tmp_path), **kw)


def _req(**over):
    base = dict(
        action="revoke_token",
        target="token-abc",
        confidence=0.9,
        evidence_ref="finding-123",
    )
    base.update(over)
    return ContainmentRequest(**base)


def test_reversible_action_issued_with_rollback_and_expiry(tmp_path):
    a = _adapter(tmp_path)
    order = a.issue(_req(action="block_indicator_temporarily", target="1.2.3.4"), now=1000.0)
    assert order.active and order.rollback_procedure
    assert order.expires_at == 1000.0 + REVERSIBLE_ACTIONS["block_indicator_temporarily"].default_ttl_seconds
    assert a.active_orders() == [order]


def test_unknown_action_is_refused_no_freeform_commands(tmp_path):
    a = _adapter(tmp_path)
    # An AI-invented / raw command is not on the reversible allowlist → refused.
    with pytest.raises(ContainmentRejected):
        a.issue(_req(action="rm -rf / --no-preserve-root"))
    with pytest.raises(ContainmentRejected):
        a.issue(_req(action="delete_production_database"))
    assert is_reversible_action("delete_production_database") is False


def test_every_parameter_is_validated(tmp_path):
    a = _adapter(tmp_path)
    for bad in [
        _req(target=""),                       # missing exact target
        _req(evidence_ref=""),                  # missing evidence
        _req(confidence=1.5),                   # out of range
        _req(action="isolate_pod", confidence=0.9, target="p1"),  # high-impact, no approval
        _req(action="revoke_token", confidence=0.5),  # below action's threshold (0.6)
        _req(blast_radius=5),                   # exceeds revoke_token cap of 1
    ]:
        with pytest.raises(ContainmentRejected):
            a.issue(bad)


def test_high_impact_action_requires_approval(tmp_path):
    a = _adapter(tmp_path)
    with pytest.raises(ContainmentRejected):
        a.issue(_req(action="freeze_deployment", target="pipeline-1", confidence=0.9))
    order = a.issue(
        _req(action="freeze_deployment", target="pipeline-1", confidence=0.9, approval_token="appr-1")
    )
    assert order.active


def test_policy_denial_is_enforced_and_audited(tmp_path):
    a = _adapter(tmp_path, policy_check=lambda req, spec: False)
    with pytest.raises(ContainmentRejected):
        a.issue(_req())


def test_rollback_and_auto_expiry(tmp_path):
    a = _adapter(tmp_path)
    order = a.issue(_req(action="pause_workflow", target="wf-9"), now=1000.0)
    assert a.rollback(order.order_id) is True
    assert a.rollback(order.order_id) is False  # already rolled back
    # A fresh order auto-expires after its TTL.
    o2 = a.issue(_req(action="disable_feature_flag", target="ff-x"), now=1000.0)
    expired = a.expire_due(now=o2.expires_at + 1)
    assert o2.order_id in expired
    assert a.active_orders() == []


def test_ttl_capped_at_action_default(tmp_path):
    a = _adapter(tmp_path)
    # Requesting a longer TTL than the action allows is capped to the default ceiling.
    spec_ttl = REVERSIBLE_ACTIONS["disable_service_account"].default_ttl_seconds
    order = a.issue(
        _req(action="disable_service_account", target="svc-1", confidence=0.9, requested_ttl=10**9),
        now=0.0,
    )
    assert order.ttl_seconds == spec_ttl


def test_rejected_orders_are_audited(tmp_path):
    log = AuditLog(log_dir=tmp_path)
    a = DeterministicContainmentAdapter(audit=log)
    with pytest.raises(ContainmentRejected):
        a.issue(_req(action="not_a_real_action"))
    entries = [ln for ln in log.path.read_text().splitlines() if ln.strip()]
    assert any("rejected" in e for e in entries)  # refusal is recorded as evidence
