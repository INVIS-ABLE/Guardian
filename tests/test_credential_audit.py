"""Credential-audit connector tests — prove the defensive guardrails hold."""

from __future__ import annotations

import pytest

from connectors import HashcatConnector, HydraConnector, JohnConnector
from core.guardrails import Approval, Guardrails, GuardrailViolation


def _approved(scope, *actions):
    gr = Guardrails(scope=scope)
    for a in actions:
        gr.record_approval(Approval(action=a, approver="ciso", ticket="SEC-AUDIT"))
    return gr


def test_hashcat_requires_synthetic_corpus(staging_scope):
    conn = HashcatConnector(staging_scope, dry_run=True, guardrails=_approved(staging_scope, "credential_audit"))
    # No corpus at all -> refuse.
    with pytest.raises(PermissionError):
        conn.run()
    # Corpus but not flagged synthetic -> refuse.
    with pytest.raises(PermissionError):
        conn.run(hash_corpus="policy-audit/test.hashes")


def test_hashcat_requires_human_approval(staging_scope):
    # Synthetic corpus provided, but no approval recorded -> approval gate refuses.
    conn = HashcatConnector(staging_scope, dry_run=True)  # default guardrails, no approvals
    with pytest.raises(GuardrailViolation):
        conn.run(hash_corpus="policy-audit/test.hashes", synthetic=True)


def test_hashcat_happy_path_dry_run(staging_scope):
    conn = HashcatConnector(staging_scope, dry_run=True, guardrails=_approved(staging_scope, "credential_audit"))
    res = conn.run(hash_corpus="policy-audit/test.hashes", synthetic=True)
    assert res.dry_run is True
    assert res.tool == "hashcat"
    assert "--potfile-disable" in res.command  # never persists recovered material


def test_john_requires_synthetic_corpus(staging_scope):
    conn = JohnConnector(staging_scope, dry_run=True, guardrails=_approved(staging_scope, "credential_audit"))
    with pytest.raises(PermissionError):
        conn.run(hash_corpus="x")  # synthetic flag missing


def test_hydra_requires_test_account_and_approval(staging_scope):
    # Missing test account -> refuse outright.
    conn = HydraConnector(staging_scope, dry_run=True,
                          guardrails=_approved(staging_scope, "high_volume_test", "account_locking_test"))
    with pytest.raises(PermissionError):
        conn.run()

    # With a test account but WITHOUT approvals -> approval gate refuses.
    conn2 = HydraConnector(staging_scope, dry_run=True)
    with pytest.raises(GuardrailViolation):
        conn2.run(test_account="standard_user_test")


def test_hydra_refuses_non_test_account(staging_scope):
    gr = _approved(staging_scope, "high_volume_test", "account_locking_test")
    conn = HydraConnector(staging_scope, dry_run=True, guardrails=gr)
    with pytest.raises(GuardrailViolation):
        conn.run(test_account="real_person@example.com")


def test_hydra_happy_path_dry_run(staging_scope):
    gr = _approved(staging_scope, "high_volume_test", "account_locking_test")
    conn = HydraConnector(staging_scope, dry_run=True, guardrails=gr)
    res = conn.run(test_account="standard_user_test")
    assert res.dry_run is True
    assert res.tool == "hydra"
    # Target defaulted to the in-scope owned staging domain.
    assert any("staging.invisable.co.uk" in part for part in res.command)
