"""Guardrail enforcement tests — the heart of Guardian's safety."""

from __future__ import annotations

import pytest

from core.guardrails import (
    BLOCKED_ACTIONS,
    Approval,
    Guardrails,
    GuardrailViolation,
)


def test_blocked_actions_always_refused(staging_scope):
    gr = Guardrails(scope=staging_scope)
    for action in BLOCKED_ACTIONS:
        with pytest.raises(GuardrailViolation):
            gr.assert_not_blocked(action)


def test_out_of_scope_domain_refused(staging_scope):
    gr = Guardrails(scope=staging_scope)
    with pytest.raises(GuardrailViolation):
        gr.assert_owned(domain="evil.example.com")


def test_out_of_scope_repo_refused(staging_scope):
    gr = Guardrails(scope=staging_scope)
    with pytest.raises(GuardrailViolation):
        gr.assert_owned(repo="github.com/someoneelse/app")


def test_mode_not_allowed_refused(staging_scope):
    gr = Guardrails(scope=staging_scope)
    with pytest.raises(GuardrailViolation):
        gr.assert_mode_allowed("container_scan")  # not in the example scope's modes


def test_non_test_account_refused(staging_scope):
    gr = Guardrails(scope=staging_scope)
    with pytest.raises(GuardrailViolation):
        gr.assert_test_account("real_person@example.com")


def test_approval_gate_blocks_without_approval(staging_scope):
    gr = Guardrails(scope=staging_scope)
    with pytest.raises(GuardrailViolation):
        gr.assert_approved("production_scan")


def test_approval_gate_passes_with_recorded_approval(staging_scope):
    gr = Guardrails(scope=staging_scope)
    gr.record_approval(Approval(action="production_scan", approver="ciso", ticket="SEC-1"))
    gr.assert_approved("production_scan")  # should not raise


def _production_scope(tmp_path):
    from core.scope import load_scope

    prod = tmp_path / "prod.yaml"
    prod.write_text(
        "asset: invisable-production\n"
        "environment: production\n"
        "allowed_domains: [invisable.co.uk]\n"
        "allowed_repos: [github.com/invisable/app]\n"
        "allowed_test_accounts: [standard_user_test]\n"
        "allowed_modes: [code_review]\n"
        "blocked_actions: []\n"
        "approval_required: [production_scan]\n",
        encoding="utf-8",
    )
    return load_scope(prod)


def test_production_refused_without_two_distinct_approvers(tmp_path):
    scope = _production_scope(tmp_path)
    gr = Guardrails(scope=scope)
    # No approvals → denied. There is no allow_production escape parameter.
    with pytest.raises(GuardrailViolation):
        gr.authorize(mode="code_review", action="code_review")
    # A single approver is still insufficient (two-person rule).
    gr.record_approval(Approval(action="production_scan", approver="ciso", ticket="SEC-1"))
    with pytest.raises(GuardrailViolation):
        gr.authorize(mode="code_review", action="code_review")


def test_production_allowed_with_two_distinct_approvers(tmp_path):
    scope = _production_scope(tmp_path)
    gr = Guardrails(scope=scope)
    gr.record_approval(Approval(action="production_scan", approver="ciso", ticket="SEC-1"))
    gr.record_approval(Approval(action="production_scan", approver="ciso", ticket="SEC-1b"))
    # Same approver twice is NOT two distinct reviewers.
    with pytest.raises(GuardrailViolation):
        gr.authorize(mode="code_review", action="code_review")
    gr.record_approval(Approval(action="production_scan", approver="head_of_eng", ticket="SEC-2"))
    gr.authorize(mode="code_review", action="code_review")  # now two distinct → allowed


def test_expired_approval_is_rejected(staging_scope):
    gr = Guardrails(scope=staging_scope)
    gr.record_approval(
        Approval(action="production_scan", approver="ciso", ticket="SEC-1", expires_at=0.0)
    )
    with pytest.raises(GuardrailViolation):
        gr.assert_approved("production_scan")  # expired ⇒ not a valid approval


def test_authorize_has_no_allow_production_parameter():
    # Acceptance gate: no allow_production escape parameter may exist.
    import inspect

    params = inspect.signature(Guardrails.authorize).parameters
    assert "allow_production" not in params


def test_full_authorize_happy_path(staging_scope):
    gr = Guardrails(scope=staging_scope)
    # A normal, in-scope safeguarding simulation on staging should be authorised.
    gr.authorize(
        mode="safeguarding",
        action="safeguarding",
        domain="staging.invisable.co.uk",
        test_account="vulnerable_user_test",
    )
