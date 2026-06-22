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


def test_production_environment_refused_by_default(tmp_path):
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
    scope = load_scope(prod)
    gr = Guardrails(scope=scope)
    with pytest.raises(GuardrailViolation):
        gr.assert_environment()  # production without allow_production must refuse
    gr.assert_environment(allow_production=True)  # explicit allow does not raise


def test_full_authorize_happy_path(staging_scope):
    gr = Guardrails(scope=staging_scope)
    # A normal, in-scope safeguarding simulation on staging should be authorised.
    gr.authorize(
        mode="safeguarding",
        action="safeguarding",
        domain="staging.invisable.co.uk",
        test_account="vulnerable_user_test",
    )
