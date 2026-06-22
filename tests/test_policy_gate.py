"""Direct tests of the central policy evaluator (core.policy_gate.decide)."""

from __future__ import annotations

from core.policy_gate import (
    BLOCKED_ACTIONS,
    PRODUCTION_MIN_REVIEWERS,
    ApprovalLite,
    PolicyInput,
    decide,
)

STAGING = dict(
    allowed_modes=["code_review", "abuse_simulation"],
    blocked_actions=[],
    approval_required=["production_scan", "high_volume_test"],
    allowed_test_accounts=["standard_user_test"],
)


def base(**over):
    kw = dict(
        actor="guardian",
        action="code_review",
        mode="code_review",
        environment="staging",
        ownership_verified=True,
        **STAGING,
    )
    kw.update(over)
    return PolicyInput(**kw)


def test_simple_staging_action_allowed():
    assert decide(base()).allow is True


def test_blocked_action_denied():
    for action in BLOCKED_ACTIONS:
        d = decide(base(action=action, mode="abuse_simulation"))
        assert d.allow is False
        assert any(r.startswith("blocked_action") for r in d.denies)


def test_mode_not_allowed_denied():
    assert decide(base(mode="zap_scan")).allow is False


def test_ownership_unverified_denied():
    d = decide(base(domain="staging.invisable.co.uk", ownership_verified=False))
    assert d.allow is False
    assert "ownership_unverified" in d.denies


def test_non_test_account_denied():
    assert decide(base(test_account="real_person")).allow is False


def test_approval_required_without_approval_denied():
    d = decide(base(action="high_volume_test", mode="abuse_simulation"))
    assert d.allow is False
    assert any(r.startswith("missing_approval") for r in d.denies)


def test_approval_required_with_valid_approval_allowed():
    d = decide(
        base(
            action="high_volume_test",
            mode="abuse_simulation",
            approvals=[ApprovalLite("high_volume_test", "ciso", None)],
        )
    )
    assert d.allow is True


def test_production_needs_two_distinct_unexpired_approvers():
    one = [ApprovalLite("production_scan", "ciso", None)]
    assert decide(base(environment="production", approvals=one)).allow is False

    two_same = [ApprovalLite("production_scan", "ciso", None)] * 2
    assert decide(base(environment="production", approvals=two_same)).allow is False

    two_distinct = [
        ApprovalLite("production_scan", "ciso", None),
        ApprovalLite("production_scan", "head_of_eng", None),
    ]
    # Also need the action itself (code_review) which isn't approval-gated → allowed.
    assert decide(base(environment="production", approvals=two_distinct)).allow is True
    assert PRODUCTION_MIN_REVIEWERS == 2


def test_expired_production_approval_does_not_count():
    expired = [
        ApprovalLite("production_scan", "ciso", 0.0),
        ApprovalLite("production_scan", "head_of_eng", 0.0),
    ]
    assert decide(base(environment="production", approvals=expired, now=10_000.0)).allow is False
