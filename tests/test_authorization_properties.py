"""Property-based proofs that no input combination bypasses the guardrails.

Acceptance gate (Testing): "Property tests prove that blocked actions and production
restrictions cannot be bypassed through input combinations." Hypothesis generates
combinations of action, environment, mode, account and approvals and asserts the
invariants always hold.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from core.policy_gate import (
    BLOCKED_ACTIONS,
    GLOBAL_APPROVAL_REQUIRED,
    PRODUCTION_MIN_REVIEWERS,
    ApprovalLite,
    PolicyInput,
    decide,
)

ACTIONS = sorted(BLOCKED_ACTIONS | GLOBAL_APPROVAL_REQUIRED | {"code_review", "safeguarding"})
MODES = ["code_review", "abuse_simulation", "zap_scan", "credential_audit", "safeguarding"]
APPROVERS = ["ciso", "head_of_eng", "dpo", "secops"]
ENVS = ["staging", "development", "production"]

approvals_strategy = st.lists(
    st.builds(
        ApprovalLite,
        action=st.sampled_from(ACTIONS),
        approver=st.sampled_from(APPROVERS),
        expires_at=st.none() | st.floats(min_value=0, max_value=2_000_000_000),
    ),
    max_size=6,
)


def _input(action, mode, environment, approvals, test_account, ownership_verified):
    return PolicyInput(
        actor="guardian",
        action=action,
        mode=mode,
        environment=environment,
        domain="staging.invisable.co.uk",
        test_account=test_account,
        ownership_verified=ownership_verified,
        allowed_modes=MODES,  # generously allow all modes so we test the OTHER gates
        blocked_actions=[],
        approval_required=list(GLOBAL_APPROVAL_REQUIRED),
        allowed_test_accounts=["standard_user_test"],
        approvals=approvals,
        now=1_000_000.0,
    )


@settings(max_examples=400)
@given(
    action=st.sampled_from(ACTIONS),
    mode=st.sampled_from(MODES),
    environment=st.sampled_from(ENVS),
    approvals=approvals_strategy,
    test_account=st.sampled_from(["standard_user_test", "real_person", None]),
    ownership_verified=st.booleans(),
)
def test_blocked_actions_are_never_allowed(action, mode, environment, approvals, test_account, ownership_verified):
    d = decide(_input(action, mode, environment, approvals, test_account, ownership_verified))
    if action in BLOCKED_ACTIONS:
        assert d.allow is False  # no combination of inputs can permit a blocked action


@settings(max_examples=400)
@given(
    action=st.sampled_from(ACTIONS),
    mode=st.sampled_from(MODES),
    approvals=approvals_strategy,
    test_account=st.sampled_from(["standard_user_test", None]),
)
def test_production_requires_two_distinct_unexpired_approvers(action, mode, approvals, test_account):
    inp = _input(action, mode, "production", approvals, test_account, ownership_verified=True)
    d = decide(inp)
    distinct = {
        a.approver for a in approvals if a.action == "production_scan" and a.is_valid(inp.now)
    }
    if len(distinct) < PRODUCTION_MIN_REVIEWERS:
        assert d.allow is False  # production can never proceed without the two-person rule


@settings(max_examples=300)
@given(
    action=st.sampled_from(sorted(GLOBAL_APPROVAL_REQUIRED)),
    approvals=approvals_strategy,
)
def test_approval_gated_actions_need_a_valid_approval(action, approvals):
    inp = _input(action, "credential_audit", "staging", approvals, None, ownership_verified=True)
    d = decide(inp)
    has_valid = any(a.action == action and a.is_valid(inp.now) for a in approvals)
    if not has_valid:
        assert d.allow is False  # gated action without a valid approval is always denied
