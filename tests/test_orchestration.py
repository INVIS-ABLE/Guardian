"""Phase 1 orchestration tests — durable state machine, approvals, engine invariants."""

from __future__ import annotations

import pytest

from core.audit import AuditLog
from core.guardrails import Approval, GuardrailViolation, Guardrails
from core.scope import load_scope
from orchestration import (
    ApprovalLedger,
    BudgetExceeded,
    IllegalTransition,
    KillSwitch,
    NotEnoughApprovers,
    ReplaySignalError,
    ReviewerSignal,
    RiskTier,
    SecurityWorkflowEngine,
    State,
    WorkflowBudget,
    WorkflowFrozen,
    WorkflowMachine,
)


# --------------------------------------------------------------------------- state machine
def test_legal_forward_path():
    m = WorkflowMachine("wf-1")
    for s in [
        State.SCOPED, State.THREAT_MODELLED, State.SCANNED, State.PATCH_PROPOSED,
        State.TESTED, State.AWAITING_APPROVAL, State.APPROVED, State.EXECUTING,
        State.DEPLOYED, State.MONITORING, State.DONE,
    ]:
        m.transition(s)
    assert m.is_terminal() and m.state == State.DONE


def test_illegal_and_backward_transitions_refused():
    m = WorkflowMachine("wf-2")
    with pytest.raises(IllegalTransition):
        m.transition(State.EXECUTING)  # cannot skip to executing from created
    m.transition(State.SCOPED)
    with pytest.raises(IllegalTransition):
        m.transition(State.CREATED)  # monotonic: no going back


def test_cancelled_is_terminal_and_cannot_resume():
    m = WorkflowMachine("wf-3")
    m.transition(State.SCOPED)
    m.cancel()
    assert m.state == State.CANCELLED
    with pytest.raises(IllegalTransition):
        m.transition(State.THREAT_MODELLED)  # cancelled cannot resume
    with pytest.raises(IllegalTransition):
        m.cancel()  # already terminal


# ------------------------------------------------------------------------------- approvals
def test_replayed_nonce_rejected():
    ledger = ApprovalLedger(workflow_run="run-1")
    ledger.submit(ReviewerSignal("ciso", "production_scan", nonce="n1"))
    with pytest.raises(ReplaySignalError):
        ledger.submit(ReviewerSignal("ciso", "production_scan", nonce="n1"))


def test_production_needs_two_distinct_reviewers():
    ledger = ApprovalLedger(workflow_run="run-1")
    ledger.submit(ReviewerSignal("ciso", "production_scan", nonce="n1"))
    assert ledger.satisfied_for_production() is False
    ledger.submit(ReviewerSignal("ciso", "production_scan", nonce="n2"))  # same person again
    assert ledger.satisfied_for_production() is False
    ledger.submit(ReviewerSignal("head_eng", "production_scan", nonce="n3"))
    assert ledger.satisfied_for_production() is True


def test_signal_bound_to_workflow_run():
    ledger = ApprovalLedger(workflow_run="run-1", commit="abc")
    with pytest.raises(ReplaySignalError):
        ledger.submit(ReviewerSignal("ciso", "production_scan", nonce="n1", workflow_run="run-2"))
    with pytest.raises(ReplaySignalError):
        ledger.submit(ReviewerSignal("ciso", "production_scan", nonce="n2", commit="def"))


# --------------------------------------------------------------------------------- engine
def _engine(scope, tmp_path, *, tier=RiskTier.MEDIUM, approvals=None):
    gr = Guardrails(scope=scope, approvals=approvals or [])
    return SecurityWorkflowEngine(
        guardrails=gr, risk_tier=tier, audit=AuditLog(log_dir=tmp_path)
    )


def _prod_scope(tmp_path):
    p = tmp_path / "prod.yaml"
    p.write_text(
        "asset: invisable-production\nenvironment: production\n"
        "allowed_domains: [invisable.co.uk]\nallowed_repos: [github.com/invisable/app]\n"
        "allowed_test_accounts: [standard_user_test]\nallowed_modes: [code_review]\n"
        "blocked_actions: []\napproval_required: [production_scan]\n",
        encoding="utf-8",
    )
    return load_scope(p)


def test_staging_happy_path_reaches_execution(staging_scope, tmp_path):
    eng = _engine(staging_scope, tmp_path)
    m = WorkflowMachine("wf-ok")
    ledger = ApprovalLedger(workflow_run="wf-ok")
    eng.advance_to_approval(m)
    ledger.submit(ReviewerSignal("lead", "approve", nonce="a1"))
    eng.grant_approval(m, ledger)
    eng.execute(m, mode="code_review", action="code_review")
    assert m.state == State.EXECUTING


def test_policy_reasked_before_execution_denies(staging_scope, tmp_path):
    # Workflow is APPROVED, but the action is approval-gated and unapproved in the policy:
    # the last-moment re-check must DENY and the workflow must never execute.
    eng = _engine(staging_scope, tmp_path)
    m = WorkflowMachine("wf-deny")
    ledger = ApprovalLedger(workflow_run="wf-deny")
    eng.advance_to_approval(m)
    ledger.submit(ReviewerSignal("lead", "approve", nonce="a1"))
    eng.grant_approval(m, ledger)
    with pytest.raises(GuardrailViolation):
        eng.execute(m, mode="abuse_simulation", action="high_volume_test")
    assert m.state == State.DENIED
    assert m.reached_execution() is False


def test_production_requires_two_distinct_reviewers_to_approve(tmp_path):
    scope = _prod_scope(tmp_path)
    eng = _engine(scope, tmp_path, tier=RiskTier.CRITICAL)
    m = WorkflowMachine("wf-prod")
    ledger = ApprovalLedger(workflow_run="wf-prod")
    eng.advance_to_approval(m)
    ledger.submit(ReviewerSignal("ciso", "production_scan", nonce="n1"))
    with pytest.raises(NotEnoughApprovers):
        eng.grant_approval(m, ledger)  # only one reviewer
    ledger.submit(ReviewerSignal("head_eng", "production_scan", nonce="n2"))
    eng.grant_approval(m, ledger)
    assert m.state == State.APPROVED


def test_production_execution_reasks_policy_for_two_approvers(tmp_path):
    scope = _prod_scope(tmp_path)
    approvals = [
        Approval(action="production_scan", approver="ciso", ticket="T1"),
        Approval(action="production_scan", approver="head_eng", ticket="T2"),
    ]
    eng = _engine(scope, tmp_path, tier=RiskTier.CRITICAL, approvals=approvals)
    m = WorkflowMachine("wf-prod2")
    ledger = ApprovalLedger(workflow_run="wf-prod2")
    eng.advance_to_approval(m)
    ledger.submit(ReviewerSignal("ciso", "production_scan", nonce="n1"))
    ledger.submit(ReviewerSignal("head_eng", "production_scan", nonce="n2"))
    eng.grant_approval(m, ledger)
    eng.execute(m, mode="code_review", action="code_review")  # policy sees 2 approvers
    assert m.state == State.EXECUTING


def test_kill_switch_halts_execution(staging_scope, tmp_path):
    eng = _engine(staging_scope, tmp_path)
    eng.killswitch = KillSwitch(global_freeze=True)
    m = WorkflowMachine("wf-frozen")
    with pytest.raises(WorkflowFrozen):
        eng.advance_to_approval(m)


def test_budget_exceeded_blocks_execution(staging_scope, tmp_path):
    eng = _engine(staging_scope, tmp_path)
    m = WorkflowMachine("wf-budget")
    ledger = ApprovalLedger(workflow_run="wf-budget")
    eng.advance_to_approval(m)
    ledger.submit(ReviewerSignal("lead", "approve", nonce="a1"))
    eng.grant_approval(m, ledger)
    with pytest.raises(BudgetExceeded):
        eng.execute(m, mode="code_review", action="code_review", budget=WorkflowBudget(max_requests=0))
    assert m.reached_execution() is False
