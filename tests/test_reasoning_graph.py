"""Tests for the LangGraph reasoning graph + failure taxonomy + Temporal seam (step 4)."""

from __future__ import annotations

import asyncio
from uuid import uuid4

from core.brain import (
    CaseStatus,
    CaseTrigger,
    ExecutionBudgets,
    GuardianCaseState,
    VerifiedScope,
    behavior_for,
    is_fatal,
    run_execution,
    run_investigation,
)
from core.brain.failures import FailureBehavior, FailureClass
from core.brain.nodes import adjudicate, challenge, scope_verify
from core.brain.state import CaseStateDelta
from core.brain.temporal_workflow import (
    GuardianCaseWorkflow,
    needs_approval,
    run_investigation_activity,
)
from core.evidence.models import EvidenceItem, Hypothesis, Provenance


def _case(*, ownership: bool = True, budgets: ExecutionBudgets | None = None) -> GuardianCaseState:
    return GuardianCaseState(
        tenant_id=uuid4(),
        scope=VerifiedScope(asset="invisable-staging", environment="staging",
                            ownership_verified=ownership),
        trigger=CaseTrigger(kind="scheduled", source="cron"),
        budgets=budgets or ExecutionBudgets(),
    )


# --- investigation graph ------------------------------------------------------
def test_investigation_happy_path_produces_finding_awaiting_approval():
    out = run_investigation(_case(ownership=True))
    assert out.status is CaseStatus.AWAITING_APPROVAL
    assert len(out.evidence) == 1
    assert len(out.findings) == 1
    assert out.findings[0].severity == "high"
    # The finding is grounded in the collected evidence.
    assert out.findings[0].evidence_ids == tuple(e.id for e in out.evidence)
    # A deterministic scope ALLOW decision is recorded.
    assert any(d.allow and d.mode == "scope_verify" for d in out.policy_decisions)


def test_investigation_fails_closed_on_unverified_ownership():
    out = run_investigation(_case(ownership=False))
    assert out.status is CaseStatus.HALTED
    # No collection/analysis happened downstream of the failed scope gate.
    assert out.evidence == ()
    assert out.findings == ()
    assert any(not d.allow and "ownership_unverified" in d.denies for d in out.policy_decisions)


def test_investigation_is_deterministic_in_structure():
    c = _case(ownership=True)
    a, b = run_investigation(c), run_investigation(c)
    assert a.status == b.status
    assert len(a.findings) == len(b.findings) == 1
    assert a.findings[0].title == b.findings[0].title


# --- bounded execution --------------------------------------------------------
def test_exhausted_budget_halts_before_running():
    budgets = ExecutionBudgets(max_iterations=5, used_iterations=5)
    out = run_investigation(_case(budgets=budgets))
    assert out.status is CaseStatus.HALTED
    assert out.evidence == ()  # graph never started


def test_step_cap_maps_runaway_to_halt():
    # A recursion limit below the graph's depth must halt, not loop or crash.
    out = run_investigation(_case(ownership=True), max_steps=1)
    assert out.status is CaseStatus.HALTED


# --- post-approval execution --------------------------------------------------
def test_execution_graph_completes_case():
    investigated = run_investigation(_case(ownership=True))
    assert investigated.status is CaseStatus.AWAITING_APPROVAL
    executed = run_execution(investigated)
    assert executed.status is CaseStatus.COMPLETED


# --- nodes --------------------------------------------------------------------
def test_scope_verify_node_denies_unverified():
    delta = scope_verify(_case(ownership=False))
    assert delta.status is CaseStatus.HALTED
    assert delta.policy_decisions[0].allow is False


def test_challenge_promotes_grounded_hypothesis():
    ev = EvidenceItem(kind="x", summary="s", provenance=Provenance(tool="t"))
    h = Hypothesis(statement="claim", supporting_evidence_ids=(ev.id,), status="unverified")
    case = _case().apply(CaseStateDelta(evidence=(ev,), hypotheses=(h,)))
    delta = challenge(case)
    assert delta.hypotheses[0].status == "supported"


def test_adjudicate_abstains_without_grounded_hypothesis():
    # An inconclusive hypothesis (no supporting evidence) yields no finding.
    h = Hypothesis(statement="ungrounded", status="inconclusive")
    case = _case().apply(CaseStateDelta(hypotheses=(h,)))
    delta = adjudicate(case)
    assert delta.status is CaseStatus.COMPLETED
    assert delta.findings == ()


# --- failure taxonomy ---------------------------------------------------------
def test_scope_failure_is_fatal():
    b = behavior_for(FailureClass.SCOPE_IDENTITY_OWNERSHIP_POLICY)
    assert b is FailureBehavior.HALT and is_fatal(b)


def test_memory_unavailable_halts_outside_development():
    assert behavior_for(FailureClass.MEMORY_UNAVAILABLE, environment="production") is FailureBehavior.HALT
    assert (
        behavior_for(FailureClass.MEMORY_UNAVAILABLE, environment="development")
        is FailureBehavior.CONTINUE_NO_RETRIEVAL
    )


def test_verification_failure_rejects_action():
    assert behavior_for(FailureClass.VERIFICATION) is FailureBehavior.REJECT


def test_observability_failure_is_risk_weighted():
    assert behavior_for(FailureClass.OBSERVABILITY, risk="high") is FailureBehavior.HALT
    assert behavior_for(FailureClass.OBSERVABILITY, risk="low") is FailureBehavior.DEGRADED_OR_HALT


# --- temporal seam ------------------------------------------------------------
def test_needs_approval_predicate():
    assert needs_approval(CaseStatus.AWAITING_APPROVAL.value) is True
    assert needs_approval(CaseStatus.COMPLETED.value) is False


def test_investigation_activity_runs_over_json_boundary():
    case_json = _case(ownership=True).model_dump(mode="json")
    out = asyncio.run(run_investigation_activity(case_json))
    assert out["status"] == CaseStatus.AWAITING_APPROVAL.value
    assert len(out["findings"]) == 1


def test_workflow_defines_run_signal_and_query():
    # The durable workflow exposes a run method, an approval signal and a query.
    assert hasattr(GuardianCaseWorkflow, "run")
    assert hasattr(GuardianCaseWorkflow, "approve")
    assert hasattr(GuardianCaseWorkflow, "decision")
