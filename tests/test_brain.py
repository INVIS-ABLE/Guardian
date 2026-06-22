"""Tests for the Guardian Brain orchestrator and OPA policy gate."""

from __future__ import annotations

import pytest

from core.brain import GuardianBrain
from core.guardrails import Approval
from core.memory import GuardianMemory, InMemoryBackend
from core.opa import build_input, evaluate


@pytest.fixture()
def memory(tmp_path):
    return GuardianMemory(backend=InMemoryBackend(store_dir=tmp_path))


# --- OPA policy gate ----------------------------------------------------------
def test_policy_allows_in_scope_action(staging_scope):
    d = evaluate(build_input(staging_scope, action="code_review", mode="code_review"))
    assert d.allow and not d.deny


def test_policy_denies_blocked_action(staging_scope):
    d = evaluate(build_input(staging_scope, action="hack_back", mode="code_review"))
    assert not d.allow


def test_policy_denies_mode_not_in_scope(staging_scope):
    d = evaluate(build_input(staging_scope, action="runtime_monitoring", mode="runtime_monitoring"))
    assert not d.allow


def test_policy_denies_unowned_target(staging_scope):
    d = evaluate(build_input(
        staging_scope, action="code_review", mode="code_review",
        target={"kind": "domain", "in_scope": True, "owned": False},
    ))
    assert not d.allow


# --- Brain workflow -----------------------------------------------------------
def test_brain_runs_and_halts_for_approval(staging_scope, memory):
    brain = GuardianBrain(staging_scope, dry_run=True, memory=memory)
    run = brain.run()
    assert run.approved is False
    assert run.halted_at == "approval"
    # Detect-stage agents that map to in-scope modes should be ok.
    by_agent = {s.agent: s for s in run.stages}
    assert by_agent["code_review"].status == "ok"
    assert by_agent["human_approval"].status == "ok"


def test_brain_refuses_out_of_scope_mode_stage(staging_scope, memory):
    # runtime_monitoring mode is not in the staging scope -> policy gate refuses it.
    brain = GuardianBrain(staging_scope, dry_run=True, memory=memory)
    run = brain.run()
    rt = next(s for s in run.stages if s.agent == "runtime_monitoring")
    assert rt.status == "refused"


def test_brain_skips_post_approval_stage_until_approved(staging_scope, memory):
    brain = GuardianBrain(staging_scope, dry_run=True, memory=memory)
    run = brain.run(workflow=(
        ("approval", "human_approval"),
        ("deploy", "patch_proposal"),
    ))
    deploy = [s for s in run.stages if s.stage == "deploy"]
    assert deploy and all(s.status == "skipped" for s in deploy)


def test_brain_writes_findings_to_memory(staging_scope, memory):
    brain = GuardianBrain(staging_scope, dry_run=True, memory=memory)
    brain.run()
    assert memory.count("run_outcomes") > 0


def test_brain_records_approval_when_supplied(staging_scope, memory):
    approvals = [Approval(action="production_scan", approver="ciso", ticket="OPS-2")]
    brain = GuardianBrain(staging_scope, dry_run=True, memory=memory, approvals=approvals)
    assert any(a.action == "production_scan" for a in brain.guardrails.approvals)
