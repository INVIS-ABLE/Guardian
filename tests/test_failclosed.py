"""Regression tests for the three fail-closed defects fixed in build-order step 2.

1. ``build_policy_input`` / ``PolicyInput`` no longer assume ownership is verified.
2. The human-approval node and the Brain agree on ``approved`` (and it is never
   self-granted), so a recorded human decision can actually release the gate.
3. ``evaluate`` fails closed when OPA is unavailable in a staging/production posture,
   instead of silently using the embedded mirror.
"""

from __future__ import annotations

from core.brain import GuardianBrain, build_policy_input
from core.guardrails import HUMAN_GATE_ACTION, Approval
from core.memory import GuardianMemory, InMemoryBackend
from core.policy_gate import PolicyInput, decide, evaluate

import pytest


@pytest.fixture()
def memory(tmp_path):
    return GuardianMemory(backend=InMemoryBackend(store_dir=tmp_path))


# --- 1. ownership defaults to UNVERIFIED (fail closed) -------------------------
def test_policy_input_ownership_defaults_to_false():
    inp = PolicyInput(
        actor="t", action="code_review", mode="code_review", environment="staging",
        domain="staging.invisable.co.uk", allowed_modes=["code_review"],
    )
    assert inp.ownership_verified is False
    d = decide(inp)
    assert d.allow is False
    assert "ownership_unverified" in d.denies


def test_build_policy_input_does_not_assume_ownership(staging_scope):
    inp = build_policy_input(staging_scope, action="code_review", mode="code_review")
    assert inp.ownership_verified is False


# --- 2. approval node and Brain agree; never self-granted ---------------------
def test_brain_still_halts_without_a_recorded_approval(staging_scope, memory):
    brain = GuardianBrain(staging_scope, dry_run=True, memory=memory)
    run = brain.run()
    assert run.approved is False
    assert run.halted_at == "approval"
    # The post-approval learning stage must NOT run without approval.
    learn = [s for s in run.stages if s.stage == "learn"]
    assert learn and all(s.status == "skipped" for s in learn)


def test_recorded_human_approval_releases_the_gate(staging_scope, memory):
    approvals = [Approval(action=HUMAN_GATE_ACTION, approver="ciso", ticket="OPS-9")]
    brain = GuardianBrain(staging_scope, dry_run=True, memory=memory, approvals=approvals)
    run = brain.run()
    assert run.approved is True
    assert run.halted_at is None
    # With approval recorded, the post-approval learning stage now executes.
    learn = [s for s in run.stages if s.stage == "learn"]
    assert learn and all(s.status == "ok" for s in learn)


def test_approval_node_reports_approved_not_auto_approve(staging_scope, memory):
    approvals = [Approval(action=HUMAN_GATE_ACTION, approver="ciso", ticket="OPS-9")]
    brain = GuardianBrain(staging_scope, dry_run=True, memory=memory, approvals=approvals)
    run = brain.run()
    gate = next(s for s in run.stages if s.agent == "human_approval")
    assert gate.output["approved"] is True
    assert gate.output["self_granted"] is False


def test_unrelated_approval_does_not_release_the_gate(staging_scope, memory):
    # An approval for a different action must not satisfy the human gate.
    approvals = [Approval(action="production_scan", approver="ciso", ticket="OPS-9")]
    brain = GuardianBrain(staging_scope, dry_run=True, memory=memory, approvals=approvals)
    run = brain.run()
    assert run.approved is False


# --- 3. OPA mandatory in staging/production posture (fail closed) -------------
def _normal_input() -> PolicyInput:
    return PolicyInput(
        actor="guardian", action="code_review", mode="code_review",
        environment="staging", ownership_verified=True, allowed_modes=["code_review"],
    )


def test_evaluate_allows_in_development_posture(monkeypatch):
    monkeypatch.delenv("GUARDIAN_ENV", raising=False)
    monkeypatch.delenv("GUARDIAN_USE_OPA", raising=False)
    assert evaluate(_normal_input()).allow is True


@pytest.mark.parametrize("posture", ["staging", "production"])
def test_evaluate_fails_closed_without_opa_in_prod_postures(monkeypatch, posture):
    monkeypatch.setenv("GUARDIAN_ENV", posture)
    monkeypatch.delenv("GUARDIAN_USE_OPA", raising=False)  # OPA not wired
    d = evaluate(_normal_input())
    assert d.allow is False
    assert any(r.startswith("opa_required") for r in d.denies)
