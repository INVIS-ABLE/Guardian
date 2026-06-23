"""Level 6 §6: the restricted Healing Runbook IR and its 10-gate compiler."""

from __future__ import annotations

from uuid import uuid4

import pytest

from adaptive.healing.compiler import (
    GateName,
    GateStatus,
    GateAttestation,
    RunbookCompileError,
    compile_runbook,
    plan_execution_jobs,
)
from adaptive.healing.contracts import Environment, HealingContract, RepairAction
from adaptive.healing.runbooks import (
    Runbook,
    RunbookBudget,
    RunbookMetadata,
    RunbookOperation,
    RunbookTrigger,
)

CONTRACT = HealingContract.from_mapping(
    {
        "metadata": {"service": "message-relay", "owner": "privacy-platform", "criticality": "critical"},
        "health": {"sloRef": "message-relay-availability"},
        "allowedRepairs": [
            {"action": "restart_replica", "environments": ["staging"], "maximumPerHour": 2},
            {
                "action": "rollback_canary",
                "environments": ["staging", "production"],
                "requires": ["approved_rollout", "failed_safety_analysis"],
            },
        ],
        "rollback": {"required": True, "verificationWindowSeconds": 600},
        "privacy": {"plaintextAccess": "forbidden", "messageKeyAccess": "forbidden"},
    }
)

TARGET = "k8s://staging/message-relay/replica-0"


def _staging_runbook(**overrides) -> Runbook:
    base = dict(
        metadata=RunbookMetadata(
            name="message-relay-restart", service="message-relay",
            owner="privacy-platform", criticality="critical",
        ),
        trigger=(RunbookTrigger(description="replica unhealthy", condition="up == 0"),),
        required_evidence=("prometheus:up == 0",),
        required_confidence=0.8,
        targets=(TARGET,),
        operations=(
            RunbookOperation(action=RepairAction.RESTART_REPLICA, target_ref=TARGET,
                             max_invocations=2, timeout_seconds=60),
        ),
        budget=RunbookBudget(max_operations=5, max_duration_seconds=600,
                             max_blast_radius=3, cooldown_seconds=300),
        environments=(Environment.STAGING,),
        success_criteria=("up == 1",),
        abort_criteria=("restart count > 2",),
        rollback_criteria=("still unhealthy after restart",),
        verification_steps=("confirm up == 1 for 600s",),
        evidence_requirements=("restart event recorded",),
        escalation_path=("page privacy-platform on-call",),
    )
    base.update(overrides)
    return Runbook(**base)


# --- runbook IR validation -----------------------------------------------------
def test_valid_runbook_constructs():
    rb = _staging_runbook()
    assert rb.worst_case_duration_seconds == 120


def test_runbook_requires_rollback_criteria():
    with pytest.raises(ValueError):
        _staging_runbook(rollback_criteria=())


def test_runbook_requires_verification_steps():
    with pytest.raises(ValueError):
        _staging_runbook(verification_steps=())


def test_operation_rejects_shell_smuggling():
    with pytest.raises(ValueError):
        RunbookOperation(action=RepairAction.RESTART_REPLICA, target_ref=TARGET,
                         args={"command": "rm -rf /"})


def test_operation_rejects_non_scalar_args():
    with pytest.raises(ValueError):
        RunbookOperation(action=RepairAction.RESTART_REPLICA, target_ref=TARGET,
                         args={"spec": {"nested": "object"}})


def test_operation_target_must_be_declared():
    with pytest.raises(ValueError):
        _staging_runbook(
            operations=(
                RunbookOperation(action=RepairAction.RESTART_REPLICA,
                                 target_ref="k8s://staging/other/replica"),
            )
        )


def test_blast_radius_enforced():
    t2 = "k8s://staging/message-relay/replica-1"
    with pytest.raises(ValueError):
        _staging_runbook(
            targets=(TARGET, t2),
            operations=(
                RunbookOperation(action=RepairAction.RESTART_REPLICA, target_ref=TARGET),
                RunbookOperation(action=RepairAction.RESTART_REPLICA, target_ref=t2),
            ),
            budget=RunbookBudget(max_operations=5, max_duration_seconds=600,
                                 max_blast_radius=1, cooldown_seconds=0),
        )


# --- compiler: gates -----------------------------------------------------------
def test_deterministic_gates_pass_for_valid_runbook():
    compiled = compile_runbook(_staging_runbook(), CONTRACT)
    assert compiled.gate(GateName.SCHEMA).status is GateStatus.PASS
    assert compiled.gate(GateName.OWNERSHIP).status is GateStatus.PASS
    assert compiled.gate(GateName.DATA_CLASSIFICATION).status is GateStatus.PASS
    assert compiled.deterministic_passed is True


def test_external_gates_pending_without_attestation():
    compiled = compile_runbook(_staging_runbook(), CONTRACT)
    assert compiled.gate(GateName.OPA_POLICY).status is GateStatus.PENDING_EXTERNAL
    assert compiled.gate(GateName.HUMAN_APPROVAL).status is GateStatus.PENDING_EXTERNAL
    # not production-eligible without all gates passing
    assert compiled.production_eligible is False
    assert GateName.HUMAN_APPROVAL in compiled.pending_gates


def test_ownership_gate_fails_when_contract_forbids_op_in_env():
    # rollback in production needs the contract to allow it; restart in production does not.
    rb = _staging_runbook(environments=(Environment.STAGING, Environment.PRODUCTION))
    compiled = compile_runbook(rb, CONTRACT)
    assert compiled.gate(GateName.OWNERSHIP).status is GateStatus.FAIL
    assert compiled.deterministic_passed is False


def test_schema_gate_fails_when_duration_exceeds_budget():
    rb = _staging_runbook(
        operations=(
            RunbookOperation(action=RepairAction.RESTART_REPLICA, target_ref=TARGET,
                             max_invocations=100, timeout_seconds=3600),
        ),
        budget=RunbookBudget(max_operations=5, max_duration_seconds=600,
                             max_blast_radius=3, cooldown_seconds=0),
    )
    compiled = compile_runbook(rb, CONTRACT)
    assert compiled.gate(GateName.SCHEMA).status is GateStatus.FAIL


def test_failed_attestation_marks_gate_failed():
    att = (GateAttestation(gate=GateName.OPA_POLICY, passed=False, attested_by="opa"),)
    compiled = compile_runbook(_staging_runbook(), CONTRACT, attestations=att)
    assert compiled.gate(GateName.OPA_POLICY).status is GateStatus.FAIL
    assert compiled.production_eligible is False


def _all_external_passed() -> tuple[GateAttestation, ...]:
    from adaptive.healing.compiler import _EXTERNAL_GATES
    return tuple(
        GateAttestation(gate=g, passed=True, attested_by="authority", evidence_ref="immudb://x")
        for g in _EXTERNAL_GATES
    )


def test_full_attestation_makes_runbook_production_eligible():
    compiled = compile_runbook(_staging_runbook(), CONTRACT, attestations=_all_external_passed())
    assert compiled.production_eligible is True
    assert compiled.pending_gates == ()


# --- compiler: planning execution jobs (fast path, §22) ------------------------
def test_plan_jobs_in_staging_when_deterministic_gates_pass():
    compiled = compile_runbook(_staging_runbook(), CONTRACT)
    jobs = plan_execution_jobs(compiled, _staging_runbook(), case_id=uuid4(),
                               environment=Environment.STAGING)
    assert len(jobs) == 1
    job = jobs[0]
    assert job.capability == "heal:restart_replica"
    assert job.target_refs == (TARGET,)
    # no shell smuggled into the sealed job
    assert "command" not in job.args and "script" not in job.args
    assert job.args["action"] == "restart_replica"


def test_plan_jobs_refuses_undeclared_environment():
    compiled = compile_runbook(_staging_runbook(), CONTRACT)
    with pytest.raises(RunbookCompileError):
        plan_execution_jobs(compiled, _staging_runbook(), case_id=uuid4(),
                            environment=Environment.PRODUCTION)


def test_plan_jobs_refuses_production_without_eligibility():
    rb = _staging_runbook(environments=(Environment.STAGING, Environment.PRODUCTION))
    # ownership fails (restart not allowed in prod) -> deterministic gates fail
    compiled = compile_runbook(rb, CONTRACT)
    with pytest.raises(RunbookCompileError):
        plan_execution_jobs(compiled, rb, case_id=uuid4(), environment=Environment.PRODUCTION)


def test_production_plan_succeeds_only_with_full_eligibility():
    # rollback_canary is contract-permitted in production.
    prod_target = "k8s://production/message-relay/rollout"
    rb = _staging_runbook(
        environments=(Environment.STAGING, Environment.PRODUCTION),
        targets=(prod_target,),
        operations=(
            RunbookOperation(action=RepairAction.ROLLBACK_CANARY, target_ref=prod_target),
        ),
    )
    compiled = compile_runbook(rb, CONTRACT, attestations=_all_external_passed())
    assert compiled.production_eligible is True
    jobs = plan_execution_jobs(compiled, rb, case_id=uuid4(), environment=Environment.PRODUCTION)
    assert jobs[0].capability == "heal:rollback_canary"
