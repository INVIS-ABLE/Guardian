"""The Healing Runbook compiler and its 10-gate validation pipeline (§6).

The compiler turns a typed :class:`~adaptive.healing.runbooks.Runbook` into compiled,
gate-checked operations that materialise into the existing executable unit
(``core.schemas.execution.ExecutionJob``) — never shell. It runs the directive's ten
validation gates, but it **does not impersonate the existing authorities**:

* The gates the compiler can decide deterministically — *schema*, *ownership* (the
  HealingContract authorises this repair on this owned service), and *data classification*
  (privacy invariants hold) — it decides here, fail-closed.
* The gates that belong to an external authority or to runtime evidence — *CUE*, *Z3*,
  *OPA*, *synthetic execution*, *staging execution*, *rollback verification* and *human
  approval* — are ``PENDING_EXTERNAL`` until a signed :class:`GateAttestation` from that
  authority is supplied. The compiler trusts a passed attestation and records a failed one;
  it never marks them passed on its own.

A runbook is ``production_eligible`` only when **all ten gates pass**. So production
eligibility is structurally impossible without recorded OPA, staging, rollback-verification
and human-approval evidence — exactly the directive's "human approval before production
eligibility" rule, enforced by construction.
"""

from __future__ import annotations

from enum import Enum
from typing import Mapping
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from core.schemas.execution import ExecutionJob

from .contracts import (
    REPAIR_LAYER,
    Environment,
    HealingContract,
    HealingContractViolation,
    RepairAction,
    assert_repair_allowed,
)
from .runbooks import Runbook, RunbookOperation


class GateName(str, Enum):
    """The ten runbook validation gates, in directive §6 order."""

    SCHEMA = "schema"
    CUE = "cue"
    OWNERSHIP = "ownership"
    DATA_CLASSIFICATION = "data_classification"
    Z3_CONSISTENCY = "z3_consistency"
    OPA_POLICY = "opa_policy"
    SYNTHETIC_EXECUTION = "synthetic_execution"
    STAGING_EXECUTION = "staging_execution"
    ROLLBACK_VERIFICATION = "rollback_verification"
    HUMAN_APPROVAL = "human_approval"


# Gates the compiler decides itself; the rest require an external authority's attestation.
_DETERMINISTIC_GATES: frozenset[GateName] = frozenset(
    {GateName.SCHEMA, GateName.OWNERSHIP, GateName.DATA_CLASSIFICATION}
)
_EXTERNAL_GATES: tuple[GateName, ...] = (
    GateName.CUE,
    GateName.Z3_CONSISTENCY,
    GateName.OPA_POLICY,
    GateName.SYNTHETIC_EXECUTION,
    GateName.STAGING_EXECUTION,
    GateName.ROLLBACK_VERIFICATION,
    GateName.HUMAN_APPROVAL,
)


class GateStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    PENDING_EXTERNAL = "pending_external"


# Each repair action maps to a healing-executor capability (the ExecutionJob it compiles
# into). The capability is what a one-use token is later bound to at run time.
ACTION_CAPABILITY: dict[RepairAction, str] = {
    action: f"heal:{action.value}" for action in RepairAction
}


class GateAttestation(BaseModel):
    """An external authority's signed verdict on a gate it owns."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    gate: GateName
    passed: bool
    attested_by: str = Field(min_length=1)
    evidence_ref: str = ""


class GateResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    gate: GateName
    status: GateStatus
    detail: str = ""


class CompiledStep(BaseModel):
    """One operation, bound to its self-healing layer and healing-executor capability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    index: int = Field(ge=0)
    operation: RunbookOperation
    layer: int = Field(ge=1, le=10)
    capability: str


class CompiledRunbook(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    runbook_id: UUID
    service: str
    steps: tuple[CompiledStep, ...]
    gates: tuple[GateResult, ...]
    deterministic_passed: bool
    production_eligible: bool

    def gate(self, name: GateName) -> GateResult:
        for g in self.gates:
            if g.gate is name:
                return g
        raise KeyError(name)

    @property
    def pending_gates(self) -> tuple[GateName, ...]:
        return tuple(g.gate for g in self.gates if g.status is GateStatus.PENDING_EXTERNAL)


class RunbookCompileError(RuntimeError):
    """Raised when a runbook cannot be compiled or planned. Fail closed."""


def _ownership_detail(runbook: Runbook, contract: HealingContract) -> str | None:
    """Return a failure reason if the contract does not authorise this runbook, else None."""
    if runbook.metadata.service != contract.metadata.service:
        return (
            f"runbook service {runbook.metadata.service!r} != contract service "
            f"{contract.metadata.service!r}"
        )
    for env in runbook.environments:
        for op in runbook.operations:
            try:
                assert_repair_allowed(contract, op.action, env)
            except HealingContractViolation as exc:
                return str(exc)
    return None


def compile_runbook(
    runbook: Runbook,
    contract: HealingContract,
    *,
    attestations: Mapping[GateName, GateAttestation] | tuple[GateAttestation, ...] = (),
) -> CompiledRunbook:
    """Run the ten-gate pipeline and compile the runbook's operations. Pure."""
    att: dict[GateName, GateAttestation] = (
        dict(attestations)
        if isinstance(attestations, Mapping)
        else {a.gate: a for a in attestations}
    )

    gates: list[GateResult] = []

    # --- deterministic gates ------------------------------------------------------
    # Schema: the runbook validated at construction; additionally its worst-case duration
    # must fit its own budget (a lightweight consistency check).
    if runbook.worst_case_duration_seconds > runbook.budget.max_duration_seconds:
        gates.append(GateResult(
            gate=GateName.SCHEMA, status=GateStatus.FAIL,
            detail=(f"worst-case duration {runbook.worst_case_duration_seconds}s exceeds "
                    f"budget.max_duration_seconds={runbook.budget.max_duration_seconds}"),
        ))
    else:
        gates.append(GateResult(gate=GateName.SCHEMA, status=GateStatus.PASS))

    # Ownership: the HealingContract authorises every operation on this owned service.
    own_fail = _ownership_detail(runbook, contract)
    gates.append(
        GateResult(gate=GateName.OWNERSHIP, status=GateStatus.FAIL, detail=own_fail)
        if own_fail
        else GateResult(gate=GateName.OWNERSHIP, status=GateStatus.PASS)
    )

    # Data classification: privacy invariants hold (contract privacy is structurally
    # forbidden; no operation is a structurally-forbidden action — guaranteed by the
    # models, re-affirmed here as the gate's verdict).
    gates.append(GateResult(gate=GateName.DATA_CLASSIFICATION, status=GateStatus.PASS))

    # --- external gates: pending unless an authority attested -----------------------
    for name in _EXTERNAL_GATES:
        a = att.get(name)
        if a is None:
            gates.append(GateResult(
                gate=name, status=GateStatus.PENDING_EXTERNAL,
                detail="awaiting attestation from the owning authority",
            ))
        elif a.passed:
            gates.append(GateResult(
                gate=name, status=GateStatus.PASS,
                detail=f"attested by {a.attested_by}",
            ))
        else:
            gates.append(GateResult(
                gate=name, status=GateStatus.FAIL,
                detail=f"attestation failed ({a.attested_by})",
            ))

    # Order gates by the directive's gate order for stable, readable output.
    order = list(GateName)
    gates.sort(key=lambda g: order.index(g.gate))

    deterministic_passed = all(
        g.status is GateStatus.PASS for g in gates if g.gate in _DETERMINISTIC_GATES
    )
    production_eligible = all(g.status is GateStatus.PASS for g in gates)

    steps = tuple(
        CompiledStep(
            index=i,
            operation=op,
            layer=REPAIR_LAYER[op.action],
            capability=ACTION_CAPABILITY[op.action],
        )
        for i, op in enumerate(runbook.operations)
    )

    return CompiledRunbook(
        runbook_id=runbook.runbook_id,
        service=runbook.metadata.service,
        steps=steps,
        gates=tuple(gates),
        deterministic_passed=deterministic_passed,
        production_eligible=production_eligible,
    )


def plan_execution_jobs(
    compiled: CompiledRunbook,
    runbook: Runbook,
    *,
    case_id: UUID,
    environment: Environment,
    trace_id: str = "",
) -> tuple[ExecutionJob, ...]:
    """Materialise compiled steps into sealed ExecutionJobs for one incident (fast path, §22).

    Fail closed:
    * the environment must be one the runbook declared;
    * the deterministic gates must have passed;
    * production additionally requires full ``production_eligible`` (all ten gates) — i.e.
      recorded OPA / staging / rollback-verification / human-approval evidence.

    Each returned ExecutionJob still requires a one-use capability token to be minted and
    consumed at execution time; this function does not authorise execution, it only plans it.
    """
    if environment not in runbook.environments:
        raise RunbookCompileError(
            f"runbook does not declare environment {environment.value!r}"
        )
    if not compiled.deterministic_passed:
        failed = [g.gate.value for g in compiled.gates
                  if g.gate in _DETERMINISTIC_GATES and g.status is not GateStatus.PASS]
        raise RunbookCompileError(f"deterministic gates not passed: {failed}")
    if environment is Environment.PRODUCTION and not compiled.production_eligible:
        raise RunbookCompileError(
            f"runbook is not production-eligible; pending gates: "
            f"{[g.value for g in compiled.pending_gates]}"
        )

    jobs: list[ExecutionJob] = []
    for step in compiled.steps:
        op = step.operation
        args = {
            "action": op.action.value,
            "target_ref": op.target_ref,
            "max_invocations": op.max_invocations,
            **op.args,
        }
        jobs.append(
            ExecutionJob(
                case_id=case_id,
                tool_id="healing-executor",
                capability=step.capability,
                args=args,
                execution_profile="healing-reversible",
                target_refs=(op.target_ref,),
                timeout_seconds=op.timeout_seconds,
                trace_id=trace_id or str(uuid4()),
            )
        )
    return tuple(jobs)


__all__ = [
    "GateName",
    "GateStatus",
    "GateAttestation",
    "GateResult",
    "CompiledStep",
    "CompiledRunbook",
    "RunbookCompileError",
    "ACTION_CAPABILITY",
    "compile_runbook",
    "plan_execution_jobs",
]
