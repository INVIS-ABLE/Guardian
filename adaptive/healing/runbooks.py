"""The Healing Runbook IR — a restricted, typed plan for autonomous reversible repair (§6).

A runbook is *not* a script. It contains **no arbitrary shell**: its operations are typed
:class:`~adaptive.healing.contracts.RepairAction`s bound to exact targets with bounded
scalar arguments. Everything a runbook can do compiles into the existing Guardian execution
unit (``core.schemas.execution.ExecutionJob``) and is gated, at run time, by a one-use
capability token (§22) — this module only defines *what a runbook is*, the compiler
(``compiler.py``) turns it into compiled, gate-checked operations.

Strict Pydantic v2: ``extra="forbid"`` and ``frozen=True`` throughout. A runbook that omits
its rollback, abort or verification criteria, exceeds its own budgets, smuggles a shell
command into an argument, or targets something it did not declare is rejected at
construction — long before it could reach the compiler, OPA or Temporal.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .contracts import Criticality, Environment, RepairAction, STRUCTURALLY_FORBIDDEN_REPAIRS

SCHEMA_VERSION = 1

# Argument keys that would smuggle arbitrary execution into a typed operation. A runbook
# operation is a RepairAction + bounded scalar args, never a command.
_FORBIDDEN_ARG_KEYS: frozenset[str] = frozenset(
    {"command", "cmd", "script", "shell", "exec", "run", "entrypoint", "bash", "sh", "code"}
)
_SCALAR_TYPES = (str, int, float, bool)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RunbookTrigger(_Model):
    """A condition that may open this runbook. A *predicate over signals*, not code."""

    description: str = Field(min_length=1)
    condition: str = Field(min_length=1)  # e.g. "message_delivery_error_rate > 0.05"


class RunbookOperation(_Model):
    """One permitted, exact-target-bound repair step (§1 Class D constraints)."""

    action: RepairAction
    target_ref: str = Field(min_length=1)  # must be one of the runbook's declared targets
    args: dict[str, Any] = Field(default_factory=dict)
    max_invocations: int = Field(ge=1, le=100, default=1)
    timeout_seconds: int = Field(ge=1, le=3600, default=120)

    @model_validator(mode="after")
    def _no_shell_and_scalar_args(self) -> "RunbookOperation":
        if self.action.value in STRUCTURALLY_FORBIDDEN_REPAIRS:
            raise ValueError(f"operation {self.action.value!r} is structurally forbidden")
        for key, value in self.args.items():
            if key.lower() in _FORBIDDEN_ARG_KEYS:
                raise ValueError(f"operation arg {key!r} would smuggle arbitrary execution")
            if not isinstance(value, _SCALAR_TYPES):
                raise ValueError(
                    f"operation arg {key!r} must be a scalar (str/int/float/bool), "
                    f"got {type(value).__name__}"
                )
        return self


class RunbookBudget(_Model):
    """Hard ceilings on a single runbook execution (§6 maxima, §35 anti-oscillation)."""

    max_operations: int = Field(ge=1, le=100)
    max_duration_seconds: int = Field(ge=1, le=86_400)
    max_blast_radius: int = Field(ge=1, le=1000)  # max distinct targets affected
    cooldown_seconds: int = Field(ge=0, le=86_400, default=0)


class RunbookMetadata(_Model):
    name: str = Field(min_length=1)
    service: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    criticality: Criticality


class Runbook(_Model):
    """A restricted, reversible, fully-specified healing plan (§6)."""

    schema_version: int = SCHEMA_VERSION
    runbook_id: UUID = Field(default_factory=uuid4)
    metadata: RunbookMetadata

    # trigger + entry conditions
    trigger: tuple[RunbookTrigger, ...]
    required_evidence: tuple[str, ...]
    required_confidence: float = Field(ge=0.0, le=1.0)
    preconditions: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()

    # exact targets + permitted operations
    targets: tuple[str, ...]
    operations: tuple[RunbookOperation, ...]
    budget: RunbookBudget
    environments: tuple[Environment, ...]

    # success / safety / recovery
    success_criteria: tuple[str, ...]
    abort_criteria: tuple[str, ...]
    rollback_criteria: tuple[str, ...]
    verification_steps: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    escalation_path: tuple[str, ...]

    @model_validator(mode="after")
    def _check_runbook(self) -> "Runbook":
        if not self.trigger:
            raise ValueError("a runbook must declare at least one trigger")
        if not self.operations:
            raise ValueError("a runbook must declare at least one operation")
        if not self.targets:
            raise ValueError("a runbook must declare its exact targets")
        if not self.environments:
            raise ValueError("a runbook must declare the environments it may run in")
        # Reversibility + verifiability are mandatory (§39 #14, #15, #17).
        if not self.rollback_criteria:
            raise ValueError("a runbook must declare rollback_criteria (every repair is reversible)")
        if not self.abort_criteria:
            raise ValueError("a runbook must declare abort_criteria")
        if not self.verification_steps:
            raise ValueError("a runbook must declare verification_steps")
        # Budgets must contain the runbook the runbook describes.
        if len(self.operations) > self.budget.max_operations:
            raise ValueError(
                f"{len(self.operations)} operations exceed budget.max_operations="
                f"{self.budget.max_operations}"
            )
        # Exact-target binding: every operation targets a declared target.
        declared = set(self.targets)
        for op in self.operations:
            if op.target_ref not in declared:
                raise ValueError(
                    f"operation target {op.target_ref!r} is not in the runbook's declared targets"
                )
        # Blast radius: distinct targets touched must fit the declared maximum.
        touched = {op.target_ref for op in self.operations}
        if len(touched) > self.budget.max_blast_radius:
            raise ValueError(
                f"{len(touched)} distinct targets exceed budget.max_blast_radius="
                f"{self.budget.max_blast_radius}"
            )
        return self

    @property
    def worst_case_duration_seconds(self) -> int:
        """Upper bound on wall time if every operation runs to its timeout, max invocations."""
        return sum(op.timeout_seconds * op.max_invocations for op in self.operations)


__all__ = [
    "SCHEMA_VERSION",
    "RunbookTrigger",
    "RunbookOperation",
    "RunbookBudget",
    "RunbookMetadata",
    "Runbook",
]
