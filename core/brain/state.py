"""Typed Brain case state — the strict replacement for the mutable blackboard.

Today the agents share a ``dict[str, Any]`` blackboard (see
``agents.base.AgentContext.blackboard``). That is convenient but unsafe: it allows
accidental overwrites, cross-agent contamination, untyped outputs, untraceable
provenance and prompt-injection propagation (target architecture §3).

``GuardianCaseState`` is the typed, immutable alternative. Reasoning nodes do not
mutate global state; they return a :class:`CaseStateDelta` and the graph applies it
to produce a *new* state. Because the state is ``frozen`` and ``extra="forbid"``,
one node cannot silently clobber another's output or smuggle in an unexpected field.

This module defines the contract only. The reasoning graph (LangGraph inner loop)
and Temporal outer workflow that consume it are later build-order steps; the linear
orchestrator in ``core.brain.orchestrator`` continues to run unchanged until the
graph is wired in behind it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from ..evidence.models import (
    SCHEMA_VERSION,
    EvidenceItem,
    Finding,
    Hypothesis,
    PolicyDecisionRecord,
    ProposedAction,
    VerificationResult,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CaseStatus(str, Enum):
    """Explicit lifecycle of a case — including explicit abort/halt states (§1)."""

    INTAKE = "intake"
    PLANNING = "planning"
    COLLECTING = "collecting"
    ANALYSING = "analysing"
    CHALLENGING = "challenging"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTING = "executing"
    OBSERVING = "observing"
    COMPLETED = "completed"
    HALTED = "halted"  # fail-closed stop (scope/identity/policy/approval/audit failure)
    ABORTED = "aborted"  # explicit, recorded abort


class ExecutionBudgets(BaseModel):
    """Hard limits on a case: depth, iterations, time, cost, tokens, tool calls (§1).

    Budgets are checked by the graph before each step; exceeding any of them is a
    bounded, recorded stop — not an open-ended loop.
    """

    model_config = ConfigDict(extra="forbid")

    max_depth: int = Field(ge=1, default=12)
    max_iterations: int = Field(ge=1, default=50)
    max_wall_seconds: int = Field(ge=1, default=3600)
    max_cost_usd: float = Field(ge=0.0, default=25.0)
    max_model_tokens: int = Field(ge=0, default=2_000_000)
    max_tool_calls: int = Field(ge=0, default=200)

    # Consumption counters (the only mutable part of the state, updated via deltas).
    used_iterations: int = Field(ge=0, default=0)
    used_wall_seconds: float = Field(ge=0.0, default=0.0)
    used_cost_usd: float = Field(ge=0.0, default=0.0)
    used_model_tokens: int = Field(ge=0, default=0)
    used_tool_calls: int = Field(ge=0, default=0)

    def exhausted(self) -> tuple[str, ...]:
        """Return the names of every budget that has been exhausted (empty == OK)."""
        breaches: list[str] = []
        if self.used_iterations >= self.max_iterations:
            breaches.append("iterations")
        if self.used_wall_seconds >= self.max_wall_seconds:
            breaches.append("wall_seconds")
        if self.used_cost_usd >= self.max_cost_usd:
            breaches.append("cost_usd")
        if self.used_model_tokens >= self.max_model_tokens:
            breaches.append("model_tokens")
        if self.used_tool_calls >= self.max_tool_calls:
            breaches.append("tool_calls")
        return tuple(breaches)


class VerifiedScope(BaseModel):
    """The verified authority boundary for a case — derived from a scope file.

    A model never populates this: scope/identity/ownership verification is
    deterministic (target architecture §1). ``ownership_verified`` defaults to
    ``False`` and must be set by a real verifier, mirroring the fail-closed default
    now used by the policy gate.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    asset: str
    environment: str
    allowed_modes: tuple[str, ...] = ()
    allowed_domains: tuple[str, ...] = ()
    allowed_repos: tuple[str, ...] = ()
    ownership_verified: bool = False


class CaseTrigger(BaseModel):
    """What opened the case (an alert, a scheduled run, a human request, a webhook)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str  # "scheduled" | "alert" | "human_request" | "webhook" | ...
    source: str
    detail: str = Field(max_length=4000, default="")
    received_at: datetime = Field(default_factory=_utcnow)


class GuardianCaseState(BaseModel):
    """The complete, typed, immutable state of one Guardian investigation (§3).

    Nodes return a :class:`CaseStateDelta`; :meth:`apply` produces a *new* state.
    Nothing mutates this object in place, so provenance stays intact and a node
    cannot corrupt another node's contribution.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    case_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    scope: VerifiedScope
    trigger: CaseTrigger
    status: CaseStatus = CaseStatus.INTAKE

    evidence: tuple[EvidenceItem, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    findings: tuple[Finding, ...] = ()
    proposed_actions: tuple[ProposedAction, ...] = ()
    policy_decisions: tuple[PolicyDecisionRecord, ...] = ()
    verification_results: tuple[VerificationResult, ...] = ()

    budgets: ExecutionBudgets = Field(default_factory=ExecutionBudgets)
    created_at: datetime = Field(default_factory=_utcnow)

    def apply(self, delta: "CaseStateDelta") -> "GuardianCaseState":
        """Return a new state with the delta's contributions appended/merged.

        Collections are *appended to* (never replaced), so one node cannot delete
        another's evidence. Scalars (status, budgets) are replaced when provided.
        """
        return self.model_copy(
            update={
                "status": delta.status or self.status,
                "budgets": delta.budgets or self.budgets,
                "evidence": self.evidence + delta.evidence,
                "hypotheses": self.hypotheses + delta.hypotheses,
                "findings": self.findings + delta.findings,
                "proposed_actions": self.proposed_actions + delta.proposed_actions,
                "policy_decisions": self.policy_decisions + delta.policy_decisions,
                "verification_results": self.verification_results
                + delta.verification_results,
            }
        )


class CaseStateDelta(BaseModel):
    """The typed contribution a single reasoning node returns (§3).

    Nodes return deltas — not mutated global state. A delta can only *add* to the
    evidence graph and optionally advance status / update budgets; it can never
    reach in and rewrite existing evidence or another node's findings.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: CaseStatus | None = None
    budgets: ExecutionBudgets | None = None
    evidence: tuple[EvidenceItem, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    findings: tuple[Finding, ...] = ()
    proposed_actions: tuple[ProposedAction, ...] = ()
    policy_decisions: tuple[PolicyDecisionRecord, ...] = ()
    verification_results: tuple[VerificationResult, ...] = ()


__all__ = [
    "CaseStatus",
    "ExecutionBudgets",
    "VerifiedScope",
    "CaseTrigger",
    "GuardianCaseState",
    "CaseStateDelta",
]
