"""Security-workflow engine (Phase 1).

Drives a WorkflowMachine through its states with the durable-workflow safety properties
from the blueprint:

  - risk tiers set how many reviewers a workflow needs;
  - a global / per-environment / per-tenant kill switch can freeze execution;
  - per-workflow budgets (time, requests) bound runaway work;
  - production needs two distinct reviewers (delegated to the ApprovalLedger + policy);
  - the policy gate is re-asked IMMEDIATELY before execution (not just at planning time),
    so a capability that has since expired / been revoked / had its commit changed is
    refused at the last moment.

Every state change and decision is audited (allowed and denied).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from time import time

from core.audit import AuditLog
from core.guardrails import GuardrailViolation, Guardrails

from .approvals import ApprovalLedger
from .state_machine import State, WorkflowMachine


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Minimum distinct reviewers per tier (production additionally forces >= 2 via policy).
TIER_MIN_REVIEWERS: dict[RiskTier, int] = {
    RiskTier.LOW: 0,
    RiskTier.MEDIUM: 1,
    RiskTier.HIGH: 2,
    RiskTier.CRITICAL: 2,
}


class WorkflowFrozen(RuntimeError):
    """Raised when a kill switch blocks a transition/execution."""


class BudgetExceeded(RuntimeError):
    """Raised when a workflow exceeds its time/request budget."""


class NotEnoughApprovers(RuntimeError):
    """Raised when approval is granted without the required distinct reviewers."""


@dataclass
class KillSwitch:
    """Global / per-environment / per-tenant freeze. Default-open; freezes fail closed."""

    global_freeze: bool = False
    frozen_envs: set[str] = field(default_factory=set)
    frozen_tenants: set[str] = field(default_factory=set)

    def frozen(self, *, environment: str | None = None, tenant: str | None = None) -> bool:
        if self.global_freeze:
            return True
        if environment is not None and environment in self.frozen_envs:
            return True
        if tenant is not None and tenant in self.frozen_tenants:
            return True
        return False

    def freeze_all(self) -> None:
        self.global_freeze = True


@dataclass
class WorkflowBudget:
    max_seconds: float = 900.0
    max_requests: int = 1000
    started_at: float = field(default_factory=time)
    requests_used: int = 0

    def consume_request(self, n: int = 1) -> None:
        self.requests_used += n
        if self.requests_used > self.max_requests:
            raise BudgetExceeded(f"request budget exceeded ({self.requests_used}/{self.max_requests})")

    def assert_within_time(self, now: float | None = None) -> None:
        now = time() if now is None else now
        if now - self.started_at > self.max_seconds:
            raise BudgetExceeded("time budget exceeded")


@dataclass
class SecurityWorkflowEngine:
    guardrails: Guardrails
    killswitch: KillSwitch = field(default_factory=KillSwitch)
    risk_tier: RiskTier = RiskTier.MEDIUM
    tenant: str | None = None
    audit: AuditLog = field(default_factory=AuditLog)

    @property
    def environment(self) -> str:
        return self.guardrails.scope.environment

    def _assert_not_frozen(self) -> None:
        if self.killswitch.frozen(environment=self.environment, tenant=self.tenant):
            raise WorkflowFrozen(
                f"kill switch active (env={self.environment}, tenant={self.tenant}); halting"
            )

    def _audit(self, event: str, decision: str, machine: WorkflowMachine, **detail: object) -> None:
        try:
            self.audit.record(
                f"workflow:{event}",
                actor="orchestration",
                scope=self.guardrails.scope.asset,
                decision=decision,
                detail={"workflow": machine.workflow_id, "state": machine.state.value, **detail},
            )
        except Exception:  # pragma: no cover - auditing must not crash the engine
            pass

    def step(self, machine: WorkflowMachine, to: State) -> None:
        """A guarded forward transition (kill switch checked first)."""
        self._assert_not_frozen()
        machine.transition(to)
        self._audit("step", "allowed", machine)

    def advance_to_approval(self, machine: WorkflowMachine) -> None:
        """Drive CREATED → … → AWAITING_APPROVAL through the analysis stages."""
        path = [
            State.SCOPED,
            State.THREAT_MODELLED,
            State.SCANNED,
            State.PATCH_PROPOSED,
            State.TESTED,
            State.AWAITING_APPROVAL,
        ]
        for nxt in path:
            self.step(machine, nxt)

    def grant_approval(self, machine: WorkflowMachine, ledger: ApprovalLedger) -> None:
        """Move AWAITING_APPROVAL → APPROVED only if reviewer requirements are met."""
        if machine.state != State.AWAITING_APPROVAL:
            raise NotEnoughApprovers("workflow is not awaiting approval")
        required = TIER_MIN_REVIEWERS[self.risk_tier]
        distinct = ledger.distinct_reviewers("production_scan") or ledger.distinct_reviewers(
            "approve"
        )
        if self.environment == "production" and not ledger.satisfied_for_production():
            self._audit("approval", "denied", machine, reason="insufficient_production_reviewers")
            raise NotEnoughApprovers("production needs two distinct reviewers")
        if len(distinct) < required:
            self._audit("approval", "denied", machine, reason="insufficient_reviewers")
            raise NotEnoughApprovers(f"need {required} distinct reviewers, have {len(distinct)}")
        ledger.close()
        self.step(machine, State.APPROVED)

    def execute(
        self,
        machine: WorkflowMachine,
        *,
        mode: str,
        action: str,
        budget: WorkflowBudget | None = None,
        **authz: object,
    ) -> None:
        """Re-ask the policy gate immediately before execution, then EXECUTE or DENY."""
        if machine.state != State.APPROVED:
            raise GuardrailViolation("execute requires an APPROVED workflow")
        self._assert_not_frozen()
        if budget is not None:
            budget.assert_within_time()
            budget.consume_request()
        # Last-moment re-authorization — the capability must STILL be valid right now.
        try:
            self.guardrails.authorize(mode=mode, action=action, **authz)  # type: ignore[arg-type]
        except GuardrailViolation:
            machine.deny()
            self._audit("execute", "denied", machine, action=action)
            raise
        self.step(machine, State.EXECUTING)
        self._audit("execute", "allowed", machine, action=action)
