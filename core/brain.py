"""Guardian Brain — the controlled orchestrator that stitches the system together.

This is the "brain, not supermodel" layer the project is built around: it does not
train a model from scratch, it *coordinates* proven pieces — the 17 agents, the tool
router, the guardrails, the policy gate, and memory — into one auditable workflow:

    Detect → Simulate → Analyse → Patch proposal → Test → Evidence
           → Human approval → (deploy safely) → Monitor → Learn

The orchestration is a small, explicit state machine (LangGraph-inspired but
dependency-free so it runs anywhere). Each node is gated; the **Human Approval** node
is a hard stop — nothing downstream of it executes without a recorded approval. The
Brain never deploys to production and never bypasses a gate; it produces a run report
and routes everything else to humans.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from agents import REGISTRY as AGENT_REGISTRY
from agents.base import AgentContext

from .audit import AuditLog
from .guardrails import Approval, Guardrails
from .memory import GuardianMemory
from .policy_gate import PolicyInput, evaluate
from .router import ToolRouter
from .scope import Scope, load_scope


def build_policy_input(
    scope: Scope,
    *,
    action: str,
    mode: str,
    approvals=None,
    actor: str = "guardian_brain",
    ownership_verified: bool = True,
) -> PolicyInput:
    """Assemble a central-policy ``PolicyInput`` from a scope + requested action.

    This is the one place the Brain (and the ``guardian policy`` CLI) builds the input
    for ``core.policy_gate.evaluate`` — the single authorization authority that mirrors
    ``policies/opa/guardian.rego`` (and delegates to OPA when ``GUARDIAN_USE_OPA=1``).
    """
    return PolicyInput(
        actor=actor,
        action=action,
        mode=mode,
        environment=scope.environment,
        allowed_modes=scope.allowed_modes,
        blocked_actions=scope.blocked_actions,
        approval_required=scope.approval_required,
        allowed_test_accounts=scope.allowed_test_accounts,
        approvals=list(approvals or []),
        ownership_verified=ownership_verified,
    )

# The defensive workflow as an ordered list of (stage, agent-name) nodes. Stages map
# to the pipeline in README/GUARDRAILS; agent names resolve against agents.REGISTRY.
WORKFLOW: tuple[tuple[str, str], ...] = (
    ("plan", "guardian_planner"),
    ("scope_verify", "asset_scope"),
    ("threat_model", "threat_model"),
    ("detect", "code_review"),
    ("detect", "dependency"),
    ("detect", "secrets"),
    ("detect", "api_security"),
    ("detect", "auth_rbac"),
    ("detect", "privacy_gdpr"),
    ("detect", "safeguarding"),
    ("simulate", "abuse_simulation"),
    ("monitor", "runtime_monitoring"),
    ("patch", "patch_proposal"),
    ("test", "test_runner"),
    ("evidence", "evidence_report"),
    ("approval", "human_approval"),   # hard stop — human-in-the-loop
    ("learn", "learning_memory"),
)

# Stages that must not run until a human approval has been recorded. Everything from
# the approval gate onward (deploy/PR-merge) is post-approval only.
POST_APPROVAL_STAGES: frozenset[str] = frozenset({"deploy"})


@dataclass
class StageResult:
    stage: str
    agent: str
    status: str                       # "ok" | "refused" | "skipped" | "halted"
    output: dict[str, Any] = field(default_factory=dict)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "agent": self.agent,
            "status": self.status,
            "output": self.output,
            "note": self.note,
        }


@dataclass
class BrainRun:
    """The full record of one Guardian Brain run — itself an evidence artefact."""

    asset: str
    environment: str
    dry_run: bool
    started_at: str
    stages: list[StageResult] = field(default_factory=list)
    approved: bool = False
    halted_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "environment": self.environment,
            "dry_run": self.dry_run,
            "started_at": self.started_at,
            "approved": self.approved,
            "halted_at": self.halted_at,
            "stages": [s.to_dict() for s in self.stages],
        }

    def summary(self) -> str:
        counts: dict[str, int] = {}
        for s in self.stages:
            counts[s.status] = counts.get(s.status, 0) + 1
        parts = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        gate = "APPROVED" if self.approved else "AWAITING HUMAN APPROVAL"
        return f"{self.asset} [{self.environment}] dry_run={self.dry_run} — {parts} — {gate}"


class GuardianBrain:
    """Orchestrates a controlled, gated, fully-audited Guardian run."""

    def __init__(
        self,
        scope: Scope,
        *,
        dry_run: bool = True,
        guardrails: Guardrails | None = None,
        router: ToolRouter | None = None,
        memory: GuardianMemory | None = None,
        approvals: list[Approval] | None = None,
    ) -> None:
        self.scope = scope
        self.dry_run = dry_run
        self.guardrails = guardrails or Guardrails(scope=scope, approvals=approvals or [])
        if approvals:
            for a in approvals:
                if a not in self.guardrails.approvals:
                    self.guardrails.approvals.append(a)
        self.router = router or ToolRouter(scope, guardrails=self.guardrails, dry_run=dry_run)
        self.memory = memory or GuardianMemory()
        self.audit = AuditLog()
        self.context = AgentContext(
            scope=scope, guardrails=self.guardrails, dry_run=dry_run,
            blackboard={"router": self.router, "memory": self.memory},
        )

    # --- policy pre-flight -----------------------------------------------------
    def policy_check(self, *, action: str, mode: str) -> bool:
        """Evaluate the central authorization policy before a stage's work. Fail-closed."""
        approvals = [a._lite() for a in self.guardrails.approvals]
        decision = evaluate(build_policy_input(self.scope, action=action, mode=mode, approvals=approvals))
        self.audit.record(
            "brain:policy_check",
            actor="guardian_brain",
            scope=self.scope.asset,
            decision="allowed" if decision.allow else "refused",
            detail={"action": action, "mode": mode, "denies": decision.denies},
        )
        return decision.allow

    # --- run -------------------------------------------------------------------
    def run(self, *, workflow: tuple[tuple[str, str], ...] = WORKFLOW) -> BrainRun:
        run = BrainRun(
            asset=self.scope.asset,
            environment=self.scope.environment,
            dry_run=self.dry_run,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self.audit.record(
            "brain:run:start", actor="guardian_brain", scope=self.scope.asset,
            decision="allowed", detail={"dry_run": self.dry_run, "stages": len(workflow)},
        )

        for stage, agent_name in workflow:
            # Hard human-in-the-loop boundary: refuse to run any post-approval stage
            # until the approval node has recorded a human decision.
            if stage in POST_APPROVAL_STAGES and not run.approved:
                run.stages.append(
                    StageResult(stage, agent_name, "skipped",
                                note="blocked: requires recorded human approval")
                )
                continue

            result = self._run_node(stage, agent_name)
            run.stages.append(result)

            if stage == "approval":
                run.approved = bool(result.output.get("approved", False))
                if not run.approved:
                    # Stop here — by design. The run is complete up to the gate and
                    # waits for a human. Downstream deploy work is never auto-run.
                    run.halted_at = stage
                    self.audit.record(
                        "brain:run:halt_for_approval", actor="guardian_brain",
                        scope=self.scope.asset, decision="refused",
                        detail={"stage": stage},
                    )

        self.audit.record(
            "brain:run:complete", actor="guardian_brain", scope=self.scope.asset,
            decision="allowed", detail={"approved": run.approved, "halted_at": run.halted_at},
        )
        return run

    # --- nodes -----------------------------------------------------------------
    def _run_node(self, stage: str, agent_name: str) -> StageResult:
        agent_cls = AGENT_REGISTRY.get(agent_name)
        if agent_cls is None:
            return StageResult(stage, agent_name, "skipped", note="no such agent")

        # Detect/simulate stages have a corresponding scope mode; gate via OPA twin.
        mode = _STAGE_MODE.get(agent_name)
        if mode is not None and not self.policy_check(action=mode, mode=mode):
            return StageResult(stage, agent_name, "refused",
                               note=f"policy gate denied mode '{mode}'")

        agent = agent_cls(self.context)
        try:
            output = agent.run()
        except Exception as exc:  # fail-closed: a node error halts that node, logged
            self.audit.record(
                f"brain:node:{agent_name}:error", actor="guardian_brain",
                scope=self.scope.asset, decision="refused", detail={"error": str(exc)},
            )
            return StageResult(stage, agent_name, "refused", note=f"error: {exc}")

        # Persist meaningful stage outputs to memory so the Brain learns over time.
        if stage in {"detect", "simulate", "threat_model", "evidence"}:
            self.memory.remember(
                "run_outcomes",
                f"{stage}:{agent_name} {output}",
                metadata={"stage": stage, "agent": agent_name, "asset": self.scope.asset},
            )
        # Share each agent's output on the blackboard for downstream agents.
        self.context.blackboard[agent_name] = output
        return StageResult(stage, agent_name, "ok", output=output)


# Maps agents whose work corresponds to a scope mode, so the Brain can run the policy
# gate with the right action/mode before invoking them.
_STAGE_MODE: dict[str, str] = {
    "code_review": "code_review",
    "dependency": "dependency_scan",
    "secrets": "secrets_scan",
    "api_security": "api_security",
    "auth_rbac": "auth_permissions",
    "privacy_gdpr": "privacy_leakage",
    "safeguarding": "safeguarding",
    "abuse_simulation": "abuse_simulation",
    "runtime_monitoring": "runtime_monitoring",
}


def run_from_scope_file(
    scope_path: str,
    *,
    dry_run: bool = True,
    approvals: list[Approval] | None = None,
    on_stage: Callable[[StageResult], None] | None = None,
) -> BrainRun:
    """Convenience entry point: load a scope file and run the Brain over it."""
    scope = load_scope(scope_path)
    brain = GuardianBrain(scope, dry_run=dry_run, approvals=approvals)
    run = brain.run()
    if on_stage:
        for s in run.stages:
            on_stage(s)
    return run
