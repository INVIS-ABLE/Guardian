"""Base class for Guardian ECC agents.

ECC is the orchestration / workflow command centre. Each Guardian agent is a bounded,
auditable unit of reasoning+action. Agents never bypass the guardrails — they call into
``core`` like everything else. This base provides the lifecycle, audit hook, and the
guardrail handle; concrete agents implement :meth:`act`.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from core.audit import AuditLog
from core.guardrails import Guardrails
from core.scope import Scope


@dataclass
class AgentContext:
    """Shared context threaded through an ECC workflow run."""

    scope: Scope
    guardrails: Guardrails
    dry_run: bool = True
    blackboard: dict[str, Any] = field(default_factory=dict)  # inter-agent shared state


class GuardianAgent(abc.ABC):
    """Base for all 17 Guardian agents."""

    #: machine name, e.g. "guardian_planner"
    name: str = "guardian_agent"
    #: one-line description used in docs/registry
    summary: str = ""

    def __init__(self, context: AgentContext) -> None:
        self.context = context
        self.audit = AuditLog()

    @property
    def guardrails(self) -> Guardrails:
        return self.context.guardrails

    @property
    def scope(self) -> Scope:
        return self.context.scope

    def run(self) -> dict[str, Any]:
        self.audit.record(
            f"agent:{self.name}:start", actor=self.name, scope=self.scope.asset,
            decision="allowed", detail={"dry_run": self.context.dry_run},
        )
        result = self.act()
        self.audit.record(
            f"agent:{self.name}:complete", actor=self.name, scope=self.scope.asset,
            decision="allowed", detail={"keys": sorted(result.keys())},
        )
        return result

    @abc.abstractmethod
    def act(self) -> dict[str, Any]:
        """Do the agent's work and return a result dict written to the blackboard."""
