"""Typed specialist-agent framework (target architecture §6).

The legacy agents in ``agents/__init__.py`` are thin stubs that return labels. A real
specialist needs a *bounded contract*: a typed task, an approved evidence view, an
approved tool-capability list, a model-routing class, an output schema, confidence and
abstention rules, a max-iteration bound, a deterministic verifier, and — critically —
**no ability to approve or execute its own recommendations**.

This module defines that contract. The four priority specialists (scope, code
analysis, evidence adjudication, patch verification) subclass :class:`Specialist`.
Each reasons through the model gateway (``core.ai``) and acts only through the tool
gateway (``core.tools``); neither can grant an approval or run an action directly.
"""

from __future__ import annotations

import abc
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from core.ai import ModelGateway, WorkClass
from core.brain.state import CaseStateDelta, VerifiedScope
from core.evidence.models import EvidenceItem, Hypothesis, ProposedAction
from core.tools import ToolExecutor

Verdict = Literal["pass", "fail", "abstain"]


class SpecialistTask(BaseModel):
    """The typed input contract for a specialist. The evidence/hypotheses/actions are
    the *approved view* the specialist is allowed to see — never the whole world."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: UUID
    tenant_id: UUID
    scope: VerifiedScope
    evidence: tuple[EvidenceItem, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    proposed_actions: tuple[ProposedAction, ...] = ()
    producer_model_family: str | None = None  # who produced an artefact under review
    params: dict[str, str] = Field(default_factory=dict)


class SpecialistResult(BaseModel):
    """The typed output contract. Contributions are returned as a typed state delta;
    the specialist never mutates global state or approves/executes anything."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    specialist: str
    verdict: Verdict
    abstained: bool = False
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    delta: CaseStateDelta = Field(default_factory=CaseStateDelta)
    high_risk: bool = False  # set when model output tripped the output firewall
    notes: tuple[str, ...] = ()


class Specialist(abc.ABC):
    """Base for a bounded specialist. Reasons via the model gateway; acts via the tool
    gateway. Cannot approve or execute — those are deterministic, human-gated steps."""

    #: machine name
    name: str = "specialist"
    #: model-routing class for this specialist's reasoning; ``None`` ⇒ deterministic only
    work_class: WorkClass | None = None
    #: tool capabilities this specialist may request (allow-list)
    allowed_capabilities: tuple[str, ...] = ()
    #: prompt-template version recorded in every model call
    prompt_version: str = "v1"
    #: hard iteration bound
    max_iterations: int = 1

    # A specialist can NEVER do these — encoded as class invariants and asserted in tests.
    can_approve: bool = False
    can_execute: bool = False

    def __init__(self, *, gateway: ModelGateway | None = None,
                 tools: ToolExecutor | None = None) -> None:
        self._gateway = gateway
        self._tools = tools

    def may_use(self, capability: str) -> bool:
        """Whether this specialist is permitted to request a tool capability."""
        return capability in self.allowed_capabilities

    @abc.abstractmethod
    def run(self, task: SpecialistTask) -> SpecialistResult:
        """Do the specialist's bounded work and return a typed result."""

    # --- shared helpers --------------------------------------------------------
    def _abstain(self, reason: str) -> SpecialistResult:
        return SpecialistResult(
            specialist=self.name, verdict="abstain", abstained=True,
            confidence=0.0, notes=(reason,),
        )


__all__ = ["Verdict", "SpecialistTask", "SpecialistResult", "Specialist"]
