"""Structured model decision schema (Final Power-Up §10).

Every model response is untrusted input and must pass a typed schema before it can reach
the router. ``GuardianDecision`` is that schema: the reasoning fabric proposes a
*capability* and validated *arguments* — never a raw command string — together with the
risk/safety assessment the policy layer needs. Invalid output cannot validate, so it
cannot select a tool.
"""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = 1

RiskLevel = Literal["informational", "low", "medium", "high", "critical"]
SafetyImpact = Literal["none", "low", "moderate", "high", "immediate"]


class GuardianDecision(BaseModel):
    """A typed, untrusted-by-default model decision (master map §10).

    The model selects a Guardian ``selected_capability`` and supplies ``arguments``;
    reviewed connectors — not the model — turn those into executable commands.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    decision_id: UUID = Field(default_factory=uuid4)
    objective: str = Field(min_length=1, max_length=4000)
    observations_used: tuple[str, ...] = ()
    hypotheses: tuple[str, ...] = ()
    selected_capability: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    expected_evidence: tuple[str, ...] = ()
    risk_level: RiskLevel = "low"
    safety_impact: SafetyImpact = "none"
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    requires_approval: bool = True
    stop_reason: str | None = None
    # Provenance: which model + prompt produced this decision (recorded in every event).
    model_id: str = ""
    prompt_version: str = ""

    def is_terminal(self) -> bool:
        """A decision with no capability and a stop reason ends the reasoning loop."""
        return self.selected_capability is None and self.stop_reason is not None


__all__ = ["GuardianDecision", "RiskLevel", "SafetyImpact", "SCHEMA_VERSION"]
