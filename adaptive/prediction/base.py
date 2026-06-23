"""Shared types for the advisory predictors (directive §29).

Predictors are *advisory*: they may recommend a preventive change, but automatic preventive
action stays limited to approved resource/scaling envelopes elsewhere. So a ``Prediction``
carries a risk level and a recommendation string, never an action and never authority.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Prediction(BaseModel):
    """An advisory forecast. Recommends; never acts (§29)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject: str
    kind: str
    risk: RiskLevel
    horizon_seconds: float | None = Field(default=None, ge=0.0)
    detail: str = ""
    recommendation: str = ""


__all__ = ["RiskLevel", "Prediction"]
