"""Environment-health signals that feed the autonomy budget (directive §34).

Autonomy must *decrease as uncertainty increases*. This module defines the typed health
picture the budget reasons over: each authority/sensor is HEALTHY, DEGRADED or MISSING,
plus the scalar inputs (telemetry completeness, recent repair success, incident severity).

There is no scoring magic here — just an honest, strict snapshot. The rules that turn this
snapshot into a permitted-autonomy set live in budgets.py so they stay auditable.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class SignalState(str, Enum):
    """Health of a single authority or sensor."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    MISSING = "missing"


class IncidentSeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EnvironmentHealth(BaseModel):
    """The inputs to the AutonomyBudget (directive §34).

    A field that is anything other than HEALTHY removes or constrains autonomy; it never
    adds any. ``telemetry_completeness`` and ``recent_repair_success_rate`` are in [0, 1];
    a silent sensor (low completeness) is treated as *uncertainty*, not health.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # scalar confidence inputs
    telemetry_completeness: float = Field(ge=0.0, le=1.0, default=1.0)
    recent_repair_success_rate: float = Field(ge=0.0, le=1.0, default=1.0)
    incident_severity: IncidentSeverity = IncidentSeverity.NONE

    # authority / sensor health
    digital_twin: SignalState = SignalState.HEALTHY
    model_health: SignalState = SignalState.HEALTHY
    model_monitoring: SignalState = SignalState.HEALTHY
    policy_authority: SignalState = SignalState.HEALTHY  # OPA
    evidence_authority: SignalState = SignalState.HEALTHY  # immudb / evidence writes
    identity_health: SignalState = SignalState.HEALTHY
    machine_attestation: SignalState = SignalState.HEALTHY
    shadow_guardian: SignalState = SignalState.HEALTHY

    def is_missing(self, *fields: str) -> bool:
        return any(getattr(self, f) is SignalState.MISSING for f in fields)

    def not_healthy(self, *fields: str) -> bool:
        return any(getattr(self, f) is not SignalState.HEALTHY for f in fields)


__all__ = ["SignalState", "IncidentSeverity", "EnvironmentHealth"]
