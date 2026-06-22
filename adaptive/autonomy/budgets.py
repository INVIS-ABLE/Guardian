"""The AutonomyBudget — authority shrinks as uncertainty grows (directive §34).

Given the control state (the structural ceiling) and the environment health, compute the
set of autonomy classes Guardian may exercise *without per-action human approval*, plus
two qualifiers the healing layer needs:

* ``model_driven_healing_allowed`` — may a Class-D repair be driven by a model decision,
  or only by deterministic rules? (Missing model monitoring / degraded model health forces
  deterministic-only.)
* ``requires_independent_verification`` — must Shadow Guardian / extra checks corroborate?

The rules are intentionally a short, ordered, readable list rather than a learned score,
because this is a safety function and must be auditable. Every removal records a reason.

Worked examples from the directive:
* Full health permits A–D within policy.
* Missing model monitoring disables *model-driven* Class D (deterministic D still allowed).
* Stale digital twin disables target-changing actions (Class D).
* Missing Shadow Guardian disables high-risk actions (Class D).
* Missing evidence disables all execution (C and D).
* Missing OPA disables all sensitive actions (D).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .degradation import EnvironmentHealth, IncidentSeverity, SignalState
from .states import AutonomyClass, ControlState, permitted_classes

# Below this telemetry completeness, Guardian is too blind to heal at all.
HEAL_MIN_COMPLETENESS = 0.5
# Below this, healing may continue but only deterministically (no model-driven repair).
MODEL_HEAL_MIN_COMPLETENESS = 0.8
# Below this recent repair success, autonomous healing is frozen (anti-oscillation, §35).
HEAL_MIN_REPAIR_SUCCESS = 0.5


class AutonomyBudget(BaseModel):
    """What Guardian may do autonomously right now, and why."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    control_state: ControlState
    permitted: frozenset[AutonomyClass]
    model_driven_healing_allowed: bool
    requires_independent_verification: bool
    telemetry_completeness: float = Field(ge=0.0, le=1.0)
    reasons: tuple[str, ...] = ()

    def allows(self, cls: AutonomyClass) -> bool:
        return cls in self.permitted

    @property
    def may_heal(self) -> bool:
        return AutonomyClass.HEAL in self.permitted


def compute_autonomy_budget(
    control_state: ControlState, health: EnvironmentHealth
) -> AutonomyBudget:
    """Deterministically derive the autonomy budget. Pure; fail-closed by construction."""
    permitted: set[AutonomyClass] = set(permitted_classes(control_state))
    # E is never autonomous; defensively ensure it can never appear in a budget.
    permitted.discard(AutonomyClass.PRODUCTION)

    model_driven = True
    needs_verification = False
    reasons: list[str] = []

    def drop(cls: AutonomyClass, why: str) -> None:
        if cls in permitted:
            permitted.discard(cls)
            reasons.append(f"removed {cls.name} (Class {cls.value}): {why}")

    # --- hard authority losses (most severe first) --------------------------------
    # Missing evidence authority → no execution at all (no engineering, no healing).
    if health.evidence_authority is SignalState.MISSING:
        drop(AutonomyClass.HEAL, "evidence authority missing — execution stops (§34)")
        drop(AutonomyClass.ENGINEER, "evidence authority missing — execution stops (§34)")
    elif health.evidence_authority is SignalState.DEGRADED:
        needs_verification = True
        reasons.append("evidence authority degraded — independent verification required")

    # Missing OPA → no sensitive (Class D) actions.
    if health.policy_authority is SignalState.MISSING:
        drop(AutonomyClass.HEAL, "policy authority (OPA) missing — sensitive actions disabled (§34)")
    elif health.policy_authority is SignalState.DEGRADED:
        needs_verification = True
        reasons.append("policy authority degraded — independent verification required")

    # Identity / attestation unhealthy → no healing (can't trust the actor/target).
    if health.not_healthy("identity_health"):
        drop(AutonomyClass.HEAL, "identity health not healthy — cannot bind exact target (§34)")
    if health.not_healthy("machine_attestation"):
        drop(AutonomyClass.HEAL, "machine attestation not healthy — workers untrusted (§34)")

    # Stale/missing digital twin → no target-changing (Class D) actions.
    if health.not_healthy("digital_twin"):
        drop(AutonomyClass.HEAL, "digital twin not fresh — target-changing actions disabled (§34)")

    # Missing Shadow Guardian → no high-risk (Class D) actions.
    if health.shadow_guardian is SignalState.MISSING:
        drop(AutonomyClass.HEAL, "Shadow Guardian missing — high-risk actions disabled (§34)")
    elif health.shadow_guardian is SignalState.DEGRADED:
        needs_verification = True
        reasons.append("Shadow Guardian degraded — independent verification required")

    # --- model trust → constrains *how* healing may be driven, not whether ----------
    if health.model_monitoring is not SignalState.HEALTHY:
        model_driven = False
        reasons.append("model monitoring not healthy — model-driven Class D disabled (§34)")
    if health.model_health is not SignalState.HEALTHY:
        model_driven = False
        needs_verification = True
        reasons.append("model health degraded — reduce model authority, raise verification (§17)")

    # --- telemetry completeness → confidence ---------------------------------------
    if health.telemetry_completeness < HEAL_MIN_COMPLETENESS:
        drop(
            AutonomyClass.HEAL,
            f"telemetry completeness {health.telemetry_completeness:.2f} < "
            f"{HEAL_MIN_COMPLETENESS} — too blind to heal (§13)",
        )
    elif health.telemetry_completeness < MODEL_HEAL_MIN_COMPLETENESS:
        if model_driven:
            model_driven = False
            reasons.append(
                f"telemetry completeness {health.telemetry_completeness:.2f} < "
                f"{MODEL_HEAL_MIN_COMPLETENESS} — deterministic healing only (§13)"
            )

    # --- recent repair success → anti-oscillation freeze (§35) ----------------------
    if health.recent_repair_success_rate < HEAL_MIN_REPAIR_SUCCESS:
        drop(
            AutonomyClass.HEAL,
            f"recent repair success {health.recent_repair_success_rate:.2f} < "
            f"{HEAL_MIN_REPAIR_SUCCESS} — automation frozen for safety (§35)",
        )

    # --- incident severity → escalate verification ----------------------------------
    if health.incident_severity in (IncidentSeverity.HIGH, IncidentSeverity.CRITICAL):
        needs_verification = True
        reasons.append(
            f"incident severity {health.incident_severity.value} — independent verification required"
        )

    return AutonomyBudget(
        control_state=control_state,
        permitted=frozenset(permitted),
        model_driven_healing_allowed=model_driven and AutonomyClass.HEAL in permitted,
        requires_independent_verification=needs_verification,
        telemetry_completeness=health.telemetry_completeness,
        reasons=tuple(reasons),
    )


__all__ = [
    "AutonomyBudget",
    "compute_autonomy_budget",
    "HEAL_MIN_COMPLETENESS",
    "MODEL_HEAL_MIN_COMPLETENESS",
    "HEAL_MIN_REPAIR_SUCCESS",
]
