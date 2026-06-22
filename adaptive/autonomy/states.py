"""Autonomic control-state machine and the five autonomy classes (directive §2–3).

Guardian must be *autonomic, not uncontrolled*. Two ideas live here:

1. **Five autonomy classes** (A–E). They describe *what kind* of freedom Guardian has,
   from reading telemetry (A) up to approval-bound production operation (E). Class E is
   never granted autonomously — it always returns to the existing identity/ownership/
   policy/approval/attestation/evidence gates. So the autonomous budget code only ever
   reasons about A–D; E is included in the enum for completeness and routing.

2. **Seven control states** with a deterministic, authority-aware transition machine.
   The Brain may *recommend* a transition but may not *force* a higher-authority state:
   escalating into states that activate controls (DEFENSIVE / CONTAINMENT / RECOVERY) or
   that restore operational power requires an external authority grant. De-escalating to a
   safer state (DEGRADED / FROZEN) is always allowed — Guardian can always make itself
   safer on its own.

This module is pure and deterministic. It grants no authority; it only classifies and
constrains. Real authority verification (capability signatures, human approval) is the
Capability Authority's and OPA's job downstream.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


# --- the five autonomy classes (directive §2) ----------------------------------
class AutonomyClass(str, Enum):
    """What kind of autonomous freedom an action needs.

    A → D may be granted autonomously *within policy and budget*. E is always
    approval-bound and is therefore never returned by the autonomy budget.
    """

    OBSERVE = "A"  # read telemetry, update the twin, build timelines, generate cases
    INVESTIGATE = "B"  # query logs/traces, run passive scanners, form hypotheses
    ENGINEER = "C"  # generate tests/rules/patches, open draft PRs (nothing to production)
    HEAL = "D"  # pre-approved, reversible, exact-target-bound healing actions
    PRODUCTION = "E"  # approval-bound production operation — never autonomous


# --- the seven control states (directive §3) -----------------------------------
class ControlState(str, Enum):
    NORMAL = "normal"
    WATCH = "watch"
    DEGRADED = "degraded"
    DEFENSIVE = "defensive"
    CONTAINMENT = "containment"
    RECOVERY = "recovery"
    FROZEN = "frozen"


# Max autonomy classes structurally permitted in each control state. The autonomy budget
# (see budgets.py) only ever *narrows* this set further based on environment health.
# Class E is never here — it is always approval-bound.
_STATE_CLASSES: dict[ControlState, frozenset[AutonomyClass]] = {
    # All approved observational + investigative functions, plus engineering and
    # pre-approved reversible healing within policy.
    ControlState.NORMAL: frozenset(
        {AutonomyClass.OBSERVE, AutonomyClass.INVESTIGATE, AutonomyClass.ENGINEER, AutonomyClass.HEAL}
    ),
    # Gather more evidence; "no increase in operational power is permitted" — so no new
    # healing is *initiated* by being in WATCH (healing stays available only via NORMAL/
    # DEFENSIVE paths, not as an escalation side effect).
    ControlState.WATCH: frozenset(
        {AutonomyClass.OBSERVE, AutonomyClass.INVESTIGATE, AutonomyClass.ENGINEER}
    ),
    # A dependency is unavailable: reduce autonomy to deterministic read/analysis.
    ControlState.DEGRADED: frozenset({AutonomyClass.OBSERVE, AutonomyClass.INVESTIGATE}),
    # Credible threat / serious control failure: pre-approved reversible controls may act.
    ControlState.DEFENSIVE: frozenset(
        {AutonomyClass.OBSERVE, AutonomyClass.INVESTIGATE, AutonomyClass.ENGINEER, AutonomyClass.HEAL}
    ),
    # Confirmed dangerous state: only explicit containment runbooks (a constrained HEAL).
    ControlState.CONTAINMENT: frozenset(
        {AutonomyClass.OBSERVE, AutonomyClass.INVESTIGATE, AutonomyClass.HEAL}
    ),
    # Signed recovery plans, validated stage by stage (a constrained HEAL).
    ControlState.RECOVERY: frozenset(
        {AutonomyClass.OBSERVE, AutonomyClass.INVESTIGATE, AutonomyClass.HEAL}
    ),
    # Capability issuance stops; only observation, evidence preservation and notification.
    ControlState.FROZEN: frozenset({AutonomyClass.OBSERVE}),
}


def permitted_classes(state: ControlState) -> frozenset[AutonomyClass]:
    """Autonomy classes structurally available in a control state (before health budget)."""
    return _STATE_CLASSES[state]


# Authority rank: higher = more authority required to *enter*. The Brain may move to a
# state of equal or lower rank on its own; entering a higher-rank state needs an external
# authority grant. FROZEN/DEGRADED are the safest (lowest rank) so Guardian can always
# self-protect; CONTAINMENT/RECOVERY are highest because they wield strong controls.
_AUTHORITY_RANK: dict[ControlState, int] = {
    ControlState.FROZEN: 0,
    ControlState.DEGRADED: 1,
    ControlState.WATCH: 1,
    ControlState.NORMAL: 2,
    ControlState.DEFENSIVE: 3,
    ControlState.RECOVERY: 4,
    ControlState.CONTAINMENT: 5,
}

# Deterministic transition graph. From any state Guardian may always make itself safer
# (→ FROZEN, → DEGRADED). The escalation ladder is single-step; de-escalation/stand-down
# is allowed back down the ladder and from DEGRADED back toward NORMAL.
_LADDER_NEXT: dict[ControlState, ControlState] = {
    ControlState.NORMAL: ControlState.WATCH,
    ControlState.WATCH: ControlState.DEFENSIVE,
    ControlState.DEFENSIVE: ControlState.CONTAINMENT,
    ControlState.CONTAINMENT: ControlState.RECOVERY,
}


def _allowed_targets(current: ControlState) -> frozenset[ControlState]:
    targets: set[ControlState] = {ControlState.FROZEN, ControlState.DEGRADED}
    # single-step escalation up the ladder
    nxt = _LADDER_NEXT.get(current)
    if nxt is not None:
        targets.add(nxt)
    # de-escalation / stand-down
    if current in (ControlState.WATCH, ControlState.DEGRADED):
        targets.update({ControlState.NORMAL})
    if current is ControlState.DEFENSIVE:
        targets.update({ControlState.WATCH, ControlState.NORMAL})
    if current is ControlState.CONTAINMENT:
        targets.update({ControlState.DEFENSIVE})
    if current is ControlState.RECOVERY:
        targets.update({ControlState.NORMAL})
    if current is ControlState.FROZEN:
        targets.update({ControlState.RECOVERY, ControlState.NORMAL})
    targets.discard(current)
    return frozenset(targets)


# --- authority + proposals -----------------------------------------------------
class AuthorityGrant(BaseModel):
    """An external authority's say-so for a state escalation.

    This is *not* the cryptographic capability — it is the typed assertion that a real
    authority (OPA policy decision, a human approver, or the Capability Authority)
    authorised the escalation. The signature/verification itself stays with those
    components; here we only require that such a grant is present and names a real role.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    granted_by: str
    role: str  # one of _AUTHORITY_ROLES


_AUTHORITY_ROLES: frozenset[str] = frozenset(
    {"opa", "human_approver", "capability_authority"}
)


class TransitionProposal(BaseModel):
    """The Brain's recommendation to change control state — never self-applied if it
    escalates authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    current: ControlState
    target: ControlState
    valid: bool
    requires_external_authority: bool
    reason: str
    evidence_ref: str | None = None


class StateTransitionError(RuntimeError):
    """Raised on an invalid transition or an unauthorised escalation. Fail closed."""


def propose_transition(
    current: ControlState,
    target: ControlState,
    *,
    reason: str,
    evidence_ref: str | None = None,
) -> TransitionProposal:
    """Classify a proposed transition. Pure; performs no transition."""
    valid = target in _allowed_targets(current)
    escalates = _AUTHORITY_RANK[target] > _AUTHORITY_RANK[current]
    return TransitionProposal(
        current=current,
        target=target,
        valid=valid,
        requires_external_authority=escalates,
        reason=reason,
        evidence_ref=evidence_ref,
    )


def apply_transition(
    current: ControlState,
    target: ControlState,
    *,
    reason: str,
    authority: AuthorityGrant | None = None,
    evidence_ref: str | None = None,
) -> ControlState:
    """Apply a transition, failing closed.

    * An invalid transition raises.
    * An escalation to a higher-authority state without a valid :class:`AuthorityGrant`
      raises — the Brain may *recommend* it but may not *force* it.
    * De-escalation to a safer state needs no authority: Guardian may always self-protect.
    """
    proposal = propose_transition(current, target, reason=reason, evidence_ref=evidence_ref)
    if not proposal.valid:
        raise StateTransitionError(
            f"invalid control-state transition {current.value} -> {target.value}"
        )
    if proposal.requires_external_authority:
        if authority is None:
            raise StateTransitionError(
                f"escalation {current.value} -> {target.value} requires external authority; "
                "the Brain may recommend but not force a higher-authority state"
            )
        if authority.role not in _AUTHORITY_ROLES:
            raise StateTransitionError(
                f"authority role '{authority.role}' is not a recognised escalation authority"
            )
    return target


__all__ = [
    "AutonomyClass",
    "ControlState",
    "permitted_classes",
    "AuthorityGrant",
    "TransitionProposal",
    "StateTransitionError",
    "propose_transition",
    "apply_transition",
]
