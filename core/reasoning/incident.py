"""Runtime-triggered investigation — wire the nervous system to the brain.

This is the capstone that connects the layers Guardian already has into one flow: a live signal
on the **event fabric** (#5) flags at-risk assets on the **digital twin** (#1, runtime fold), the
**causal engine** (#8) explains how the compromise would reach the crown jewels, the signals are
turned into typed **evidence**, competing hypotheses are adjudicated by the **council** (#9), and
the result is an incident verdict that — because a raw runtime signal is unverified tool output —
**escalates to a human** with the whole picture rather than acting on its own.

It realises the Sovereign diagram directly: *event fabric → reasoning council → (escalate)*.
Read-only and metadata-only end to end; it explains and escalates, it never executes.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from core.evidence.models import (
    Classification,
    EvidenceItem,
    Hypothesis,
    Provenance,
    TestProposal,
    TrustLevel,
    ValidationState,
)
from core.event_fabric import EventFabric, EventSeverity, Outcome
from core.twin import DigitalTwin, RuntimeSignal, apply_runtime, live_risk
from core.twin.assessment import Severity, _sink_severity

from .council import Case, CouncilDecision, convene

# Outcomes where a CONTROL held (argues containment, contradicts active compromise).
_CONTAINING = frozenset({Outcome.DENY, Outcome.BLOCKED})
# Outcomes where malicious behaviour was OBSERVED to occur (argues active compromise).
_OCCURRED = frozenset({Outcome.DETECTED, Outcome.SUCCESS})


class IncidentVerdict(BaseModel):
    """The end-to-end outcome: what is at risk, how, and the council's human-facing decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    triggered: bool                       # did any notable live signal fire?
    at_risk: tuple[str, ...]              # crown-jewel + reachable assets implicated now
    target_sink: str | None              # the most sensitive asset reached
    decision: CouncilDecision
    requires_human: bool
    summary: str


def _signal_evidence(sig: RuntimeSignal) -> EvidenceItem:
    """A runtime signal as a typed, metadata-only evidence item — unverified tool output."""
    return EvidenceItem(
        kind=f"event:{sig.action}",
        summary=f"{sig.action} on {sig.asset_id}"
        + (f" ({sig.outcome.value})" if sig.outcome else ""),
        classification=Classification.INTERNAL,        # never private content
        trust_level=TrustLevel.TOOL_OUTPUT,            # a sensor alert is not proof on its own
        validation_state=ValidationState.UNVALIDATED,
        provenance=Provenance(tool="event_fabric", interpreted_by="incident_pipeline"),
    )


def _most_sensitive_reached(live: DigitalTwin, origins: list[str]) -> tuple[str | None, Severity]:
    best: str | None = None
    best_sev = Severity.NONE
    for origin in origins:
        for item in live.blast_radius(origin).impacted:
            sev, _ = _sink_severity(item.asset)
            if sev > best_sev:
                best, best_sev = item.asset.id, sev
    return best, best_sev


def investigate(
    twin: DigitalTwin,
    fabric: EventFabric,
    *,
    since: datetime | None = None,
    min_severity: EventSeverity = EventSeverity.HIGH,
) -> IncidentVerdict:
    """Turn live event-fabric signals into an adjudicated, human-ready incident verdict."""
    risk = live_risk(twin, fabric, since=since, min_severity=min_severity)
    if not risk.signals:
        return IncidentVerdict(
            triggered=False, at_risk=(), target_sink=None,
            decision="insufficient_evidence", requires_human=False,
            summary="no notable runtime signals",
        )

    live = apply_runtime(twin, fabric, since=since)
    origins = sorted({s.asset_id for s in risk.signals if s.asset_id in live})
    sink, _sev = _most_sensitive_reached(live, origins)

    # Competing hypotheses, grounded in the signals:
    #   H1 active compromise  — supported by OBSERVED-malicious signals, contradicted by controls;
    #   H2 contained/blocked  — the mirror image.
    evidence = [_signal_evidence(s) for s in risk.signals]
    by_sig = list(zip(risk.signals, evidence))
    occurred = [e.id for s, e in by_sig if s.outcome in _OCCURRED]
    contained = [e.id for s, e in by_sig if s.outcome in _CONTAINING]

    h_compromise = Hypothesis(
        statement=f"Active compromise reaching {sink or 'an asset'}",
        supporting_evidence_ids=tuple(occurred),
        contradicting_evidence_ids=tuple(contained),
        falsification_tests=(TestProposal(
            description="Correlate with an independent sensor + verify the artifact digest",
            expected_if_true="second source confirms the same target/time",
            expected_if_false="no corroborating signal; controls held",
        ),),
    )
    h_contained = Hypothesis(
        statement="Activity was blocked/denied — controls held, no active compromise",
        supporting_evidence_ids=tuple(contained),
        contradicting_evidence_ids=tuple(occurred),
    )

    verdict = convene(Case(
        evidence=tuple(evidence),
        hypotheses=(h_compromise, h_contained),
        twin=live,
        observed=tuple(origins),
        sink=sink,
    ))

    parts = [f"{len(risk.signals)} notable signal(s); {len(risk.at_risk)} asset(s) at risk"]
    if sink:
        parts.append(f"reaching {sink}")
    parts.append(f"council: {verdict.decision.upper().replace('_', ' ')}")
    if verdict.attack_path and verdict.attack_path.root_cause:
        parts.append(f"root cause: {verdict.attack_path.root_cause}")

    return IncidentVerdict(
        triggered=True,
        at_risk=risk.at_risk,
        target_sink=sink,
        decision=verdict.decision,
        requires_human=verdict.requires_human,
        summary="; ".join(parts),
    )
