"""Reasoning-graph nodes — pure functions that return typed state deltas (§1, §3, §4).

Each node takes the current :class:`GuardianCaseState` and returns a
:class:`CaseStateDelta`. Nodes never mutate shared state and never decide authority;
they only contribute evidence, hypotheses, findings and status transitions. The graph
(``core.brain.graph``) wires them together with conditional edges and runs them under
hard budget/iteration limits.

The collectors/analysers here are deliberately thin but *grounded*: ``collect`` emits
typed evidence with provenance, ``analyse`` forms a hypothesis that cites that
evidence, ``challenge`` plays sceptic, and ``adjudicate`` will only raise a finding for
a grounded hypothesis — otherwise it abstains ("insufficient evidence"). Real scanners
and model-backed specialists slot in behind these same typed contracts later in the
build order.
"""

from __future__ import annotations

from ..evidence.models import (
    AssetRef,
    Classification,
    EvidenceItem,
    Finding,
    Hypothesis,
    PolicyDecisionRecord,
    Provenance,
    TrustLevel,
    ValidationState,
)
from .state import CaseStateDelta, CaseStatus, GuardianCaseState


def intake(case: GuardianCaseState) -> CaseStateDelta:
    """Open the case and move to planning."""
    return CaseStateDelta(status=CaseStatus.PLANNING)


def scope_verify(case: GuardianCaseState) -> CaseStateDelta:
    """Deterministic scope/identity/ownership gate. Fail closed (§12).

    A model never reaches this decision: it is derived from the verified scope. If
    ownership is unverified the case HALTS and no downstream collection/analysis runs.
    """
    if not case.scope.ownership_verified:
        return CaseStateDelta(
            status=CaseStatus.HALTED,
            policy_decisions=(
                PolicyDecisionRecord(
                    action="proceed_case",
                    mode="scope_verify",
                    allow=False,
                    denies=("ownership_unverified",),
                ),
            ),
        )
    return CaseStateDelta(
        status=CaseStatus.COLLECTING,
        policy_decisions=(
            PolicyDecisionRecord(action="proceed_case", mode="scope_verify", allow=True),
        ),
    )


def plan(case: GuardianCaseState) -> CaseStateDelta:
    """Produce an evidence-acquisition plan (status only for now)."""
    return CaseStateDelta(status=CaseStatus.COLLECTING)


def collect(case: GuardianCaseState) -> CaseStateDelta:
    """Collect evidence. Emits typed evidence with provenance (TOOL_OUTPUT trust)."""
    item = EvidenceItem(
        kind="sarif_result",
        summary=f"static-analysis finding on asset {case.scope.asset}",
        classification=Classification.INTERNAL,
        trust_level=TrustLevel.TOOL_OUTPUT,
        validation_state=ValidationState.VALIDATED,
        provenance=Provenance(tool="semgrep", tool_version="0.0.0", asset=case.scope.asset),
        assets=(AssetRef(kind="asset", identifier=case.scope.asset),),
    )
    return CaseStateDelta(status=CaseStatus.ANALYSING, evidence=(item,))


def analyse(case: GuardianCaseState) -> CaseStateDelta:
    """Form a hypothesis that cites collected evidence. Abstains if there is none."""
    if not case.evidence:
        return CaseStateDelta(status=CaseStatus.CHALLENGING)
    evidence_ids = tuple(e.id for e in case.evidence)
    hypothesis = Hypothesis(
        statement=f"asset {case.scope.asset} has an exploitable static-analysis finding",
        supporting_evidence_ids=evidence_ids,
        affected_assets=(AssetRef(kind="asset", identifier=case.scope.asset),),
        confidence=0.5,
        status="unverified",
    )
    return CaseStateDelta(status=CaseStatus.CHALLENGING, hypotheses=(hypothesis,))


def challenge(case: GuardianCaseState) -> CaseStateDelta:
    """Sceptic: promote a hypothesis to 'supported' only if it is grounded.

    A hypothesis with no supporting evidence, or with unresolved contradictions, is
    marked 'inconclusive' rather than supported (no majority-vote, evidence-led §7).
    """
    promoted: list[Hypothesis] = []
    for h in case.hypotheses:
        if h.has_supporting_evidence and not h.contradicting_evidence_ids:
            promoted.append(h.model_copy(update={"status": "supported", "confidence": 0.7}))
        else:
            promoted.append(h.model_copy(update={"status": "inconclusive"}))
    # Note: nodes append; the adjudicator reads the latest 'supported'/'inconclusive'
    # status by hypothesis id when more than one revision exists.
    return CaseStateDelta(status=CaseStatus.CHALLENGING, hypotheses=tuple(promoted))


def adjudicate(case: GuardianCaseState) -> CaseStateDelta:
    """Raise a finding for a grounded, supported hypothesis — else abstain.

    Abstention is a first-class outcome: if no hypothesis is grounded the case
    completes with no finding and the Brain can explicitly report insufficient
    evidence, rather than inventing a conclusion (§4, acceptance gate).
    """
    grounded = _latest_grounded(case)
    if grounded is None:
        return CaseStateDelta(status=CaseStatus.COMPLETED)
    finding = Finding(
        title=f"Confirmed finding on {case.scope.asset}",
        severity="high",
        description=grounded.statement,
        asset=AssetRef(kind="asset", identifier=case.scope.asset),
        evidence_ids=grounded.supporting_evidence_ids,
        hypothesis_id=grounded.id,
        provenance=Provenance(tool="guardian_adjudicator", asset=case.scope.asset),
    )
    return CaseStateDelta(status=CaseStatus.AWAITING_APPROVAL, findings=(finding,))


# --- post-approval execution nodes --------------------------------------------
def controlled_execution(case: GuardianCaseState) -> CaseStateDelta:
    """Run the approved action under control (placeholder)."""
    return CaseStateDelta(status=CaseStatus.EXECUTING)


def observe(case: GuardianCaseState) -> CaseStateDelta:
    """Observe the post-action state."""
    return CaseStateDelta(status=CaseStatus.OBSERVING)


def learn(case: GuardianCaseState) -> CaseStateDelta:
    """Curated learning — only ever reached post-approval. Completes the case."""
    return CaseStateDelta(status=CaseStatus.COMPLETED)


# --- helpers -------------------------------------------------------------------
def _latest_grounded(case: GuardianCaseState) -> Hypothesis | None:
    """Most recent revision per hypothesis id that is grounded and supported/confirmed."""
    latest: dict = {}
    for h in case.hypotheses:
        latest[h.id] = h  # later revisions overwrite earlier ones
    for h in latest.values():
        if h.status in ("supported", "confirmed") and h.is_grounded:
            return h
    return None


__all__ = [
    "intake",
    "scope_verify",
    "plan",
    "collect",
    "analyse",
    "challenge",
    "adjudicate",
    "controlled_execution",
    "observe",
    "learn",
]
