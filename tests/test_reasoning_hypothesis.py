"""Tests for the evidence & competing-hypothesis engine (Sovereign #7)."""

from __future__ import annotations

from core.evidence.models import (
    EvidenceItem,
    Hypothesis,
    Provenance,
    TrustLevel,
    ValidationState,
)
from core.reasoning import Calibrator, adjudicate, adjudicate_hypothesis


def _ev(*, verified: bool) -> EvidenceItem:
    return EvidenceItem(
        kind="log_line",
        summary="evidence",
        provenance=Provenance(tool="test"),
        trust_level=TrustLevel.VERIFIED_EVIDENCE if verified else TrustLevel.UNTRUSTED_EVIDENCE,
        validation_state=ValidationState.VALIDATED if verified else ValidationState.UNVALIDATED,
    )


def test_no_evidence_is_unverified_and_insufficient():
    h = Hypothesis(statement="X happened", status="confirmed", confidence=0.99)
    v = adjudicate_hypothesis(h, {})
    assert v.status == "unverified"
    assert v.insufficient_evidence and v.confidence == 0.0


def test_unverified_support_cannot_ground_a_positive_claim():
    e = _ev(verified=False)
    h = Hypothesis(statement="X", supporting_evidence_ids=(e.id,))
    v = adjudicate_hypothesis(h, {e.id: e})
    assert v.status == "inconclusive"
    assert v.insufficient_evidence


def test_verified_support_is_supported_then_confirmed():
    e1, e2 = _ev(verified=True), _ev(verified=True)
    one = Hypothesis(statement="X", supporting_evidence_ids=(e1.id,))
    v1 = adjudicate_hypothesis(one, {e1.id: e1})
    assert v1.status == "supported" and not v1.insufficient_evidence
    two = Hypothesis(statement="X", supporting_evidence_ids=(e1.id, e2.id))
    v2 = adjudicate_hypothesis(two, {e1.id: e1, e2.id: e2})
    assert v2.status == "confirmed" and v2.confidence > v1.confidence


def test_unresolved_contradiction_blocks_supported():
    s, c = _ev(verified=True), _ev(verified=True)
    h = Hypothesis(statement="X", supporting_evidence_ids=(s.id,), contradicting_evidence_ids=(c.id,))
    v = adjudicate_hypothesis(h, {s.id: s, c.id: c})
    # Equal verified support + contradiction ⇒ contradicted (never silently 'supported').
    assert v.status == "contradicted"


def test_calibration_forces_abstention_on_overconfidence():
    e1, e2 = _ev(verified=True), _ev(verified=True)
    h = Hypothesis(statement="X", supporting_evidence_ids=(e1.id, e2.id))
    cal = Calibrator()
    for i in range(20):
        cal.record(1.0, correct=(i % 10 == 0))  # 10% actual at top confidence
    v = adjudicate_hypothesis(h, {e1.id: e1, e2.id: e2}, calibrator=cal)
    assert v.status == "inconclusive" and v.insufficient_evidence


def test_adjudicate_picks_evidence_grounded_leader_not_vote():
    grounded_ev = _ev(verified=True)
    leader = Hypothesis(statement="real cause", supporting_evidence_ids=(grounded_ev.id,))
    # Three rivals that merely *claim* high confidence but cite nothing verified.
    noise = [Hypothesis(statement=f"guess {i}", confidence=0.99) for i in range(3)]
    case = adjudicate([leader, *noise], [grounded_ev])
    assert case.leading_hypothesis_id == leader.id
    assert not case.abstained
    assert not case.unresolved_disagreement


def test_adjudicate_flags_unresolved_disagreement():
    e1, e2 = _ev(verified=True), _ev(verified=True)
    h1 = Hypothesis(statement="cause A", supporting_evidence_ids=(e1.id,))
    h2 = Hypothesis(statement="cause B", supporting_evidence_ids=(e2.id,))
    case = adjudicate([h1, h2], [e1, e2])
    assert case.unresolved_disagreement is True  # two evidence-supported rivals


def test_adjudicate_abstains_when_nothing_grounded():
    case = adjudicate([Hypothesis(statement="guess", confidence=0.95)], [])
    assert case.abstained and case.leading_hypothesis_id is None
