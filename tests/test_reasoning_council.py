"""Tests for the multi-model reasoning council (Sovereign #9)."""

from __future__ import annotations

from core.evidence.models import (
    Classification,
    EvidenceItem,
    Hypothesis,
    Provenance,
    TestProposal as TProposal,
    TrustLevel,
    ValidationState,
)
from core.reasoning import Case, convene


def _ev(*, verified: bool = True, classification: Classification = Classification.INTERNAL) -> EvidenceItem:
    return EvidenceItem(
        kind="log_line", summary="e", provenance=Provenance(tool="t"),
        classification=classification,
        trust_level=TrustLevel.VERIFIED_EVIDENCE if verified else TrustLevel.UNTRUSTED_EVIDENCE,
        validation_state=ValidationState.VALIDATED if verified else ValidationState.UNVALIDATED,
    )


def _falsifiable(stmt, ev_id):
    return Hypothesis(
        statement=stmt, supporting_evidence_ids=(ev_id,),
        falsification_tests=(TProposal(description="t", expected_if_true="x", expected_if_false="y"),),
    )


def test_insufficient_evidence_escalates_to_human():
    case = Case(hypotheses=(Hypothesis(statement="guess", confidence=0.9),))
    v = convene(case)
    assert v.decision == "insufficient_evidence" and v.requires_human


def test_single_hypothesis_still_requires_human_even_if_grounded():
    e1, e2 = _ev(), _ev()
    h = Hypothesis(statement="X", supporting_evidence_ids=(e1.id, e2.id),
                   falsification_tests=(TProposal(description="t", expected_if_true="a",
                                                     expected_if_false="b"),))
    v = convene(Case(evidence=(e1, e2), hypotheses=(h,)))
    # Grounded, but only one hypothesis ⇒ no real contest ⇒ human required.
    assert v.case_verdict.leading() is not None
    assert v.alternatives_considered == 1 and v.requires_human


def test_two_grounded_rivals_escalate_as_disagreement():
    e1, e2 = _ev(), _ev()
    h1 = _falsifiable("cause A", e1.id)
    h2 = _falsifiable("cause B", e2.id)
    v = convene(Case(evidence=(e1, e2), hypotheses=(h1, h2)))
    assert v.case_verdict.unresolved_disagreement
    assert v.decision == "escalate" and v.requires_human


def test_privacy_forbidden_evidence_blocks_and_escalates():
    secret = _ev(classification=Classification.MESSAGE_PLAINTEXT)
    good = _ev()
    h = _falsifiable("X", good.id)
    v = convene(Case(evidence=(secret, good), hypotheses=(h,)))
    assert v.privacy_violations == (str(secret.id),)
    assert v.decision == "escalate" and v.requires_human


def test_sceptic_flags_missing_falsification_test():
    e1, e2 = _ev(), _ev()
    # Two grounded hypotheses but the leader proposes no falsification test.
    h_lead = Hypothesis(statement="A", supporting_evidence_ids=(e1.id, e2.id))  # 2 verified ⇒ confirmed
    h_alt = _falsifiable("B", e1.id)
    v = convene(Case(evidence=(e1, e2), hypotheses=(h_lead, h_alt)))
    assert any("falsification" in c for c in v.sceptic_challenges)


def test_attack_path_is_attached_when_incident_supplied():
    from core.twin import AssetKind, AssetNode, DigitalTwin, Relationship, RelationKind

    t = DigitalTwin()
    t.add_asset(AssetNode(id="attacker", kind=AssetKind.IDENTITY, name="a", subtype="machine"))
    t.add_asset(AssetNode(id="svc", kind=AssetKind.SERVICE, name="s"))
    t.add_asset(AssetNode(id="data", kind=AssetKind.DATA_CLASS, name="d", classification="health"))
    t.add_relationship(Relationship(src="attacker", dst="svc", kind=RelationKind.CAN_ACCESS))
    t.add_relationship(Relationship(src="svc", dst="data", kind=RelationKind.READS))
    e = _ev()
    case = Case(evidence=(e,), hypotheses=(_falsifiable("X", e.id),),
                twin=t, observed=("attacker",), sink="data")
    v = convene(case)
    assert v.attack_path is not None and v.attack_path.sink == "data"
