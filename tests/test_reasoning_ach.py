"""Tests for the ACH overlay + case ingestion (Sovereign plane, Wave 2, system #7).

These cover the *complementary* view added on top of the merged adjudicator
(``core.reasoning.hypothesis``): the consistency matrix, diagnosticity, least-contradicted
ranking, and the case spec loader. Weighting is the adjudicator's — these tests assert the
overlay reuses it rather than re-deriving it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.evidence.models import (
    EvidenceItem,
    Hypothesis,
    Provenance,
    TrustLevel,
    ValidationState,
)
from core.reasoning import (
    Consistency,
    ach_matrix,
    adjudicate,
    analyze,
    build_case_from_spec,
    diagnostic_split,
    from_case_store,
    load_case,
)

CASE = Path(__file__).resolve().parent.parent / "cases" / "invisable-ci-token-case.yaml"


def _ev(summary: str, *, verified: bool = True) -> EvidenceItem:
    return EvidenceItem(
        kind="test", summary=summary, provenance=Provenance(tool="t"),
        trust_level=TrustLevel.VERIFIED_EVIDENCE if verified else TrustLevel.RETRIEVED_MEMORY,
        validation_state=ValidationState.VALIDATED if verified else ValidationState.UNVALIDATED,
    )


# --- the matrix ----------------------------------------------------------------
def test_matrix_marks_consistency():
    e1, e2, e3 = _ev("e1"), _ev("e2"), _ev("e3")
    h = Hypothesis(statement="h", supporting_evidence_ids=(e1.id,),
                   contradicting_evidence_ids=(e2.id,))
    rows = ach_matrix([h], [e1, e2, e3])
    cells = {c.evidence_id: c.consistency for c in rows[0].cells}
    assert cells[e1.id] is Consistency.CONSISTENT
    assert cells[e2.id] is Consistency.INCONSISTENT
    assert cells[e3.id] is Consistency.NEUTRAL


# --- least-contradicted ranking (reusing the adjudicator's weight) -------------
def test_least_contradicted_leads_over_more_supported():
    e1, e2 = _ev("e1"), _ev("e2")
    clean = Hypothesis(statement="clean", supporting_evidence_ids=(e1.id,))
    dirty = Hypothesis(statement="dirty", supporting_evidence_ids=(e1.id, e2.id),
                       contradicting_evidence_ids=(e2.id,))
    view = analyze([dirty, clean], [e1, e2])
    # ACH ranks the least-contradicted first, even though 'dirty' cites more support.
    assert view.leading_id == clean.id
    assert view.ranked[0].contradiction_weight == 0.0
    assert view.ranked[1].contradiction_weight > 0.0


def test_unverified_contradiction_weighs_less_than_verified():
    strong, weak = _ev("verified", verified=True), _ev("memory", verified=False)
    h_strong = Hypothesis(statement="contradicted by verified", contradicting_evidence_ids=(strong.id,))
    h_weak = Hypothesis(statement="contradicted by memory", contradicting_evidence_ids=(weak.id,))
    view = analyze([h_strong, h_weak], [strong, weak])
    # The hypothesis contradicted only by low-trust memory is less contradicted → leads.
    assert view.leading_id == h_weak.id
    assert view.ranked[0].contradiction_weight < view.ranked[1].contradiction_weight


# --- diagnosticity -------------------------------------------------------------
def test_evidence_consistent_with_all_is_non_diagnostic():
    shared, splitter = _ev("shared"), _ev("splitter")
    h1 = Hypothesis(statement="h1", supporting_evidence_ids=(shared.id,),
                    contradicting_evidence_ids=(splitter.id,))
    h2 = Hypothesis(statement="h2", supporting_evidence_ids=(shared.id, splitter.id))
    diagnostic, non_diagnostic = diagnostic_split([h1, h2], [shared, splitter])
    diag_ids = {d.evidence_id for d in diagnostic}
    assert splitter.id in diag_ids     # contradicts h1 but not h2 → discriminates
    assert shared.id in non_diagnostic  # consistent with both → decides nothing


# --- the sample case -----------------------------------------------------------
@pytest.fixture()
def sample():
    return load_case(CASE)


def test_sample_external_attacker_leads_decisively(sample):
    view = analyze(sample.hypotheses, sample.evidence)
    leading = next(h for h in sample.hypotheses if h.id == view.leading_id)
    assert "External attacker" in leading.statement
    assert view.ranked[0].contradiction_weight == 0.0
    assert view.decisive is True
    assert view.next_tests  # the leader carries a falsification test to run next


def test_sample_denied_deploys_are_non_diagnostic(sample):
    view = analyze(sample.hypotheses, sample.evidence)
    summaries = {d.summary for d in view.diagnostic_evidence}
    # The three denied deploys are consistent with every hypothesis → decide nothing.
    assert not any("production_deploy" in s for s in summaries)


def test_sample_adjudicator_and_ach_agree_on_leader(sample):
    # The complementary views should agree here: the grounded leader is also least-contradicted.
    adjudicated = adjudicate(sample.hypotheses, sample.evidence)
    view = analyze(sample.hypotheses, sample.evidence)
    assert adjudicated.leading_hypothesis_id == view.leading_id


# --- case ingestion ------------------------------------------------------------
def test_build_case_from_spec_maps_keys():
    case = build_case_from_spec({
        "evidence": [{"key": "A", "kind": "k", "summary": "a", "provenance": {"tool": "t"}}],
        "hypotheses": [{"statement": "h", "consistent": ["A"]}],
    })
    assert len(case.hypotheses) == 1
    assert len(case.hypotheses[0].supporting_evidence_ids) == 1


def test_build_case_rejects_unknown_key():
    with pytest.raises(ValueError):
        build_case_from_spec({"evidence": [], "hypotheses": [{"statement": "h", "consistent": ["Z"]}]})


def test_from_case_store_fails_closed():
    with pytest.raises(NotImplementedError):
        from_case_store()


def test_load_case_missing_file():
    with pytest.raises(FileNotFoundError):
        load_case(Path("/no/such/case.yaml"))
