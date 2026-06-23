"""Level 6 §20: learning from outcomes — proposals enter review, never auto-apply."""

from __future__ import annotations

from uuid import uuid4

import pytest

from adaptive.learning import (
    LearningProposal,
    OutcomeRecord,
    ProposalKind,
    ProposalStatus,
    propose_from_outcome,
)


def _outcome(**kw) -> OutcomeRecord:
    base = dict(case_id=uuid4(), initial_trigger="alert:relay-error-spike",
                initial_confidence=0.7)
    base.update(kw)
    return OutcomeRecord(**base)


def test_proposal_must_start_proposed():
    with pytest.raises(ValueError):
        LearningProposal(case_id=uuid4(), kind=ProposalKind.NEW_DETECTION,
                         summary="x", status=ProposalStatus.APPROVED)


def test_false_positive_proposes_threshold_tuning():
    props = propose_from_outcome(_outcome(false_positive=True, final_conclusion="benign"))
    kinds = {p.kind for p in props}
    assert ProposalKind.UPDATED_THRESHOLD in kinds
    assert all(p.status is ProposalStatus.PROPOSED for p in props)


def test_missing_evidence_proposes_new_detection():
    props = propose_from_outcome(_outcome(missing_evidence=("egress_logs",)))
    assert any(p.kind is ProposalKind.NEW_DETECTION for p in props)


def test_rollback_proposes_eval_case():
    props = propose_from_outcome(_outcome(rollback_required=True))
    assert any(p.kind is ProposalKind.NEW_EVALUATION_CASE for p in props)


def test_confirmed_lessons_proposed_as_documentation():
    props = propose_from_outcome(_outcome(actual_result="contained",
                                          lessons=("rotate sooner",)))
    assert any(p.kind is ProposalKind.NEW_DOCUMENTATION for p in props)


def test_all_proposals_are_review_bound():
    props = propose_from_outcome(_outcome(false_positive=True, rollback_required=True,
                                          missing_evidence=("x",)))
    assert props  # produced something
    assert all(p.status is ProposalStatus.PROPOSED for p in props)
