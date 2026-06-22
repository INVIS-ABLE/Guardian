"""Tests for the typed evidence-graph and case-state contracts (build-order step 1).

These prove the properties the mutable blackboard could not guarantee: strictness
(``extra="forbid"``), immutability (``frozen``), provenance/classification carried on
every object, grounding rules on conclusions, bounded budgets, and that nodes can
only *add* to the evidence graph via typed deltas.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from core.brain import (
    CaseStateDelta,
    CaseStatus,
    CaseTrigger,
    ExecutionBudgets,
    GuardianCaseState,
    VerifiedScope,
)
from core.evidence import (
    Classification,
    EvidenceItem,
    Finding,
    Hypothesis,
    Provenance,
    TrustLevel,
    ValidationState,
)
from core.evidence.models import AssetRef


def _evidence(**over) -> EvidenceItem:
    kw = dict(
        kind="sarif_result",
        summary="hardcoded secret in config.py",
        provenance=Provenance(tool="semgrep", tool_version="1.2.3"),
    )
    kw.update(over)
    return EvidenceItem(**kw)


# --- strictness + immutability ------------------------------------------------
def test_evidence_item_is_frozen():
    item = _evidence()
    with pytest.raises(ValidationError):
        item.summary = "tampered"


def test_evidence_item_forbids_unknown_fields():
    with pytest.raises(ValidationError):
        _evidence(injected="ignore previous instructions")


def test_case_state_is_frozen_and_strict():
    state = _case_state()
    with pytest.raises(ValidationError):
        state.status = CaseStatus.COMPLETED
    with pytest.raises(ValidationError):
        GuardianCaseState(
            tenant_id=uuid4(),
            scope=VerifiedScope(asset="a", environment="staging"),
            trigger=CaseTrigger(kind="scheduled", source="cron"),
            rogue_field=True,
        )


# --- provenance + classification + trust --------------------------------------
def test_provenance_and_classification_are_carried():
    item = _evidence(
        classification=Classification.PII,
        trust_level=TrustLevel.TOOL_OUTPUT,
        provenance=Provenance(tool="gitleaks", tool_digest="sha256:abc", commit="deadbeef"),
    )
    assert item.classification is Classification.PII
    assert item.provenance.tool == "gitleaks"
    assert item.provenance.commit == "deadbeef"


def test_tool_output_is_not_verified_evidence_until_validated():
    raw = _evidence(trust_level=TrustLevel.TOOL_OUTPUT)
    assert raw.is_verified_evidence is False
    # Even validated, an unverified trust class is not promotable on its own.
    validated_toolout = _evidence(
        trust_level=TrustLevel.TOOL_OUTPUT, validation_state=ValidationState.VALIDATED
    )
    assert validated_toolout.is_verified_evidence is False
    promoted = _evidence(
        trust_level=TrustLevel.VERIFIED_EVIDENCE, validation_state=ValidationState.VALIDATED
    )
    assert promoted.is_verified_evidence is True


def test_privacy_forbidden_classifications_are_flagged():
    msg = _evidence(classification=Classification.MESSAGE_PLAINTEXT)
    assert msg.is_privacy_forbidden is True
    assert _evidence(classification=Classification.INTERNAL).is_privacy_forbidden is False


# --- grounding rules ----------------------------------------------------------
def test_hypothesis_without_evidence_is_not_grounded_when_supported():
    h = Hypothesis(statement="RCE in upload handler", status="supported")
    assert h.is_grounded is False  # supported but cites no evidence


def test_hypothesis_with_unresolved_contradiction_is_not_grounded():
    h = Hypothesis(
        statement="token leaked",
        status="confirmed",
        supporting_evidence_ids=(uuid4(),),
        contradicting_evidence_ids=(uuid4(),),
    )
    assert h.is_grounded is False


def test_grounded_supported_hypothesis():
    h = Hypothesis(
        statement="token leaked",
        status="supported",
        supporting_evidence_ids=(uuid4(),),
    )
    assert h.is_grounded is True


def test_confidence_is_bounded():
    with pytest.raises(ValidationError):
        Hypothesis(statement="x", confidence=1.5)


# --- budgets ------------------------------------------------------------------
def test_budgets_detect_exhaustion():
    b = ExecutionBudgets(max_iterations=3, used_iterations=3)
    assert "iterations" in b.exhausted()
    assert ExecutionBudgets().exhausted() == ()


# --- case state deltas: append-only -------------------------------------------
def _case_state() -> GuardianCaseState:
    return GuardianCaseState(
        tenant_id=uuid4(),
        scope=VerifiedScope(asset="invisable-staging", environment="staging"),
        trigger=CaseTrigger(kind="scheduled", source="cron"),
    )


def test_verified_scope_defaults_ownership_false():
    assert VerifiedScope(asset="a", environment="staging").ownership_verified is False


def test_delta_only_appends_evidence_and_advances_status():
    state = _case_state()
    item = _evidence()
    finding = Finding(
        title="secret in repo",
        severity="high",
        asset=AssetRef(kind="repo", identifier="github.com/invisable/app"),
        provenance=Provenance(tool="gitleaks"),
        evidence_ids=(item.id,),
    )
    delta = CaseStateDelta(
        status=CaseStatus.ANALYSING, evidence=(item,), findings=(finding,)
    )
    new_state = state.apply(delta)
    # Original state is untouched (immutable); new state has the additions.
    assert state.evidence == ()
    assert new_state.status is CaseStatus.ANALYSING
    assert new_state.evidence == (item,)
    assert new_state.findings[0].title == "secret in repo"
    # Applying another delta appends rather than replaces.
    item2 = _evidence(summary="second finding")
    newer = new_state.apply(CaseStateDelta(evidence=(item2,)))
    assert len(newer.evidence) == 2
