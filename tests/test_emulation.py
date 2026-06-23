"""Tests for the continuous adversary-emulation lab (Sovereign plane, Wave 3, system #13)."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.emulation import (
    AdversaryLab,
    EmulationError,
    LabOnlyViolation,
    RegressionReason,
    Tactic,
    Technique,
    TechniqueResult,
    Verdict,
    build_from_spec,
    from_caldera,
    load_operation,
)

OPERATION = Path(__file__).resolve().parent.parent / "emulation" / "invisable-attack-plan.yaml"


def _tech(tid="T1", tactic=Tactic.EXECUTION) -> Technique:
    return Technique(id=tid, name=f"name-{tid}", tactic=tactic)


# --- verdict logic -------------------------------------------------------------
def test_verdict_blocked_detected_bypass():
    blocked = TechniqueResult(technique=_tech(), prevented=True)
    detected = TechniqueResult(technique=_tech(), prevented=False, detected_by="falco")
    bypass = TechniqueResult(technique=_tech(), prevented=False, detected_by=None)
    assert blocked.verdict is Verdict.BLOCKED
    assert detected.verdict is Verdict.DETECTED
    assert bypass.verdict is Verdict.BYPASS and bypass.is_bypass


def test_evidence_gap_flag():
    assert TechniqueResult(technique=_tech(), prevented=True, evidence_preserved=False).evidence_gap
    assert not TechniqueResult(technique=_tech(), prevented=True).evidence_gap


# --- the cardinal rule: lab only -----------------------------------------------
def test_lab_only_refuses_production():
    with pytest.raises(LabOnlyViolation):
        AdversaryLab(environment="production")
    with pytest.raises(LabOnlyViolation):
        build_from_spec({"operation": "x", "environment": "prod", "results": []})


def test_lab_environments_accepted():
    for env in ("range", "lab", "test", "cyber_range"):
        assert AdversaryLab(environment=env).environment == env


# --- regression generation: every bypass / evidence gap → a test ----------------
def test_bypass_mints_regression():
    lab = AdversaryLab(environment="range")
    report = lab.report("op", [
        TechniqueResult(technique=_tech("T1098", Tactic.PERSISTENCE), prevented=False, detected_by=None),
    ])
    assert report.has_bypass
    assert len(report.regression_tests) == 1
    assert report.regression_tests[0].reason is RegressionReason.BYPASS
    assert "must be prevented or detected" in report.regression_tests[0].requirement


def test_evidence_gap_also_mints_regression():
    lab = AdversaryLab(environment="range")
    # Bypass AND no evidence → two regressions for one technique.
    report = lab.report("op", [
        TechniqueResult(technique=_tech("T1562.001", Tactic.DEFENSE_EVASION),
                        prevented=False, detected_by=None, evidence_preserved=False),
    ])
    reasons = {t.reason for t in report.regression_tests}
    assert reasons == {RegressionReason.BYPASS, RegressionReason.EVIDENCE_GAP}


def test_blocked_and_detected_mint_no_regression():
    lab = AdversaryLab(environment="range")
    report = lab.report("op", [
        TechniqueResult(technique=_tech("a"), prevented=True),
        TechniqueResult(technique=_tech("b"), prevented=False, detected_by="falco"),
    ])
    assert report.regression_tests == ()
    assert not report.has_bypass


def test_duplicate_technique_is_refused():
    lab = AdversaryLab(environment="range")
    with pytest.raises(EmulationError):
        lab.report("op", [
            TechniqueResult(technique=_tech("dup"), prevented=True),
            TechniqueResult(technique=_tech("dup"), prevented=True),
        ])


def test_empty_operation_name_refused():
    with pytest.raises(EmulationError):
        AdversaryLab(environment="range").report("  ", [])


# --- the sample operation ------------------------------------------------------
@pytest.fixture()
def report():
    return load_operation(OPERATION)


def test_sample_counts_and_gate(report):
    assert report.blocked == 2
    assert report.detected == 2
    assert len(report.bypasses) == 2          # T1098, T1562.001
    assert report.has_bypass is True
    # Three regressions: T1098 (bypass) + T1562.001 (bypass + evidence gap).
    assert len(report.regression_tests) == 3
    assert {t.technique_id for t in report.regression_tests} == {"T1098", "T1562.001"}


def test_sample_coverage_spans_tactics(report):
    coverage = report.coverage()
    assert coverage["execution"] == 1
    assert coverage["exfiltration"] == 1
    assert sum(coverage.values()) == 6


# --- ingestion seam ------------------------------------------------------------
def test_from_caldera_fails_closed():
    with pytest.raises(NotImplementedError):
        from_caldera()


def test_load_operation_missing_file():
    with pytest.raises(FileNotFoundError):
        load_operation(Path("/no/such/op.yaml"))
