"""Tests for the digital-twin chaos & recovery simulator (Sovereign plane, Wave 3, system #17)."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.chaos import (
    ChaosError,
    ChaosResult,
    ChaosSimulator,
    FailureMode,
    FailureScenario,
    ProductionTargetRefused,
    SurpriseKind,
    build_from_spec,
    from_chaos_platform,
    load_run,
)

GAMEDAY = Path(__file__).resolve().parent.parent / "chaos" / "invisable-gameday.yaml"


def _scenario(sid="s", predicted=()) -> FailureScenario:
    return FailureScenario(id=sid, mode=FailureMode.REGION_OUTAGE, target="svc:x",
                           predicted_impact=tuple(predicted))


# --- clone-only rule -----------------------------------------------------------
def test_production_target_refused():
    with pytest.raises(ProductionTargetRefused):
        ChaosSimulator(clone_of="twin:invisable-production")
    with pytest.raises(ChaosError):
        ChaosSimulator(clone_of="")


def test_clone_reference_accepted():
    for ref in ("twin:clone-x", "shadow-twin", "replica:2026", "ephemeral-twin"):
        assert ChaosSimulator(clone_of=ref).clone_of == ref


# --- surprise detection (predicted vs actual) ----------------------------------
def test_unpredicted_impact_is_a_map_gap():
    sim = ChaosSimulator(clone_of="twin:clone")
    result = ChaosResult(scenario=_scenario(predicted=["a"]), actual_impact=("a", "b"), recovered=True)
    surprises = {(s.asset, s.kind) for s in result.surprises}
    assert ("b", SurpriseKind.UNPREDICTED_IMPACT) in surprises
    report = sim.report("run", [result])
    assert report.has_gap
    assert [s.asset for s in report.unpredicted] == ["b"]


def test_overpredicted_impact_is_resilience_not_a_gap():
    sim = ChaosSimulator(clone_of="twin:clone")
    result = ChaosResult(scenario=_scenario(predicted=["a", "b"]), actual_impact=("a",), recovered=True)
    kinds = {s.kind for s in result.surprises}
    assert kinds == {SurpriseKind.OVERPREDICTED_IMPACT}
    # Overprediction alone is not a gap (no RTO breach here either).
    assert not sim.report("run", [result]).has_gap


def test_accurate_model_has_no_surprises():
    result = ChaosResult(scenario=_scenario(predicted=["a", "b"]), actual_impact=("a", "b"), recovered=True)
    assert result.model_accurate
    assert result.surprises == ()


# --- RTO breach ----------------------------------------------------------------
def test_rto_breach_is_a_gap():
    sim = ChaosSimulator(clone_of="twin:clone")
    result = ChaosResult(scenario=_scenario(predicted=["a"]), actual_impact=("a",),
                         recovered=True, rto_seconds=600, rto_objective_seconds=300)
    assert result.rto_breached
    assert sim.report("run", [result]).has_gap


def test_duplicate_scenario_refused():
    sim = ChaosSimulator(clone_of="twin:clone")
    with pytest.raises(ChaosError):
        sim.report("run", [
            ChaosResult(scenario=_scenario("dup"), actual_impact=(), recovered=True),
            ChaosResult(scenario=_scenario("dup"), actual_impact=(), recovered=True),
        ])


# --- sample --------------------------------------------------------------------
def test_sample_surfaces_map_gap_and_rto_breach():
    report = load_run(GAMEDAY)
    # s1 has an unpredicted db:mailbox impact (map gap); s3 breaches RTO.
    assert "db:mailbox" in [s.asset for s in report.unpredicted]
    assert any(r.scenario.id == "s3" for r in report.rto_breaches)
    assert report.has_gap
    assert 0.0 <= report.model_accuracy() <= 1.0


def test_build_from_spec_roundtrip():
    report = build_from_spec({
        "run": "r", "clone_of": "twin:clone",
        "results": [{"scenario": {"id": "s", "mode": "idp_outage", "target": "svc:x",
                                  "predicted_impact": ["svc:x"]},
                     "actual_impact": ["svc:x"], "recovered": True}],
    })
    assert report.model_accuracy() == 1.0


def test_from_chaos_platform_fails_closed():
    with pytest.raises(NotImplementedError):
        from_chaos_platform()


def test_load_run_missing_file():
    with pytest.raises(FileNotFoundError):
        load_run(Path("/no/such/r.yaml"))
