"""Tests for the twin-driven chaos & recovery engine (Sovereign plane, Wave 3, system #17).

These assert the prediction and the actual impact are COMPUTED from the real digital twin — not
read from a spec — which is the whole point of the rework.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.chaos.simulator import ProductionTargetRefused
from core.twin import (
    TwinChaosScenario,
    load_gameday,
    load_twin,
    run_gameday,
    simulate_failure,
    working_protections,
)
from core.twin.graph import TwinError

TWIN = Path(__file__).resolve().parent.parent / "twin" / "invisable-sample.yaml"
GAMEDAY = Path(__file__).resolve().parent.parent / "chaos" / "invisable-twin-gameday.yaml"


@pytest.fixture()
def twin():
    return load_twin(TWIN)


# --- the prediction is computed from the twin, not given -----------------------
def test_predicted_impact_equals_blast_radius(twin):
    result = simulate_failure(twin, "svc:messaging-relay")
    expected = set(twin.blast_radius("svc:messaging-relay").asset_ids())
    assert set(result.predicted_impact) == expected
    # No control protects these, so actual == predicted (nothing contained).
    assert set(result.actual_impact) == expected
    assert result.contained_by_controls == ()


# --- a working control is a real firebreak -------------------------------------
def test_working_control_contains_the_blast(twin):
    # Sigstore PROTECTS img:messaging; a repo compromise can't be admitted → fully contained.
    result = simulate_failure(twin, "repo:guardian")
    assert result.fully_contained
    assert result.actual_impact == ()
    assert "ctrl:sigstore" in result.controls_engaged
    # Everything the model predicted was saved by the control.
    assert set(result.contained_by_controls) == set(result.predicted_impact)


def test_degraded_control_restores_the_full_blast(twin):
    intact = simulate_failure(twin, "repo:guardian")
    degraded = simulate_failure(twin, "repo:guardian", degraded_controls=("ctrl:sigstore",))
    # With the control down, the firebreak is gone and the full predicted blast actually lands.
    assert set(degraded.actual_impact) == set(degraded.predicted_impact)
    assert degraded.actual_impact and not intact.actual_impact
    assert degraded.controls_engaged == ()


def test_working_protections_map(twin):
    assert working_protections(twin, frozenset()) == {"img:messaging": "ctrl:sigstore"}
    # A degraded control no longer protects anything.
    assert working_protections(twin, frozenset({"ctrl:sigstore"})) == {}


def test_unknown_target_raises(twin):
    with pytest.raises(TwinError):
        simulate_failure(twin, "svc:does-not-exist")


# --- game-day: clone-only + RTO + aggregates -----------------------------------
def test_gameday_refuses_production_twin(twin):
    with pytest.raises(ProductionTargetRefused):
        run_gameday(twin, "run", "twin:invisable-production", [])


def test_gameday_duplicate_scenario_refused(twin):
    sc = TwinChaosScenario(id="dup", mode="region_outage", target="repo:guardian")
    with pytest.raises(TwinError):
        run_gameday(twin, "run", "twin:clone", [sc, sc])


def test_sample_gameday(twin):
    report = load_gameday(TWIN, GAMEDAY)
    by_id = {r.scenario.id: r for r in report.results}
    # s1: repo compromise, sigstore working → fully contained, control engaged.
    assert by_id["s1-repo-compromise"].fully_contained
    assert "ctrl:sigstore" in by_id["s1-repo-compromise"].controls_engaged
    # s2: same compromise, sigstore down → uncontained full blast.
    assert by_id["s2-repo-compromise-control-down"].actual_impact
    # s3: service outage, no control, RTO 540 > 300 → breach.
    assert by_id["s3-service-outage"].rto_breached
    assert report.has_finding                      # the RTO breach is the gate signal
    assert report.controls_that_worked() == {"ctrl:sigstore": 1}


def test_rto_breach_logic(twin):
    ok = simulate_failure(twin, "svc:messaging-relay").model_copy(update={
        "scenario": TwinChaosScenario(id="x", mode="region_outage", target="svc:messaging-relay",
                                      rto_seconds=100, rto_objective_seconds=200)})
    assert not ok.rto_breached
    bad = ok.model_copy(update={
        "scenario": TwinChaosScenario(id="y", mode="region_outage", target="svc:messaging-relay",
                                      rto_seconds=300, rto_objective_seconds=200)})
    assert bad.rto_breached


def test_load_gameday_missing_file(twin):
    with pytest.raises(FileNotFoundError):
        load_gameday(TWIN, Path("/no/such/gameday.yaml"))
