"""Tests for the autonomous threat-hunting engine (Sovereign #11)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from core.identity_graph import load_graph as load_identity
from core.lineage import load_graph as load_lineage
from core.reasoning import run_hunts
from core.reasoning.hunting import hunt_external_reaches_regulated
from core.twin import AssetKind, AssetNode, DigitalTwin, Relationship, RelationKind

ROOT = Path(__file__).resolve().parent.parent
IDENTITY = ROOT / "identity_graph" / "invisable-identity-sample.yaml"
LINEAGE = ROOT / "lineage" / "invisable-lineage-sample.yaml"


def _twin_to_health() -> DigitalTwin:
    t = DigitalTwin()
    t.add_asset(AssetNode(id="ext", kind=AssetKind.IDENTITY, name="ext", subtype="machine"))
    t.add_asset(AssetNode(id="svc", kind=AssetKind.SERVICE, name="svc"))
    t.add_asset(AssetNode(id="phr", kind=AssetKind.DATA_CLASS, name="records", classification="health"))
    t.add_relationship(Relationship(src="ext", dst="svc", kind=RelationKind.CAN_ACCESS))
    t.add_relationship(Relationship(src="svc", dst="phr", kind=RelationKind.READS))
    return t


def test_external_reaches_regulated_data():
    r = hunt_external_reaches_regulated(_twin_to_health())
    assert r is not None and r.hits == ("ext",) and r.severity == "high"
    assert "detection" in r.model_dump() and r.detection


def test_no_regulated_sink_means_no_hunt():
    t = DigitalTwin()
    t.add_asset(AssetNode(id="a", kind=AssetKind.SERVICE, name="a"))
    assert hunt_external_reaches_regulated(t) is None


def test_budget_truncates_hits():
    t = DigitalTwin()
    t.add_asset(AssetNode(id="phr", kind=AssetKind.DATA_CLASS, name="d", classification="health"))
    for i in range(5):
        t.add_asset(AssetNode(id=f"ext{i}", kind=AssetKind.IDENTITY, name=f"e{i}", subtype="machine"))
        t.add_relationship(Relationship(src=f"ext{i}", dst="phr", kind=RelationKind.CAN_ACCESS))
    r = hunt_external_reaches_regulated(t, budget=2)
    assert r is not None and len(r.hits) == 2 and r.truncated is True


def test_identity_hunts_find_escalation_and_dormancy():
    identity = load_identity(IDENTITY)
    results = run_hunts(identity=identity, as_of=date(2026, 6, 22))
    by_id = {r.hunt_id: r for r in results}
    # The sample has an escalation seam (human-dev → release-admin) and a dormant legacy bot.
    assert "privilege_escalation_path" in by_id
    assert "id:human-dev" in by_id["privilege_escalation_path"].hits
    assert "dormant_sensitive_identity" in by_id


def test_lineage_hunts_find_boundary_and_retention():
    lineage = load_lineage(LINEAGE)
    by_id = {r.hunt_id: r for r in run_hunts(lineage=lineage)}
    assert "data_outside_boundary" in by_id        # health/PII in the analytics zone
    assert "retention_violation" in by_id


def test_run_hunts_skips_absent_graphs():
    # No graphs supplied ⇒ no hunts, no error.
    assert run_hunts() == ()


def test_run_hunts_over_all_graphs():
    results = run_hunts(twin=_twin_to_health(), identity=load_identity(IDENTITY),
                        lineage=load_lineage(LINEAGE), as_of=date(2026, 6, 22))
    assert len(results) >= 4  # at least one hit from each domain
