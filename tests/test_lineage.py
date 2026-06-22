"""Tests for the data lineage & privacy graph (Sovereign plane, Wave 1, system #3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.evidence.models import Classification
from core.lineage import (
    Boundary,
    Field,
    Flow,
    LineageError,
    LineageGraph,
    build_from_spec,
    from_datahub,
    load_graph,
    peak,
)

SAMPLE = Path(__file__).resolve().parent.parent / "lineage" / "invisable-lineage-sample.yaml"


# --- models / privacy boundary -------------------------------------------------
def test_field_refuses_private_content_classification():
    # A field holds metadata only — it can never BE message plaintext or a key.
    with pytest.raises(ValueError):
        Field(id="f", dataset="d", name="n", classification=Classification.MESSAGE_PLAINTEXT)
    with pytest.raises(ValueError):
        Field(id="g", dataset="d", name="n", classification=Classification.DECRYPTION_KEY)


def test_field_rejects_empty_id():
    with pytest.raises(ValueError):
        Field(id="  ", dataset="d", name="n")


def test_peak_picks_most_sensitive():
    assert peak(frozenset({Classification.INTERNAL, Classification.HEALTH})) == Classification.HEALTH
    assert peak(frozenset()) == Classification.INTERNAL


def test_boundary_coerces_approved_list_to_set():
    b = Boundary(id="z", name="Zone", approved=["pii", "internal"])
    assert Classification.PII in b.approved
    assert Classification.HEALTH not in b.approved


# --- graph construction --------------------------------------------------------
def test_field_with_unknown_boundary_is_refused():
    g = LineageGraph()
    with pytest.raises(LineageError):
        g.add_field(Field(id="f", dataset="d", name="n", boundary="zone:ghost"))


def test_flow_to_unknown_field_is_refused():
    g = LineageGraph()
    g.add_field(Field(id="a", dataset="d", name="a"))
    with pytest.raises(LineageError):
        g.add_flow(Flow(src="a", dst="ghost"))


def test_duplicate_field_is_refused():
    g = LineageGraph()
    g.add_field(Field(id="a", dataset="d", name="a"))
    with pytest.raises(LineageError):
        g.add_field(Field(id="a", dataset="d", name="a2"))


# --- the four questions the graph answers --------------------------------------
@pytest.fixture()
def graph() -> LineageGraph:
    return load_graph(SAMPLE)


def test_downstream_and_upstream_lineage(graph):
    down = graph.downstream("f:ehr.diagnosis")
    assert [n.field.id for n in down] == ["f:analytics.diag_stats"]
    assert down[0].path[-1].via == "nightly_etl"
    up = graph.upstream("f:analytics.diag_stats")
    assert [n.field.id for n in up] == ["f:ehr.diagnosis"]


def test_classification_propagates_downstream(graph):
    # diag_stats declares nothing (defaults INTERNAL) but inherits HEALTH from its source.
    classes = graph.propagated_classifications("f:analytics.diag_stats")
    assert Classification.HEALTH in classes
    assert Classification.INTERNAL in classes
    assert graph.peak_classification("f:analytics.diag_stats") == Classification.HEALTH
    # The clinical source carries only its own declared class.
    assert graph.propagated_classifications("f:ehr.diagnosis") == frozenset({Classification.HEALTH})


def test_boundary_violation_detects_health_and_pii_leaving_clinical(graph):
    violations = graph.boundary_violations()
    by_field = {(v.field, v.offending) for v in violations}
    # Health reached the analytics warehouse, which is not approved for it.
    assert ("f:analytics.diag_stats", Classification.HEALTH) in by_field
    # PII reached the analytics warehouse too, via the pseudonymize job.
    assert ("f:analytics.cohort_id", Classification.PII) in by_field
    # The clinical fields sit in a boundary approved for their data — no violation.
    assert not any(v.field.startswith("f:ehr.") for v in violations)
    # Each violation points at the upstream field that introduced the data.
    health = next(v for v in violations if v.field == "f:analytics.diag_stats")
    assert health.introduced_by == "f:ehr.diagnosis"


def test_boundary_violation_is_categorical_not_rank_based():
    # A boundary approved for PII must still reject HEALTH even though both are RESTRICTED-tier.
    g = build_from_spec({
        "boundaries": [{"id": "z", "name": "z", "approved": ["pii", "internal"]}],
        "fields": [
            {"id": "src", "dataset": "d", "name": "s", "classification": "health"},
            {"id": "dst", "dataset": "d", "name": "t", "classification": "pii", "boundary": "z"},
        ],
        "flows": [{"src": "src", "dst": "dst"}],
    })
    violations = g.boundary_violations()
    assert [(v.field, v.offending) for v in violations] == [("dst", Classification.HEALTH)]


def test_retention_obligation_propagates(graph):
    violations = {v.field: v for v in graph.retention_violations()}
    # diag_stats declares no retention but descends from a field with a 3650-day obligation.
    assert "f:analytics.diag_stats" in violations
    assert violations["f:analytics.diag_stats"].declared_days is None
    assert violations["f:analytics.diag_stats"].obligation_days == 3650
    # cohort_id keeps data 7300 days — longer than its 3650-day upstream obligation.
    assert violations["f:analytics.cohort_id"].declared_days == 7300
    assert violations["f:analytics.cohort_id"].obligation_days == 3650


def test_no_retention_violation_when_within_obligation():
    g = build_from_spec({
        "fields": [
            {"id": "src", "dataset": "d", "name": "s", "retention_days": 365},
            {"id": "dst", "dataset": "d", "name": "t", "retention_days": 90},  # stricter — OK
        ],
        "flows": [{"src": "src", "dst": "dst"}],
    })
    assert g.retention_violations() == ()


def test_unknown_field_raises(graph):
    with pytest.raises(LineageError):
        graph.downstream("nope")
    with pytest.raises(LineageError):
        graph.propagated_classifications("nope")


# --- ingestion seam ------------------------------------------------------------
def test_build_from_spec_roundtrip():
    g = build_from_spec({
        "fields": [
            {"id": "a", "dataset": "d", "name": "a", "classification": "pii"},
            {"id": "b", "dataset": "d", "name": "b"},
        ],
        "flows": [{"src": "a", "dst": "b", "via": "etl"}],
    })
    assert len(g) == 2
    assert [n.field.id for n in g.downstream("a")] == ["b"]
    assert Classification.PII in g.propagated_classifications("b")


def test_from_datahub_fails_closed():
    # Until wired, the production source must raise rather than return an empty graph.
    with pytest.raises(NotImplementedError):
        from_datahub()


def test_load_graph_missing_file():
    with pytest.raises(FileNotFoundError):
        load_graph(Path("/no/such/lineage.yaml"))
