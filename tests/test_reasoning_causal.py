"""Tests for the causal root-cause engine (Sovereign #8)."""

from __future__ import annotations

from core.reasoning import root_cause
from core.twin import AssetKind, AssetNode, DigitalTwin, Relationship, RelationKind


def _chain() -> DigitalTwin:
    # attacker → token → repo → image → service → data(health)
    t = DigitalTwin()
    nodes = [
        ("attacker", AssetKind.IDENTITY), ("token", AssetKind.IDENTITY),
        ("repo", AssetKind.REPOSITORY), ("image", AssetKind.CONTAINER_IMAGE),
        ("service", AssetKind.SERVICE),
    ]
    for nid, kind in nodes:
        t.add_asset(AssetNode(id=nid, kind=kind, name=nid,
                              subtype="machine" if kind == AssetKind.IDENTITY else None))
    t.add_asset(AssetNode(id="data", kind=AssetKind.DATA_CLASS, name="phr", classification="health"))
    edges = [("attacker", "token", RelationKind.HAS_ROLE),
             ("token", "repo", RelationKind.CAN_WRITE),
             ("repo", "image", RelationKind.BUILDS),
             ("image", "service", RelationKind.DEPLOYS),
             ("service", "data", RelationKind.READS)]
    for s, d, k in edges:
        t.add_relationship(Relationship(src=s, dst=d, kind=k))
    return t


def test_first_event_is_the_observed_entry():
    r = root_cause(_chain(), observed=["attacker"], sink="data")
    assert r.first_event == "attacker"
    assert r.sink == "data"


def test_enabling_conditions_are_the_interior_hops():
    r = root_cause(_chain(), observed=["attacker"], sink="data")
    assert r.enabling_conditions == ("token", "repo", "image", "service")


def test_symptoms_are_the_last_hop_and_sink():
    r = root_cause(_chain(), observed=["attacker"], sink="data")
    assert r.symptoms == ("service", "data")


def test_root_cause_is_a_necessary_link():
    # In a pure chain every interior node is necessary; the earliest beyond the foothold is root.
    r = root_cause(_chain(), observed=["attacker"], sink="data")
    assert r.root_cause == "token"
    # Its counterfactual breaks the chain.
    cf = {c.node: c.breaks_chain for c in r.counterfactuals}
    assert cf["token"] is True and cf["service"] is True


def test_unreachable_sink_yields_no_cause():
    t = _chain()
    t.add_asset(AssetNode(id="island", kind=AssetKind.SERVICE, name="island"))
    r = root_cause(t, observed=["island"], sink="data")
    assert r.first_event is None and r.root_cause is None


def test_amplifiers_are_chokepoints_on_the_incident():
    r = root_cause(_chain(), observed=["attacker"], sink="data")
    # Every interior node cuts the single chain, so amplifiers are drawn from them.
    assert set(r.amplifiers) <= {"token", "repo", "image", "service"}
    assert r.amplifiers  # non-empty
