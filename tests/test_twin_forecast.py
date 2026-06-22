"""Tests for control-cut / chokepoint forecasting over the twin."""

from __future__ import annotations

from core.twin import (
    AssetKind,
    AssetNode,
    DigitalTwin,
    Relationship,
    RelationKind,
    attack_surface,
    chokepoint_ranking,
    default_sinks,
    default_sources,
)


def _diamond() -> DigitalTwin:
    """attacker → choke → {a, b} → data(health). 'choke' is the single cut node."""
    t = DigitalTwin()
    t.add_asset(AssetNode(id="attacker", kind=AssetKind.IDENTITY, name="att", subtype="machine"))
    t.add_asset(AssetNode(id="choke", kind=AssetKind.SERVICE, name="gateway"))
    t.add_asset(AssetNode(id="a", kind=AssetKind.SERVICE, name="a"))
    t.add_asset(AssetNode(id="b", kind=AssetKind.SERVICE, name="b"))
    t.add_asset(AssetNode(id="data", kind=AssetKind.DATA_CLASS, name="phr", classification="health"))
    t.add_relationship(Relationship(src="attacker", dst="choke", kind=RelationKind.CAN_ACCESS))
    t.add_relationship(Relationship(src="choke", dst="a", kind=RelationKind.CAN_ACCESS))
    t.add_relationship(Relationship(src="choke", dst="b", kind=RelationKind.CAN_ACCESS))
    t.add_relationship(Relationship(src="a", dst="data", kind=RelationKind.READS))
    t.add_relationship(Relationship(src="b", dst="data", kind=RelationKind.READS))
    return t


def test_default_sources_and_sinks():
    t = _diamond()
    assert default_sources(t) == ("attacker",)        # only node with no inbound
    assert default_sinks(t) == ("data",)              # only sensitive sink


def test_attack_surface_finds_the_pair():
    assert attack_surface(_diamond()) == (("attacker", "data"),)


def test_chokepoint_is_the_single_cut_node():
    ranking = chokepoint_ranking(_diamond())
    # Removing 'choke' severs the only attacker→data path; a/b individually do not (the other
    # branch still reaches data).
    assert ranking[0].node == "choke"
    assert ranking[0].paths_cut == 1
    assert ranking[0].protects_sinks == ("data",)
    non_choke = {c.node: c for c in ranking}
    assert "a" not in non_choke and "b" not in non_choke  # neither alone cuts the path


def test_sources_and_sinks_are_excluded_as_chokepoints():
    nodes = {c.node for c in chokepoint_ranking(_diamond())}
    assert "attacker" not in nodes and "data" not in nodes


def test_no_path_means_no_chokepoints():
    t = DigitalTwin()
    t.add_asset(AssetNode(id="attacker", kind=AssetKind.IDENTITY, name="x", subtype="machine"))
    t.add_asset(AssetNode(id="data", kind=AssetKind.DATA_CLASS, name="d", classification="health"))
    # no edge between them
    assert attack_surface(t) == ()
    assert chokepoint_ranking(t) == ()
