"""Tests for the live cyber digital twin (Sovereign plane, Wave 1, system #1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.evidence.models import Classification
from core.twin import (
    AssetKind,
    AssetNode,
    DigitalTwin,
    Relationship,
    RelationKind,
    TwinError,
    build_from_spec,
    from_cartography,
    load_twin,
)

SAMPLE = Path(__file__).resolve().parent.parent / "twin" / "invisable-sample.yaml"


# --- models / privacy boundary -------------------------------------------------
def test_node_refuses_private_content_classification():
    # The twin holds metadata only — a node can never BE message plaintext or a key.
    with pytest.raises(ValueError):
        AssetNode(id="x", kind=AssetKind.ENCRYPTION_KEY, name="k",
                  classification=Classification.DECRYPTION_KEY)
    with pytest.raises(ValueError):
        AssetNode(id="y", kind=AssetKind.DATA_CLASS, name="d",
                  classification=Classification.MESSAGE_PLAINTEXT)


def test_node_rejects_empty_id():
    with pytest.raises(ValueError):
        AssetNode(id="  ", kind=AssetKind.SERVICE, name="svc")


# --- graph construction --------------------------------------------------------
def test_relationship_to_unknown_asset_is_refused():
    twin = DigitalTwin()
    twin.add_asset(AssetNode(id="a", kind=AssetKind.SERVICE, name="a"))
    with pytest.raises(TwinError):
        twin.add_relationship(Relationship(src="a", dst="ghost", kind=RelationKind.READS))


def test_duplicate_asset_is_refused():
    twin = DigitalTwin()
    twin.add_asset(AssetNode(id="a", kind=AssetKind.SERVICE, name="a"))
    with pytest.raises(TwinError):
        twin.add_asset(AssetNode(id="a", kind=AssetKind.SERVICE, name="a2"))


# --- the two questions the twin answers ---------------------------------------
@pytest.fixture()
def sample() -> DigitalTwin:
    return load_twin(SAMPLE)


def test_blast_radius_reaches_messaging_and_ciphertext(sample):
    radius = sample.blast_radius("id:ci-token")
    ids = set(radius.asset_ids())
    # A leaked CI token reaches the repo, the built image, the service, the DB and the data.
    assert {"repo:guardian", "img:messaging", "svc:messaging-relay",
            "db:mailbox", "data:ciphertext", "api:messaging"} <= ids
    # The origin is not in its own blast radius.
    assert "id:ci-token" not in ids
    # The human dev is UPstream (has_role → token); compromising the token does not reach them.
    assert "id:human-dev" not in ids


def test_blast_radius_distances_are_shortest(sample):
    radius = sample.blast_radius("id:ci-token")
    by_id = {i.asset.id: i for i in radius.impacted}
    assert by_id["repo:guardian"].distance == 1
    assert by_id["img:messaging"].distance == 2
    assert by_id["data:ciphertext"].distance == 5  # token→repo→img→svc→db→data


def test_max_depth_limits_propagation(sample):
    shallow = sample.blast_radius("id:ci-token", max_depth=2)
    ids = set(shallow.asset_ids())
    assert "img:messaging" in ids          # depth 2 included
    assert "svc:messaging-relay" not in ids  # depth 3 excluded


def test_attack_path_is_the_chain(sample):
    path = sample.attack_path("id:ci-token", "data:ciphertext")
    assert path is not None
    vias = [s.via for s in path]
    assert vias == [
        RelationKind.CAN_WRITE, RelationKind.BUILDS, RelationKind.DEPLOYS,
        RelationKind.READS, RelationKind.STORES,
    ]
    assert path[-1].asset == "data:ciphertext"


def test_attack_path_none_when_unreachable(sample):
    # The signing key signs the image, but nothing points back to the developer.
    assert sample.attack_path("data:ciphertext", "id:ci-token") is None


def test_blast_radius_of_kind_filter(sample):
    radius = sample.blast_radius("id:ci-token")
    dbs = radius.of_kind(AssetKind.DATABASE)
    assert [i.asset.id for i in dbs] == ["db:mailbox"]


def test_unknown_origin_raises(sample):
    with pytest.raises(TwinError):
        sample.blast_radius("nope")


# --- ingestion seam ------------------------------------------------------------
def test_build_from_spec_roundtrip():
    twin = build_from_spec({
        "assets": [
            {"id": "i", "kind": "identity", "name": "svc", "subtype": "service"},
            {"id": "db", "kind": "database", "name": "db"},
        ],
        "relationships": [{"src": "i", "dst": "db", "kind": "can_access"}],
    })
    assert len(twin) == 2
    assert twin.blast_radius("i").asset_ids() == ("db",)


def test_from_cartography_fails_closed():
    # Until wired, the production source must raise rather than return an empty twin.
    with pytest.raises(NotImplementedError):
        from_cartography()
