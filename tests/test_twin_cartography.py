"""Tests for Cartography/CloudQuery export ingestion into the twin."""

from __future__ import annotations

import pytest

from core.twin import (
    AssetKind,
    CartographyExportError,
    RelationKind,
    from_cartography,
    from_cartography_export,
)

EXPORT = {
    "nodes": [
        {"id": "role:deployer", "labels": ["AWSRole"], "name": "Deployer"},
        {"id": "img:app", "labels": ["ECRImage"], "name": "app:1.0"},
        {"id": "svc:app", "labels": ["ECSService"], "name": "App service"},
        {"id": "db:app", "labels": ["RDSInstance"], "name": "App DB"},
        {"id": "weird:thing", "labels": ["SomethingNovel"], "name": "mystery"},
    ],
    "relationships": [
        {"start": "role:deployer", "end": "svc:app", "type": "CAN_ACCESS"},
        {"start": "img:app", "end": "svc:app", "type": "DEPLOYS"},
        {"start": "svc:app", "end": "db:app", "type": "READS"},
        {"start": "svc:app", "end": "weird:thing", "type": "MYSTERY_REL"},
    ],
}


def test_labels_map_to_asset_kinds():
    twin = from_cartography_export(EXPORT)
    assert twin.asset("img:app").kind == AssetKind.CONTAINER_IMAGE
    assert twin.asset("svc:app").kind == AssetKind.SERVICE
    assert twin.asset("db:app").kind == AssetKind.DATABASE
    assert twin.asset("role:deployer").kind == AssetKind.IDENTITY


def test_unknown_label_falls_back_to_cloud_resource():
    twin = from_cartography_export(EXPORT)
    assert twin.asset("weird:thing").kind == AssetKind.CLOUD_RESOURCE


def test_relationship_types_map_and_unknown_is_conservative():
    twin = from_cartography_export(EXPORT)
    kinds = {(r.src, r.dst): r.kind for r in twin.relationships()}
    assert kinds[("img:app", "svc:app")] == RelationKind.DEPLOYS
    assert kinds[("svc:app", "db:app")] == RelationKind.READS
    # Unknown relationship type → conservative CAN_ACCESS (still propagates compromise).
    assert kinds[("svc:app", "weird:thing")] == RelationKind.CAN_ACCESS


def test_ingested_twin_supports_blast_radius():
    twin = from_cartography_export(EXPORT)
    assert "db:app" in set(twin.blast_radius("role:deployer").asset_ids())


def test_dangling_relationship_fails_closed():
    bad = {"nodes": [{"id": "a", "labels": ["ECSService"]}],
           "relationships": [{"start": "a", "end": "ghost", "type": "READS"}]}
    with pytest.raises(CartographyExportError):
        from_cartography_export(bad)


def test_missing_nodes_key_raises():
    with pytest.raises(CartographyExportError):
        from_cartography_export({"relationships": []})


def test_live_cartography_still_fails_closed():
    # The live-service seam must not silently return an empty twin.
    with pytest.raises(NotImplementedError):
        from_cartography()
