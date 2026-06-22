"""Tests for cross-domain federation of the twin + identity + lineage graphs."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.identity_graph import load_graph as load_identity
from core.lineage import load_graph as load_lineage
from core.twin import AssetKind, federate, load_twin

ROOT = Path(__file__).resolve().parent.parent
TWIN = ROOT / "twin" / "invisable-sample.yaml"
IDENTITY = ROOT / "identity_graph" / "invisable-identity-sample.yaml"
LINEAGE = ROOT / "lineage" / "invisable-lineage-sample.yaml"
BRIDGES = ROOT / "twin" / "invisable-bridges.yaml"


@pytest.fixture()
def federated():
    import yaml
    bridges = tuple(
        (b["src"], b["relation"], b["dst"])
        for b in (yaml.safe_load(BRIDGES.read_text()) or {}).get("bridges", [])
    )
    return federate(
        load_twin(TWIN),
        identity=load_identity(IDENTITY),
        lineage=load_lineage(LINEAGE),
        bridges=bridges,
    )


def test_identity_perms_bridge_into_the_twin(federated):
    # The deployer grant (identity) on svc:messaging-relay (twin) becomes a CAN_WRITE edge,
    # so the CI token's blast radius now reaches the messaging service.
    ids = set(federated.blast_radius("id:ci-token").asset_ids())
    assert "svc:messaging-relay" in ids


def test_cross_domain_path_reaches_regulated_fields(federated):
    # A developer who can escalate reaches infra AND the lineage health/PII fields.
    ids = set(federated.blast_radius("id:human-dev").asset_ids())
    assert {"repo:guardian", "svc:messaging-relay", "db:mailbox",
            "f:ehr.diagnosis", "f:ehr.patient_id"} <= ids


def test_lineage_flows_propagate(federated):
    # Health field flows to its derived analytics field inside the federated graph.
    ids = set(federated.blast_radius("f:ehr.diagnosis").asset_ids())
    assert "f:analytics.diag_stats" in ids


def test_shared_ids_are_unified_not_duplicated(federated):
    # repo:guardian exists in both twin and identity grants — it must be ONE node.
    repos = [a for a in federated.assets() if a.id == "repo:guardian"]
    assert len(repos) == 1


def test_federation_does_not_mutate_inputs():
    twin = load_twin(TWIN)
    before = len(twin)
    federate(twin, identity=load_identity(IDENTITY))
    assert len(twin) == before  # the original twin is untouched


def test_lineage_field_keeps_its_classification(federated):
    diagnosis = federated.asset("f:ehr.diagnosis")
    assert diagnosis.kind == AssetKind.DATA_CLASS
    assert diagnosis.classification.value == "health"


def test_federate_with_no_inputs_is_empty():
    assert len(federate()) == 0
