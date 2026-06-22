"""Ingest a Cartography/CloudQuery relationship export into the digital twin.

In production the twin is populated from Cartography (lyft/cartography), which models the estate
in Neo4j and can export nodes + relationships as JSON. :func:`from_cartography_export` maps that
export onto twin assets/relationships, translating Cartography node labels and relationship types
to the twin's typed vocabulary. The live ``ingest.from_cartography()`` (a running Cartography
service) stays fail-closed; this function ingests an already-produced, reviewable export.

Export shape (a subset of Cartography's JSON)::

    {
      "nodes": [{"id": "...", "labels": ["GitHubRepository"], "name": "..."}, ...],
      "relationships": [{"start": "...", "end": "...", "type": "RESOURCE"}, ...]
    }

Unknown labels map to ``cloud_resource`` and unknown relationship types to ``can_access`` — the
conservative choices (a generic asset, and an access edge that still propagates compromise).
"""

from __future__ import annotations

from typing import Any

from .graph import DigitalTwin
from .models import AssetKind, AssetNode, Relationship, RelationKind

# Cartography node label → twin asset kind.
_LABEL_KIND: dict[str, AssetKind] = {
    "GitHubRepository": AssetKind.REPOSITORY,
    "GitHubBranch": AssetKind.REPOSITORY,
    "ECRImage": AssetKind.CONTAINER_IMAGE,
    "ECRRepositoryImage": AssetKind.CONTAINER_IMAGE,
    "ContainerImage": AssetKind.CONTAINER_IMAGE,
    "ECSService": AssetKind.SERVICE,
    "KubernetesService": AssetKind.SERVICE,
    "KubernetesPod": AssetKind.K8S_WORKLOAD,
    "KubernetesDeployment": AssetKind.K8S_WORKLOAD,
    "APIGatewayRestAPI": AssetKind.API,
    "Domain": AssetKind.DOMAIN,
    "AWSDNSRecord": AssetKind.DOMAIN,
    "Certificate": AssetKind.CERTIFICATE,
    "RDSInstance": AssetKind.DATABASE,
    "DynamoDBTable": AssetKind.DATABASE,
    "SQSQueue": AssetKind.QUEUE,
    "KMSKey": AssetKind.ENCRYPTION_KEY,
    "AWSPrincipal": AssetKind.IDENTITY,
    "AWSRole": AssetKind.IDENTITY,
    "AWSUser": AssetKind.IDENTITY,
    "GitHubUser": AssetKind.IDENTITY,
    "Dependency": AssetKind.DEPENDENCY,
    "PythonLibrary": AssetKind.DEPENDENCY,
    "EC2Instance": AssetKind.CLOUD_RESOURCE,
    "S3Bucket": AssetKind.DATABASE,
}

# Cartography relationship type → twin relation kind (oriented to compromise propagation).
_TYPE_RELATION: dict[str, RelationKind] = {
    "MEMBER_OF": RelationKind.HAS_ROLE,
    "STS_ASSUME_ROLE_ALLOW": RelationKind.HAS_ROLE,
    "CAN_ACCESS": RelationKind.CAN_ACCESS,
    "PERMISSION": RelationKind.CAN_ACCESS,
    "WRITES": RelationKind.CAN_WRITE,
    "PUSHES_TO": RelationKind.CAN_WRITE,
    "BUILDS": RelationKind.BUILDS,
    "PRODUCES": RelationKind.PRODUCES,
    "SIGNS": RelationKind.SIGNS,
    "DEPLOYS": RelationKind.DEPLOYS,
    "RESOURCE": RelationKind.DEPLOYS,
    "DEPENDS_ON": RelationKind.DEPENDS_ON,
    "REQUIRES": RelationKind.DEPENDS_ON,
    "EXPOSES": RelationKind.EXPOSES,
    "READS": RelationKind.READS,
    "STORES": RelationKind.STORES,
}


class CartographyExportError(ValueError):
    """Raised when an export is malformed."""


def _node_kind(labels: list[str]) -> AssetKind:
    for label in labels:
        if label in _LABEL_KIND:
            return _LABEL_KIND[label]
    return AssetKind.CLOUD_RESOURCE


def from_cartography_export(export: dict[str, Any]) -> DigitalTwin:
    """Build a :class:`DigitalTwin` from a Cartography/CloudQuery JSON export.

    Relationships referencing an unknown node id raise (a dangling edge means an incomplete
    export — fail closed rather than silently dropping the relationship).
    """
    nodes = export.get("nodes")
    if nodes is None:
        raise CartographyExportError("export missing 'nodes'")

    twin = DigitalTwin()
    for n in nodes:
        nid = n.get("id")
        if not nid:
            raise CartographyExportError(f"node missing id: {n!r}")
        labels = list(n.get("labels", []))
        twin.add_asset(AssetNode(
            id=nid,
            kind=_node_kind(labels),
            name=n.get("name") or nid,
            owner=n.get("owner"),
        ))

    for r in export.get("relationships", []):
        start, end, rtype = r.get("start"), r.get("end"), r.get("type", "")
        if start not in twin or end not in twin:
            raise CartographyExportError(f"relationship references unknown node: {r!r}")
        twin.add_relationship(Relationship(
            src=start, dst=end,
            kind=_TYPE_RELATION.get(rtype, RelationKind.CAN_ACCESS),
        ))
    return twin
