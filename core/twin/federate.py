"""Cross-domain federation: fold the identity and lineage graphs into the digital twin.

The twin answers *"what is affected if this asset is compromised?"*; the identity graph
([`core/identity_graph/`](../identity_graph)) answers *who can do what*; the lineage graph
([`core/lineage/`](../lineage)) answers *where sensitive data flows*. Separately they each see
one domain. Federated into a single :class:`DigitalTwin`, blast radius spans all three — so
Guardian can trace a true cross-domain attack path:

    principal → (effective permission) → repo → image → service → database → regulated field

Federation works because the three graphs already share an id vocabulary: an identity grant's
``resource`` (e.g. ``svc:messaging-relay``) and a lineage field id are the same strings the twin
uses for its assets, so equal ids become the same node. Anything that does not line up by id is
joined with explicit ``bridges``. Metadata-only throughout — the federated graph never holds
content (the per-domain privacy boundaries still apply to every node).
"""

from __future__ import annotations

from typing import Iterable

from .graph import DigitalTwin
from .models import AssetKind, AssetNode, Relationship, RelationKind

# id-prefix → asset kind, used to type a resource that an identity grant references but the twin
# does not already model (so the federated edge still lands on a well-typed placeholder asset).
_PREFIX_KIND: dict[str, AssetKind] = {
    "repo": AssetKind.REPOSITORY,
    "img": AssetKind.CONTAINER_IMAGE,
    "svc": AssetKind.SERVICE,
    "api": AssetKind.API,
    "domain": AssetKind.DOMAIN,
    "cert": AssetKind.CERTIFICATE,
    "db": AssetKind.DATABASE,
    "queue": AssetKind.QUEUE,
    "key": AssetKind.ENCRYPTION_KEY,
    "dep": AssetKind.DEPENDENCY,
    "ctrl": AssetKind.SECURITY_CONTROL,
    "data": AssetKind.DATA_CLASS,
    "f": AssetKind.DATA_CLASS,
    "id": AssetKind.IDENTITY,
    "role": AssetKind.IDENTITY,
    "group": AssetKind.IDENTITY,
}

# Action verbs that imply WRITE/modify authority (vs. read access) — drives the edge kind so a
# write-capable principal propagates compromise into the resource, not merely reads it.
_WRITE_VERBS = ("write", "deploy", "push", "merge", "modify", "delete", "rotate",
                "grant", "approve", "admin", "create", "update", "release")


def _kind_for(asset_id: str) -> AssetKind:
    prefix = asset_id.split(":", 1)[0] if ":" in asset_id else ""
    return _PREFIX_KIND.get(prefix, AssetKind.CLOUD_RESOURCE)


def _grant_relation(action: str) -> RelationKind:
    a = action.lower()
    return RelationKind.CAN_WRITE if any(v in a for v in _WRITE_VERBS) else RelationKind.CAN_ACCESS


class _Builder:
    """Accumulates assets/edges into a fresh twin, de-duplicating by id/edge."""

    def __init__(self) -> None:
        self.twin = DigitalTwin()
        self._edges: set[tuple[str, str, RelationKind]] = set()

    def asset(self, node: AssetNode) -> None:
        if node.id not in self.twin:
            self.twin.add_asset(node)

    def placeholder(self, asset_id: str, *, name: str | None = None) -> None:
        if asset_id not in self.twin:
            self.twin.add_asset(AssetNode(id=asset_id, kind=_kind_for(asset_id), name=name or asset_id))

    def edge(self, src: str, dst: str, kind: RelationKind) -> None:
        if src == dst:
            return
        key = (src, dst, kind)
        if key in self._edges:
            return
        self._edges.add(key)
        self.twin.add_relationship(Relationship(src=src, dst=dst, kind=kind))


def federate(
    twin: DigitalTwin | None = None,
    *,
    identity: object | None = None,
    lineage: object | None = None,
    bridges: Iterable[tuple[str, str, str]] = (),
) -> DigitalTwin:
    """Merge a digital twin, an identity graph and a lineage graph into one graph.

    ``bridges`` are explicit ``(src_id, relation, dst_id)`` cross-domain edges (e.g. linking a
    twin database to the lineage field it stores). Resources/fields that share an id are unified
    automatically. Returns a new :class:`DigitalTwin`; the inputs are not mutated.
    """
    b = _Builder()

    # 1. The infrastructure twin, verbatim.
    if twin is not None:
        for node in twin.assets():
            b.asset(node)
        for rel in twin.relationships():
            b.edge(rel.src, rel.dst, rel.kind)

    # 2. Identity principals + their EFFECTIVE (transitive) permissions as edges into resources.
    #    Flattening inheritance/escalation means a compromised principal reaches every resource
    #    its full permission set can touch — directly, in one hop.
    if identity is not None:
        for p in identity.principals():
            b.asset(AssetNode(id=p.id, kind=AssetKind.IDENTITY, name=p.name,
                              subtype=p.kind.value, owner=p.owner))
        for p in identity.principals():
            for perm in identity.effective_permissions(p.id):
                if perm.resource in (None, "*", ""):
                    continue
                b.placeholder(perm.resource)
                b.edge(p.id, perm.resource, _grant_relation(perm.action))

    # 3. Lineage fields as data-class nodes + flows as edges (src contributes to dst).
    if lineage is not None:
        for f in lineage.fields():
            b.asset(AssetNode(id=f.id, kind=AssetKind.DATA_CLASS,
                              name=f"{f.dataset}.{f.name}", classification=f.classification,
                              owner=f.owner))
        for flow in lineage.flows():
            b.placeholder(flow.src)
            b.placeholder(flow.dst)
            b.edge(flow.src, flow.dst, RelationKind.WRITES)

    # 4. Explicit cross-domain bridges.
    for src, relation, dst in bridges:
        b.placeholder(src)
        b.placeholder(dst)
        b.edge(src, dst, RelationKind(relation))

    return b.twin
