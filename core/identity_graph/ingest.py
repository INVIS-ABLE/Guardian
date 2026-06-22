"""Identity-graph ingestion seam — build an :class:`IdentityGraph` from a spec, or BloodHound.

For development/CI and for declaring a known sub-graph, the identity graph is built from a
plain spec (dict or YAML). In production the same graph is populated from BloodHound (and the
cloud IAM / directory connectors that feed it); that wiring lands at :func:`from_bloodhound`,
which fails closed (raises) until the source is provisioned rather than returning a silently
empty graph — an empty escalation result would falsely imply "no escalation is possible".

Spec shape::

    principals:
      - {id: "id:dev", kind: human, name: Developer, last_active: 2026-06-01}
      - {id: "role:deployer", kind: role, name: Deployer}
    edges:
      - {src: "id:dev", dst: "role:deployer", kind: can_assume}
    grants:
      - {holder: "role:deployer", action: deploy, resource: "svc:relay", duty: deploy, sensitive: true}
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from .graph import IdentityGraph
from .models import Grant, IdentityEdge, Principal


def build_from_spec(spec: dict[str, Any]) -> IdentityGraph:
    """Construct an identity graph from a ``{principals, edges, grants}`` mapping.

    Pydantic validates every principal/edge/grant; structural errors (unknown ids, duplicate
    principals, grants to unknown holders) raise ``IdentityError``.
    """
    principals = [Principal(**p) for p in spec.get("principals", [])]
    edges = [IdentityEdge(**e) for e in spec.get("edges", [])]
    grants = [Grant(**g) for g in spec.get("grants", [])]
    graph = IdentityGraph()
    graph.extend(principals, edges, grants)
    return graph


def load_graph(path: str | Path) -> IdentityGraph:
    """Load an identity graph from a YAML spec file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"identity-graph spec not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return build_from_spec(data)


def from_bloodhound(_config: Any | None = None) -> IdentityGraph:
    """Populate the graph from the production source (BloodHound + IAM/directory connectors).

    Not yet wired. Fails closed so a production caller never reasons over a silently-empty
    graph: an empty escalation/SoD result would falsely imply "nothing is exposed". Until the
    source is provisioned, callers must supply an explicit spec via :func:`build_from_spec`.
    """
    raise NotImplementedError(
        "BloodHound / IAM ingestion is not wired yet; build the graph from an explicit spec "
        "(build_from_spec/load_graph). Set GUARDIAN_ENV=development to use spec-based graphs."
    )


def production_source_required() -> bool:
    """Whether a real identity source is required (staging/production), mirroring the policy gate."""
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in {"staging", "production"}
