"""Lineage ingestion seam — build a :class:`LineageGraph` from a spec, or from DataHub.

For development/CI and for declaring a known sub-graph, the lineage graph is built from a
plain spec (dict or YAML). In production the same graph is populated from DataHub (fed by
OpenLineage run events); that wiring lands at :func:`from_datahub`, which fails closed
(raises) until the source is provisioned rather than returning a silently-empty graph — an
empty boundary-violation result would falsely imply "no data has crossed a boundary".

Spec shape::

    boundaries:
      - {id: "zone:analytics", name: Analytics, approved: [public, internal, confidential]}
    fields:
      - {id: "f:ehr.diagnosis", dataset: ehr.records, name: diagnosis, classification: health,
         boundary: "zone:clinical", retention_days: 3650}
    flows:
      - {src: "f:ehr.diagnosis", dst: "f:analytics.diag", via: nightly_etl}
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from .graph import LineageGraph
from .models import Boundary, Field, Flow


def build_from_spec(spec: dict[str, Any]) -> LineageGraph:
    """Construct a lineage graph from a ``{boundaries, fields, flows}`` mapping.

    Pydantic validates every boundary/field/flow (including the privacy boundary on field
    classification); structural errors (unknown ids, duplicate fields) raise ``LineageError``.
    """
    boundaries = [Boundary(**b) for b in spec.get("boundaries", [])]
    fields = [Field(**f) for f in spec.get("fields", [])]
    flows = [Flow(**fl) for fl in spec.get("flows", [])]
    graph = LineageGraph()
    graph.extend(boundaries, fields, flows)
    return graph


def load_graph(path: str | Path) -> LineageGraph:
    """Load a lineage graph from a YAML spec file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"lineage spec not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return build_from_spec(data)


def from_datahub(_config: Any | None = None) -> LineageGraph:
    """Populate the graph from the production source (DataHub + OpenLineage run events).

    Not yet wired. Fails closed so a production caller never reasons over a silently-empty
    graph: an empty boundary/retention result would falsely imply "nothing crossed a
    boundary". Until the source is provisioned, callers must supply an explicit spec via
    :func:`build_from_spec`.
    """
    raise NotImplementedError(
        "DataHub / OpenLineage ingestion is not wired yet; build the graph from an explicit "
        "spec (build_from_spec/load_graph). Set GUARDIAN_ENV=development to use spec-based graphs."
    )


def production_source_required() -> bool:
    """Whether a real lineage source is required (staging/production), mirroring the policy gate."""
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in {"staging", "production"}
