"""Guardian data lineage & privacy graph (Sovereign plane, Wave 1, system #3).

The third Wave-1 omniscience system, beside the live cyber digital twin ([`core/twin/`](../twin))
and the identity attack graph ([`core/identity_graph/`](../identity_graph)). It reasons over
data fields and how they flow — field-level lineage, classification propagation, processor
boundaries, and retention/deletion obligations (docs/sovereign_ops_plane.md). Its canonical
detection: *"a new integration moves a health field outside its approved boundary."*

Metadata-only by construction: a field's classification is a label, never a record. The
lineage graph is structurally outside private content (mirrors the digital twin).
"""

from __future__ import annotations

from .graph import LineageError, LineageGraph
from .ingest import build_from_spec, from_datahub, load_graph, production_source_required
from .models import (
    Boundary,
    BoundaryViolation,
    Field,
    Flow,
    FlowStep,
    LineageNode,
    RetentionViolation,
    peak,
    rank,
)

__all__ = [
    "LineageGraph",
    "LineageError",
    "Boundary",
    "Field",
    "Flow",
    "FlowStep",
    "LineageNode",
    "BoundaryViolation",
    "RetentionViolation",
    "rank",
    "peak",
    "build_from_spec",
    "load_graph",
    "from_datahub",
    "production_source_required",
]
