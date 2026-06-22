"""Guardian live cyber digital twin (Sovereign plane, Wave 1, system #1).

A typed relationship graph of the INVISABLE estate that answers, instantly and auditably,
"what is affected if this asset is compromised?" — the foundation the identity graph,
attack-path forecasting and blast-radius reasoning all build on (docs/sovereign_ops_plane.md).

Metadata-only by construction: the twin is structurally outside private content.
"""

from __future__ import annotations

from .graph import DigitalTwin, TwinError
from .assessment import (
    AssetAssessment,
    BlastAssessment,
    SensitiveHit,
    Severity,
    assess_change,
)
from .changemap import resolve_changed_assets
from .ingest import build_from_spec, from_cartography, load_twin, production_source_required
from .models import (
    AssetKind,
    AssetNode,
    BlastRadius,
    ImpactedAsset,
    ImpactStep,
    Relationship,
    RelationKind,
)

__all__ = [
    "DigitalTwin",
    "TwinError",
    "AssetKind",
    "AssetNode",
    "Relationship",
    "RelationKind",
    "BlastRadius",
    "ImpactedAsset",
    "ImpactStep",
    "build_from_spec",
    "load_twin",
    "from_cartography",
    "production_source_required",
    "Severity",
    "SensitiveHit",
    "AssetAssessment",
    "BlastAssessment",
    "assess_change",
    "resolve_changed_assets",
]
