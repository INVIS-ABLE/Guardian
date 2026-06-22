"""Guardian endpoint intelligence fabric (Sovereign plane, Wave 1, system #4).

The fourth Wave-1 omniscience system, beside the digital twin (#1), identity attack graph (#2)
and data lineage graph (#3). It gives Guardian structured OS-state visibility across the fleet
— but only through **signed, reviewed osquery query packs, never model-generated commands**
(docs/sovereign_ops_plane.md). ``EndpointFabric`` is the reference monitor that enforces it:
admit only correctly-signed, independently-reviewed packs; refuse every query not in one.

Read-only by construction (osquery only ``SELECT``s OS state) and structurally outside private
content — it reports OS metadata, never message contents.
"""

from __future__ import annotations

from .fabric import EndpointError, EndpointFabric, UnapprovedQueryError
from .ingest import (
    build_from_spec,
    from_fleet,
    load_reviewed_packs,
    production_source_required,
    seal_and_admit,
    sign_pack,
)
from .models import (
    OsqueryQuery,
    PackSignature,
    Platform,
    QueryPack,
    QueryVerdict,
)

__all__ = [
    "EndpointFabric",
    "EndpointError",
    "UnapprovedQueryError",
    "Platform",
    "OsqueryQuery",
    "QueryPack",
    "PackSignature",
    "QueryVerdict",
    "load_reviewed_packs",
    "build_from_spec",
    "seal_and_admit",
    "sign_pack",
    "from_fleet",
    "production_source_required",
]
