"""Guardian identity & permission attack graph (Sovereign plane, Wave 1, system #2).

The BloodHound-style companion to the live cyber digital twin ([`core/twin/`](../twin)). The
twin answers *"what is affected if this asset is compromised?"*; the identity graph answers
the principal/permission questions from docs/sovereign_ops_plane.md — effective + transitive
permissions, privilege-escalation paths, dormant privilege, and separation-of-duties breaks.

Metadata-only by construction: principals are identifiers and grants name actions on
resources, never the data itself. Guardian protects the access-control system while remaining
structurally outside private content.
"""

from __future__ import annotations

from .graph import IdentityError, IdentityGraph
from .ingest import build_from_spec, from_bloodhound, load_graph, production_source_required
from .models import (
    DormantPrincipal,
    DutyConflict,
    EdgeKind,
    EffectivePermission,
    EscalationPath,
    Grant,
    IdentityEdge,
    Principal,
    PrincipalKind,
    PrivilegeStep,
    SoDBreak,
)

__all__ = [
    "IdentityGraph",
    "IdentityError",
    "PrincipalKind",
    "EdgeKind",
    "Principal",
    "IdentityEdge",
    "Grant",
    "EffectivePermission",
    "PrivilegeStep",
    "EscalationPath",
    "DormantPrincipal",
    "DutyConflict",
    "SoDBreak",
    "build_from_spec",
    "load_graph",
    "from_bloodhound",
    "production_source_required",
]
