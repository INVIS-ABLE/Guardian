"""Guardian real-time security event fabric (Sovereign plane, Wave 1, system #5).

The fifth Wave-1 omniscience system — Guardian's nervous system. It unifies OPA / Temporal /
GitHub / identity / Cilium / Falco / build / model events into one canonical shape on a single
durable, ordered, tamper-evident stream that doubles as an analytical store
(docs/sovereign_ops_plane.md). Filtered queries, aggregation, and per-actor spike detection
turn the flat log into correlated signal.

Metadata-only by construction: the fabric records *that* a policy denied an action or *that* a
syscall fired — never message bodies or key material. Structurally outside private content.
"""

from __future__ import annotations

from .ingest import (
    NORMALIZERS,
    build_from_spec,
    from_redpanda,
    load_stream,
    normalize,
    normalize_falco,
    normalize_github,
    normalize_model,
    normalize_opa,
    production_source_required,
)
from .models import (
    EventSeverity,
    EventSource,
    Outcome,
    SecurityEvent,
    Spike,
    StoredEvent,
    severity_rank,
)
from .stream import GENESIS, EventFabric, EventFabricError

__all__ = [
    "EventFabric",
    "EventFabricError",
    "GENESIS",
    "EventSource",
    "EventSeverity",
    "Outcome",
    "SecurityEvent",
    "StoredEvent",
    "Spike",
    "severity_rank",
    "normalize",
    "normalize_opa",
    "normalize_github",
    "normalize_falco",
    "normalize_model",
    "NORMALIZERS",
    "build_from_spec",
    "load_stream",
    "from_redpanda",
    "production_source_required",
]
