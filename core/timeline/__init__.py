"""Guardian forensic timeline reconstruction (Sovereign plane, Wave 1, system #6).

The capstone of Wave 1. It consumes the real-time event fabric (#5, ``core/event_fabric/``) and
reconstructs an incident chronology — ordered, timed, phase-bucketed and narratable — so the
Brain reasons from *sequence*, not isolated alerts (docs/sovereign_ops_plane.md; Timesketch).

Joins to the rest of Wave 1: each event's ``actor`` is an identity-graph principal and its
``target`` a digital-twin asset, so a reconstructed thread points straight at `id-escalate` and
`twin-blast`. Metadata-only by construction — structurally outside private content.
"""

from __future__ import annotations

from .ingest import (
    build_from_spec,
    classify_phase,
    from_fabric,
    from_timesketch,
    load_sketch,
    production_source_required,
)
from .models import (
    Beat,
    DwellMetrics,
    Phase,
    PhaseBucket,
    TimelineEvent,
    phase_rank,
)
from .sketch import Sketch, TimelineError

__all__ = [
    "Sketch",
    "TimelineError",
    "Phase",
    "TimelineEvent",
    "Beat",
    "PhaseBucket",
    "DwellMetrics",
    "phase_rank",
    "from_fabric",
    "build_from_spec",
    "load_sketch",
    "classify_phase",
    "from_timesketch",
    "production_source_required",
]
