"""Typed models for forensic timeline reconstruction (Sovereign plane, Wave 1, system #6).

The capstone of Wave 1. The event fabric (#5, ``core/event_fabric/``) gives Guardian one durable
stream of normalized events; this system turns that stream into an **incident chronology** — an
ordered, annotated story with inter-event timing and kill-chain phases — so the Brain reasons
from *sequence*, not isolated alerts (docs/sovereign_ops_plane.md; upstream: Timesketch).

This module defines the *shapes*: the forensic :class:`TimelineEvent`, the incident
:class:`Phase` vocabulary, and the reconstruction outputs (:class:`Beat`, :class:`PhaseBucket`,
:class:`DwellMetrics`). The reconstruction engine is :class:`~core.timeline.sketch.Sketch`; the
ingestion seam (from the event fabric, a spec, or Timesketch) is in ``ingest.py``.

Privacy boundary (same as every Wave-1 system): timeline events carry **metadata only** — *that*
something happened and when, never message contents or key material.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.event_fabric import EventSeverity

SCHEMA_VERSION = 1


class Phase(str, Enum):
    """Incident phases, ordered roughly along an intrusion's lifecycle.

    Used to bucket a chronology so the story reads as *recon → access → … → containment*
    rather than a flat list. ``BENIGN`` is for ordinary activity that is part of the record but
    not part of the attack narrative.
    """

    RECON = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    ESCALATION = "privilege_escalation"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    CONTAINMENT = "containment"
    BENIGN = "benign"


_PHASE_RANK: dict[Phase, int] = {
    Phase.RECON: 0,
    Phase.INITIAL_ACCESS: 1,
    Phase.EXECUTION: 2,
    Phase.ESCALATION: 3,
    Phase.EXFILTRATION: 4,
    Phase.IMPACT: 5,
    Phase.CONTAINMENT: 6,
    Phase.BENIGN: 7,
}


def phase_rank(phase: Phase) -> int:
    """Lifecycle order of a phase (lower = earlier); ``BENIGN`` sorts last."""
    return _PHASE_RANK[phase]


class TimelineEvent(BaseModel):
    """One forensic event on the timeline. Immutable, strict, metadata-only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    id: str
    ts: datetime
    source: str                    # originating system (e.g. "opa", "falco")
    message: str                   # human-readable account of what happened
    severity: EventSeverity = EventSeverity.INFO
    actor: str | None = None       # principal id (joins to the identity graph)
    target: str | None = None      # asset id (joins to the digital twin)
    phase: Phase = Phase.BENIGN
    key: bool = False              # a pivot/key event — the skeleton of the story
    tags: tuple[str, ...] = ()

    @field_validator("id", "message", "source")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("timeline event id/message/source must be non-empty")
        return v


class Beat(BaseModel):
    """One step in the chronology: an event plus its timing relative to neighbours and start."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    index: int
    event: TimelineEvent
    delta_seconds: float           # seconds since the previous beat (0 for the first)
    elapsed_seconds: float         # seconds since the first event


class PhaseBucket(BaseModel):
    """All events assigned to one incident phase, in time order."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: Phase
    events: tuple[TimelineEvent, ...]


class DwellMetrics(BaseModel):
    """Forensic timing of the incident: span and time-to-respond (dwell)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    first_event: datetime
    last_event: datetime
    total_span_seconds: float
    first_response: datetime | None        # first CONTAINMENT-phase event, if any
    time_to_respond_seconds: float | None  # first_response − first_event, if a response occurred
    events: int = Field(ge=0)
