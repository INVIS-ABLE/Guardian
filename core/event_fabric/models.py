"""Typed models for the real-time security event fabric (Sovereign plane, Wave 1, system #5).

The fifth Wave-1 omniscience system — **Guardian's nervous system**. Heterogeneous security
signals (OPA decisions, Temporal workflows, GitHub, identity, Cilium network, Falco runtime,
build, model-gateway) are normalized into **one canonical event shape** and appended to a
single durable, ordered, tamper-evident stream that doubles as an analytical store
(docs/sovereign_ops_plane.md: ClickHouse analytical store fed by Redpanda).

This module defines the *shapes*: the canonical :class:`SecurityEvent`, the source/severity/
outcome vocabularies, and :class:`StoredEvent` (an event plus its stream offset and chained
digest). The stream + analytical queries live in ``stream.py``; the per-source normalizers and
the production ingestion seam in ``ingest.py``.

Privacy boundary (same as the other Wave-1 systems): events carry **metadata only, never
private content**. A node may never be classified ``MESSAGE_PLAINTEXT`` or ``DECRYPTION_KEY``;
the fabric records *that* a policy denied an action or *that* a syscall fired, never message
bodies or key material.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.evidence.models import Classification

SCHEMA_VERSION = 1

_FORBIDDEN_EVENT_CLASSES = frozenset({Classification.MESSAGE_PLAINTEXT, Classification.DECRYPTION_KEY})


class EventSource(str, Enum):
    """The signal sources the fabric unifies into one stream."""

    OPA = "opa"            # policy decisions (reference monitor)
    TEMPORAL = "temporal"  # workflow lifecycle
    GITHUB = "github"      # source / PR / push activity
    IDENTITY = "identity"  # auth / session / credential use
    CILIUM = "cilium"      # network flows / policy
    FALCO = "falco"        # runtime syscall / behaviour
    BUILD = "build"        # CI build / provenance / signing
    MODEL = "model"        # model-gateway reasoning events


class EventSeverity(str, Enum):
    """Ordered severity. Use :func:`severity_rank` to compare."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEV_RANK: dict[EventSeverity, int] = {
    EventSeverity.INFO: 0,
    EventSeverity.LOW: 1,
    EventSeverity.MEDIUM: 2,
    EventSeverity.HIGH: 3,
    EventSeverity.CRITICAL: 4,
}


def severity_rank(severity: EventSeverity) -> int:
    """Numeric rank (higher = more severe) for threshold comparisons."""
    return _SEV_RANK[severity]


class Outcome(str, Enum):
    """Normalized outcome across sources (not every event has one)."""

    ALLOW = "allow"
    DENY = "deny"
    SUCCESS = "success"
    FAILURE = "failure"
    DETECTED = "detected"
    BLOCKED = "blocked"
    OBSERVED = "observed"


class SecurityEvent(BaseModel):
    """One normalized security event. Immutable, strict, metadata-only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    id: str                        # stable source event id, e.g. "opa:2026-06-22:0007"
    ts: datetime                   # event time at the source (tz-aware recommended)
    source: EventSource
    action: str                    # normalized verb, e.g. "policy.decision", "pr.force_push"
    severity: EventSeverity = EventSeverity.INFO
    outcome: Outcome | None = None
    actor: str | None = None       # principal/identity id (joins to the identity graph)
    target: str | None = None      # asset/resource id (joins to the digital twin)
    classification: Classification = Classification.INTERNAL
    labels: dict[str, str] = Field(default_factory=dict)  # normalized source fields (metadata only)

    @field_validator("id", "action")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("event id/action must be non-empty")
        return v

    @field_validator("classification")
    @classmethod
    def _no_private_content(cls, v: Classification) -> Classification:
        if v in _FORBIDDEN_EVENT_CLASSES:
            raise ValueError(
                f"event fabric holds metadata only — classification '{v.value}' denotes private "
                "content and is refused (the fabric is structurally outside private content)"
            )
        return v


class StoredEvent(BaseModel):
    """An event as it sits on the stream: with its ordered offset and chained digest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    offset: int                    # monotonic position on the stream (0-based)
    event: SecurityEvent
    digest: str                    # sha256(prev_digest + canonical(event)) — tamper-evidence


class Spike(BaseModel):
    """A burst of matching events from one actor within a sliding time window."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    actor: str
    count: int
    window_seconds: int
    first_ts: datetime
    last_ts: datetime
