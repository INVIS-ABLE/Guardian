"""Typed models for the data lineage & privacy graph (Sovereign plane, Wave 1, system #3).

The third Wave-1 omniscience system, alongside the digital twin ([`core/twin/`](../twin))
and the identity attack graph ([`core/identity_graph/`](../identity_graph)). Where those
reason over assets and principals, this graph reasons over **data fields and how they flow**,
answering the questions the Sovereign doc asks of data (docs/sovereign_ops_plane.md):

  * **field-level lineage** — where did this field's data come from, and where does it go?
  * **classification propagation** — a field's true sensitivity is the union of every
    upstream contributor's classification, not just what it was declared.
  * **processor boundaries** — every field lives in an *approved boundary*; data that flows
    into a boundary not approved for its sensitivity is a violation. This is the canonical
    detection: *"a new integration moves a health field outside its approved boundary."*
  * **retention / deletion obligations** — a deletion deadline propagates downstream: derived
    data may not outlive the strictest obligation of any field it was derived from.

This module defines the *shapes* only; the graph algorithms live in ``graph.py`` and the
ingestion seam (DataHub / OpenLineage → store, in production) in ``ingest.py``.

Privacy boundary (same as the twin): this graph holds **metadata about fields, never their
contents**. A field classified ``HEALTH`` is a *label* ("this column holds health data"),
never a record. A node may never be classified ``MESSAGE_PLAINTEXT`` or ``DECRYPTION_KEY`` —
those denote content itself, and the lineage graph is structurally outside private content.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, field_validator

from core.evidence.models import Classification

SCHEMA_VERSION = 1

# Classifications that denote private *content* — never permitted on a field node, which only
# ever carries metadata (mirrors core/twin/models.py and the Verifier's boundary).
_FORBIDDEN_FIELD_CLASSES = frozenset({Classification.MESSAGE_PLAINTEXT, Classification.DECRYPTION_KEY})

# Sensitivity rank for *display and "peak" selection only*. Boundary checks are categorical
# (a boundary approved for PII but not HEALTH must still reject HEALTH), so the authoritative
# comparison is set membership, not this rank — see graph.boundary_violations.
_RANK: dict[Classification, int] = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.CONFIDENTIAL: 2,
    Classification.RESTRICTED: 3,
    Classification.PII: 3,
    Classification.HEALTH: 4,
}


def rank(classification: Classification) -> int:
    """Coarse sensitivity rank (higher = more sensitive); unknown labels treated as RESTRICTED."""
    return _RANK.get(classification, 3)


def peak(classifications: frozenset[Classification]) -> Classification:
    """The single most-sensitive label in a set (for reporting); INTERNAL for an empty set."""
    if not classifications:
        return Classification.INTERNAL
    return max(classifications, key=lambda c: (rank(c), c.value))


class Boundary(BaseModel):
    """A processing zone with an explicit allow-list of classifications it may hold."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    id: str                       # e.g. "zone:analytics"
    name: str
    approved: frozenset[Classification] = frozenset()  # classifications permitted in this zone
    purpose: str | None = None

    @field_validator("id", "name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("boundary id/name must be non-empty")
        return v


class Field(BaseModel):
    """One data field (a column / message attribute). Immutable, strict, metadata-only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    id: str                       # stable identifier, e.g. "f:ehr.records.diagnosis"
    dataset: str                  # owning dataset/table/stream, e.g. "ehr.records"
    name: str                     # field name, e.g. "diagnosis"
    classification: Classification = Classification.INTERNAL  # declared sensitivity
    boundary: str | None = None   # id of the Boundary this field lives in
    retention_days: int | None = None  # deletion obligation in days (None = unspecified)
    owner: str | None = None

    @field_validator("id", "dataset", "name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("field id/dataset/name must be non-empty")
        return v

    @field_validator("classification")
    @classmethod
    def _no_private_content(cls, v: Classification) -> Classification:
        if v in _FORBIDDEN_FIELD_CLASSES:
            raise ValueError(
                f"lineage nodes hold metadata only — classification '{v.value}' denotes private "
                "content and is refused (the lineage graph is structurally outside private content)"
            )
        return v


class Flow(BaseModel):
    """A directed data-flow edge: ``src`` field contributes to ``dst`` field, via a job."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    src: str
    dst: str
    via: str = "transform"        # the job/transform that produced the flow (OpenLineage run)

    @field_validator("src", "dst")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("flow src/dst must be non-empty field ids")
        return v


class FlowStep(BaseModel):
    """One hop on a lineage path: ``via`` job reaching ``field``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    via: str
    field: str


class LineageNode(BaseModel):
    """A field reachable up- or down-stream of an origin, with the shortest path to it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: Field
    distance: int
    path: tuple[FlowStep, ...]


class BoundaryViolation(BaseModel):
    """A field whose propagated data is more sensitive than its boundary is approved to hold."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str                    # the field sitting in the wrong boundary
    boundary: str                 # the boundary it lives in
    offending: Classification     # the classification that is not approved here
    introduced_by: str            # the (nearest) upstream field that introduced that class


class RetentionViolation(BaseModel):
    """A field that would retain data longer than an upstream deletion obligation allows."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str
    declared_days: int | None     # the field's own retention (None = no obligation recorded)
    obligation_days: int          # the strictest upstream obligation it must honour
    source: str                   # the upstream field that imposes the obligation
