"""Immune memory — five memory classes with decaying trust (directive §21).

Guardian keeps five distinct kinds of memory: known-good baselines, confirmed incidents,
repair history, control evidence, and unresolved uncertainty. Every item carries provenance
and a confidence, and — crucially — *trust decays unless revalidated*. No item is ever
permanently trusted: an old, unrevalidated "known-good" baseline is not as trustworthy as a
freshly confirmed one, and a retracted or expired item carries no trust at all.

Pure logic + an in-memory store (the durable record lives in immudb/evidence). This module
computes effective trust and serves only live items.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

# Trust half-life: an unrevalidated item loses half its confidence over this many days.
DEFAULT_HALF_LIFE_DAYS = 30.0


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MemoryClass(str, Enum):
    KNOWN_GOOD = "known_good"      # verified configs, artifacts, identities, baselines
    INCIDENT = "incident"          # confirmed incidents, timelines, outcomes
    REPAIR = "repair"              # successful and failed repair attempts
    CONTROL = "control"            # which controls blocked / detected / missed events
    UNCERTAINTY = "uncertainty"    # unresolved and contradictory cases


class ImmuneMemoryItem(BaseModel):
    """One memory item. Trust is derived, never stored as a fixed truth (§21)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    item_id: UUID = Field(default_factory=uuid4)
    memory_class: MemoryClass
    summary: str = Field(min_length=1)
    provenance: str = Field(min_length=1)
    owner: str = ""
    tenant_id: str = ""
    classification: str = "internal"
    confidence: float = Field(ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=_utcnow)
    last_validated_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime | None = None
    retracted: bool = False
    half_life_days: float = Field(gt=0.0, default=DEFAULT_HALF_LIFE_DAYS)

    def effective_trust(self, *, now: datetime | None = None) -> float:
        """Confidence decayed by time since last validation. Zero if retracted/expired."""
        now = now or _utcnow()
        if self.retracted:
            return 0.0
        if self.expires_at is not None and now >= self.expires_at:
            return 0.0
        age_days = max(0.0, (now - self.last_validated_at).total_seconds() / 86_400.0)
        decay = math.pow(0.5, age_days / self.half_life_days)
        return self.confidence * decay


class ImmuneMemory:
    """In-memory store of immune-memory items, indexed by class."""

    def __init__(self) -> None:
        self._items: dict[UUID, ImmuneMemoryItem] = {}

    def add(self, item: ImmuneMemoryItem) -> None:
        self._items[item.item_id] = item

    def get(self, item_id: UUID) -> ImmuneMemoryItem | None:
        return self._items.get(item_id)

    def revalidate(
        self, item_id: UUID, *, confidence: float | None = None, now: datetime | None = None
    ) -> ImmuneMemoryItem:
        """Reset the decay clock (and optionally the confidence). Trust must be re-earned."""
        item = self._items[item_id]
        updated = item.model_copy(update={
            "last_validated_at": now or _utcnow(),
            **({"confidence": confidence} if confidence is not None else {}),
        })
        self._items[item_id] = updated
        return updated

    def retract(self, item_id: UUID) -> ImmuneMemoryItem:
        item = self._items[item_id].model_copy(update={"retracted": True})
        self._items[item_id] = item
        return item

    def live_items(
        self,
        memory_class: MemoryClass | None = None,
        *,
        min_trust: float = 0.0,
        now: datetime | None = None,
    ) -> list[ImmuneMemoryItem]:
        """Non-retracted, non-expired items meeting a trust floor (optionally by class)."""
        now = now or _utcnow()
        out = []
        for item in self._items.values():
            if memory_class is not None and item.memory_class is not memory_class:
                continue
            if item.effective_trust(now=now) < min_trust:
                continue
            out.append(item)
        return out


__all__ = [
    "DEFAULT_HALF_LIFE_DAYS",
    "MemoryClass",
    "ImmuneMemoryItem",
    "ImmuneMemory",
]
