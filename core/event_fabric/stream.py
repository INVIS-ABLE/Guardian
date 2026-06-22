"""The event-fabric stream + analytical store (Sovereign plane, Wave 1, system #5).

``EventFabric`` is a single, ordered, append-only stream of normalized security events that
doubles as the analytical store — the in-memory read-model standing in for Redpanda (the
durable stream) and ClickHouse (the analytical store) until those are wired (see ``ingest.py``).

Two properties make it trustworthy as "Guardian's nervous system":

  * **Durable & ordered** — every event gets a monotonic offset and a hash-chained digest
    (``sha256(prev_digest + canonical(event))``, mirroring ``core/audit.py``), so the stream is
    replayable from any offset and any retroactive edit is detectable via :meth:`verify`.
  * **Analytical** — the queries you would run on ClickHouse: filtered :meth:`query`,
    :meth:`counts_by` aggregation, and :meth:`spikes` sliding-window burst detection that turns
    a flat log into correlated signal (e.g. "one actor, five policy denials in 60 s").
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime
from typing import Iterable, Iterator

from .models import (
    EventSource,
    EventSeverity,
    Outcome,
    SecurityEvent,
    Spike,
    StoredEvent,
    severity_rank,
)

GENESIS = "0" * 64

# The fields counts_by / aggregation can group on.
_GROUPABLE = frozenset({"source", "severity", "outcome", "actor", "target", "action"})


def _canonical(event: SecurityEvent) -> bytes:
    return json.dumps(event.model_dump(mode="json"), sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _digest(prev: str, event: SecurityEvent) -> str:
    return hashlib.sha256(prev.encode("utf-8") + _canonical(event)).hexdigest()


class EventFabricError(ValueError):
    """Raised on structural errors (bad group field, unknown offset)."""


class EventFabric:
    """An append-only, hash-chained stream of security events with analytical queries."""

    def __init__(self) -> None:
        self._log: list[StoredEvent] = []

    # --- ingestion (append-only) ----------------------------------------------
    def append(self, event: SecurityEvent) -> StoredEvent:
        """Append one event, assigning the next offset and extending the hash chain."""
        prev = self._log[-1].digest if self._log else GENESIS
        stored = StoredEvent(offset=len(self._log), event=event, digest=_digest(prev, event))
        self._log.append(stored)
        return stored

    def extend(self, events: Iterable[SecurityEvent]) -> None:
        for e in events:
            self.append(e)

    # --- accessors / stream consumption ---------------------------------------
    def __len__(self) -> int:
        return len(self._log)

    def __iter__(self) -> Iterator[StoredEvent]:
        return iter(self._log)

    def replay(self, from_offset: int = 0) -> tuple[StoredEvent, ...]:
        """Ordered events from ``from_offset`` onward — a stream consumer resuming its cursor."""
        if from_offset < 0 or from_offset > len(self._log):
            raise EventFabricError(f"offset out of range: {from_offset}")
        return tuple(self._log[from_offset:])

    # --- analytical store ------------------------------------------------------
    def query(
        self,
        *,
        source: EventSource | None = None,
        min_severity: EventSeverity | None = None,
        actor: str | None = None,
        target: str | None = None,
        outcome: Outcome | None = None,
        action_prefix: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> tuple[StoredEvent, ...]:
        """Filtered scan over the stream (ClickHouse-style ``WHERE``), preserving order."""
        floor = severity_rank(min_severity) if min_severity is not None else None
        out = []
        for s in self._log:
            e = s.event
            if source is not None and e.source != source:
                continue
            if floor is not None and severity_rank(e.severity) < floor:
                continue
            if actor is not None and e.actor != actor:
                continue
            if target is not None and e.target != target:
                continue
            if outcome is not None and e.outcome != outcome:
                continue
            if action_prefix is not None and not e.action.startswith(action_prefix):
                continue
            if since is not None and e.ts < since:
                continue
            if until is not None and e.ts > until:
                continue
            out.append(s)
        return tuple(out)

    def counts_by(self, field: str) -> dict[str, int]:
        """Aggregate event counts grouped by a field (``source``/``outcome``/``actor``/…)."""
        if field not in _GROUPABLE:
            raise EventFabricError(f"cannot group by '{field}'; allowed: {sorted(_GROUPABLE)}")
        counts: dict[str, int] = defaultdict(int)
        for s in self._log:
            value = getattr(s.event, field)
            if value is None:
                key = "(none)"
            elif isinstance(value, (EventSource, EventSeverity, Outcome)):
                key = value.value
            else:
                key = str(value)
            counts[key] += 1
        return dict(counts)

    def spikes(
        self,
        *,
        window_seconds: int,
        threshold: int,
        source: EventSource | None = None,
        outcome: Outcome | None = None,
        min_severity: EventSeverity | None = None,
    ) -> tuple[Spike, ...]:
        """Per-actor sliding-window burst detection over matching events.

        Reports any actor with ``threshold`` or more matching events inside *some* window of
        ``window_seconds`` — the correlation step that turns a flat log into signal (e.g. a
        credential racking up policy denials). Events without an actor are ignored.
        """
        if window_seconds <= 0 or threshold <= 0:
            raise EventFabricError("window_seconds and threshold must be positive")
        matching = self.query(source=source, outcome=outcome, min_severity=min_severity)
        by_actor: dict[str, list[datetime]] = defaultdict(list)
        for s in matching:
            if s.event.actor is not None:
                by_actor[s.event.actor].append(s.event.ts)

        spikes: list[Spike] = []
        for actor, times in by_actor.items():
            times.sort()
            left = 0
            best = 0
            best_span: tuple[datetime, datetime] | None = None
            for right in range(len(times)):
                while (times[right] - times[left]).total_seconds() > window_seconds:
                    left += 1
                size = right - left + 1
                if size > best:
                    best = size
                    best_span = (times[left], times[right])
            if best >= threshold and best_span is not None:
                spikes.append(Spike(actor=actor, count=best, window_seconds=window_seconds,
                                    first_ts=best_span[0], last_ts=best_span[1]))
        spikes.sort(key=lambda sp: (-sp.count, sp.actor))
        return tuple(spikes)

    # --- durability ------------------------------------------------------------
    def verify(self) -> bool:
        """Recompute the hash chain from genesis; ``False`` if any event was altered/reordered."""
        prev = GENESIS
        for offset, stored in enumerate(self._log):
            if stored.offset != offset:
                return False
            expected = _digest(prev, stored.event)
            if expected != stored.digest:
                return False
            prev = stored.digest
        return True
