"""The forensic timeline reconstruction engine (Sovereign plane, Wave 1, system #6).

A ``Sketch`` (Timesketch's term for an investigation) ingests forensic events and reconstructs
an incident chronology the Brain can reason over as a *sequence*:

  * ``chronology()``        — events in time order, each with its delta from the previous event
    and elapsed time from the start (the spacing that distinguishes a slow burn from a smash).
  * ``for_actor`` / ``for_target`` — the same story scoped to one principal or asset, so a
    single credential's or service's thread can be followed end to end.
  * ``window(id, …)``       — the events surrounding a pivot, the way an analyst pulls context
    around an alert.
  * ``key_events(…)``       — the skeleton: high-severity or flagged pivots only.
  * ``phases()``            — events bucketed into intrusion phases (recon → … → containment).
  * ``dwell()``             — span and time-to-respond (dwell time).
  * ``narrate()``           — the chronology rendered as a numbered, timestamped story.

All ordering is by ``(timestamp, id)`` so reconstruction is deterministic even when events share
a timestamp.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Iterable, Iterator

from core.event_fabric import EventSeverity, severity_rank

from .models import (
    Beat,
    DwellMetrics,
    Phase,
    PhaseBucket,
    TimelineEvent,
    phase_rank,
)


class TimelineError(ValueError):
    """Raised on structural errors (unknown event id, empty sketch where one is required)."""


class Sketch:
    """A forensic investigation: a set of timeline events reconstructed into a chronology."""

    def __init__(self) -> None:
        self._events: dict[str, TimelineEvent] = {}

    # --- construction ----------------------------------------------------------
    def add(self, event: TimelineEvent) -> None:
        if event.id in self._events:
            raise TimelineError(f"duplicate timeline event id: {event.id}")
        self._events[event.id] = event

    def extend(self, events: Iterable[TimelineEvent]) -> None:
        for e in events:
            self.add(e)

    # --- accessors -------------------------------------------------------------
    def __len__(self) -> int:
        return len(self._events)

    def __iter__(self) -> Iterator[TimelineEvent]:
        return iter(self._ordered())

    def event(self, event_id: str) -> TimelineEvent:
        try:
            return self._events[event_id]
        except KeyError as exc:
            raise TimelineError(f"unknown timeline event: {event_id}") from exc

    def _ordered(self) -> list[TimelineEvent]:
        return sorted(self._events.values(), key=lambda e: (e.ts, e.id))

    # --- 1) the chronology -----------------------------------------------------
    def chronology(self, events: list[TimelineEvent] | None = None) -> tuple[Beat, ...]:
        """Time-ordered beats with per-step delta and elapsed time from the start."""
        ordered = events if events is not None else self._ordered()
        if not ordered:
            return ()
        start = ordered[0].ts
        beats: list[Beat] = []
        prev_ts = start
        for i, e in enumerate(ordered):
            beats.append(Beat(
                index=i, event=e,
                delta_seconds=(e.ts - prev_ts).total_seconds(),
                elapsed_seconds=(e.ts - start).total_seconds(),
            ))
            prev_ts = e.ts
        return tuple(beats)

    # --- 2) scoped stories -----------------------------------------------------
    def for_actor(self, actor: str) -> tuple[Beat, ...]:
        """The chronology scoped to a single principal — that credential's thread."""
        return self.chronology([e for e in self._ordered() if e.actor == actor])

    def for_target(self, target: str) -> tuple[Beat, ...]:
        """The chronology scoped to a single asset — that service's thread."""
        return self.chronology([e for e in self._ordered() if e.target == target])

    # --- 3) context around a pivot ---------------------------------------------
    def window(self, event_id: str, *, before: int = 60, after: int = 60) -> tuple[Beat, ...]:
        """Events within ``before``/``after`` seconds of a pivot event (analyst context pull)."""
        centre = self.event(event_id)
        lo, hi = centre.ts - timedelta(seconds=before), centre.ts + timedelta(seconds=after)
        return self.chronology([e for e in self._ordered() if lo <= e.ts <= hi])

    # --- 4) the skeleton -------------------------------------------------------
    def key_events(self, *, min_severity: EventSeverity = EventSeverity.HIGH) -> tuple[TimelineEvent, ...]:
        """The pivots: events flagged ``key`` or at/above ``min_severity`` — the story skeleton."""
        floor = severity_rank(min_severity)
        return tuple(e for e in self._ordered()
                     if e.key or severity_rank(e.severity) >= floor)

    # --- 5) phase reconstruction -----------------------------------------------
    def phases(self) -> tuple[PhaseBucket, ...]:
        """Events bucketed by intrusion phase, buckets ordered along the lifecycle."""
        buckets: dict[Phase, list[TimelineEvent]] = {}
        for e in self._ordered():
            buckets.setdefault(e.phase, []).append(e)
        return tuple(
            PhaseBucket(phase=phase, events=tuple(buckets[phase]))
            for phase in sorted(buckets, key=phase_rank)
        )

    # --- 6) dwell metrics ------------------------------------------------------
    def dwell(self) -> DwellMetrics:
        """Span of the incident and time from first event to first containment (dwell time)."""
        ordered = self._ordered()
        if not ordered:
            raise TimelineError("cannot compute dwell metrics for an empty sketch")
        first, last = ordered[0].ts, ordered[-1].ts
        response = next((e.ts for e in ordered if e.phase == Phase.CONTAINMENT), None)
        ttr = (response - first).total_seconds() if response is not None else None
        return DwellMetrics(
            first_event=first, last_event=last,
            total_span_seconds=(last - first).total_seconds(),
            first_response=response, time_to_respond_seconds=ttr, events=len(ordered),
        )

    # --- 7) the story ----------------------------------------------------------
    def narrate(self) -> tuple[str, ...]:
        """Render the chronology as numbered, timestamped story lines."""
        lines: list[str] = []
        for beat in self.chronology():
            e = beat.event
            mark = "★" if e.key else " "
            at = f"+{beat.elapsed_seconds:>5.0f}s"
            who = f" [{e.actor or '·'}→{e.target or '·'}]" if (e.actor or e.target) else ""
            lines.append(f"{mark} {at} ({e.phase.value}) {e.message}{who}")
        return tuple(lines)
