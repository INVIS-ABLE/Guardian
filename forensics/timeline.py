"""Forensic timeline reconstruction."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class TimelineEvent:
    """A canonical security event (a subset of the §16 event envelope)."""

    event_id: str
    source: str                # emitting system: opa | temporal | connector | shadow | evidence | github | ...
    action: str
    timestamp: float           # source-local epoch seconds (may be skewed)
    case_id: str | None = None
    trace_id: str | None = None
    asset: str | None = None
    actor: str | None = None
    outcome: str = ""          # "success" | "failure" | "denied" | ""
    integrity_ok: bool = True  # did this event arrive with a valid integrity signal?
    attributes: dict[str, Any] = field(default_factory=dict)

    def correlation(self) -> str | None:
        return self.case_id or self.trace_id


@dataclass(frozen=True)
class TimelineEntry:
    event: TimelineEvent
    corrected_timestamp: float
    preceded_by: str | None = None  # event_id of the prior event in the same correlation group


@dataclass
class TimelineReport:
    entries: list[TimelineEntry]
    duplicates_removed: int = 0
    anomalies: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.anomalies

    def chain_of_custody(self) -> list[dict[str, Any]]:
        """An ordered, exportable record for evidence hand-off."""
        return [
            {
                "event_id": e.event.event_id,
                "source": e.event.source,
                "action": e.event.action,
                "outcome": e.event.outcome,
                "corrected_timestamp": e.corrected_timestamp,
                "case_id": e.event.case_id,
                "preceded_by": e.preceded_by,
                "integrity_ok": e.event.integrity_ok,
            }
            for e in self.entries
        ]


class ForensicTimeline:
    """Builds an ordered, corroborated timeline from raw events. Read-only."""

    def __init__(
        self,
        *,
        clock_offsets: Mapping[str, float] | None = None,
        expected_sequences: Mapping[str, Sequence[str]] | None = None,
        corroboration: Mapping[str, str] | None = None,
    ) -> None:
        # source -> seconds to ADD to its timestamps to align it to the reference clock.
        self.clock_offsets = dict(clock_offsets or {})
        # trigger action -> follow-up actions that MUST appear later in the same case.
        self.expected_sequences = {k: list(v) for k, v in (expected_sequences or {}).items()}
        # a successful action -> the source whose independent event must corroborate it.
        self.corroboration = dict(corroboration or {})

    def build(self, events: Sequence[TimelineEvent]) -> TimelineReport:
        # 1. de-duplicate by event_id (a replayed/repeated delivery is not a second event).
        unique: dict[str, TimelineEvent] = {}
        duplicates = 0
        for ev in events:
            if ev.event_id in unique:
                duplicates += 1
                continue
            unique[ev.event_id] = ev
        deduped = list(unique.values())

        # 2. clock-skew correction + 3. stable ordering by corrected time.
        def corrected(ev: TimelineEvent) -> float:
            return ev.timestamp + self.clock_offsets.get(ev.source, 0.0)

        ordered = sorted(deduped, key=lambda e: (corrected(e), e.event_id))

        # 4. causal links: the prior event in the same correlation group.
        entries: list[TimelineEntry] = []
        last_in_group: dict[str, str] = {}
        for ev in ordered:
            grp = ev.correlation()
            preceded_by = last_in_group.get(grp) if grp else None
            entries.append(TimelineEntry(event=ev, corrected_timestamp=corrected(ev),
                                         preceded_by=preceded_by))
            if grp:
                last_in_group[grp] = ev.event_id

        anomalies: list[str] = []
        by_case: dict[str, list[TimelineEvent]] = {}
        for ev in ordered:
            grp = ev.correlation()
            if grp:
                by_case.setdefault(grp, []).append(ev)

        # 5. integrity anomalies.
        for ev in ordered:
            if not ev.integrity_ok:
                anomalies.append(f"integrity_failed:{ev.source}:{ev.event_id}")

        # 6. missing expected events.
        for grp, evs in by_case.items():
            actions = {e.action for e in evs}
            for trigger, follow_ups in self.expected_sequences.items():
                if trigger in actions:
                    for needed in follow_ups:
                        if needed not in actions:
                            anomalies.append(f"missing_event:{grp}:{needed}")

        # 7. unsupported success — a tool claims success but the required independent
        #    evidence is absent in the same case. The forensic heart of §17.
        for grp, evs in by_case.items():
            sources = {e.source for e in evs}
            for ev in evs:
                if ev.outcome == "success" and ev.action in self.corroboration:
                    required_source = self.corroboration[ev.action]
                    if required_source not in sources:
                        anomalies.append(
                            f"unsupported_success:{grp}:{ev.action}:no_{required_source}"
                        )

        return TimelineReport(entries=entries, duplicates_removed=duplicates, anomalies=anomalies)
