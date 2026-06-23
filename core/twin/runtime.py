"""Fold the real-time event fabric into the twin — runtime signals as live state.

The digital twin is *declared* topology. Reality drifts: a service talks to a database the
manifest never mentioned; a denied policy decision or a Falco syscall marks an asset as live and
hot. This module overlays the event fabric (:mod:`core.event_fabric`, Sovereign #5) onto the twin
so blast radius reflects **current** state, not just what was declared:

  * **runtime edges** — observed ``actor → target`` interactions become ephemeral graph edges, so
    reachability includes connections that actually happened, not only the ones on paper;
  * **active-risk signals** — notable events (high severity, or denied/blocked/failed outcomes)
    flag the assets they touch, and their blast radius over the live twin is "what is at risk
    right now".

The event fabric is metadata-only (it records *that* a syscall fired, never its contents), so the
overlay is too. Read-only: it explains current exposure, it changes nothing.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from core.event_fabric import EventFabric, EventSeverity, Outcome, SecurityEvent, severity_rank

from .federate import _kind_for
from .graph import DigitalTwin
from .models import AssetNode, Relationship, RelationKind

# Outcomes that make an event notable regardless of severity (something was refused / failed).
_NOTABLE_OUTCOMES: frozenset[Outcome] = frozenset(
    {Outcome.DENY, Outcome.BLOCKED, Outcome.FAILURE, Outcome.DETECTED}
)

# Normalized event verbs → the twin relation an observed interaction represents.
_ACTION_RELATION: dict[str, RelationKind] = {
    "network.connect": RelationKind.CAN_ACCESS,
    "network.flow": RelationKind.CAN_ACCESS,
    "db.read": RelationKind.READS,
    "db.write": RelationKind.WRITES,
    "pr.force_push": RelationKind.CAN_WRITE,
    "repo.write": RelationKind.CAN_WRITE,
    "deploy": RelationKind.DEPLOYS,
    "image.deploy": RelationKind.DEPLOYS,
    "image.sign": RelationKind.SIGNS,
}


def _relation_for(action: str) -> RelationKind:
    if action in _ACTION_RELATION:
        return _ACTION_RELATION[action]
    a = action.lower()
    if any(v in a for v in ("write", "push", "deploy", "modif", "delete")):
        return RelationKind.CAN_WRITE
    if "read" in a or "access" in a:
        return RelationKind.READS
    return RelationKind.CAN_ACCESS


def _notable(ev: SecurityEvent, min_rank: int) -> bool:
    return severity_rank(ev.severity) >= min_rank or (ev.outcome in _NOTABLE_OUTCOMES)


class RuntimeSignal(BaseModel):
    """An asset implicated by a notable runtime event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    asset_id: str
    action: str
    severity: EventSeverity
    outcome: Outcome | None
    actor: str | None
    ts: datetime


class LiveRisk(BaseModel):
    """The runtime view: what is hot now, the observed edges, and the live blast radius."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signals: tuple[RuntimeSignal, ...]
    runtime_edges: tuple[Relationship, ...]
    at_risk: tuple[str, ...]   # union of blast radii from flagged in-twin assets (sorted)


def _events(fabric: EventFabric, *, since: datetime | None) -> list[SecurityEvent]:
    return [se.event for se in fabric.replay() if since is None or se.event.ts >= since]


def runtime_edges(fabric: EventFabric, *, since: datetime | None = None) -> tuple[Relationship, ...]:
    """Observed ``actor → target`` interactions, as deduplicated typed edges."""
    seen: set[tuple[str, str, RelationKind]] = set()
    edges: list[Relationship] = []
    for ev in _events(fabric, since=since):
        if not ev.actor or not ev.target or ev.actor == ev.target:
            continue
        kind = _relation_for(ev.action)
        key = (ev.actor, ev.target, kind)
        if key in seen:
            continue
        seen.add(key)
        edges.append(Relationship(src=ev.actor, dst=ev.target, kind=kind))
    return tuple(edges)


def apply_runtime(
    twin: DigitalTwin, fabric: EventFabric, *, since: datetime | None = None
) -> DigitalTwin:
    """Return a NEW twin = declared twin + observed runtime edges (placeholders for unknown ids)."""
    live = DigitalTwin()
    for a in twin.assets():
        live.add_asset(a)
    existing_edges = {(r.src, r.dst, r.kind) for r in twin.relationships()}
    for r in twin.relationships():
        live.add_relationship(r)
    for edge in runtime_edges(fabric, since=since):
        for node_id in (edge.src, edge.dst):
            if node_id not in live:
                live.add_asset(AssetNode(id=node_id, kind=_kind_for(node_id), name=node_id))
        if (edge.src, edge.dst, edge.kind) not in existing_edges:
            live.add_relationship(edge)
            existing_edges.add((edge.src, edge.dst, edge.kind))
    return live


def live_risk(
    twin: DigitalTwin,
    fabric: EventFabric,
    *,
    since: datetime | None = None,
    min_severity: EventSeverity = EventSeverity.HIGH,
) -> LiveRisk:
    """Overlay the fabric on the twin and compute what is at risk right now.

    Notable events (>= ``min_severity`` or a denied/blocked/failed outcome) flag the asset they
    target; the live blast radius is the union of each flagged in-twin asset's reach over the twin
    augmented with observed runtime edges.
    """
    min_rank = severity_rank(min_severity)
    signals: list[RuntimeSignal] = []
    for ev in _events(fabric, since=since):
        if ev.target and _notable(ev, min_rank):
            signals.append(RuntimeSignal(
                asset_id=ev.target, action=ev.action, severity=ev.severity,
                outcome=ev.outcome, actor=ev.actor, ts=ev.ts,
            ))

    edges = runtime_edges(fabric, since=since)
    live = apply_runtime(twin, fabric, since=since)

    at_risk: set[str] = set()
    for sig in signals:
        if sig.asset_id in live:
            at_risk.add(sig.asset_id)
            at_risk.update(live.blast_radius(sig.asset_id).asset_ids())
    return LiveRisk(signals=tuple(signals), runtime_edges=edges, at_risk=tuple(sorted(at_risk)))
