"""Timeline ingestion — reconstruct a sketch from the event fabric, a spec, or Timesketch.

The capstone's primary input is the event fabric (#5): :func:`from_fabric` turns a stream of
normalized :class:`~core.event_fabric.SecurityEvent` into forensic :class:`TimelineEvent`s,
synthesizing a human-readable message and inferring an intrusion :class:`Phase` for each. It
also accepts an explicit spec/YAML (:func:`build_from_spec`, :func:`load_sketch`) for
standalone timelines, and :func:`from_timesketch` is the production seam (fails closed).

Phase inference (:func:`classify_phase`) is a transparent heuristic over the canonical
``source``/``action``/``outcome`` so the chronology auto-buckets into recon → … → containment;
an explicit ``phase`` in a spec always wins.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from core.event_fabric import EventFabric, Outcome, SecurityEvent

from .models import EventSeverity, Phase, TimelineEvent
from .sketch import Sketch


def classify_phase(source: str, action: str, outcome: str | None) -> Phase:
    """Infer an intrusion phase from a canonical event. Transparent, keyword-based, fail-soft."""
    a = action.lower()
    if source == "temporal" or any(k in a for k in ("containment", "isolate", "quarantine", "response")):
        return Phase.CONTAINMENT
    if source == "cilium" or "egress" in a or "exfil" in a:
        return Phase.EXFILTRATION
    if source == "falco" or any(k in a for k in ("shell", "exec", "runtime", "tamper")):
        return Phase.EXECUTION
    if "escalat" in a or "assume" in a or (source == "opa" and outcome == Outcome.DENY.value):
        return Phase.ESCALATION
    if source == "identity" or any(k in a for k in ("auth", "session", "login", "credential")):
        return Phase.INITIAL_ACCESS
    if "force_push" in a or "write" in a:
        return Phase.EXECUTION
    if any(k in a for k in ("scan", "recon", "enumerate", "probe")):
        return Phase.RECON
    if source in ("build", "model"):
        return Phase.BENIGN
    return Phase.EXECUTION


def _message(event: SecurityEvent) -> str:
    """Synthesize a human-readable account from a canonical event."""
    parts = [event.action]
    if event.outcome is not None:
        parts.append(f"→ {event.outcome.value.upper()}")
    return " ".join(parts)


def from_fabric(fabric: EventFabric) -> Sketch:
    """Reconstruct a forensic sketch from an event-fabric stream (the #5 → #6 integration).

    Each event becomes a TimelineEvent with a synthesized message and inferred phase; HIGH+
    severity events are flagged as key (story pivots).
    """
    sketch = Sketch()
    for stored in fabric:
        e = stored.event
        phase = classify_phase(e.source.value, e.action, e.outcome.value if e.outcome else None)
        sketch.add(TimelineEvent(
            id=e.id, ts=e.ts, source=e.source.value, message=_message(e),
            severity=e.severity, actor=e.actor, target=e.target, phase=phase,
            key=e.severity in (EventSeverity.HIGH, EventSeverity.CRITICAL),
            tags=tuple(f"{k}={v}" for k, v in sorted(e.labels.items())),
        ))
    return sketch


def build_from_spec(spec: dict[str, Any]) -> Sketch:
    """Build a sketch from an explicit ``{events: [...]}`` mapping of timeline events.

    Each event may set ``phase`` explicitly; if omitted, it is inferred from source/action.
    """
    sketch = Sketch()
    for raw in spec.get("events", []):
        data = dict(raw)
        if "phase" not in data:
            data["phase"] = classify_phase(
                data.get("source", ""), data.get("message", data.get("action", "")), data.get("outcome"),
            )
        data.pop("outcome", None)  # 'outcome' is an inference hint only, not a TimelineEvent field
        sketch.add(TimelineEvent(**data))
    return sketch


def load_sketch(path: str | Path) -> Sketch:
    """Load a sketch from a YAML spec of timeline events."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"timeline spec not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return build_from_spec(data)


def from_timesketch(_config: Any | None = None) -> Sketch:
    """Populate a sketch from the production source (Timesketch).

    Not yet wired. Fails closed so a production caller never reasons over a silently-empty
    chronology: an empty timeline would falsely imply "nothing happened in sequence". Until the
    source is provisioned, reconstruct from the event fabric (:func:`from_fabric`) or a spec.
    """
    raise NotImplementedError(
        "Timesketch ingestion is not wired yet; reconstruct from the event fabric (from_fabric) "
        "or an explicit spec (build_from_spec/load_sketch). Set GUARDIAN_ENV=development to use "
        "spec-based sketches."
    )


def production_source_required() -> bool:
    """Whether a real timeline source is required (staging/production), mirroring the policy gate."""
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in {"staging", "production"}
