"""Event-fabric ingestion — normalize heterogeneous sources, or consume Redpanda/ClickHouse.

The fabric's job is to collapse many raw signal shapes into one canonical :class:`SecurityEvent`.
This module provides:

  * per-source **normalizers** (``normalize_opa``, ``normalize_github``, ``normalize_falco``,
    ``normalize_model``) and a :func:`normalize` dispatcher — each maps a source's raw payload to
    the canonical shape, demonstrating the "one stream from many sources" unification;
  * spec/YAML builders (:func:`build_from_spec`, :func:`load_stream`) for already-canonical
    events (development/CI and the committed sample); and
  * :func:`from_redpanda`, the production seam, which fails closed.

In production the canonical stream is produced by **Redpanda** (durable log) and queried from
**ClickHouse** (analytical store). Normalizers run at the edge as events arrive.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

import yaml

from .models import EventSeverity, EventSource, Outcome, SecurityEvent
from .stream import EventFabric


def normalize_opa(raw: dict[str, Any]) -> SecurityEvent:
    """OPA decision log → canonical event. ``result.allow`` drives severity/outcome."""
    allow = bool(raw.get("result", {}).get("allow", False))
    return SecurityEvent(
        id=raw["decision_id"],
        ts=raw["timestamp"],
        source=EventSource.OPA,
        action=f"policy.{raw.get('path', 'decision')}",
        severity=EventSeverity.INFO if allow else EventSeverity.HIGH,
        outcome=Outcome.ALLOW if allow else Outcome.DENY,
        actor=raw.get("input", {}).get("actor"),
        target=raw.get("input", {}).get("resource"),
        labels={"query": str(raw.get("path", ""))},
    )


def normalize_github(raw: dict[str, Any]) -> SecurityEvent:
    """GitHub webhook → canonical event. A force-push is escalated."""
    action = raw.get("action", "event")
    forced = bool(raw.get("forced", False))
    return SecurityEvent(
        id=raw["delivery_id"],
        ts=raw["timestamp"],
        source=EventSource.GITHUB,
        action="pr.force_push" if forced else f"github.{action}",
        severity=EventSeverity.HIGH if forced else EventSeverity.LOW,
        outcome=Outcome.OBSERVED,
        actor=raw.get("sender"),
        target=raw.get("repository"),
    )


def normalize_falco(raw: dict[str, Any]) -> SecurityEvent:
    """Falco runtime alert → canonical event. Falco priority maps to severity."""
    priority = str(raw.get("priority", "Notice")).lower()
    sev = {
        "emergency": EventSeverity.CRITICAL, "alert": EventSeverity.CRITICAL,
        "critical": EventSeverity.CRITICAL, "error": EventSeverity.HIGH,
        "warning": EventSeverity.MEDIUM, "notice": EventSeverity.LOW,
    }.get(priority, EventSeverity.LOW)
    return SecurityEvent(
        id=raw["uuid"],
        ts=raw["time"],
        source=EventSource.FALCO,
        action=f"runtime.{raw.get('rule', 'alert').lower().replace(' ', '_')}",
        severity=sev,
        outcome=Outcome.DETECTED,
        target=raw.get("output_fields", {}).get("container.id"),
        labels={"rule": str(raw.get("rule", ""))},
    )


def normalize_model(raw: dict[str, Any]) -> SecurityEvent:
    """Model-gateway event → canonical event (a reasoning/tool-call record, metadata only)."""
    return SecurityEvent(
        id=raw["call_id"],
        ts=raw["timestamp"],
        source=EventSource.MODEL,
        action=f"model.{raw.get('kind', 'completion')}",
        severity=EventSeverity.INFO,
        outcome=Outcome.SUCCESS if raw.get("ok", True) else Outcome.FAILURE,
        actor=raw.get("agent"),
        labels={"model": str(raw.get("model", ""))},
    )


NORMALIZERS: dict[EventSource, Callable[[dict[str, Any]], SecurityEvent]] = {
    EventSource.OPA: normalize_opa,
    EventSource.GITHUB: normalize_github,
    EventSource.FALCO: normalize_falco,
    EventSource.MODEL: normalize_model,
}


def normalize(source: EventSource, raw: dict[str, Any]) -> SecurityEvent:
    """Dispatch a raw payload to its source normalizer."""
    try:
        return NORMALIZERS[source](raw)
    except KeyError as exc:
        raise NotImplementedError(
            f"no normalizer for source '{source.value}' yet; supply a canonical SecurityEvent "
            "via build_from_spec, or add a normalizer"
        ) from exc


def build_from_spec(spec: dict[str, Any]) -> EventFabric:
    """Build a fabric from a ``{events: [ ... ]}`` mapping of already-canonical events."""
    fabric = EventFabric()
    fabric.extend(SecurityEvent(**e) for e in spec.get("events", []))
    return fabric


def load_stream(path: str | Path) -> EventFabric:
    """Load a fabric from a YAML stream spec."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"event stream spec not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return build_from_spec(data)


def from_redpanda(_config: Any | None = None) -> EventFabric:
    """Populate the fabric from the production source (Redpanda stream → ClickHouse store).

    Not yet wired. Fails closed so a production caller never reasons over a silently-empty
    stream: an empty fabric would falsely imply "no security events" — blinding the nervous
    system. Until the source is provisioned, callers must supply events explicitly.
    """
    raise NotImplementedError(
        "Redpanda/ClickHouse ingestion is not wired yet; build the stream from canonical events "
        "(build_from_spec/load_stream) or normalize raw payloads (normalize). Set "
        "GUARDIAN_ENV=development to use spec-based streams."
    )


def production_source_required() -> bool:
    """Whether a real event source is required (staging/production), mirroring the policy gate."""
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in {"staging", "production"}
