"""Tests for the runtime-triggered investigation pipeline (event fabric → council)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from core.event_fabric import (
    EventFabric,
    EventSeverity,
    EventSource,
    Outcome,
    SecurityEvent,
    load_stream,
)
from core.reasoning import investigate
from core.twin import AssetKind, AssetNode, DigitalTwin, RelationKind, Relationship, load_twin

ROOT = Path(__file__).resolve().parent.parent
TWIN = ROOT / "twin" / "invisable-sample.yaml"
STREAM = ROOT / "event_fabric" / "invisable-stream.yaml"


def _ev(action, *, target, severity=EventSeverity.CRITICAL, outcome=Outcome.DETECTED, n=0):
    return SecurityEvent(
        id=f"e:{n}", ts=datetime(2026, 6, 22, 22, n % 60, tzinfo=timezone.utc),
        source=EventSource.FALCO, action=action, severity=severity, outcome=outcome,
        target=target,
    )


def _twin() -> DigitalTwin:
    t = DigitalTwin()
    t.add_asset(AssetNode(id="svc", kind=AssetKind.SERVICE, name="svc"))
    t.add_asset(AssetNode(id="db", kind=AssetKind.DATABASE, name="db"))
    t.add_asset(AssetNode(id="data", kind=AssetKind.DATA_CLASS, name="d", classification="health"))
    t.add_relationship(Relationship(src="svc", dst="db", kind=RelationKind.READS))
    t.add_relationship(Relationship(src="db", dst="data", kind=RelationKind.STORES))
    return t


def test_no_signal_means_not_triggered():
    v = investigate(_twin(), EventFabric())
    assert v.triggered is False and v.requires_human is False


def test_live_signal_triggers_and_escalates_to_human():
    f = EventFabric()
    f.append(_ev("runtime.shell_in_container", target="svc"))
    v = investigate(_twin(), f)
    assert v.triggered
    # A raw sensor signal is unverified tool output ⇒ the council can't confirm ⇒ escalate.
    assert v.decision == "insufficient_evidence" and v.requires_human


def test_incident_identifies_the_sensitive_sink_reached():
    f = EventFabric()
    f.append(_ev("runtime.shell_in_container", target="svc"))
    v = investigate(_twin(), f)
    assert v.target_sink == "data"                 # the health data class, reached from svc
    assert {"svc", "db", "data"} <= set(v.at_risk)


def test_low_noise_does_not_trigger():
    f = EventFabric()
    f.append(_ev("noise", target="svc", severity=EventSeverity.LOW, outcome=Outcome.OBSERVED))
    assert investigate(_twin(), f).triggered is False


def test_never_executes_only_escalates():
    # The verdict is advisory: there is no "execute"/"contain" decision in the type.
    v = investigate(_twin(), EventFabric())
    assert v.decision in {"proceed", "insufficient_evidence", "contradicted", "escalate"}


def test_end_to_end_over_samples_reaches_ciphertext_and_escalates():
    v = investigate(load_twin(TWIN), load_stream(STREAM))
    assert v.triggered and v.requires_human
    assert v.target_sink == "data:ciphertext"
    assert "data:ciphertext" in v.at_risk and "db:mailbox" in v.at_risk
