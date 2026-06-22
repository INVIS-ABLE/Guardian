"""Tests for the real-time security event fabric (Sovereign plane, Wave 1, system #5)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.evidence.models import Classification
from core.event_fabric import (
    EventFabric,
    EventFabricError,
    EventSeverity,
    EventSource,
    Outcome,
    SecurityEvent,
    build_from_spec,
    from_redpanda,
    load_stream,
    normalize,
    normalize_opa,
)

SAMPLE = Path(__file__).resolve().parent.parent / "event_fabric" / "invisable-stream.yaml"


_BASE = datetime(2026, 6, 22, 22, 0, 0, tzinfo=timezone.utc)


def _ev(i: int, *, source=EventSource.OPA, sev=EventSeverity.INFO, actor=None, outcome=None,
        ts=None, action="x.y") -> SecurityEvent:
    return SecurityEvent(
        id=f"e{i}", ts=ts or (_BASE + timedelta(seconds=i)),
        source=source, action=action, severity=sev, actor=actor, outcome=outcome,
    )


# --- models / privacy boundary -------------------------------------------------
def test_event_refuses_private_content_classification():
    with pytest.raises(ValueError):
        SecurityEvent(id="e", ts=datetime.now(timezone.utc), source=EventSource.MODEL,
                      action="model.completion", classification=Classification.MESSAGE_PLAINTEXT)


def test_event_rejects_empty_action():
    with pytest.raises(ValueError):
        SecurityEvent(id="e", ts=datetime.now(timezone.utc), source=EventSource.OPA, action="  ")


# --- durability: ordering + hash chain -----------------------------------------
def test_append_assigns_offsets_and_chains():
    fabric = EventFabric()
    a = fabric.append(_ev(1))
    b = fabric.append(_ev(2))
    assert (a.offset, b.offset) == (0, 1)
    assert b.digest != a.digest
    assert fabric.verify() is True


def test_verify_detects_tampering():
    fabric = EventFabric()
    fabric.extend([_ev(1), _ev(2), _ev(3)])
    assert fabric.verify() is True
    # Mutate a stored event's payload in place (bypassing append) — chain must break.
    bad = fabric._log[1].model_copy(update={"event": _ev(99)})
    fabric._log[1] = bad
    assert fabric.verify() is False


def test_replay_from_offset():
    fabric = EventFabric()
    fabric.extend([_ev(i) for i in range(5)])
    assert [s.offset for s in fabric.replay(2)] == [2, 3, 4]
    with pytest.raises(EventFabricError):
        fabric.replay(99)


# --- analytical queries --------------------------------------------------------
@pytest.fixture()
def sample() -> EventFabric:
    return load_stream(SAMPLE)


def test_query_filters(sample):
    highs = sample.query(min_severity=EventSeverity.HIGH)
    assert all(s.event.severity in {EventSeverity.HIGH, EventSeverity.CRITICAL} for s in highs)
    opa_denies = sample.query(source=EventSource.OPA, outcome=Outcome.DENY)
    assert len(opa_denies) == 3
    assert all(s.event.actor == "id:ci-token" for s in opa_denies)


def test_query_time_window(sample):
    window = sample.query(
        since=datetime(2026, 6, 22, 22, 1, 0, tzinfo=timezone.utc),
        until=datetime(2026, 6, 22, 22, 1, 59, tzinfo=timezone.utc),
    )
    assert {s.event.id for s in window} == {"opa:dec:5001", "opa:dec:5002", "opa:dec:5003"}


def test_counts_by(sample):
    by_source = sample.counts_by("source")
    assert by_source["opa"] == 3
    assert sum(by_source.values()) == len(sample)
    assert sample.counts_by("outcome")["deny"] == 3
    with pytest.raises(EventFabricError):
        sample.counts_by("nonsense")


# --- spike detection -----------------------------------------------------------
def test_spikes_detects_denial_burst(sample):
    spikes = sample.spikes(window_seconds=60, threshold=3, outcome=Outcome.DENY)
    assert len(spikes) == 1
    assert spikes[0].actor == "id:ci-token"
    assert spikes[0].count == 3


def test_spikes_respects_window():
    fabric = EventFabric()
    # Three denials spread over 5 minutes — never 3 within a 60s window.
    for i, sec in enumerate([0, 150, 300]):
        fabric.append(_ev(i, actor="id:x", outcome=Outcome.DENY, ts=_BASE + timedelta(seconds=sec)))
    assert fabric.spikes(window_seconds=60, threshold=3, outcome=Outcome.DENY) == ()


def test_spikes_validates_args(sample):
    with pytest.raises(EventFabricError):
        sample.spikes(window_seconds=0, threshold=3)


# --- normalizers (one stream from many sources) --------------------------------
def test_normalize_opa_deny():
    raw = {
        "decision_id": "d1", "timestamp": "2026-06-22T22:01:00Z", "path": "production_deploy",
        "result": {"allow": False}, "input": {"actor": "id:ci-token", "resource": "svc:relay"},
    }
    e = normalize_opa(raw)
    assert e.source == EventSource.OPA and e.outcome == Outcome.DENY
    assert e.severity == EventSeverity.HIGH and e.actor == "id:ci-token"
    assert e.action == "policy.production_deploy"


def test_normalize_dispatch_and_unknown_source():
    raw = {"decision_id": "d", "timestamp": "2026-06-22T22:00:00Z", "result": {"allow": True}}
    assert normalize(EventSource.OPA, raw).outcome == Outcome.ALLOW
    with pytest.raises(NotImplementedError):
        normalize(EventSource.CILIUM, {})  # no normalizer yet


# --- ingestion seam ------------------------------------------------------------
def test_sample_loads_and_verifies(sample):
    assert len(sample) == 10
    assert sample.verify() is True


def test_build_from_spec_roundtrip():
    fabric = build_from_spec({"events": [
        {"id": "a", "ts": "2026-06-22T00:00:00Z", "source": "opa", "action": "policy.x"},
    ]})
    assert len(fabric) == 1


def test_from_redpanda_fails_closed():
    with pytest.raises(NotImplementedError):
        from_redpanda()


def test_load_stream_missing_file():
    with pytest.raises(FileNotFoundError):
        load_stream(Path("/no/such/stream.yaml"))
