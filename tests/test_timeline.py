"""Tests for forensic timeline reconstruction (Sovereign plane, Wave 1, system #6)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.event_fabric import load_stream
from core.timeline import (
    Phase,
    Sketch,
    TimelineError,
    TimelineEvent,
    build_from_spec,
    classify_phase,
    from_fabric,
    from_timesketch,
    load_sketch,
    phase_rank,
)

STREAM = Path(__file__).resolve().parent.parent / "event_fabric" / "invisable-stream.yaml"
_BASE = datetime(2026, 6, 22, 22, 0, 0, tzinfo=timezone.utc)


def _te(i: int, *, phase=Phase.EXECUTION, actor=None, target=None, sec=0, key=False, sev="info"):
    return TimelineEvent(id=f"t{i}", ts=_BASE + timedelta(seconds=sec), source="opa",
                         message=f"event {i}", phase=phase, actor=actor, target=target,
                         key=key, severity=sev)


# --- models --------------------------------------------------------------------
def test_event_rejects_empty_message():
    with pytest.raises(ValueError):
        TimelineEvent(id="t", ts=_BASE, source="opa", message="  ")


def test_duplicate_event_is_refused():
    s = Sketch()
    s.add(_te(1))
    with pytest.raises(TimelineError):
        s.add(_te(1))


# --- phase classification ------------------------------------------------------
def test_classify_phase_heuristics():
    assert classify_phase("identity", "auth.session_new_asn", "observed") == Phase.INITIAL_ACCESS
    assert classify_phase("opa", "policy.production_deploy", "deny") == Phase.ESCALATION
    assert classify_phase("falco", "runtime.shell_in_container", "detected") == Phase.EXECUTION
    assert classify_phase("cilium", "network.unexpected_egress", "blocked") == Phase.EXFILTRATION
    assert classify_phase("temporal", "workflow.containment_started", "success") == Phase.CONTAINMENT
    assert classify_phase("build", "build.image_signed", "success") == Phase.BENIGN


# --- chronology / sequence reasoning -------------------------------------------
@pytest.fixture()
def sketch() -> Sketch:
    return from_fabric(load_stream(STREAM))


def test_chronology_is_ordered_with_deltas(sketch):
    beats = sketch.chronology()
    assert len(beats) == 10
    # Beats are time-ordered and indices are sequential.
    assert [b.index for b in beats] == list(range(10))
    assert all(beats[i].event.ts <= beats[i + 1].event.ts for i in range(len(beats) - 1))
    # First beat has zero delta/elapsed; elapsed is monotonic non-decreasing.
    assert beats[0].delta_seconds == 0 and beats[0].elapsed_seconds == 0
    assert all(b.elapsed_seconds >= 0 for b in beats)
    # The three denials are 20s apart.
    deny_beats = [b for b in beats if "production_deploy" in b.event.message]
    assert deny_beats[1].delta_seconds == 20


def test_for_actor_scopes_the_thread(sketch):
    beats = sketch.for_actor("id:ci-token")
    assert beats  # the token has a thread
    assert all(b.event.actor == "id:ci-token" for b in beats)
    # The Falco detection has no actor, so it is excluded from the token's thread.
    assert all(b.event.source != "falco" for b in beats)


def test_window_around_pivot(sketch):
    # Around the first denial (22:01:00), ±30s catches the other denials but not the 21:55 build.
    beats = sketch.window("opa:dec:5001", before=30, after=60)
    ids = {b.event.id for b in beats}
    assert {"opa:dec:5001", "opa:dec:5002", "opa:dec:5003"} <= ids
    assert "build:img:messaging:1042" not in ids


def test_key_events_are_the_skeleton(sketch):
    keys = sketch.key_events()  # HIGH+ by default
    # The benign build/model/identity(medium) events are not pivots; the denials/falco are.
    assert all(e.key for e in keys)
    assert any(e.id == "falco:evt:3310" for e in keys)
    assert not any(e.id == "build:img:messaging:1042" for e in keys)


def test_phases_are_lifecycle_ordered(sketch):
    phases = [b.phase for b in sketch.phases()]
    # Buckets are ordered along the lifecycle and containment comes after escalation/exfiltration.
    assert phases == sorted(phases, key=phase_rank)
    assert Phase.CONTAINMENT in phases
    assert phases.index(Phase.ESCALATION) < phases.index(Phase.CONTAINMENT)


def test_dwell_metrics(sketch):
    d = sketch.dwell()
    assert d.events == 10
    # Span from 21:55:00 (build) to 22:02:40 (model) = 460s.
    assert d.total_span_seconds == 460
    # First event is the 21:55:00 build; first containment (temporal) is 22:02:30 → 450s.
    assert d.time_to_respond_seconds == 450


def test_narrate_marks_key_events(sketch):
    story = sketch.narrate()
    assert len(story) == 10
    assert any(line.startswith("★") for line in story)  # at least one pivot is starred


# --- ingestion seam ------------------------------------------------------------
def test_build_from_spec_infers_phase_when_omitted():
    s = build_from_spec({"events": [
        {"id": "a", "ts": "2026-06-22T22:00:00Z", "source": "identity",
         "message": "auth.session_new_asn", "outcome": "observed"},
    ]})
    assert s.event("a").phase == Phase.INITIAL_ACCESS


def test_build_from_spec_explicit_phase_wins():
    s = build_from_spec({"events": [
        {"id": "a", "ts": "2026-06-22T22:00:00Z", "source": "falco",
         "message": "runtime.shell", "phase": "impact"},
    ]})
    assert s.event("a").phase == Phase.IMPACT


def test_dwell_on_empty_sketch_raises():
    with pytest.raises(TimelineError):
        Sketch().dwell()


def test_from_timesketch_fails_closed():
    with pytest.raises(NotImplementedError):
        from_timesketch()


def test_load_sketch_missing_file():
    with pytest.raises(FileNotFoundError):
        load_sketch(Path("/no/such/timeline.yaml"))
