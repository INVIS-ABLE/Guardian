"""Tests for folding the event fabric into the twin (runtime signals as live state)."""

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
from core.twin import (
    AssetKind,
    AssetNode,
    DigitalTwin,
    RelationKind,
    Relationship,
    apply_runtime,
    live_risk,
    load_twin,
    runtime_edges,
)

ROOT = Path(__file__).resolve().parent.parent
TWIN = ROOT / "twin" / "invisable-sample.yaml"
STREAM = ROOT / "event_fabric" / "invisable-stream.yaml"


def _ev(action, *, target=None, actor=None, severity=EventSeverity.INFO, outcome=None, n=0):
    return SecurityEvent(
        id=f"e:{action}:{n}", ts=datetime(2026, 6, 22, 22, n % 60, tzinfo=timezone.utc),
        source=EventSource.FALCO, action=action, severity=severity, outcome=outcome,
        actor=actor, target=target,
    )


def _small_twin() -> DigitalTwin:
    t = DigitalTwin()
    t.add_asset(AssetNode(id="svc", kind=AssetKind.SERVICE, name="svc"))
    t.add_asset(AssetNode(id="db", kind=AssetKind.DATABASE, name="db"))
    t.add_asset(AssetNode(id="data", kind=AssetKind.DATA_CLASS, name="d", classification="health"))
    t.add_relationship(Relationship(src="svc", dst="db", kind=RelationKind.READS))
    t.add_relationship(Relationship(src="db", dst="data", kind=RelationKind.STORES))
    return t


# --- runtime edges -------------------------------------------------------------
def test_runtime_edges_are_observed_interactions():
    f = EventFabric()
    f.append(_ev("network.connect", actor="svc", target="db"))
    edges = runtime_edges(f)
    assert len(edges) == 1
    assert (edges[0].src, edges[0].dst, edges[0].kind) == ("svc", "db", RelationKind.CAN_ACCESS)


def test_runtime_edges_dedup_and_skip_self_and_actorless():
    f = EventFabric()
    f.extend([
        _ev("db.read", actor="svc", target="db", n=1),
        _ev("db.read", actor="svc", target="db", n=2),   # duplicate
        _ev("x", actor="svc", target="svc", n=3),        # self-edge, skipped
        _ev("y", target="db", n=4),                      # no actor, skipped
    ])
    assert len(runtime_edges(f)) == 1


def test_apply_runtime_augments_reachability():
    twin = DigitalTwin()
    twin.add_asset(AssetNode(id="attacker", kind=AssetKind.IDENTITY, name="a", subtype="machine"))
    twin.add_asset(AssetNode(id="db", kind=AssetKind.DATABASE, name="db"))
    # No declared edge attacker→db; an observed connection makes db reachable.
    f = EventFabric()
    f.append(_ev("network.connect", actor="attacker", target="db"))
    assert "db" not in set(twin.blast_radius("attacker").asset_ids())
    live = apply_runtime(twin, f)
    assert "db" in set(live.blast_radius("attacker").asset_ids())


def test_apply_runtime_does_not_mutate_input():
    twin = _small_twin()
    before = len(twin.relationships())
    f = EventFabric()
    f.append(_ev("network.connect", actor="svc", target="data"))
    apply_runtime(twin, f)
    assert len(twin.relationships()) == before


# --- live risk -----------------------------------------------------------------
def test_live_risk_flags_notable_events_only():
    t = _small_twin()
    f = EventFabric()
    f.extend([
        _ev("noise", target="svc", severity=EventSeverity.LOW, outcome=Outcome.OBSERVED, n=1),
        _ev("runtime.shell", target="svc", severity=EventSeverity.CRITICAL,
            outcome=Outcome.DETECTED, n=2),
    ])
    risk = live_risk(t, f)
    assert [s.action for s in risk.signals] == ["runtime.shell"]   # the low/observed one is dropped


def test_denied_outcome_is_notable_even_at_low_severity():
    t = _small_twin()
    f = EventFabric()
    f.append(_ev("policy.deploy", target="svc", severity=EventSeverity.MEDIUM, outcome=Outcome.DENY))
    risk = live_risk(t, f)   # default min_severity=HIGH, but a DENY is notable regardless
    assert len(risk.signals) == 1


def test_live_risk_computes_blast_radius_of_flagged_assets():
    t = _small_twin()
    f = EventFabric()
    f.append(_ev("runtime.shell", target="svc", severity=EventSeverity.CRITICAL,
                 outcome=Outcome.DETECTED))
    risk = live_risk(t, f)
    # svc is hot ⇒ db and the health data class are at risk now.
    assert set(risk.at_risk) == {"svc", "db", "data"}


def test_live_risk_over_samples_reaches_crown_jewels():
    risk = live_risk(load_twin(TWIN), load_stream(STREAM))
    assert "data:ciphertext" in risk.at_risk and "db:mailbox" in risk.at_risk
