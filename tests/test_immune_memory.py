"""Level 6 §21: immune memory with decaying trust."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from adaptive.memory import ImmuneMemory, ImmuneMemoryItem, MemoryClass

NOW = datetime(2026, 6, 23, 12, 0, 0, tzinfo=timezone.utc)


def _item(**kw) -> ImmuneMemoryItem:
    base = dict(
        memory_class=MemoryClass.KNOWN_GOOD, summary="baseline config", provenance="scan:123",
        confidence=1.0, created_at=NOW, last_validated_at=NOW, half_life_days=30.0,
    )
    base.update(kw)
    return ImmuneMemoryItem(**base)


def test_fresh_item_keeps_confidence():
    assert _item().effective_trust(now=NOW) == 1.0


def test_trust_decays_without_revalidation():
    it = _item()
    # one half-life later -> ~0.5
    later = NOW + timedelta(days=30)
    assert abs(it.effective_trust(now=later) - 0.5) < 1e-6
    # two half-lives -> ~0.25
    assert abs(it.effective_trust(now=NOW + timedelta(days=60)) - 0.25) < 1e-6


def test_retracted_item_has_zero_trust():
    assert _item(retracted=True).effective_trust(now=NOW) == 0.0


def test_expired_item_has_zero_trust():
    it = _item(expires_at=NOW + timedelta(days=1))
    assert it.effective_trust(now=NOW + timedelta(days=2)) == 0.0


def test_revalidation_resets_decay():
    mem = ImmuneMemory()
    it = _item()
    mem.add(it)
    later = NOW + timedelta(days=30)
    assert abs(mem.get(it.item_id).effective_trust(now=later) - 0.5) < 1e-6
    mem.revalidate(it.item_id, now=later)
    # immediately after revalidation, full trust again
    assert mem.get(it.item_id).effective_trust(now=later) == 1.0


def test_live_items_filters_by_class_and_trust():
    mem = ImmuneMemory()
    good = _item(memory_class=MemoryClass.KNOWN_GOOD)
    incident = _item(memory_class=MemoryClass.INCIDENT, summary="confirmed incident")
    stale = _item(summary="old", last_validated_at=NOW - timedelta(days=120))
    for x in (good, incident, stale):
        mem.add(x)
    known = mem.live_items(MemoryClass.KNOWN_GOOD, min_trust=0.5, now=NOW)
    names = {i.summary for i in known}
    assert "baseline config" in names and "old" not in names
    assert all(i.memory_class is MemoryClass.KNOWN_GOOD for i in known)
