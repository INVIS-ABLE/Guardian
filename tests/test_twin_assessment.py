"""Tests for the PR-time blast-radius assessment gate (core/twin/assessment)."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.twin import (
    AssetKind,
    Severity,
    TwinError,
    assess_change,
    load_twin,
)

SAMPLE = Path(__file__).resolve().parent.parent / "twin" / "invisable-sample.yaml"


@pytest.fixture()
def sample():
    return load_twin(SAMPLE)


def test_severity_is_ordered():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.NONE


def test_severity_from_label_roundtrip():
    assert Severity.from_label("high") is Severity.HIGH
    with pytest.raises(ValueError):
        Severity.from_label("spicy")


def test_ci_token_change_reaches_confidential_data(sample):
    # The sample's ciphertext data class is CONFIDENTIAL → reaching it is HIGH.
    result = assess_change(sample, ["id:ci-token"])
    assert result.severity == Severity.HIGH
    a = result.assessments[0]
    reasons = " | ".join(h.reason for h in a.hits)
    assert "data class" in reasons and "data store" in reasons
    # Hits carry the explanatory path so a reviewer sees HOW the change reaches the sink.
    db_hit = next(h for h in a.hits if h.asset.kind == AssetKind.DATABASE)
    assert db_hit.path[-1].asset == "db:mailbox"


def test_gate_fails_on_threshold(sample):
    result = assess_change(sample, ["id:ci-token"])
    assert result.breaches(Severity.HIGH) is True
    assert result.breaches(Severity.CRITICAL) is False  # nothing reaches regulated data here


def test_isolated_change_is_clean(sample):
    # The exposed API is a leaf — compromising it reaches no sensitive sink.
    result = assess_change(sample, ["api:messaging"])
    assert result.severity == Severity.NONE
    assert result.breaches(Severity.LOW) is False


def test_health_data_is_critical():
    twin = load_twin(SAMPLE)  # reuse loader; build a tiny health-bearing graph via spec instead
    from core.twin import build_from_spec

    twin = build_from_spec({
        "assets": [
            {"id": "svc:export", "kind": "service", "name": "Export API"},
            {"id": "db:health", "kind": "database", "name": "Health store"},
            {"id": "data:phr", "kind": "data_class", "name": "Patient records",
             "classification": "health"},
        ],
        "relationships": [
            {"src": "svc:export", "dst": "db:health", "kind": "reads"},
            {"src": "db:health", "dst": "data:phr", "kind": "stores"},
        ],
    })
    result = assess_change(twin, ["svc:export"])
    assert result.severity == Severity.CRITICAL
    assert result.breaches(Severity.CRITICAL) is True


def test_unknown_changed_asset_raises(sample):
    # A typo must not silently produce a clean bill of health.
    with pytest.raises(TwinError):
        assess_change(sample, ["repo:does-not-exist"])


def test_multiple_changed_assets_take_the_worst(sample):
    result = assess_change(sample, ["api:messaging", "id:ci-token"])
    assert result.severity == Severity.HIGH  # max across the change set
    assert len(result.assessments) == 2
