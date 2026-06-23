"""Level 6 §13: telemetry-completeness — a silent sensor is not a healthy system."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from adaptive.telemetry import (
    SensorHealth,
    compute_completeness,
    service_completeness,
)

NOW = datetime(2026, 6, 23, 12, 0, 0, tzinfo=timezone.utc)


def _sensor(**kw) -> SensorHealth:
    base = dict(
        source="prometheus", service="message-relay",
        last_event_at=NOW - timedelta(seconds=10),
        expected_interval_seconds=30.0, schema_version=2, expected_schema_version=2,
    )
    base.update(kw)
    return SensorHealth(**base)


def test_healthy_sensor_scores_high():
    c = compute_completeness(_sensor(), now=NOW)
    assert c.score == 1.0
    assert c.silent is False


def test_silent_sensor_is_not_healthy():
    c = compute_completeness(_sensor(last_event_at=NOW - timedelta(seconds=600)), now=NOW)
    assert c.silent is True
    assert c.score < 0.5
    assert any("silent" in r for r in c.reasons)


def test_schema_drift_lowers_score():
    c = compute_completeness(_sensor(schema_version=1, expected_schema_version=2), now=NOW)
    assert c.score < 1.0
    assert any("schema" in r for r in c.reasons)


def test_unauthenticated_or_unsigned_source_heavily_penalised():
    assert compute_completeness(_sensor(source_authenticated=False), now=NOW).score <= 0.5
    assert compute_completeness(_sensor(signature_valid=False), now=NOW).score <= 0.5


def test_data_loss_lowers_score():
    c = compute_completeness(_sensor(data_loss_fraction=0.3), now=NOW)
    assert c.score < 1.0


def test_service_completeness_is_weakest_sensor():
    good = _sensor(source="a")
    silent = _sensor(source="b", last_event_at=NOW - timedelta(seconds=600))
    score = service_completeness([good, silent], now=NOW)
    assert score == compute_completeness(silent, now=NOW).score
    assert score < 0.5


def test_no_sensors_means_zero_completeness():
    assert service_completeness([], now=NOW) == 0.0
