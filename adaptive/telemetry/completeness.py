"""Telemetry-completeness authority (directive §13).

Guardian must assess the health of its own senses. A *silent sensor is not a healthy
system* — it is missing information, and missing information must lower confidence and
autonomy, never be read as "all clear". This module turns a sensor's health signals into a
``TelemetryCompleteness`` score in [0, 1] per service; that score feeds the autonomy
budget's ``telemetry_completeness`` input (``adaptive.autonomy.budgets``).

Pure and deterministic. Each deduction is recorded with a reason so an auditor can see why
Guardian trusted its telemetry less.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

# A sensor is "silent" once it is this many expected intervals late.
SILENT_INTERVALS = 3.0


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SensorHealth(BaseModel):
    """The raw health signals for one telemetry source on one service (§13)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str = Field(min_length=1)
    service: str = Field(min_length=1)
    last_event_at: datetime
    expected_interval_seconds: float = Field(gt=0.0)
    schema_version: int = Field(ge=0)
    expected_schema_version: int = Field(ge=0)
    clock_skew_seconds: float = Field(ge=0.0, default=0.0)
    data_loss_fraction: float = Field(ge=0.0, le=1.0, default=0.0)
    duplicate_fraction: float = Field(ge=0.0, le=1.0, default=0.0)
    parse_failure_fraction: float = Field(ge=0.0, le=1.0, default=0.0)
    cardinality_growth_ratio: float = Field(ge=0.0, default=1.0)  # 1.0 == stable
    collection_latency_seconds: float = Field(ge=0.0, default=0.0)
    source_authenticated: bool = True
    signature_valid: bool = True
    storage_acknowledged: bool = True


class TelemetryCompleteness(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str
    service: str
    score: float = Field(ge=0.0, le=1.0)
    silent: bool
    reasons: tuple[str, ...] = ()


def compute_completeness(
    sensor: SensorHealth, *, now: datetime | None = None
) -> TelemetryCompleteness:
    """Deterministically score one sensor's completeness. Fail-closed: unknowns reduce it."""
    now = now or _utcnow()
    score = 1.0
    reasons: list[str] = []

    def deduct(amount: float, why: str) -> None:
        nonlocal score
        score -= amount
        reasons.append(why)

    # Silence: a sensor that has stopped reporting is treated as missing information.
    age = (now - sensor.last_event_at).total_seconds()
    silent = age > SILENT_INTERVALS * sensor.expected_interval_seconds
    if silent:
        deduct(0.6, f"sensor silent: {age:.0f}s since last event "
                    f"(> {SILENT_INTERVALS}x expected interval)")
    elif age > sensor.expected_interval_seconds:
        deduct(0.1, f"sensor late: {age:.0f}s since last event")

    if sensor.schema_version != sensor.expected_schema_version:
        deduct(0.15, f"schema drift: v{sensor.schema_version} != "
                     f"expected v{sensor.expected_schema_version}")
    if not sensor.source_authenticated:
        deduct(0.5, "source not authenticated")
    if not sensor.signature_valid:
        deduct(0.5, "event signature invalid")
    if not sensor.storage_acknowledged:
        deduct(0.2, "storage did not acknowledge write")
    if sensor.clock_skew_seconds > 5.0:
        deduct(min(0.2, sensor.clock_skew_seconds / 300.0), "clock skew")
    if sensor.data_loss_fraction > 0:
        deduct(min(0.3, sensor.data_loss_fraction), f"data loss {sensor.data_loss_fraction:.2f}")
    if sensor.duplicate_fraction > 0.1:
        deduct(0.05, f"duplicates {sensor.duplicate_fraction:.2f}")
    if sensor.parse_failure_fraction > 0:
        deduct(min(0.2, sensor.parse_failure_fraction), "parse failures")
    if sensor.cardinality_growth_ratio > 5.0:
        deduct(0.1, f"cardinality growth {sensor.cardinality_growth_ratio:.1f}x")
    if sensor.collection_latency_seconds > sensor.expected_interval_seconds:
        deduct(0.05, "collection latency above expected interval")

    score = max(0.0, min(1.0, score))
    return TelemetryCompleteness(
        source=sensor.source, service=sensor.service, score=score,
        silent=silent, reasons=tuple(reasons),
    )


def service_completeness(
    sensors: list[SensorHealth], *, now: datetime | None = None
) -> float:
    """Aggregate per-service completeness as the *weakest* sensor (fail-closed).

    A service is only as observable as its blindest critical sensor; taking the minimum
    means one silent sensor lowers the whole service's score (and thus autonomy).
    """
    if not sensors:
        return 0.0  # no sensors == no observability == zero completeness
    return min(compute_completeness(s, now=now).score for s in sensors)


__all__ = [
    "SILENT_INTERVALS",
    "SensorHealth",
    "TelemetryCompleteness",
    "compute_completeness",
    "service_completeness",
]
