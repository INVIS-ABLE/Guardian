"""Telemetry-quality authority (directive §13)."""

from .completeness import (
    SILENT_INTERVALS,
    SensorHealth,
    TelemetryCompleteness,
    compute_completeness,
    service_completeness,
)

__all__ = [
    "SILENT_INTERVALS",
    "SensorHealth",
    "TelemetryCompleteness",
    "compute_completeness",
    "service_completeness",
]
