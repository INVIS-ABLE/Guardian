"""Linux IMA/EVM runtime-integrity collection.

Collects the runtime measurement (IMA log state) from a source. In production this reads the IMA
measurement list and verifies the EVM-protected aggregate; here the contract — an ``ima_ok`` verdict
plus the log hash that anchors it — is what the verifier consumes.
"""

from __future__ import annotations

from typing import Protocol

from .schemas import RuntimeMeasurement


class RuntimeSource(Protocol):
    """A source of runtime-integrity measurements (production: IMA/EVM; tests: a stub)."""

    def read_runtime(self, node_id: str) -> RuntimeMeasurement: ...


def collect_runtime_measurement(source: RuntimeSource, node_id: str) -> RuntimeMeasurement:
    return source.read_runtime(node_id)


def runtime_intact(measurement: RuntimeMeasurement) -> bool:
    """A runtime measurement is intact only if IMA reports OK *and* carries an anchoring log hash."""
    return measurement.ima_ok and bool(measurement.ima_log_hash)


__all__ = ["RuntimeSource", "collect_runtime_measurement", "runtime_intact"]
