"""Measured-boot / Secure Boot collection.

Collects the platform's boot measurements (TPM PCRs + firmware/kernel + Secure Boot state) from a
source, and compares them against the enrolled golden baseline. ``boot_drift`` is the primitive the
verifier uses to detect — and durably record — platform drift.
"""

from __future__ import annotations

from typing import Protocol

from .schemas import BootMeasurement


class BootSource(Protocol):
    """A source of boot measurements (production: TPM event log via Keylime/IMA; tests: a stub)."""

    def read_boot(self, node_id: str) -> BootMeasurement: ...


def collect_boot_measurement(source: BootSource, node_id: str) -> BootMeasurement:
    return source.read_boot(node_id)


def boot_drift(measurement: BootMeasurement, golden_pcrs: dict[str, str]) -> tuple[str, ...]:
    """Return the set of drift reasons: which PCRs differ from (or are missing vs.) the baseline.

    A missing golden baseline is itself drift (we cannot prove integrity against nothing).
    """
    if not golden_pcrs:
        return ("no_golden_baseline",)
    reasons: list[str] = []
    for index, golden in sorted(golden_pcrs.items()):
        if measurement.pcrs.get(index) != golden:
            reasons.append(f"pcr{index}_drift")
    # Extra, unexpected PCRs the baseline does not cover are also drift.
    for index in sorted(set(measurement.pcrs) - set(golden_pcrs)):
        reasons.append(f"pcr{index}_unexpected")
    return tuple(reasons)


__all__ = ["BootSource", "collect_boot_measurement", "boot_drift"]
