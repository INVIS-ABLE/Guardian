"""TPM quote assembly.

Turns collected boot + runtime measurements into a signed ``AttestationReport`` (the TPM-quote
type owned by ``core.machine_attestation``). The real TPM signs the quote with its Attestation Key
(AK); ``SoftwareTpm`` is a deterministic stand-in for tests that signs with ``core.signing`` so the
full signature path is exercised offline.
"""

from __future__ import annotations

from typing import Protocol

from core import signing
from core.machine_attestation import AttestationReport

from .schemas import BootMeasurement, RuntimeMeasurement


def build_report(
    boot: BootMeasurement,
    runtime: RuntimeMeasurement,
    *,
    nonce: str,
    quarantined: bool = False,
) -> AttestationReport:
    """Assemble the canonical attestation report from independent collectors + the challenge nonce."""
    return AttestationReport(
        node_id=boot.node_id,
        nonce=nonce,
        pcrs=dict(boot.pcrs),
        firmware=boot.firmware,
        kernel=boot.kernel,
        secure_boot=boot.secure_boot,
        ima_ok=runtime.ima_ok,
        quarantined=quarantined,
    )


class TpmQuoteSource(Protocol):
    """A source of signed TPM quotes (production: real TPM/Keylime; tests: ``SoftwareTpm``)."""

    def quote(self, node_id: str, nonce: str) -> tuple[AttestationReport, str]: ...


class SoftwareTpm:
    """Deterministic software TPM: holds a node's AK private key + its current measurements, and
    produces a genuinely-signed quote bound to the challenge nonce. For tests and local runs only."""

    def __init__(
        self,
        node_id: str,
        ak_private_key: str,
        boot: BootMeasurement,
        runtime: RuntimeMeasurement,
        *,
        quarantined: bool = False,
    ) -> None:
        self.node_id = node_id
        self._ak_private = ak_private_key
        self._boot = boot
        self._runtime = runtime
        self._quarantined = quarantined

    def quote(self, node_id: str, nonce: str) -> tuple[AttestationReport, str]:
        report = build_report(self._boot, self._runtime, nonce=nonce, quarantined=self._quarantined)
        signature = signing.sign(self._ak_private, report.canonical())
        return report, signature


__all__ = ["build_report", "TpmQuoteSource", "SoftwareTpm"]
