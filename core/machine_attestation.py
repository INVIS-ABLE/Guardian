"""Machine attestation — remote-attestation verification for the machine root.

Models TPM/Keylime-style remote attestation: a node produces a quote over its boot/runtime
measurements (PCRs) plus a challenge nonce, signed by its Attestation Key (AK). The verifier
checks, independently and fail-closed:

  * the **AK signature** over the canonical report (only a genuine node can produce it),
  * the **nonce** matches the one we issued (anti-replay — a stale quote is rejected),
  * the **PCRs** match the approved golden measurements (Secure Boot / measured boot integrity),
  * **firmware** and **kernel** are on the approved allow-list,
  * **IMA** runtime measurement is intact, and the node is **not quarantined**.

The cryptographic primitive + golden-PCR comparison is real (via ``core.signing``); in
production the quote comes from a real TPM and the AK keys are enrolled out of band. The
verification logic is the point. Maps to the machine root via
``core.trust_producers.machine_trust_from_verification``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import signing


@dataclass(frozen=True)
class AttestationReport:
    """A node's signed measurements (a TPM-quote stand-in). Public, non-secret."""

    node_id: str
    nonce: str                       # the challenge we issued; binds the quote to this round
    pcrs: dict[str, str]             # PCR index -> sha256 digest
    firmware: str
    kernel: str
    secure_boot: bool = False
    ima_ok: bool = False
    quarantined: bool = True         # fail-closed default: a node is untrusted until proven

    def canonical(self) -> bytes:
        return json.dumps(
            {
                "node_id": self.node_id, "nonce": self.nonce, "pcrs": self.pcrs,
                "firmware": self.firmware, "kernel": self.kernel,
                "secure_boot": self.secure_boot, "ima_ok": self.ima_ok,
                "quarantined": self.quarantined,
            },
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")


@dataclass(frozen=True)
class MachineVerification:
    ok: bool
    node_id: str
    reasons: tuple[str, ...] = ()


@dataclass
class MachineAttestationVerifier:
    """Verifies attestation quotes against enrolled AK keys + golden measurements."""

    ak_public_keys: dict[str, str] = field(default_factory=dict)   # node_id -> AK public key (hex)
    golden_pcrs: dict[str, dict[str, str]] = field(default_factory=dict)  # node_id|"*" -> golden PCRs
    approved_firmware: set[str] = field(default_factory=set)
    approved_kernels: set[str] = field(default_factory=set)

    def verify(
        self, report: AttestationReport, signature: str, *, expected_nonce: str
    ) -> MachineVerification:
        reasons: list[str] = []

        pub = self.ak_public_keys.get(report.node_id)
        if not pub or not signing.verify(pub, report.canonical(), signature):
            reasons.append("ak_signature_invalid")
        if report.nonce != expected_nonce:
            reasons.append("nonce_mismatch")   # replayed or stale quote

        golden = self.golden_pcrs.get(report.node_id) or self.golden_pcrs.get("*")
        if golden is None or report.pcrs != golden:
            reasons.append("pcr_mismatch")     # measured/secure-boot integrity broken
        if not report.secure_boot:
            reasons.append("secure_boot_off")
        if report.firmware not in self.approved_firmware:
            reasons.append("firmware_not_approved")
        if report.kernel not in self.approved_kernels:
            reasons.append("kernel_not_approved")
        if not report.ima_ok:
            reasons.append("ima_failed")
        if report.quarantined:
            reasons.append("node_quarantined")

        return MachineVerification(ok=not reasons, node_id=report.node_id, reasons=tuple(reasons))


__all__ = ["AttestationReport", "MachineVerification", "MachineAttestationVerifier"]
