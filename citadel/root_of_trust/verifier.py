"""Root-of-Trust verifier — the independent verifier for Citadel System 21.

The **authoritative** attestation check is ``core.machine_attestation.MachineAttestationVerifier``
(the owner). This module is the *independently implemented* verifier (the Citadel rule: one owner +
one independent verifier). It re-derives the verdict with its own logic, then cross-checks the
authoritative result and flags any divergence — and adds what the core check does not:

  * **inventory membership** — an unknown platform can never be attested (so it can never receive a
    production capability via the existing roots-of-trust gate),
  * **nonce issuance + one-shot consumption** — anti-replay it owns end to end,
  * **freshness** — an attestation older than the policy max age is not valid for a capability,
  * **drift handling** — a measurement that drifts from the golden baseline emits a durable event and
    opens a case, and quarantines the platform (fail closed).

It does not grant authority. Its output maps to the machine root (``core.roots_of_trust.MachineTrust``)
which the capability broker already enforces before issuing a token.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from core import signing
from core.machine_attestation import AttestationReport, MachineAttestationVerifier, MachineVerification
from core.roots_of_trust import MachineTrust

from .inventory import PlatformInventory
from .measured_boot import BootMeasurement, boot_drift
from .revocation import quarantine
from .schemas import (
    AttestationPolicy,
    AttestationResult,
    DriftEvent,
    PlatformAttestation,
    PlatformCase,
    PlatformIdentity,
)

# Reasons that mean the platform's measured state drifted from its golden baseline (as opposed to a
# bad signature, a replay, or an unknown platform). These are what open a drift case.
_DRIFT_REASONS = frozenset(
    {"pcr_mismatch", "secure_boot_off", "firmware_not_approved", "kernel_not_approved", "ima_failed"}
)


@dataclass
class RootOfTrustVerifier:
    inventory: PlatformInventory
    policy: AttestationPolicy = field(default_factory=AttestationPolicy)
    event_sink: Callable[[DriftEvent], None] | None = None   # durable event (e.g. AuditLog)
    case_sink: Callable[[PlatformCase], None] | None = None   # opens a case for follow-up
    _nonces: dict[str, str] = field(default_factory=dict, init=False)

    # --- challenge / anti-replay -------------------------------------------------------------
    def issue_nonce(self, node_id: str) -> str:
        """Issue a fresh single-use challenge nonce binding the next quote to this round."""
        nonce = secrets.token_hex(16)
        self._nonces[node_id] = nonce
        return nonce

    # --- independent verification ------------------------------------------------------------
    def _independent_reasons(
        self, report: AttestationReport, signature: str, identity: PlatformIdentity, expected_nonce: str | None
    ) -> list[str]:
        reasons: list[str] = []
        if not signing.verify(identity.ak_public_key, report.canonical(), signature):
            reasons.append("ak_signature_invalid")
        if expected_nonce is None or report.nonce != expected_nonce:
            reasons.append("nonce_mismatch")
        boot = BootMeasurement(report.node_id, report.pcrs, report.firmware, report.kernel, report.secure_boot)
        if boot_drift(boot, identity.golden_pcrs):
            reasons.append("pcr_mismatch")
        if self.policy.require_secure_boot and not report.secure_boot:
            reasons.append("secure_boot_off")
        if report.firmware not in identity.approved_firmware:
            reasons.append("firmware_not_approved")
        if report.kernel not in identity.approved_kernels:
            reasons.append("kernel_not_approved")
        if self.policy.require_ima and not report.ima_ok:
            reasons.append("ima_failed")
        if report.quarantined:
            reasons.append("node_quarantined")
        return reasons

    def _authoritative(self, report: AttestationReport, signature: str, identity: PlatformIdentity,
                       expected_nonce: str | None) -> MachineVerification:
        owner = MachineAttestationVerifier(
            ak_public_keys={identity.node_id: identity.ak_public_key},
            golden_pcrs={identity.node_id: dict(identity.golden_pcrs)},
            approved_firmware=set(identity.approved_firmware),
            approved_kernels=set(identity.approved_kernels),
        )
        return owner.verify(report, signature, expected_nonce=expected_nonce or "")

    def attest(self, report: AttestationReport, signature: str, *, now: float) -> PlatformAttestation:
        """Independently verify a quote and produce the platform attestation verdict.

        Unknown / revoked / quarantined platforms are denied without inspecting the quote. Drift
        emits a durable event + case and quarantines the platform.
        """
        node_id = report.node_id
        identity = self.inventory.get(node_id)
        if identity is None:
            return self._verdict(node_id, ["unknown_platform"], now)
        if not identity.active:
            return self._verdict(node_id, [f"platform_{identity.status.value}"], now)

        expected_nonce = self._nonces.pop(node_id, None)   # one-shot: consume the issued challenge
        reasons = self._independent_reasons(report, signature, identity, expected_nonce)

        # Cross-check against the authoritative owner; any divergence is itself a failure.
        owner_reasons = set(self._authoritative(report, signature, identity, expected_nonce).reasons)
        if owner_reasons != set(reasons):
            reasons.append("verifier_divergence")

        # Drift: durably record, open a case, and quarantine (fail closed).
        drift = [r for r in reasons if r in _DRIFT_REASONS]
        if drift:
            self._raise_drift(node_id, tuple(drift), now)

        return self._verdict(node_id, reasons, now)

    def _verdict(self, node_id: str, reasons: list[str], now: float) -> PlatformAttestation:
        identity = self.inventory.get(node_id)
        max_age = identity.attestation_max_age_seconds if identity else self.policy.max_age_seconds
        return PlatformAttestation(
            node_id=node_id, ok=not reasons, reasons=tuple(reasons),
            attested_at=now, expires_at=now + max_age,
        )

    def _raise_drift(self, node_id: str, reasons: tuple[str, ...], now: float) -> None:
        if self.event_sink is not None:
            self.event_sink(DriftEvent(
                event_type="guardian.boot.drift", node_id=node_id, reasons=reasons, at=now,
                detail="platform measurements drifted from golden baseline",
            ))
        if self.case_sink is not None:
            self.case_sink(PlatformCase(
                case_id=str(uuid.uuid4()), node_id=node_id,
                title=f"Platform integrity drift: {node_id}", reasons=reasons,
                opened_at=now, severity="high",
            ))
        quarantine(self.inventory, node_id)

    # --- capability gate ---------------------------------------------------------------------
    def gate(self, attestation: PlatformAttestation, *, now: float) -> AttestationResult:
        """Decide whether a platform may receive a production capability right now.

        Allow only if the attestation passed AND is still fresh (not past its max age).
        """
        reasons = list(attestation.reasons)
        if attestation.ok and attestation.is_expired(now):
            reasons.append("attestation_expired")
        allow = not reasons
        return AttestationResult(allow=allow, node_id=attestation.node_id,
                                 reasons=tuple(reasons), attestation=attestation)

    def machine_trust(self, report: AttestationReport, signature: str, *, now: float) -> MachineTrust:
        """Bridge to the existing six-roots gate: produce the machine root the broker enforces.

        An unknown / failed platform yields an empty (all-false) MachineTrust, so the existing
        capability broker refuses to issue a token — unknown platforms get no production capability.
        A fully-passing attestation asserts every machine-root anchor.
        """
        attestation = self.attest(report, signature, now=now)
        if not self.gate(attestation, now=now).allow:
            return MachineTrust()
        return MachineTrust(
            secure_boot=True, tpm_attested=True, measured_boot=True,
            ima_ok=True, approved_firmware=True, not_quarantined=True,
        )


__all__ = ["RootOfTrustVerifier"]
