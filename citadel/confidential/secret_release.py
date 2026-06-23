"""Attestation-bound secret release (Citadel System 22).

A secret is sealed to an EXACT workload measurement. It is released only when a worker presents a
passing workload attestation whose measurement equals the one the secret was sealed to. A failed
attestation — or the right attestation but the wrong measurement — releases nothing. The broker
never holds plaintext for an unattested workload (fail closed). No private-message content here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .attestation import WorkloadAttestation


class SecretReleaseDenied(Exception):
    """Raised when a secret cannot be released (failed/empty attestation or measurement mismatch)."""

    def __init__(self, secret_id: str, reasons: tuple[str, ...]):
        self.secret_id = secret_id
        self.reasons = reasons
        super().__init__(f"secret {secret_id} not released: {', '.join(reasons)}")


@dataclass(frozen=True)
class SealedSecret:
    """A secret bound to one workload measurement. ``material`` is opaque (e.g. a wrapped key)."""

    secret_id: str
    bound_measurement: str
    material: str


@dataclass(frozen=True)
class SecretReleaseResult:
    allowed: bool
    secret_id: str
    worker_id: str
    reasons: tuple[str, ...]
    material: str | None = None


class SecretBroker:
    """Holds sealed secrets and releases them only against a matching, passing attestation."""

    def __init__(self) -> None:
        self._secrets: dict[str, SealedSecret] = {}

    def seal(self, secret_id: str, *, bound_measurement: str, material: str) -> SealedSecret:
        sealed = SealedSecret(secret_id=secret_id, bound_measurement=bound_measurement, material=material)
        self._secrets[secret_id] = sealed
        return sealed

    def evaluate(self, secret_id: str, attestation: WorkloadAttestation) -> SecretReleaseResult:
        """Decide release without raising — returns the structured decision."""
        sealed = self._secrets.get(secret_id)
        reasons: list[str] = []
        if sealed is None:
            reasons.append("unknown_secret")
        if not attestation.ok:
            reasons.extend(attestation.reasons or ("attestation_failed",))
        if sealed is not None and attestation.measurement != sealed.bound_measurement:
            reasons.append("measurement_mismatch")   # secret is sealed to a different workload

        if reasons:
            return SecretReleaseResult(
                allowed=False, secret_id=secret_id, worker_id=attestation.worker_id,
                reasons=tuple(reasons),
            )
        return SecretReleaseResult(
            allowed=True, secret_id=secret_id, worker_id=attestation.worker_id,
            reasons=(), material=sealed.material,
        )

    def release(self, secret_id: str, attestation: WorkloadAttestation) -> str:
        """Release the secret material, or raise SecretReleaseDenied. Fail closed."""
        result = self.evaluate(secret_id, attestation)
        if not result.allowed or result.material is None:
            raise SecretReleaseDenied(secret_id, result.reasons or ("denied",))
        return result.material


__all__ = ["SecretReleaseDenied", "SealedSecret", "SecretReleaseResult", "SecretBroker"]
