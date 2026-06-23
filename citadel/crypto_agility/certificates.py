"""Certificate inventory (Citadel System 23).

Tracks certificates with their signature algorithm, key size and expiry so weak or soon-to-expire
certificates surface as findings before they fail in production.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .algorithms import AlgorithmPolicy, AlgorithmStatus


@dataclass(frozen=True)
class Certificate:
    cert_id: str
    subject: str
    algorithm: str
    key_size: int
    not_after: float          # epoch seconds


@dataclass
class CertificateInventory:
    certs: dict[str, Certificate] = field(default_factory=dict)

    def register(self, cert: Certificate) -> None:
        self.certs[cert.cert_id] = cert

    def expiring(self, *, now: float, within_days: int) -> list[Certificate]:
        horizon = now + within_days * 86400
        return [c for c in self.certs.values() if c.not_after <= horizon]

    def weak(self, policy: AlgorithmPolicy | None = None) -> list[Certificate]:
        pol = policy or AlgorithmPolicy.default()
        weak: list[Certificate] = []
        for c in self.certs.values():
            status = pol.classify(c.algorithm)
            if status in (None, AlgorithmStatus.DEPRECATED, AlgorithmStatus.FORBIDDEN):
                weak.append(c)
        return weak


__all__ = ["Certificate", "CertificateInventory"]
