"""Short-lived credential broker (Phase 2 / blueprint area 4).

Guardian receives SHORT-LIVED, per-workflow credentials — never long-lived tokens. OpenBao
issues dynamic credentials in deployment; this in-process broker enforces the same contract
(TTL, expiry, revocation) and is testable. A credential past its TTL is refused.
"""

from __future__ import annotations

import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from time import time

# Hard ceiling: no credential may outlive this, regardless of requested TTL. Long-lived
# credentials are a stop-the-line item — they must not exist.
MAX_TTL_SECONDS = 3600


class CredentialExpired(RuntimeError):
    pass


class CredentialRevoked(RuntimeError):
    pass


@dataclass(frozen=True)
class Credential:
    id: str
    secret: str
    scope: str  # what this credential is for, e.g. "connector:trivy@staging"
    issued_at: float
    expires_at: float
    workflow_run: str | None = None

    def valid(self, now: float | None = None) -> bool:
        now = time() if now is None else now
        return now < self.expires_at

    def remaining(self, now: float | None = None) -> float:
        now = time() if now is None else now
        return max(0.0, self.expires_at - now)


class CredentialBroker(ABC):
    @abstractmethod
    def issue(self, scope: str, *, ttl: int, workflow_run: str | None = None) -> Credential:
        """Issue a short-lived credential for ``scope`` with the given TTL."""

    @abstractmethod
    def redeem(self, credential_id: str, secret: str, *, now: float | None = None) -> Credential:
        """Return the credential if valid; raise if expired/revoked/unknown."""

    @abstractmethod
    def revoke(self, credential_id: str) -> None:
        """Revoke a credential so it can no longer be redeemed."""


class InMemoryCredentialBroker(CredentialBroker):
    """Reference broker for dev/tests. Production uses OpenBaoBroker."""

    def __init__(self) -> None:
        self._issued: dict[str, Credential] = {}
        self._revoked: set[str] = set()

    def issue(self, scope: str, *, ttl: int, workflow_run: str | None = None) -> Credential:
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        if ttl > MAX_TTL_SECONDS:
            raise ValueError(f"ttl {ttl}s exceeds max {MAX_TTL_SECONDS}s; no long-lived creds")
        now = time()
        cred = Credential(
            id=secrets.token_hex(8),
            secret=secrets.token_urlsafe(24),
            scope=scope,
            issued_at=now,
            expires_at=now + ttl,
            workflow_run=workflow_run,
        )
        self._issued[cred.id] = cred
        return cred

    def redeem(self, credential_id: str, secret: str, *, now: float | None = None) -> Credential:
        cred = self._issued.get(credential_id)
        if cred is None or not secrets.compare_digest(cred.secret, secret):
            raise CredentialRevoked("unknown or invalid credential")
        if credential_id in self._revoked:
            raise CredentialRevoked("credential revoked")
        if not cred.valid(now):
            raise CredentialExpired("credential expired")
        return cred

    def revoke(self, credential_id: str) -> None:
        self._revoked.add(credential_id)


class OpenBaoBroker(CredentialBroker):  # pragma: no cover - needs OpenBao service
    """Adapter to OpenBao dynamic secrets (lazy). Configure in deployment."""

    def __init__(self, client: object | None = None) -> None:
        if client is None:
            try:
                import hvac  # type: ignore  # OpenBao is Vault-API compatible
            except Exception as exc:
                raise RuntimeError(
                    "OpenBao/Vault client not available; install hvac and configure, "
                    "or use InMemoryCredentialBroker for dev/tests"
                ) from exc
            client = hvac
        self._client = client

    def issue(self, scope: str, *, ttl: int, workflow_run: str | None = None) -> Credential:
        raise NotImplementedError("wire to OpenBao dynamic secrets engine in deployment")

    def redeem(self, credential_id: str, secret: str, *, now: float | None = None) -> Credential:
        raise NotImplementedError

    def revoke(self, credential_id: str) -> None:
        raise NotImplementedError
