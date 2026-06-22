"""One-use capability tokens (target architecture §13).

When the executor decides a capability may run, it does not just call a tool — it mints
a single-use capability token bound to everything that makes the call safe and unique:
the case, the pinned tool digest, the exact arguments, the input artifact hashes, the
environment, the network policy, the resource budget and an expiry. The token is
verified again at execution time and consumed once, so it cannot authorise a different
call, be replayed, or outlive its window.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .manifest import NetworkMode, ResourceLimits, ToolManifest


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_args(args: dict) -> str:
    """Deterministic hash of a call's arguments."""
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class CapabilityToken(BaseModel):
    """A single-use authorisation to run one exact tool call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    token_id: UUID = Field(default_factory=uuid4)
    case_id: UUID
    capability: str
    tool_digest: str  # the manifest's image_digest
    args_hash: str
    input_artifact_hashes: tuple[str, ...] = ()
    environment: str
    network: NetworkMode
    limits: ResourceLimits
    issued_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or _utcnow()) >= self.expires_at

    def matches(self, *, case_id: UUID, tool_digest: str, args_hash: str,
                environment: str) -> bool:
        """Whether this token authorises exactly this call (binding check)."""
        return (
            self.case_id == case_id
            and self.tool_digest == tool_digest
            and self.args_hash == args_hash
            and self.environment == environment
        )


def issue_token(
    manifest: ToolManifest,
    *,
    case_id: UUID,
    args: dict,
    environment: str,
    ttl_seconds: int = 1200,
    input_artifact_hashes: tuple[str, ...] = (),
    now: datetime | None = None,
) -> CapabilityToken:
    """Mint a one-use token bound to this exact call."""
    from datetime import timedelta

    issued = now or _utcnow()
    return CapabilityToken(
        case_id=case_id,
        capability=manifest.capability,
        tool_digest=manifest.image_digest,
        args_hash=hash_args(args),
        input_artifact_hashes=input_artifact_hashes,
        environment=environment,
        network=manifest.network,
        limits=manifest.limits,
        issued_at=issued,
        expires_at=issued + timedelta(seconds=ttl_seconds),
    )


class TokenStore:
    """Tracks consumed tokens so a capability token can be used at most once."""

    def __init__(self) -> None:
        self._consumed: set[UUID] = set()

    def consume(self, token: CapabilityToken, *, now: datetime | None = None) -> bool:
        """Consume a token. Returns False if expired or already used (fail closed)."""
        if token.is_expired(now):
            return False
        if token.token_id in self._consumed:
            return False
        self._consumed.add(token.token_id)
        return True


__all__ = ["CapabilityToken", "issue_token", "TokenStore", "hash_args"]
