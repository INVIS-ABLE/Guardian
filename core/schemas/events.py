"""Canonical Guardian event envelope (Final Power-Up §27).

Every significant state transition emits a ``CaseEvent`` — a typed, versioned, hashable
envelope. This is the genuinely-missing piece of Wave 1: the case/finding/evidence/
verification models already live in ``core.evidence.models`` and ``core.brain.state``;
what did not yet exist is the common event envelope that carries them across the mesh.

The envelope is content-addressable: ``payload_sha256`` is computed over the canonical
JSON of the payload, so an event cannot be silently altered, and a detached signature
may be attached without re-serialising the payload.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = 1


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonical_payload_hash(payload: dict[str, Any]) -> str:
    """Deterministic ``sha256:`` digest over a payload's canonical JSON form."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class CaseEvent(BaseModel):
    """The common Guardian event envelope (mesh family ``guardian.*``).

    Mirrors the master-map §27 envelope. ``payload_sha256`` binds the payload; build
    instances through :meth:`create` so the hash is always computed consistently.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    event_id: UUID = Field(default_factory=uuid4)
    event_type: str = Field(min_length=1, max_length=200)
    version: int = 1
    occurred_at: datetime = Field(default_factory=_utcnow)
    case_id: UUID | None = None
    workflow_id: str = ""
    trace_id: str = ""
    actor: str = Field(min_length=1, max_length=200)
    asset_refs: tuple[str, ...] = ()
    classification: str = "internal"
    payload: dict[str, Any] = Field(default_factory=dict)
    payload_sha256: str = ""
    signature: str | None = None

    @classmethod
    def create(
        cls,
        *,
        event_type: str,
        actor: str,
        payload: dict[str, Any] | None = None,
        case_id: UUID | None = None,
        workflow_id: str = "",
        trace_id: str = "",
        asset_refs: tuple[str, ...] = (),
        classification: str = "internal",
        occurred_at: datetime | None = None,
    ) -> CaseEvent:
        """Construct an event with ``payload_sha256`` computed from ``payload``."""
        body = payload or {}
        return cls(
            event_type=event_type,
            actor=actor,
            payload=body,
            payload_sha256=canonical_payload_hash(body),
            case_id=case_id,
            workflow_id=workflow_id,
            trace_id=trace_id,
            asset_refs=asset_refs,
            classification=classification,
            occurred_at=occurred_at or _utcnow(),
        )

    def payload_intact(self) -> bool:
        """True when the recorded hash matches a fresh hash of the payload."""
        return self.payload_sha256 == canonical_payload_hash(self.payload)

    def signed(self, signature: str) -> CaseEvent:
        """Return a copy carrying a detached signature (payload hash unchanged)."""
        return self.model_copy(update={"signature": signature})


__all__ = ["CaseEvent", "SCHEMA_VERSION", "canonical_payload_hash"]
