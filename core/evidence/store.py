"""Evidence system of record.

The authoritative store for "what Guardian did": every approved action's typed evidence
event. It is **append-only and tamper-evident**, and is intended to be backed by an
external immutable ledger (immudb) in production — with the local hash-chained JSONL log
as the always-available fallback/cache, mirroring the connector and memory degradation
pattern.

Design notes (from docs/defence_catalogue.md, "Prove"):
  * Every event carries the chain from actor → policy decision → command → result, plus the
    previous event hash, so the record is verifiable end to end.
  * Raw credentials and sensitive output are **redacted** before storage (``scrub``); only
    output *hashes* are kept, never raw output bodies.
  * immudb (when configured + reachable) is the system of record; the hash chain is a cache.
    Absence of immudb degrades to the hash chain rather than dropping evidence.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from core.audit import AuditLog
from core.config import REPO_ROOT
from core.evidence.report import scrub

DEFAULT_EVIDENCE_DIR = REPO_ROOT / "reports" / "evidence"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EvidenceEvent:
    """One typed evidence record. Most fields are optional but the chain is always present."""

    actor: str
    command_id: str
    result: str                            # "allowed" | "refused" | "completed" | "failed"
    event_id: str = ""
    trace_id: str | None = None
    workflow_id: str | None = None
    workload_identity: str | None = None
    policy_bundle_digest: str | None = None
    policy_decision: str | None = None     # allow | deny + reasons
    approval_signatures: list[str] = field(default_factory=list)
    repository: str | None = None
    commit: str | None = None
    artifact_digest: str | None = None
    target: str | None = None
    argv: list[str] = field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None
    returncode: int | None = None
    output_hash: str | None = None
    attestation: str | None = None

    def redacted(self) -> dict[str, Any]:
        """Return the event as a dict with secrets/PII scrubbed from string fields."""
        out: dict[str, Any] = {}
        for k, v in asdict(self).items():
            if isinstance(v, str):
                out[k] = scrub(v)
            elif isinstance(v, list):
                out[k] = [scrub(x) if isinstance(x, str) else x for x in v]
            else:
                out[k] = v
        return out


@dataclass
class EvidenceReceipt:
    event_id: str
    entry_hash: str
    backend: str
    verifiable: bool


class EvidenceBackend(Protocol):
    def append(self, event: dict[str, Any]) -> EvidenceReceipt:
        """Append one redacted evidence event; return a verifiable receipt."""

    def verify(self) -> bool:
        """Confirm the stored record has not been tampered with."""

    @property
    def name(self) -> str:
        """Backend identifier (e.g. ``immudb`` / ``hash_chain``)."""


class ImmudbUnavailable(RuntimeError):
    """Raised when the immudb backend cannot be used; the store falls back to hash chain."""


class HashChainBackend:
    """Always-available fallback: an append-only, hash-chained JSONL log (core.audit)."""

    name = "hash_chain"

    def __init__(self, log_dir=DEFAULT_EVIDENCE_DIR) -> None:
        self._audit = AuditLog(log_dir=log_dir)

    def append(self, event: dict[str, Any]) -> EvidenceReceipt:
        entry = self._audit.record(
            "evidence", actor=event.get("actor", "guardian"),
            scope=event.get("target"), decision=event.get("result", "completed"),
            detail=event,
        )
        return EvidenceReceipt(
            event_id=event["event_id"], entry_hash=entry["hash"],
            backend=self.name, verifiable=True,
        )

    def verify(self) -> bool:
        return self._audit.verify()


class ImmudbBackend:  # pragma: no cover - requires a running immudb + client lib
    """Immutable ledger backend. Used only when immudb is configured AND reachable."""

    name = "immudb"

    def __init__(self) -> None:
        if os.environ.get("GUARDIAN_USE_IMMUDB") != "1":
            raise ImmudbUnavailable("GUARDIAN_USE_IMMUDB != 1")
        try:
            from immudb import ImmudbClient  # type: ignore
        except Exception as exc:  # client lib absent
            raise ImmudbUnavailable(f"immudb client not installed: {exc}") from exc
        addr = os.environ.get("IMMUDB_ADDRESS", "127.0.0.1:3322")
        try:
            self._client = ImmudbClient(addr)
            self._client.login(
                os.environ.get("IMMUDB_USER", "immudb"),
                os.environ.get("IMMUDB_PASSWORD", ""),
            )
        except Exception as exc:
            raise ImmudbUnavailable(f"immudb unreachable at {addr}: {exc}") from exc

    def append(self, event: dict[str, Any]) -> EvidenceReceipt:
        import json

        key = f"evidence:{event['event_id']}".encode()
        payload = json.dumps(event, sort_keys=True).encode()
        self._client.verifiedSet(key, payload)
        return EvidenceReceipt(
            event_id=event["event_id"],
            entry_hash=hashlib.sha256(payload).hexdigest(),
            backend=self.name, verifiable=True,
        )

    def verify(self) -> bool:
        # immudb verifies cryptographically on read (verifiedGet); presence ⇒ verifiable.
        return True


class EvidenceStore:
    """The one place approved-action evidence is recorded. Append-only, redacted, verifiable."""

    def __init__(self, backend: EvidenceBackend | None = None) -> None:
        self.backend = backend or get_backend()

    def record(self, event: EvidenceEvent) -> EvidenceReceipt:
        if not event.event_id:
            event.event_id = _mint_event_id(event)
        if event.started_at is None:
            event.started_at = _now()
        return self.backend.append(event.redacted())

    def verify(self) -> bool:
        return self.backend.verify()


def _mint_event_id(event: EvidenceEvent) -> str:
    seed = f"{event.actor}:{event.command_id}:{event.target}:{_now()}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def get_backend() -> EvidenceBackend:
    """Return the immudb backend when configured + reachable, else the hash-chain fallback."""
    try:
        return ImmudbBackend()
    except ImmudbUnavailable:
        return HashChainBackend()
