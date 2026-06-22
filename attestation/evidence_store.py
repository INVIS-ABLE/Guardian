"""Immutable evidence system of record (Phase 2 / blueprint area 5).

The local hash-chained JSONL (`core/audit.py`) is a fast CACHE. The authoritative system of
record is an append-only, cryptographically verifiable store — immudb in deployment — that
lives in a separate trust boundary, so **deleting local logs does not delete the authoritative
evidence** (bulletproof test #10). Every record is hash-chained AND signed.

This module provides:
  - `EvidenceStore` interface + `InMemoryEvidenceStore` (verifiable, for tests/dev),
  - `ImmudbEvidenceStore` (lazy adapter to the real service),
  - `SystemOfRecord` which writes to the authoritative store and the local cache together,
    and verifies the store independently of the cache.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .signing import Signer, canonical, default_signer

GENESIS = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Attestation:
    seq: int
    ts: str
    record: dict[str, Any]
    prev: str
    hash: str
    signature: str
    algorithm: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "record": self.record,
            "prev": self.prev,
            "hash": self.hash,
            "signature": self.signature,
            "algorithm": self.algorithm,
        }


class EvidenceStore(ABC):
    """Append-only, verifiable evidence store."""

    @abstractmethod
    def append(self, record: dict[str, Any]) -> Attestation:
        """Append a record and return its signed, chained attestation."""

    @abstractmethod
    def all(self) -> list[Attestation]:
        """Return all attestations in order."""

    @abstractmethod
    def verify(self) -> bool:
        """Recompute the chain + signatures; True if intact."""


class InMemoryEvidenceStore(EvidenceStore):
    """Hash-chained + signed store. Independent of any local file (separate trust boundary)."""

    def __init__(self, signer: Signer | None = None) -> None:
        self._signer = signer or default_signer()
        self._entries: list[Attestation] = []

    def append(self, record: dict[str, Any]) -> Attestation:
        prev = self._entries[-1].hash if self._entries else GENESIS
        seq = len(self._entries)
        body = {"seq": seq, "ts": _now(), "record": record, "prev": prev}
        digest = hashlib.sha256(canonical(body)).hexdigest()
        signature = self._signer.sign({**body, "hash": digest})
        att = Attestation(
            seq=seq, ts=body["ts"], record=record, prev=prev, hash=digest,
            signature=signature, algorithm=self._signer.algorithm,
        )
        self._entries.append(att)
        return att

    def all(self) -> list[Attestation]:
        return list(self._entries)

    def verify(self) -> bool:
        prev = GENESIS
        for att in self._entries:
            body = {"seq": att.seq, "ts": att.ts, "record": att.record, "prev": prev}
            if att.prev != prev:
                return False
            if hashlib.sha256(canonical(body)).hexdigest() != att.hash:
                return False
            if not self._signer.verify({**body, "hash": att.hash}, att.signature):
                return False
            prev = att.hash
        return True


class ImmudbEvidenceStore(EvidenceStore):  # pragma: no cover - needs the immudb service
    """Adapter to a running immudb instance (lazy import). Configure in deployment."""

    def __init__(self, client: Any | None = None) -> None:
        if client is None:
            try:
                from immudb import ImmudbClient  # type: ignore
            except Exception as exc:
                raise RuntimeError(
                    "immudb client not available; install immudb-py and configure, "
                    "or use InMemoryEvidenceStore for dev/tests"
                ) from exc
            client = ImmudbClient()
        self._client = client
        self._signer = default_signer()

    def append(self, record: dict[str, Any]) -> Attestation:
        raise NotImplementedError("wire to immudb verifiedSet in deployment")

    def all(self) -> list[Attestation]:
        raise NotImplementedError

    def verify(self) -> bool:
        raise NotImplementedError


@dataclass
class SystemOfRecord:
    """Writes evidence to the authoritative store AND the local cache.

    The store is the system of record; the cache (core.audit.AuditLog) is a convenience.
    Verification runs against the STORE, so losing/wiping the local cache does not weaken the
    evidence.
    """

    store: EvidenceStore
    cache: Any | None = None  # a core.audit.AuditLog (optional)
    _count: int = field(default=0, init=False)

    def record(
        self,
        action: str,
        *,
        actor: str,
        decision: str = "allowed",
        detail: dict[str, Any] | None = None,
    ) -> Attestation:
        rec = {"action": action, "actor": actor, "decision": decision, "detail": detail or {}}
        att = self.store.append(rec)
        if self.cache is not None:
            try:
                self.cache.record(action, actor=actor, decision=decision, detail=detail or {})
            except Exception:
                pass  # cache failure must never lose the authoritative record
        self._count += 1
        return att

    def verify(self) -> bool:
        return self.store.verify()
