"""Guardian memory layer — controlled RAG over Guardian's own knowledge.

The memory layer is how the Guardian Brain *learns*: findings, threat models,
policies, and run outcomes are embedded and stored so future runs can retrieve
relevant prior context. It is deliberately defensive-by-design:

  * **Backends are pluggable** — Qdrant / pgvector / Chroma in production, with a
    dependency-free in-memory backend as the always-available fallback (mirroring
    the graceful-degradation pattern used by the connectors).
  * **Secrets/PII are scrubbed** before anything is written (``core.evidence.scrub``),
    so memory can never become an exfiltration channel or a store of real user data.
  * **Collections are fixed** by ``guardian.config.yaml`` — memory cannot invent new
    namespaces at runtime.
  * **Every write/read is audited.**

This module provides the abstraction and the in-memory fallback. Real vector backends
are wired in via :func:`get_backend` when their client libraries and services are
present; absence degrades to the local store rather than failing the run.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Protocol

from .audit import AuditLog
from .config import REPO_ROOT, GuardianConfig, load_config
from .evidence import scrub

DEFAULT_STORE_DIR = REPO_ROOT / "reports" / "memory"

# Metadata keys whose *values* are redacted wholesale, even if the value alone doesn't
# match an inline secret pattern (e.g. {"password": "hunter2"}). Defence in depth: a
# sensitively-named field never lands in memory in the clear.
_SENSITIVE_KEYS = re.compile(r"(?i)(pass(word|wd)?|pwd|secret|token|api[_-]?key|credential)")

# Collections Guardian is allowed to use. Anything outside this set is refused so
# memory cannot quietly grow new, unreviewed namespaces.
DEFAULT_COLLECTIONS: tuple[str, ...] = (
    "invisable_repos",
    "policies",
    "threat_models",
    "app_docs",
    "support_flows",
    "safeguarding_rules",
    "run_outcomes",
)


@dataclass
class MemoryRecord:
    """A single stored memory item."""

    id: str
    collection: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)
    embedding: list[float] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "collection": self.collection,
            "text": self.text,
            "metadata": self.metadata,
        }


@dataclass
class SearchHit:
    record: MemoryRecord
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {"score": round(self.score, 4), **self.record.to_dict()}


def hash_embed(text: str, dims: int = 256) -> list[float]:
    """Deterministic, dependency-free bag-of-words hashing embedding.

    This is *not* a semantic model — it is a stable fallback so retrieval works in
    any environment (CI, offline, air-gapped) without pulling a heavyweight model.
    Production backends override this with a real embedding model via
    ``GuardianMemory(embedder=...)``.
    """
    vec = [0.0] * dims
    for token in re.findall(r"[a-z0-9]+", text.lower()):
        h = int(hashlib.sha256(token.encode("utf-8")).hexdigest(), 16)
        idx = h % dims
        sign = 1.0 if (h >> 8) & 1 else -1.0
        vec[idx] += sign
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))  # both are unit-normalised


class MemoryBackend(Protocol):
    """Minimal contract every memory backend implements."""

    def upsert(self, record: MemoryRecord) -> None:
        """Insert or replace a record."""

    def query(self, collection: str, embedding: list[float], top_k: int) -> list[SearchHit]:
        """Return the ``top_k`` nearest records in ``collection`` to ``embedding``."""

    def count(self, collection: str | None = None) -> int:
        """Number of stored records, optionally scoped to one collection."""


class InMemoryBackend:
    """Always-available, JSONL-persisted fallback backend.

    Stores records on disk so memory survives between runs without an external
    service. Search is exact cosine over the hashing embedding — correct, if not
    as fast or semantic as a real vector DB.
    """

    def __init__(self, store_dir: Path | str = DEFAULT_STORE_DIR) -> None:
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.store_dir / "memory.jsonl"
        self._records: list[MemoryRecord] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            self._records.append(
                MemoryRecord(
                    id=d["id"],
                    collection=d["collection"],
                    text=d["text"],
                    metadata=d.get("metadata", {}),
                    embedding=d.get("embedding", []),
                )
            )

    def upsert(self, record: MemoryRecord) -> None:
        self._records = [r for r in self._records if r.id != record.id]
        self._records.append(record)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {**record.to_dict(), "embedding": record.embedding}, sort_keys=True
                )
                + "\n"
            )

    def query(self, collection: str, embedding: list[float], top_k: int) -> list[SearchHit]:
        hits = [
            SearchHit(record=r, score=cosine(embedding, r.embedding))
            for r in self._records
            if r.collection == collection
        ]
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:top_k]

    def count(self, collection: str | None = None) -> int:
        if collection is None:
            return len(self._records)
        return sum(1 for r in self._records if r.collection == collection)


class GuardianMemory:
    """The Guardian Brain's controlled long-term memory.

    Safe-by-default: collections are whitelisted, text is scrubbed before storage,
    and every operation is audited.
    """

    def __init__(
        self,
        *,
        backend: MemoryBackend | None = None,
        config: GuardianConfig | None = None,
        embedder=hash_embed,
        collections: Iterable[str] | None = None,
    ) -> None:
        self.config = config or load_config()
        self.backend = backend or InMemoryBackend()
        self.embed = embedder
        cfg_collections = (
            self.config.raw.get("guardian", {})
            .get("agents", {})
            .get("rag", {})
            .get("collections")
        )
        self.collections = tuple(collections or cfg_collections or DEFAULT_COLLECTIONS)
        self.audit = AuditLog()

    # --- write -----------------------------------------------------------------
    def remember(
        self,
        collection: str,
        text: str,
        *,
        metadata: dict[str, Any] | None = None,
        record_id: str | None = None,
    ) -> MemoryRecord:
        """Scrub, embed, and store a piece of knowledge. Refuses unknown collections."""
        self._assert_collection(collection)
        clean = scrub(text)
        meta = {
            k: ("[REDACTED]" if _SENSITIVE_KEYS.search(k) else scrub(str(v)))
            for k, v in (metadata or {}).items()
        }
        rid = record_id or hashlib.sha256(f"{collection}:{clean}".encode("utf-8")).hexdigest()[:16]
        record = MemoryRecord(
            id=rid,
            collection=collection,
            text=clean,
            metadata={**meta, "stored_at": datetime.now(timezone.utc).isoformat()},
            embedding=self.embed(clean),
        )
        self.backend.upsert(record)
        self.audit.record(
            "memory:remember",
            actor="learning_memory_agent",
            decision="allowed",
            detail={"collection": collection, "id": rid, "chars": len(clean)},
        )
        return record

    def remember_finding(self, finding: dict[str, Any], *, collection: str = "run_outcomes") -> MemoryRecord:
        """Convenience: store a connector/simulator finding as a searchable memory."""
        summary = " ".join(
            str(finding.get(k, "")) for k in ("rule", "tool", "scenario_name", "message", "severity")
        ).strip()
        return self.remember(collection, summary or json.dumps(finding), metadata=finding)

    # --- read ------------------------------------------------------------------
    def search(self, collection: str, query: str, *, top_k: int = 5) -> list[SearchHit]:
        """Retrieve the most relevant prior knowledge for a query."""
        self._assert_collection(collection)
        hits = self.backend.query(collection, self.embed(scrub(query)), top_k)
        self.audit.record(
            "memory:search",
            actor="learning_memory_agent",
            decision="allowed",
            detail={"collection": collection, "top_k": top_k, "hits": len(hits)},
        )
        return hits

    def count(self, collection: str | None = None) -> int:
        return self.backend.count(collection)

    # --- internals -------------------------------------------------------------
    def _assert_collection(self, collection: str) -> None:
        if collection not in self.collections:
            raise ValueError(
                f"Collection '{collection}' is not a permitted Guardian memory collection "
                f"(allowed: {', '.join(self.collections)})."
            )


# Deployment postures in which the local JSONL fallback is NOT an acceptable backend —
# mirrors core.policy_gate._OPA_REQUIRED_ENVS so memory and authorization fail closed alike.
_BACKEND_REQUIRED_ENVS: frozenset[str] = frozenset({"staging", "production"})


def _vector_backend_required() -> bool:
    """Whether an unavailable approved vector backend must FAIL CLOSED rather than fall back.

    Keys off Guardian's deployment posture (``GUARDIAN_ENV``), exactly as the policy gate
    does — where Guardian itself runs, not a target's environment. ``development``/``ci``
    (the default) permit the always-available local store so offline tests/dev work;
    ``staging``/``production`` require the real backend. ``GUARDIAN_REQUIRE_VECTOR_BACKEND=1``
    forces the requirement regardless of posture.
    """
    if os.environ.get("GUARDIAN_REQUIRE_VECTOR_BACKEND") == "1":
        return True
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in _BACKEND_REQUIRED_ENVS


def _build_vector_backend(rag: dict[str, Any]) -> MemoryBackend | None:
    """Construct the configured production vector backend, or None if it can't be built.

    Real Qdrant/pgvector/Chroma wiring is added here as those services are provisioned
    (their client library + a reachable service). Until then this returns None, and the
    caller decides whether that is fatal (staging/production) or acceptable (development/ci).
    """
    return None


def get_backend(config: GuardianConfig | None = None) -> MemoryBackend:
    """Return the configured vector backend.

    In development/ci this degrades to the always-available in-memory (JSONL) store. In
    Guardian's staging/production postures it **fails closed**: if the approved vector
    backend cannot be built we raise rather than silently dropping to local JSONL — which
    would quietly lose the production knowledge store and its access controls.
    """
    cfg = config or load_config()
    rag = cfg.raw.get("guardian", {}).get("agents", {}).get("rag", {})
    if not rag.get("enabled", True):
        return InMemoryBackend()
    backend = _build_vector_backend(rag)
    if backend is not None:
        return backend
    if _vector_backend_required():
        raise RuntimeError(
            f"Approved vector backend '{rag.get('vector_db', 'unknown')}' is unavailable and "
            "this Guardian deployment posture requires it; refusing to silently fall back to "
            "the local JSONL store (fail closed). Set GUARDIAN_ENV=development to permit it."
        )
    return InMemoryBackend()
