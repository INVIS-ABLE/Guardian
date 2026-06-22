"""Tamper-evident audit log. Every Guardian action is logged here as evidence.

Entries are hash-chained (each record embeds the SHA-256 of the previous record),
so any retroactive edit breaks the chain and is detectable via ``verify()``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import REPO_ROOT

DEFAULT_LOG_DIR = REPO_ROOT / "reports" / "audit"
GENESIS = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(record: dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSONL audit log."""

    def __init__(self, log_dir: Path | str = DEFAULT_LOG_DIR) -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.log_dir / "guardian-audit.jsonl"

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = json.loads(line)["hash"]
        return last

    def record(
        self,
        action: str,
        *,
        actor: str,
        scope: str | None = None,
        decision: str = "allowed",
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append an audit entry and return it."""
        body = {
            "ts": _now(),
            "actor": actor,
            "action": action,
            "scope": scope,
            "decision": decision,
            "detail": detail or {},
            "prev": self._last_hash(),
        }
        entry = {**body, "hash": _hash(body)}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def verify(self) -> bool:
        """Recompute the chain and confirm it has not been tampered with."""
        if not self.path.exists():
            return True
        prev = GENESIS
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            stored = entry.pop("hash")
            if entry.get("prev") != prev:
                return False
            if _hash(entry) != stored:
                return False
            prev = stored
        return True
