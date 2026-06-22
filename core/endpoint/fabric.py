"""The endpoint intelligence fabric reference monitor (Sovereign plane, Wave 1, system #4).

``EndpointFabric`` is the gate that enforces the system's one rule: **structured OS state via
signed, reviewed query packs only — never model-generated commands** (docs/sovereign_ops_plane.md).

It admits a pack only when ALL hold:
  * the pack is signed by a **trusted reviewer key** the fabric was told to trust, and the
    signature verifies over the pack's canonical bytes (so the reviewed content is exactly
    what runs — tampering breaks admission);
  * the pack's **reviewer is not its author** (separation of duties); and
  * the pack id is new (no silent redefinition).

Thereafter ``vet_query`` / ``require`` answer the only question that matters at run time: is
this exact query a member of an admitted pack? Anything else — an ad-hoc query, a
model-generated one, a whitespace-mangled variant — is refused, fail-closed. The fabric never
executes anything; it decides what *may* be scheduled, and ``schedule()`` emits that config.
"""

from __future__ import annotations

import re
from typing import Iterable, Iterator

from core.signing import verify

from .models import OsqueryQuery, PackSignature, QueryPack, QueryVerdict

_WS = re.compile(r"\s+")


def _normalize(sql: str) -> str:
    """Collapse whitespace and drop a trailing semicolon so equivalent queries compare equal.

    Case is preserved: a case-changed query is treated as a *different* query and refused
    (fail-closed), never silently matched to an approved one.
    """
    return _WS.sub(" ", sql.strip()).rstrip(";").strip()


class EndpointError(ValueError):
    """Raised on structural/trust errors (unknown key, bad signature, author==reviewer)."""


class UnapprovedQueryError(EndpointError):
    """Raised when a query is not a member of any signed, reviewed pack (the core refusal)."""


class EndpointFabric:
    """Reference monitor over signed osquery query packs."""

    def __init__(self, trusted_reviewers: dict[str, str]) -> None:
        # key_id -> reviewer public key (hex). Provisioned out of band; the model never edits it.
        self._trusted: dict[str, str] = dict(trusted_reviewers)
        self._packs: dict[str, QueryPack] = {}
        self._admitted_by: dict[str, str] = {}             # pack_id -> admitting key_id
        self._by_sql: dict[str, tuple[str, str]] = {}      # normalized sql -> (pack_id, query)

    # --- admission (the gate) --------------------------------------------------
    def admit(self, pack: QueryPack, signature: PackSignature) -> None:
        """Admit a pack iff it is signed by a trusted reviewer and independently reviewed."""
        public = self._trusted.get(signature.key_id)
        if public is None:
            raise EndpointError(
                f"pack '{pack.id}' signed by untrusted key '{signature.key_id}' — refused"
            )
        if not verify(public, pack.canonical_bytes(), signature.signature):
            raise EndpointError(
                f"signature on pack '{pack.id}' does not verify — refused (content may be tampered)"
            )
        if pack.author.strip() == pack.reviewed_by.strip():
            raise EndpointError(
                f"pack '{pack.id}' author and reviewer are the same principal "
                f"('{pack.author}') — separation of duties requires an independent reviewer"
            )
        if pack.id in self._packs:
            raise EndpointError(f"duplicate pack id: {pack.id}")
        self._packs[pack.id] = pack
        self._admitted_by[pack.id] = signature.key_id
        for q in pack.queries:
            self._by_sql.setdefault(_normalize(q.query), (pack.id, q.name))

    # --- vetting (run-time decision) -------------------------------------------
    def vet_query(self, sql: str) -> QueryVerdict:
        """Decide whether ``sql`` may run: approved only if it is verbatim in an admitted pack."""
        hit = self._by_sql.get(_normalize(sql))
        if hit is None:
            return QueryVerdict(
                sql=sql, approved=False, pack=None, query=None,
                reason="not a member of any signed, reviewed pack — ad-hoc / model-generated "
                       "osquery is refused (the fabric runs reviewed packs only)",
            )
        pack_id, qname = hit
        return QueryVerdict(sql=sql, approved=True, pack=pack_id, query=qname, reason="approved")

    def require(self, sql: str) -> tuple[str, str]:
        """Vetting variant for executors: return ``(pack_id, query_name)`` or raise."""
        verdict = self.vet_query(sql)
        if not verdict.approved:
            raise UnapprovedQueryError(verdict.reason)
        assert verdict.pack is not None and verdict.query is not None
        return verdict.pack, verdict.query

    # --- accessors -------------------------------------------------------------
    def __contains__(self, pack_id: object) -> bool:
        return pack_id in self._packs

    def __len__(self) -> int:
        return len(self._packs)

    def packs(self) -> Iterator[QueryPack]:
        return iter(self._packs.values())

    def admitting_key(self, pack_id: str) -> str:
        try:
            return self._admitted_by[pack_id]
        except KeyError as exc:
            raise EndpointError(f"unknown pack: {pack_id}") from exc

    def approved_queries(self) -> tuple[OsqueryQuery, ...]:
        """Every query across all admitted packs (the full approved read-only surface)."""
        return tuple(q for p in self._packs.values() for q in p.queries)

    def schedule(self) -> dict[str, dict[str, object]]:
        """The osquery schedule config assembled from admitted packs only.

        Shape mirrors osquery's ``schedule`` map (``{name: {query, interval, ...}}``) so it can
        be handed to Fleet/osqueryd as-is. Names are namespaced by pack id to stay unique.
        """
        out: dict[str, dict[str, object]] = {}
        for pack in self._packs.values():
            for q in pack.queries:
                out[f"{pack.id}.{q.name}"] = {
                    "query": q.query,
                    "interval": q.interval,
                    "platform": q.platform.value,
                }
        return out

    # --- convenience -----------------------------------------------------------
    def admit_all(self, signed: Iterable[tuple[QueryPack, PackSignature]]) -> None:
        for pack, sig in signed:
            self.admit(pack, sig)
