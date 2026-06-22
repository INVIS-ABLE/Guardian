"""Typed models for the endpoint intelligence fabric (Sovereign plane, Wave 1, system #4).

The fourth Wave-1 omniscience system. Unlike the twin/identity/lineage graphs, its defining
property is a **governance invariant**, not a query: Guardian gets *structured OS-state
visibility* across the fleet, but only ever through **signed, reviewed osquery query packs —
never model-generated commands** (docs/sovereign_ops_plane.md). The model never writes ad-hoc
osquery SQL; a human reviewer signs a reviewed pack offline, and only those packs may run.

This module defines the *shapes* only. The reference monitor that enforces the invariant —
admit only correctly-signed, reviewed packs; refuse every query not in one — lives in
``graph.py`` (``EndpointFabric``); the ingestion seam (Fleet → store, in production) is in
``ingest.py``.

osquery is itself read-only (it can only ``SELECT`` OS state), and these models add
defence-in-depth: a query that is not a ``SELECT``/``WITH`` is refused before it can be
packed, and a pack's author may never be its own reviewer (separation of duties).
"""

from __future__ import annotations

import json
from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

SCHEMA_VERSION = 1


class Platform(str, Enum):
    """The platforms a query targets (osquery runs cross-platform)."""

    LINUX = "linux"
    DARWIN = "darwin"
    WINDOWS = "windows"
    ALL = "all"


class OsqueryQuery(BaseModel):
    """One named, scheduled osquery query. Read-only (``SELECT``/``WITH``) by construction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    name: str
    query: str                    # the osquery SQL
    description: str = ""
    platform: Platform = Platform.ALL
    interval: int = 3600          # schedule interval in seconds

    @field_validator("name", "query")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("query name/sql must be non-empty")
        return v

    @field_validator("query")
    @classmethod
    def _read_only(cls, v: str) -> str:
        head = v.lstrip().split(None, 1)[0].lower() if v.strip() else ""
        if head not in {"select", "with"}:
            raise ValueError(
                "osquery queries must be read-only (start with SELECT/WITH); refusing a query "
                "that is not a pure read — Guardian never issues mutating endpoint commands"
            )
        return v

    @field_validator("interval")
    @classmethod
    def _positive_interval(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("query interval must be a positive number of seconds")
        return v


class QueryPack(BaseModel):
    """A reviewed bundle of osquery queries, attributable to an author and a distinct reviewer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    id: str
    name: str
    version: str = "1.0.0"
    author: str                   # who wrote the pack
    reviewed_by: str              # who reviewed/approved it (must differ from the author)
    queries: tuple[OsqueryQuery, ...]

    @field_validator("id", "name", "author", "reviewed_by")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("pack id/name/author/reviewed_by must be non-empty")
        return v

    @field_validator("queries")
    @classmethod
    def _non_empty_queries(cls, v: tuple[OsqueryQuery, ...]) -> tuple[OsqueryQuery, ...]:
        if not v:
            raise ValueError("a query pack must contain at least one query")
        names = [q.name for q in v]
        if len(names) != len(set(names)):
            raise ValueError("query names within a pack must be unique")
        return v

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization the reviewer signs over (stable across processes)."""
        return json.dumps(self.model_dump(mode="json"), sort_keys=True,
                          separators=(",", ":")).encode("utf-8")


class PackSignature(BaseModel):
    """A reviewer's detached signature over a pack's ``canonical_bytes``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str                   # which trusted reviewer key produced it
    signature: str                # hex signature (see core/signing.py)

    @field_validator("key_id", "signature")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("signature key_id/signature must be non-empty")
        return v


class QueryVerdict(BaseModel):
    """The result of vetting a candidate query against the admitted packs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sql: str
    approved: bool
    pack: str | None              # admitting pack id, when approved
    query: str | None             # the matched query name, when approved
    reason: str
