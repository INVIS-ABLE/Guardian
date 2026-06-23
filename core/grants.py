"""Authorisation-grant store — issue, persist, revoke, and authorise (Phase D).

Phase A introduced the :class:`~core.tenancy.AuthorisationGrant` value type and the
pure :func:`~core.tenancy.authorise_target` decision. This module gives grants a
durable home and a lifecycle, so a tenant's authority is a *managed, revocable
record* rather than an in-memory object that vanishes between runs.

Design constraints (charter):

* **Default deny.** An empty/missing store authorises nothing.
* **Fail closed.** A malformed store file, an unknown tenant, or any read error
  yields no grants — never a permissive fallback.
* **Tenant isolation.** Grants are indexed by tenant; a lookup for one tenant can
  never return another tenant's grant.
* **Tamper-evident.** Grants are signed (Ed25519 / HMAC fallback via
  :mod:`core.signing`); the signature is persisted and re-verified on authorise.
* **No self-granted authority.** This store *records* authority a human/tenant admin
  issues; it does not let an agent mint its own (issuance requires the signing key).

The on-disk format is a single JSON document::

    {"schema_version": 1, "grants": [ {<AuthorisationGrant.to_dict()>}, ... ]}
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from time import time

from core.tenancy import (
    AuthorisationGrant,
    AuthorityBasis,
    GrantDecision,
    RevocationStatus,
    TenantRegistry,
    authorise_target,
)

SCHEMA_VERSION = 1


class GrantStoreError(ValueError):
    """Raised on a structurally invalid store. Fails closed."""


class GrantStore:
    """A durable, tenant-indexed collection of authorisation grants."""

    def __init__(self, grants: list[AuthorisationGrant] | None = None) -> None:
        self._grants: dict[str, AuthorisationGrant] = {}
        for g in grants or []:
            self._grants[g.grant_id] = g

    # --- persistence -------------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "GrantStore":
        """Load a store from JSON. A missing file is an empty store (default deny)."""
        p = Path(path)
        if not p.exists():
            return cls([])
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise GrantStoreError(f"unreadable grant store {p}: {exc}") from exc
        if not isinstance(data, dict) or "grants" not in data:
            raise GrantStoreError(f"grant store {p} missing 'grants' list")
        try:
            grants = [AuthorisationGrant.from_dict(g) for g in data["grants"]]
        except (KeyError, ValueError) as exc:
            raise GrantStoreError(f"malformed grant in {p}: {exc}") from exc
        return cls(grants)

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "grants": [g.to_dict() for g in self._grants.values()],
        }
        p.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    # --- lifecycle ---------------------------------------------------------------
    def issue(
        self,
        *,
        grant_id: str,
        tenant_id: str,
        asset_ids: tuple[str, ...],
        authorising_identity: str,
        authority_basis: AuthorityBasis,
        evidence: str,
        permitted_capabilities: frozenset[str],
        environments: frozenset[str],
        signer_private_key: str,
        prohibited_capabilities: frozenset[str] = frozenset(),
        test_window: tuple[float, float] | None = None,
        ttl_seconds: float | None = None,
        now: float | None = None,
    ) -> AuthorisationGrant:
        """Construct, sign, and record a new grant. Returns the signed grant.

        ``signer_private_key`` is required — issuance is an authority-bearing act, so a
        grant cannot be minted without the key a human/tenant-admin controls.
        """
        now = time() if now is None else now
        if grant_id in self._grants:
            raise GrantStoreError(f"grant_id '{grant_id}' already exists")
        grant = AuthorisationGrant(
            grant_id=grant_id,
            tenant_id=tenant_id,
            asset_ids=asset_ids,
            authorising_identity=authorising_identity,
            authority_basis=authority_basis,
            evidence=evidence,
            permitted_capabilities=permitted_capabilities,
            prohibited_capabilities=prohibited_capabilities,
            environments=environments,
            test_window=test_window,
            issued_at=now,
            expires_at=None if ttl_seconds is None else now + ttl_seconds,
        ).signed(signer_private_key)
        self._grants[grant_id] = grant
        return grant

    def revoke(self, grant_id: str) -> AuthorisationGrant:
        """Mark a grant revoked. Idempotent; fails closed on an unknown id."""
        existing = self._grants.get(grant_id)
        if existing is None:
            raise GrantStoreError(f"cannot revoke unknown grant '{grant_id}'")
        revoked = replace(existing, revocation_status=RevocationStatus.REVOKED)
        self._grants[grant_id] = revoked
        return revoked

    def get(self, grant_id: str) -> AuthorisationGrant | None:
        return self._grants.get(grant_id)

    # --- queries -----------------------------------------------------------------
    def grants_for(self, tenant_id: str) -> list[AuthorisationGrant]:
        """All grants belonging to a tenant (isolation: never another tenant's)."""
        return [g for g in self._grants.values() if g.tenant_id == tenant_id]

    def active_grants(self, tenant_id: str, now: float | None = None) -> list[AuthorisationGrant]:
        now = time() if now is None else now
        return [g for g in self.grants_for(tenant_id) if g.is_active(now)]

    def authorise(
        self,
        *,
        tenant_id: str,
        asset_id: str,
        capability: str,
        environment: str,
        now: float | None = None,
        verify_key: str | None = None,
        require_signature: bool = False,
        tenants: TenantRegistry | None = None,
    ) -> GrantDecision:
        """Decide authorisation using only this tenant's grants (fail-closed)."""
        return authorise_target(
            self.grants_for(tenant_id),
            tenant_id=tenant_id,
            asset_id=asset_id,
            capability=capability,
            environment=environment,
            now=now,
            verify_key=verify_key,
            require_signature=require_signature,
            tenants=tenants,
        )

    def __len__(self) -> int:
        return len(self._grants)

    def all_grants(self) -> list[AuthorisationGrant]:
        return list(self._grants.values())
