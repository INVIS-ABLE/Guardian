"""Live, expiring, fail-closed ownership verifier (blueprint area 2).

Drop-in for ``Guardrails.ownership_verifier``: it is callable as ``verifier(kind, target) -> bool``.
Unlike scope-file membership (which is *intent*, not *proof*), this re-proves ownership against
live resolvers and only trusts the result for a bounded freshness window:

  - domain: an injected DNS resolver must return the expected ``guardian-verification=<token>``
    TXT record for that domain.
  - repo:   an injected GitHub resolver must report an owning login on the allowlist.

Everything fails **closed**: no resolver, no expected token, an unknown kind, a resolver error,
or a mismatch all yield "not owned". With the default ``ttl_seconds=0`` every call re-resolves,
so ownership is verified immediately before the sensitive action — never assumed from a months-
old check. A positive proof can be cached for ``ttl_seconds`` to bound resolver load.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import time
from typing import Callable

from .evidence import OwnershipEvidence, ProofMethod

# Injected, side-effecting resolvers. Kept abstract so no network client is imported here.
DnsResolver = Callable[[str], list[str]]  # domain -> its TXT records
GithubResolver = Callable[[str], "str | None"]  # repo -> owning login (or None)

DNS_PREFIX = "guardian-verification="
INVISABLE_TENANT_ID = "invisable"


@dataclass
class OwnershipVerifier:
    """Tenant-aware ownership verifier. Fails closed.

    The flat ``expected_dns_token`` / ``allowed_repo_owners`` belong to ``tenant``
    (the founding INVISABLE tenant by default), preserving the single-tenant API.
    Additional tenants are configured via ``tenant_dns_tokens`` /
    ``tenant_repo_owners`` (tenant -> the same maps). A request for a tenant with no
    configuration fails closed — ownership is never assumed across a tenant boundary.
    Caching is keyed per ``(kind, target, tenant)`` so one tenant's proof can never be
    served for another (cross-tenant cache isolation).
    """

    expected_dns_token: dict[str, str] = field(default_factory=dict)  # domain -> required token
    allowed_repo_owners: set[str] = field(default_factory=set)  # acceptable owning logins
    dns_resolver: DnsResolver | None = None
    github_resolver: GithubResolver | None = None
    ttl_seconds: float = 0.0  # 0 => re-resolve on every call (verify immediately before use)
    audit: object | None = None  # optional AuditLog-like with .record(...)
    actor: str = "ownership"
    tenant: str = INVISABLE_TENANT_ID  # the tenant the flat maps above belong to
    tenant_dns_tokens: dict[str, dict[str, str]] = field(default_factory=dict)
    tenant_repo_owners: dict[str, set[str]] = field(default_factory=dict)
    _cache: dict[tuple[str, str, str], OwnershipEvidence] = field(default_factory=dict)

    # --- Guardrails hook: callable(kind, target) -> bool -----------------------------------
    def __call__(self, kind: str, target: str) -> bool:
        return self.verify(kind, target) is not None

    def verify(
        self, kind: str, target: str, now: float | None = None, tenant: str | None = None
    ) -> OwnershipEvidence | None:
        """Return fresh evidence of ownership for ``tenant``, or None (fail closed).

        ``tenant`` defaults to this verifier's configured tenant, so existing
        single-tenant callers are unchanged. Re-resolves when stale.
        """
        tenant = self.tenant if tenant is None else tenant
        now = time() if now is None else now
        key = (kind, target, tenant)
        cached = self._cache.get(key)
        if cached is not None and cached.fresh(now):
            return cached

        evidence = self._reverify(kind, target, tenant, now)
        if evidence is not None:
            self._cache[key] = evidence
        else:
            self._cache.pop(key, None)  # never let stale proof linger
            self._audit_fail(kind, target, tenant)
        return evidence

    # --- tenant-scoped configuration -------------------------------------------------------
    def _dns_tokens_for(self, tenant: str) -> dict[str, str]:
        if tenant in self.tenant_dns_tokens:
            return self.tenant_dns_tokens[tenant]
        if tenant == self.tenant:
            return self.expected_dns_token
        return {}  # unconfigured tenant: fail closed

    def _repo_owners_for(self, tenant: str) -> set[str]:
        if tenant in self.tenant_repo_owners:
            return self.tenant_repo_owners[tenant]
        if tenant == self.tenant:
            return self.allowed_repo_owners
        return set()  # unconfigured tenant: fail closed

    # --- proof methods ---------------------------------------------------------------------
    def _reverify(
        self, kind: str, target: str, tenant: str, now: float
    ) -> OwnershipEvidence | None:
        if kind == "domain":
            return self._verify_domain(target, tenant, now)
        if kind == "repo":
            return self._verify_repo(target, tenant, now)
        return None  # unknown kind: fail closed

    def _verify_domain(self, domain: str, tenant: str, now: float) -> OwnershipEvidence | None:
        token = self._dns_tokens_for(tenant).get(domain)
        if not token or self.dns_resolver is None:
            return None
        try:
            records = self.dns_resolver(domain)
        except Exception:  # resolver failure must not be read as success
            return None
        if DNS_PREFIX + token in records or token in records:
            return self._evidence("domain", domain, ProofMethod.DNS_TXT, token, tenant, now)
        return None

    def _verify_repo(self, repo: str, tenant: str, now: float) -> OwnershipEvidence | None:
        owners = self._repo_owners_for(tenant)
        if self.github_resolver is None or not owners:
            return None
        try:
            owner = self.github_resolver(repo)
        except Exception:
            return None
        if owner is not None and owner in owners:
            return self._evidence("repo", repo, ProofMethod.GITHUB_APP, owner, tenant, now)
        return None

    def _evidence(
        self, kind: str, target: str, method: ProofMethod, proof: str, tenant: str, now: float
    ) -> OwnershipEvidence:
        expires_at = now + self.ttl_seconds if self.ttl_seconds > 0 else now
        return OwnershipEvidence(
            kind=kind, target=target, method=method, proof=proof,
            verified_at=now, expires_at=expires_at, tenant=tenant,
        )

    def _audit_fail(self, kind: str, target: str, tenant: str) -> None:
        if self.audit is None:
            return
        try:
            self.audit.record(
                f"ownership:unverified:{kind}", actor=self.actor,
                scope=target, decision="denied",
            )
        except Exception:  # pragma: no cover - auditing must never crash enforcement
            pass


def dns_challenge_record(token: str) -> str:
    """The exact TXT record an owner must publish to prove control of a domain."""
    return DNS_PREFIX + token
