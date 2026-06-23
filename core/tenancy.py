"""Guardian tenancy & authorised-target foundation.

Guardian began as internal INVISABLE tooling: a single, implicit owner was baked
into the scope schema, the ownership verifier, and the policy gate. This module is
the first foundation stone of the *vendor-neutral* control plane described in
``docs/platform/`` — it generalises "INVISABLE owns everything" into an explicit,
**tenant-aware, default-deny** model without removing any existing protection.

Two ideas live here:

* :class:`Tenant` — the operator/customer boundary. Every identifier and every
  authorisation belongs to exactly one tenant. INVISABLE is preserved as the
  first, built-in tenant (:data:`INVISABLE_TENANT`) so existing deployments and
  scope files keep working unchanged.

* :class:`AuthorisationGrant` — verifiable, expiring proof that a tenant is
  authorised to exercise specific capabilities against specific assets in
  specific environments. This is the generalisation of "the target is on the
  INVISABLE allowlist": a target is now legitimate only when a *current,
  non-revoked, signed* grant covers it.

Everything fails **closed**. No grant, an expired grant, a revoked grant, a
cross-tenant grant, a prohibited capability, an out-of-window request, or an
invalid signature all yield "not authorised". This mirrors the posture already
enforced in :mod:`core.policy_gate` and :mod:`ownership.verifier`; tenancy adds
the missing dimension (which tenant) rather than relaxing anything.

The non-negotiable rules this implements (see the master platform prompt):

* Default deny (rule 1).
* No scan without an authorised target and valid scope (rule 3).
* No third-party target testing without explicit authorisation evidence (rule 4).
* Authorisation/target uncertainty fails closed (rule 12).
* Tenant isolation is preserved; cross-tenant leakage is prevented (rule 19).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from time import time
from typing import Any

from core import signing

# INVISABLE remains the founding organisation and first deployment profile. Its
# tenant id is stable and reserved so the existing scope files / registries (which
# predate tenancy and carry no explicit tenant) resolve to it by default.
INVISABLE_TENANT_ID = "invisable"


class DeploymentMode(str, Enum):
    """How a tenant's Guardian is deployed. Drives data-residency / egress policy."""

    SINGLE_TENANT_SELF_HOSTED = "single_tenant_self_hosted"
    MULTI_TENANT_SAAS = "multi_tenant_saas"
    PRIVATE_CLOUD = "private_cloud"
    MANAGED_DEDICATED = "managed_dedicated"
    AIR_GAPPED = "air_gapped"
    HYBRID = "hybrid"


class TenantStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class AuthorityBasis(str, Enum):
    """On what basis a tenant is authorised to test a target.

    These mirror the authorised-target model in
    ``docs/platform/TENANT_AND_AUTHORISED_TARGET_MODEL.md``. Each basis must be
    backed by recorded evidence; the basis alone is never sufficient.
    """

    VERIFIED_OWNERSHIP = "verified_ownership"
    DNS_CHALLENGE = "dns_challenge"
    REPO_INSTALLATION = "repo_installation"
    CLOUD_ACCOUNT = "cloud_account"
    SIGNED_DECLARATION = "signed_declaration"
    CONTRACT_REFERENCE = "contract_reference"
    DELEGATED_ADMIN = "delegated_admin"


class RevocationStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


# A capability token meaning "every capability not explicitly prohibited". Used
# sparingly (e.g. the built-in INVISABLE grant); prohibited_capabilities always wins.
CAPABILITY_WILDCARD = "*"


class TenancyError(ValueError):
    """Raised for structurally invalid tenancy objects. Fails closed."""


@dataclass(frozen=True)
class Tenant:
    """An operator or customer boundary. The unit of isolation."""

    tenant_id: str
    legal_name: str
    deployment_mode: DeploymentMode = DeploymentMode.SINGLE_TENANT_SELF_HOSTED
    region: str = "unspecified"
    data_residency: str = "unspecified"
    encryption_profile: str = "default"
    retention_policy: str = "default"
    administrators: tuple[str, ...] = ()
    status: TenantStatus = TenantStatus.ACTIVE

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.tenant_id.strip():
            raise TenancyError("tenant_id must be a non-empty string")

    @property
    def active(self) -> bool:
        return self.status == TenantStatus.ACTIVE


# The founding tenant. Generalisation, not removal: the historical "INVISABLE owns
# everything" assumption becomes one concrete, first-class tenant.
INVISABLE_TENANT = Tenant(
    tenant_id=INVISABLE_TENANT_ID,
    legal_name="INVISABLE",
    deployment_mode=DeploymentMode.SINGLE_TENANT_SELF_HOSTED,
)


def _canonical(payload: dict[str, Any]) -> bytes:
    """Deterministic bytes for signing/verification (sorted keys, no whitespace)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


@dataclass(frozen=True)
class AuthorisationGrant:
    """Verifiable, expiring authority for a tenant to test specific assets.

    A grant is the generalisation of the INVISABLE allowlist. It is the *only*
    thing that makes a target legitimate, and it is bound to a single tenant. The
    signature (optional in dev, required in production) is computed over
    :meth:`signing_payload` so a grant cannot be silently widened after issue.
    """

    grant_id: str
    tenant_id: str
    asset_ids: tuple[str, ...]
    authorising_identity: str
    authority_basis: AuthorityBasis
    evidence: str  # reference/digest of the proof (DNS token, repo install id, contract ref…)
    permitted_capabilities: frozenset[str] = frozenset()
    prohibited_capabilities: frozenset[str] = frozenset()
    environments: frozenset[str] = frozenset()
    test_window: tuple[float, float] | None = None  # (start_epoch, end_epoch) inclusive
    issued_at: float = 0.0
    expires_at: float | None = None
    revocation_status: RevocationStatus = RevocationStatus.ACTIVE
    signature: str | None = None

    def __post_init__(self) -> None:
        if not self.grant_id or not self.grant_id.strip():
            raise TenancyError("grant_id must be a non-empty string")
        if not self.tenant_id or not self.tenant_id.strip():
            raise TenancyError("grant_id %r has empty tenant_id" % self.grant_id)
        if not self.asset_ids:
            raise TenancyError("grant %r authorises no assets" % self.grant_id)

    # --- signing -----------------------------------------------------------------
    def signing_payload(self) -> dict[str, Any]:
        """The exact, signature-free content a signature commits to."""
        return {
            "grant_id": self.grant_id,
            "tenant_id": self.tenant_id,
            "asset_ids": sorted(self.asset_ids),
            "authorising_identity": self.authorising_identity,
            "authority_basis": self.authority_basis.value,
            "evidence": self.evidence,
            "permitted_capabilities": sorted(self.permitted_capabilities),
            "prohibited_capabilities": sorted(self.prohibited_capabilities),
            "environments": sorted(self.environments),
            "test_window": list(self.test_window) if self.test_window else None,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "revocation_status": self.revocation_status.value,
        }

    def signed(self, private_hex: str) -> "AuthorisationGrant":
        """Return a copy carrying a detached signature over the grant content."""
        from dataclasses import replace

        sig = signing.sign(private_hex, _canonical(self.signing_payload()))
        return replace(self, signature=sig)

    def signature_valid(self, public_hex: str) -> bool:
        if not self.signature:
            return False
        return signing.verify(public_hex, _canonical(self.signing_payload()), self.signature)

    # --- serialisation (persistence) ---------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """Full serialisable form, including the signature (unlike signing_payload)."""
        d = self.signing_payload()
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuthorisationGrant":
        """Reconstruct a grant from :meth:`to_dict`. Fails closed on malformed input."""
        tw = d.get("test_window")
        return cls(
            grant_id=d["grant_id"],
            tenant_id=d["tenant_id"],
            asset_ids=tuple(d.get("asset_ids", ())),
            authorising_identity=d.get("authorising_identity", ""),
            authority_basis=AuthorityBasis(d["authority_basis"]),
            evidence=d.get("evidence", ""),
            permitted_capabilities=frozenset(d.get("permitted_capabilities", ())),
            prohibited_capabilities=frozenset(d.get("prohibited_capabilities", ())),
            environments=frozenset(d.get("environments", ())),
            test_window=(float(tw[0]), float(tw[1])) if tw else None,
            issued_at=float(d.get("issued_at", 0.0)),
            expires_at=None if d.get("expires_at") is None else float(d["expires_at"]),
            revocation_status=RevocationStatus(d.get("revocation_status", "active")),
            signature=d.get("signature"),
        )

    # --- liveness ----------------------------------------------------------------
    def is_active(self, now: float | None = None) -> bool:
        """True only if the grant is non-revoked, not expired, and in its test window."""
        now = time() if now is None else now
        if self.revocation_status != RevocationStatus.ACTIVE:
            return False
        if self.expires_at is not None and now >= self.expires_at:
            return False
        if self.test_window is not None:
            start, end = self.test_window
            if now < start or now > end:
                return False
        return True

    def permits(self, capability: str) -> bool:
        """Capability check: prohibited always wins; otherwise must be explicitly permitted."""
        if capability in self.prohibited_capabilities:
            return False
        return capability in self.permitted_capabilities or CAPABILITY_WILDCARD in self.permitted_capabilities


@dataclass(frozen=True)
class GrantDecision:
    """The fail-closed outcome of authorising a target. Default is *denied*."""

    allowed: bool
    reason: str
    tenant_id: str
    asset_id: str
    capability: str
    environment: str
    grant_id: str | None = None

    @classmethod
    def deny(cls, reason: str, *, tenant_id: str, asset_id: str, capability: str,
             environment: str) -> "GrantDecision":
        return cls(False, reason, tenant_id, asset_id, capability, environment, None)


@dataclass
class TenantRegistry:
    """In-memory registry of tenants. INVISABLE is always present."""

    _tenants: dict[str, Tenant] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._tenants.setdefault(INVISABLE_TENANT_ID, INVISABLE_TENANT)

    def add(self, tenant: Tenant) -> None:
        self._tenants[tenant.tenant_id] = tenant

    def get(self, tenant_id: str) -> Tenant | None:
        return self._tenants.get(tenant_id)

    def __contains__(self, tenant_id: object) -> bool:
        return tenant_id in self._tenants


def authorise_target(
    grants: list[AuthorisationGrant],
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
    """Decide whether ``tenant_id`` may exercise ``capability`` on ``asset_id``.

    This is the single, fail-closed authorisation chokepoint for targets. It is
    intentionally pure (no I/O) so it is trivially testable and can sit in front of
    the policy gate. The first grant that fully covers the request authorises it;
    if none does, the request is denied with the most specific reason available.

    Tenant isolation is structural: a grant only ever authorises its own
    ``tenant_id``. A grant issued to tenant A can never authorise tenant B, even
    for an identical asset id.
    """
    now = time() if now is None else now
    deny = lambda reason: GrantDecision.deny(  # noqa: E731 - local shorthand
        reason, tenant_id=tenant_id, asset_id=asset_id,
        capability=capability, environment=environment,
    )

    if not tenant_id:
        return deny("no tenant identity")

    # An explicitly non-active tenant (suspended/archived) is denied outright.
    if tenants is not None:
        tenant = tenants.get(tenant_id)
        if tenant is None:
            return deny(f"unknown tenant '{tenant_id}'")
        if not tenant.active:
            return deny(f"tenant '{tenant_id}' is {tenant.status.value}")

    # Track the closest near-miss so the denial reason is actionable.
    saw_tenant_grant = False
    saw_asset_grant = False
    near_miss: str | None = None

    for grant in grants:
        if grant.tenant_id != tenant_id:
            continue  # cross-tenant: never matches (isolation)
        saw_tenant_grant = True
        if asset_id not in grant.asset_ids:
            continue
        saw_asset_grant = True

        if not grant.is_active(now):
            near_miss = f"grant '{grant.grant_id}' is not active (expired/revoked/out-of-window)"
            continue
        if environment not in grant.environments:
            near_miss = f"grant '{grant.grant_id}' does not cover environment '{environment}'"
            continue
        if not grant.permits(capability):
            near_miss = f"grant '{grant.grant_id}' does not permit capability '{capability}'"
            continue
        if require_signature or verify_key is not None:
            if verify_key is None:
                near_miss = f"grant '{grant.grant_id}' cannot be signature-verified (no key)"
                continue
            if not grant.signature_valid(verify_key):
                near_miss = f"grant '{grant.grant_id}' has an invalid signature"
                continue

        return GrantDecision(
            allowed=True,
            reason=f"authorised by grant '{grant.grant_id}'",
            tenant_id=tenant_id,
            asset_id=asset_id,
            capability=capability,
            environment=environment,
            grant_id=grant.grant_id,
        )

    if near_miss is not None:
        return deny(near_miss)
    if saw_asset_grant:
        return deny(f"no active grant covers asset '{asset_id}'")
    if saw_tenant_grant:
        return deny(f"no grant for tenant '{tenant_id}' covers asset '{asset_id}'")
    return deny(f"no authorisation grant for tenant '{tenant_id}'")
