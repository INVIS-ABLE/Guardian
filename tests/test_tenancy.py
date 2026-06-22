"""Tenancy & authorised-target foundation: default-deny, fail-closed, isolated.

These tests pin the security-critical behaviour of core/tenancy.py. They map
directly onto the platform testing requirements: tenant boundary violations,
cross-tenant identifiers, missing/expired/revoked authorisation, target mismatch,
capability escalation, environment mismatch, and signature failure.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from core import signing
from core.scope import load_scope
from core.tenancy import (
    INVISABLE_TENANT_ID,
    AuthorisationGrant,
    AuthorityBasis,
    DeploymentMode,
    GrantDecision,
    RevocationStatus,
    Tenant,
    TenantRegistry,
    TenantStatus,
    TenancyError,
    authorise_target,
)

NOW = 1_000_000.0
HOUR = 3600.0


def _grant(**over) -> AuthorisationGrant:
    kw = dict(
        grant_id="g-1",
        tenant_id="acme",
        asset_ids=("acme-staging",),
        authorising_identity="admin@acme.example",
        authority_basis=AuthorityBasis.DNS_CHALLENGE,
        evidence="dns-token:abc123",
        permitted_capabilities=frozenset({"static_code", "dependency"}),
        environments=frozenset({"staging"}),
        issued_at=NOW - HOUR,
        expires_at=NOW + HOUR,
    )
    kw.update(over)
    return AuthorisationGrant(**kw)


def _authorise(grants, **over) -> GrantDecision:
    kw = dict(
        tenant_id="acme",
        asset_id="acme-staging",
        capability="static_code",
        environment="staging",
        now=NOW,
    )
    kw.update(over)
    return authorise_target(grants, **kw)


# --- happy path ---------------------------------------------------------------
def test_valid_grant_authorises():
    d = _authorise([_grant()])
    assert d.allowed is True
    assert d.grant_id == "g-1"


# --- default deny -------------------------------------------------------------
def test_no_grants_is_denied():
    d = _authorise([])
    assert d.allowed is False
    assert "no authorisation grant" in d.reason


def test_empty_tenant_is_denied():
    d = _authorise([_grant()], tenant_id="")
    assert d.allowed is False


# --- tenant isolation ---------------------------------------------------------
def test_cross_tenant_grant_never_authorises():
    """A grant for 'acme' must never authorise 'globex', even for the same asset id."""
    g = _grant(tenant_id="acme", asset_ids=("shared-asset",))
    d = authorise_target(
        [g], tenant_id="globex", asset_id="shared-asset",
        capability="static_code", environment="staging", now=NOW,
    )
    assert d.allowed is False
    assert "globex" in d.reason


def test_suspended_tenant_denied_even_with_grant():
    reg = TenantRegistry()
    reg.add(Tenant("acme", "Acme Ltd", status=TenantStatus.SUSPENDED))
    d = _authorise([_grant()], tenants=reg)
    assert d.allowed is False
    assert "suspended" in d.reason


def test_unknown_tenant_denied_when_registry_supplied():
    reg = TenantRegistry()  # only INVISABLE present
    d = _authorise([_grant()], tenants=reg)
    assert d.allowed is False
    assert "unknown tenant" in d.reason


# --- target / asset mismatch --------------------------------------------------
def test_asset_mismatch_is_denied():
    d = _authorise([_grant(asset_ids=("other-asset",))])
    assert d.allowed is False
    assert "acme-staging" in d.reason


# --- expiry / revocation / window ---------------------------------------------
def test_expired_grant_is_denied():
    d = _authorise([_grant(expires_at=NOW - 1)])
    assert d.allowed is False
    assert "not active" in d.reason


def test_revoked_grant_is_denied():
    d = _authorise([_grant(revocation_status=RevocationStatus.REVOKED)])
    assert d.allowed is False
    assert "not active" in d.reason


def test_grant_outside_test_window_is_denied():
    g = _grant(test_window=(NOW + HOUR, NOW + 2 * HOUR))
    d = _authorise([g])
    assert d.allowed is False


def test_grant_inside_test_window_is_allowed():
    g = _grant(test_window=(NOW - HOUR, NOW + HOUR))
    d = _authorise([g])
    assert d.allowed is True


# --- capability escalation ----------------------------------------------------
def test_capability_not_permitted_is_denied():
    d = _authorise([_grant()], capability="dast")
    assert d.allowed is False
    assert "dast" in d.reason


def test_prohibited_capability_beats_wildcard():
    g = _grant(
        permitted_capabilities=frozenset({"*"}),
        prohibited_capabilities=frozenset({"exploit_deployment"}),
    )
    assert _authorise([g], capability="static_code").allowed is True
    assert _authorise([g], capability="exploit_deployment").allowed is False


# --- environment mismatch -----------------------------------------------------
def test_environment_mismatch_is_denied():
    d = _authorise([_grant()], environment="production")
    assert d.allowed is False
    assert "production" in d.reason


# --- signature verification ---------------------------------------------------
def test_signature_required_but_missing_is_denied():
    kp = signing.generate_keypair()
    d = _authorise([_grant()], verify_key=kp.public)
    assert d.allowed is False
    assert "signature" in d.reason


def test_valid_signature_passes():
    kp = signing.generate_keypair()
    g = _grant().signed(kp.private)
    assert g.signature_valid(kp.public) is True
    d = _authorise([g], verify_key=kp.public)
    assert d.allowed is True


def test_tampered_grant_fails_signature():
    kp = signing.generate_keypair()
    g = _grant().signed(kp.private)
    # Widen the asset set after signing — the signature must no longer verify.
    tampered = replace(g, asset_ids=("acme-staging", "acme-production"))
    assert tampered.signature_valid(kp.public) is False
    d = authorise_target(
        [tampered], tenant_id="acme", asset_id="acme-production",
        capability="static_code", environment="staging", now=NOW,
        verify_key=kp.public,
    )
    assert d.allowed is False


def test_require_signature_without_key_is_denied():
    d = _authorise([_grant()], require_signature=True)
    assert d.allowed is False


# --- structural validation ----------------------------------------------------
def test_grant_with_no_assets_is_rejected():
    with pytest.raises(TenancyError):
        _grant(asset_ids=())


def test_tenant_requires_id():
    with pytest.raises(TenancyError):
        Tenant(tenant_id="  ", legal_name="x")


# --- INVISABLE preserved as first tenant --------------------------------------
def test_invisable_tenant_built_in():
    reg = TenantRegistry()
    inv = reg.get(INVISABLE_TENANT_ID)
    assert inv is not None
    assert inv.active
    assert inv.deployment_mode == DeploymentMode.SINGLE_TENANT_SELF_HOSTED


def test_pre_tenancy_scope_defaults_to_invisable(tmp_path):
    """A scope file with no `tenant:` key resolves to the founding INVISABLE tenant."""
    scope = load_scope("scope/invisable-staging.yaml")
    assert scope.tenant == INVISABLE_TENANT_ID
