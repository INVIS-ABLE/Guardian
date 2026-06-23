"""Tenant-aware policy enforcement (Phase B).

The policy gate gains an *outer AND*: when GUARDIAN_TENANCY_ENFORCE is on, a request
that names a target must also be covered by a current authorisation grant for the
request's tenant (core.tenancy.authorise_target). These tests pin that behaviour and,
critically, that it is INERT by default so the founding INVISABLE deployment is
unchanged. They also confirm the action policy and the tenant gate combine as an AND.
"""

from __future__ import annotations

import pytest

from core.policy_gate import INVISABLE_TENANT_ID, PolicyInput, evaluate
from core.tenancy import AuthorisationGrant, AuthorityBasis

NOW = 1_000_000.0
HOUR = 3600.0


@pytest.fixture
def enforce(monkeypatch):
    monkeypatch.setenv("GUARDIAN_TENANCY_ENFORCE", "1")


def _grant(**over) -> AuthorisationGrant:
    kw = dict(
        grant_id="g-acme",
        tenant_id="acme",
        asset_ids=("staging.acme.example",),
        authorising_identity="admin@acme.example",
        authority_basis=AuthorityBasis.DNS_CHALLENGE,
        evidence="dns-token:xyz",
        permitted_capabilities=frozenset({"static_code"}),
        environments=frozenset({"staging"}),
        expires_at=NOW + HOUR,
    )
    kw.update(over)
    return AuthorisationGrant(**kw)


def _inp(**over) -> PolicyInput:
    kw = dict(
        actor="guardian",
        action="code_review",
        mode="code_review",
        environment="staging",
        tenant_id="acme",
        domain="staging.acme.example",
        capability="static_code",
        ownership_verified=True,
        allowed_modes=["code_review"],
        now=NOW,
    )
    kw.update(over)
    return PolicyInput(**kw)


# --- default OFF: behaviour is unchanged --------------------------------------
def test_tenancy_inert_by_default():
    """With enforcement off, a request with NO grants is still allowed by the action policy."""
    d = evaluate(_inp(grants=[]))
    assert d.allow is True


def test_default_tenant_is_invisable():
    assert PolicyInput(actor="a", action="x", mode="m", environment="staging").tenant_id == (
        INVISABLE_TENANT_ID
    )


# --- enforcement ON -----------------------------------------------------------
def test_enforced_allows_with_valid_grant(enforce):
    d = evaluate(_inp(grants=[_grant()]))
    assert d.allow is True


def test_enforced_denies_without_grant(enforce):
    d = evaluate(_inp(grants=[]))
    assert d.allow is False
    assert any("tenant_unauthorised" in x for x in d.denies)


def test_enforced_denies_cross_tenant_grant(enforce):
    """A grant for globex must not authorise an acme request for the same asset."""
    g = _grant(tenant_id="globex")
    d = evaluate(_inp(grants=[g]))
    assert d.allow is False
    assert any("tenant_unauthorised" in x for x in d.denies)


def test_enforced_denies_missing_capability(enforce):
    d = evaluate(_inp(grants=[_grant()], capability=None))
    assert d.allow is False
    assert "tenant_capability_unspecified" in d.denies


def test_enforced_denies_capability_escalation(enforce):
    d = evaluate(_inp(grants=[_grant()], capability="dast"))
    assert d.allow is False
    assert any("tenant_unauthorised" in x for x in d.denies)


def test_enforced_non_target_action_left_to_action_policy(enforce):
    """An action naming no target (no domain/repo/asset) is governed by the action policy."""
    d = evaluate(_inp(grants=[], domain=None, capability=None))
    assert d.allow is True  # action policy allows code_review in staging


# --- the two gates combine as an AND ------------------------------------------
def test_tenant_and_action_policy_are_anded(enforce):
    """Valid grant but a blocked action ⇒ denied (action policy still applies)."""
    d = evaluate(_inp(grants=[_grant(permitted_capabilities=frozenset({"hack_back"}))],
                      action="hack_back", capability="hack_back"))
    assert d.allow is False
    assert any("blocked_action" in x for x in d.denies)


def test_tenant_denial_and_action_denial_both_reported(enforce):
    """No grant AND a blocked action ⇒ both reasons surface."""
    d = evaluate(_inp(grants=[], action="hack_back", capability="hack_back"))
    assert d.allow is False
    assert any("tenant_unauthorised" in x for x in d.denies)
    assert any("blocked_action" in x for x in d.denies)


# --- signature enforcement flows through --------------------------------------
def test_enforced_requires_valid_signature_when_key_set(enforce):
    from core import signing

    kp = signing.generate_keypair()
    signed = _grant().signed(kp.private)
    assert evaluate(_inp(grants=[signed], verify_grant_key=kp.public)).allow is True
    # Unsigned grant with a verify key required ⇒ denied.
    assert evaluate(_inp(grants=[_grant()], verify_grant_key=kp.public)).allow is False
