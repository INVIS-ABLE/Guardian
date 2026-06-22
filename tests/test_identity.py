"""Phase 2 — short-lived credentials + OIDC identity/role enforcement."""

from __future__ import annotations

import time

import pytest

from identity import (
    Forbidden,
    InMemoryCredentialBroker,
    MAX_TTL_SECONDS,
    CredentialExpired,
    CredentialRevoked,
    Unauthenticated,
    principal_from_headers,
    require_roles,
)


# --------------------------------------------------------------------- credentials
def test_credential_redeems_then_expires():
    broker = InMemoryCredentialBroker()
    cred = broker.issue("connector:trivy@staging", ttl=2)
    assert broker.redeem(cred.id, cred.secret).scope == "connector:trivy@staging"
    # Past expiry → refused.
    with pytest.raises(CredentialExpired):
        broker.redeem(cred.id, cred.secret, now=time.time() + 10)


def test_no_long_lived_credentials():
    broker = InMemoryCredentialBroker()
    with pytest.raises(ValueError):
        broker.issue("x", ttl=MAX_TTL_SECONDS + 1)


def test_revoked_credential_refused():
    broker = InMemoryCredentialBroker()
    cred = broker.issue("x", ttl=60)
    broker.revoke(cred.id)
    with pytest.raises(CredentialRevoked):
        broker.redeem(cred.id, cred.secret)


def test_wrong_secret_refused():
    broker = InMemoryCredentialBroker()
    cred = broker.issue("x", ttl=60)
    with pytest.raises(CredentialRevoked):
        broker.redeem(cred.id, "not-the-secret")


# ---------------------------------------------------------------------------- OIDC
def test_unauthenticated_when_headers_untrusted():
    with pytest.raises(Unauthenticated):
        principal_from_headers({"x-forwarded-user": "alice"}, trust_forwarded_headers=False)


def test_unauthenticated_when_no_identity():
    with pytest.raises(Unauthenticated):
        principal_from_headers({}, trust_forwarded_headers=True)


def test_principal_and_role_enforcement():
    p = principal_from_headers(
        {"X-Forwarded-User": "alice", "X-Forwarded-Email": "a@x", "X-Forwarded-Groups": "admin,secops"},
        trust_forwarded_headers=True,
    )
    assert p.subject == "alice" and p.email == "a@x"
    require_roles(p, {"admin"})  # holds admin → ok
    with pytest.raises(Forbidden):
        require_roles(p, {"superuser"})  # lacks role → forbidden
