"""Grant store: issue, persist, load, revoke, authorise — fail-closed & isolated (Phase D)."""

from __future__ import annotations

import pytest

from core import signing
from core.grants import GrantStore, GrantStoreError
from core.tenancy import AuthorityBasis, RevocationStatus

NOW = 1_000_000.0
HOUR = 3600.0


def _issue(store: GrantStore, key: str, **over):
    kw = dict(
        grant_id="g1",
        tenant_id="acme",
        asset_ids=("acme-staging",),
        authorising_identity="admin@acme",
        authority_basis=AuthorityBasis.DNS_CHALLENGE,
        evidence="dns:tok",
        permitted_capabilities=frozenset({"static_code"}),
        environments=frozenset({"staging"}),
        signer_private_key=key,
        ttl_seconds=HOUR,
        now=NOW,
    )
    kw.update(over)
    return store.issue(**kw)


# --- default deny / fail closed -----------------------------------------------
def test_empty_store_authorises_nothing():
    store = GrantStore()
    d = store.authorise(tenant_id="acme", asset_id="acme-staging",
                        capability="static_code", environment="staging", now=NOW)
    assert d.allowed is False


def test_missing_file_is_empty_store(tmp_path):
    store = GrantStore.load(tmp_path / "nope.json")
    assert len(store) == 0


def test_malformed_file_fails_closed(tmp_path):
    p = tmp_path / "g.json"
    p.write_text("{ not json")
    with pytest.raises(GrantStoreError):
        GrantStore.load(p)


def test_missing_grants_key_fails_closed(tmp_path):
    p = tmp_path / "g.json"
    p.write_text('{"schema_version": 1}')
    with pytest.raises(GrantStoreError):
        GrantStore.load(p)


# --- issue + authorise --------------------------------------------------------
def test_issued_grant_authorises():
    kp = signing.generate_keypair()
    store = GrantStore()
    _issue(store, kp.private)
    d = store.authorise(tenant_id="acme", asset_id="acme-staging",
                        capability="static_code", environment="staging", now=NOW,
                        verify_key=kp.public)
    assert d.allowed is True and d.grant_id == "g1"


def test_issue_requires_signing_key_and_signature_verifies():
    kp = signing.generate_keypair()
    store = GrantStore()
    g = _issue(store, kp.private)
    assert g.signature_valid(kp.public) is True


def test_duplicate_grant_id_rejected():
    kp = signing.generate_keypair()
    store = GrantStore()
    _issue(store, kp.private)
    with pytest.raises(GrantStoreError):
        _issue(store, kp.private)


# --- persistence round-trip ---------------------------------------------------
def test_round_trip_preserves_grant_and_signature(tmp_path):
    kp = signing.generate_keypair()
    store = GrantStore()
    _issue(store, kp.private, test_window=(NOW - HOUR, NOW + HOUR),
           prohibited_capabilities=frozenset({"dast"}))
    path = tmp_path / "grants.json"
    store.save(path)

    reloaded = GrantStore.load(path)
    g = reloaded.get("g1")
    assert g is not None
    assert g.signature_valid(kp.public) is True          # signature survives serialisation
    assert g.test_window == (NOW - HOUR, NOW + HOUR)
    assert "dast" in g.prohibited_capabilities
    d = reloaded.authorise(tenant_id="acme", asset_id="acme-staging",
                           capability="static_code", environment="staging", now=NOW,
                           verify_key=kp.public)
    assert d.allowed is True


# --- revocation ---------------------------------------------------------------
def test_revoke_denies_subsequent_authorisation():
    kp = signing.generate_keypair()
    store = GrantStore()
    _issue(store, kp.private)
    store.revoke("g1")
    assert store.get("g1").revocation_status == RevocationStatus.REVOKED
    d = store.authorise(tenant_id="acme", asset_id="acme-staging",
                        capability="static_code", environment="staging", now=NOW)
    assert d.allowed is False


def test_revoke_unknown_fails_closed():
    with pytest.raises(GrantStoreError):
        GrantStore().revoke("nope")


def test_revocation_persists(tmp_path):
    kp = signing.generate_keypair()
    store = GrantStore()
    _issue(store, kp.private)
    store.revoke("g1")
    path = tmp_path / "g.json"
    store.save(path)
    assert GrantStore.load(path).get("g1").revocation_status == RevocationStatus.REVOKED


# --- tenant isolation ---------------------------------------------------------
def test_grants_for_is_tenant_isolated():
    kp = signing.generate_keypair()
    store = GrantStore()
    _issue(store, kp.private, grant_id="a", tenant_id="acme", asset_ids=("shared",))
    _issue(store, kp.private, grant_id="b", tenant_id="globex", asset_ids=("shared",))
    assert {g.grant_id for g in store.grants_for("acme")} == {"a"}
    assert {g.grant_id for g in store.grants_for("globex")} == {"b"}


def test_authorise_never_crosses_tenant():
    kp = signing.generate_keypair()
    store = GrantStore()
    _issue(store, kp.private, grant_id="a", tenant_id="acme", asset_ids=("shared",))
    # globex has no grant for 'shared' even though acme does.
    d = store.authorise(tenant_id="globex", asset_id="shared",
                        capability="static_code", environment="staging", now=NOW)
    assert d.allowed is False


def test_active_grants_excludes_expired_and_revoked():
    kp = signing.generate_keypair()
    store = GrantStore()
    _issue(store, kp.private, grant_id="live")
    _issue(store, kp.private, grant_id="dead", ttl_seconds=1)  # expires at NOW+1
    _issue(store, kp.private, grant_id="gone")
    store.revoke("gone")
    active = {g.grant_id for g in store.active_grants("acme", now=NOW + 10)}
    assert active == {"live"}
