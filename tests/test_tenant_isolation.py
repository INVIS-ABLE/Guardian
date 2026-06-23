"""Cross-tenant isolation across the data plane (Phase C).

These tests pin tenant isolation on the surfaces generalised in Phase C: the
ownership verifier (per-tenant config + cache), the target root of trust, the signed
connector authorisation (tenant bound into the signature), and the evidence/finding
models. Together with test_tenancy.py and test_policy_tenancy.py they cover the
platform "cross-tenant" testing requirements.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from connectors.contract import (
    ActionRequest,
    ContractViolation,
    authorize_execution,
    canonical_request,
    sign_authorization,
)
from core import signing
from core.evidence.models import EvidenceItem, Finding, Provenance, AssetRef
from core.roots_of_trust import RootsOfTrust, TargetTrust, TrustContext, Root
from core.tenancy import INVISABLE_TENANT_ID
from ownership import OwnershipVerifier, dns_challenge_record


def _dns(records):
    return lambda d: records.get(d, [])


# --- ownership verifier: per-tenant config + cache isolation ------------------
def test_flat_maps_belong_to_default_invisable_tenant():
    v = OwnershipVerifier(
        expected_dns_token={"app.invisable.io": "tok"},
        dns_resolver=_dns({"app.invisable.io": [dns_challenge_record("tok")]}),
    )
    ev = v.verify("domain", "app.invisable.io")
    assert ev is not None and ev.tenant == INVISABLE_TENANT_ID


def test_unconfigured_tenant_fails_closed():
    """A tenant with no DNS config cannot borrow another tenant's flat map."""
    v = OwnershipVerifier(
        expected_dns_token={"app.invisable.io": "tok"},
        dns_resolver=_dns({"app.invisable.io": [dns_challenge_record("tok")]}),
    )
    assert v.verify("domain", "app.invisable.io", tenant="acme") is None


def test_per_tenant_dns_config_is_isolated():
    v = OwnershipVerifier(
        dns_resolver=_dns({"x.acme.example": [dns_challenge_record("acme-tok")]}),
        tenant_dns_tokens={"acme": {"x.acme.example": "acme-tok"}},
    )
    assert v.verify("domain", "x.acme.example", tenant="acme") is not None
    # A different tenant must not be authorised for acme's domain.
    assert v.verify("domain", "x.acme.example", tenant="globex") is None


def test_cache_is_keyed_per_tenant():
    v = OwnershipVerifier(
        dns_resolver=_dns({"x.acme.example": [dns_challenge_record("acme-tok")]}),
        tenant_dns_tokens={"acme": {"x.acme.example": "acme-tok"}},
        ttl_seconds=1000,
    )
    assert v.verify("domain", "x.acme.example", tenant="acme", now=1.0) is not None
    assert ("domain", "x.acme.example", "acme") in v._cache
    # globex shares the target string but must not hit acme's cached proof.
    assert v.verify("domain", "x.acme.example", tenant="globex", now=1.0) is None


def test_repo_owners_per_tenant():
    v = OwnershipVerifier(
        github_resolver=lambda r: "ACME-ORG" if r == "ACME-ORG/app" else None,
        tenant_repo_owners={"acme": {"ACME-ORG"}},
    )
    assert v.verify("repo", "ACME-ORG/app", tenant="acme") is not None
    assert v.verify("repo", "ACME-ORG/app", tenant="globex") is None


# --- target root of trust: tenant dimension -----------------------------------
def _full_target(**over):
    kw = dict(ownership_verified=True, environment="staging",
              resolved_addresses=("203.0.113.5",), dns_unchanged=True, not_third_party=True)
    kw.update(over)
    return TargetTrust(**kw)


def test_target_root_requires_tenant():
    """An empty tenant fails the target root even when everything else holds."""
    gate = RootsOfTrust()
    ctx = TrustContext(target=_full_target(tenant_id=""))
    report = gate.verify(ctx, environment="staging", required=frozenset({Root.TARGET}))
    assert report.allow is False
    assert "target:no_tenant" in report.reasons()


def test_target_root_defaults_to_invisable_and_passes():
    gate = RootsOfTrust()
    ctx = TrustContext(target=_full_target())  # tenant_id defaults to invisable
    report = gate.verify(ctx, environment="staging", required=frozenset({Root.TARGET}))
    assert report.allow is True


# --- connector authorisation: tenant bound into the signature -----------------
def test_tenant_bound_into_signed_authorization():
    kp = signing.generate_keypair()
    req = ActionRequest(action="scan", target="staging.acme.example", tenant_id="acme")
    auth = sign_authorization(req, signer_private_key=kp.private, approver="admin")
    # Valid for the acme request.
    authorize_execution(auth, verify_key=kp.public)
    # Re-pointing the same authorisation at a globex request breaks the signature.
    forged = replace(auth, request=replace(req, tenant_id="globex"))
    with pytest.raises(ContractViolation):
        authorize_execution(forged, verify_key=kp.public)


def test_canonical_request_includes_tenant():
    a = canonical_request(ActionRequest(action="s", target="t", tenant_id="acme"))
    b = canonical_request(ActionRequest(action="s", target="t", tenant_id="globex"))
    assert a != b


# --- evidence & findings carry a tenant ---------------------------------------
def test_evidence_item_defaults_to_invisable():
    item = EvidenceItem(kind="dns_txt", summary="x", provenance=Provenance(tool="dns"))
    assert item.tenant_id == INVISABLE_TENANT_ID


def test_evidence_and_finding_tenant_is_explicit_and_isolating():
    prov = Provenance(tool="semgrep")
    a = EvidenceItem(kind="sarif", summary="x", provenance=prov, tenant_id="acme")
    b = EvidenceItem(kind="sarif", summary="x", provenance=prov, tenant_id="globex")
    assert a.tenant_id != b.tenant_id
    f = Finding(title="t", asset=AssetRef(kind="repo", identifier="acme/app"),
                provenance=prov, tenant_id="acme")
    assert f.tenant_id == "acme"
