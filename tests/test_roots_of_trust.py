"""The six roots of trust gate sensitive capability issuance and fail closed."""

from __future__ import annotations

from uuid import uuid4

import pytest

from core.roots_of_trust import (
    ALL_ROOTS,
    EvidenceTrust,
    HumanTrust,
    MachineTrust,
    Root,
    RootsOfTrust,
    SoftwareTrust,
    TargetTrust,
    TrustContext,
    WorkloadTrust,
    require_roots,
)


def _full_human(production: bool = False) -> HumanTrust:
    approvers = ("ciso", "head_of_eng") if production else ("ciso",)
    return HumanTrust(
        authenticated=True, phishing_resistant=True, active=True, role="security-analyst",
        requester="alice", approvers=approvers, approval_valid=True, envelope_bound=True,
    )


def _full_context(environment: str = "staging", production: bool = False) -> TrustContext:
    return TrustContext(
        human=_full_human(production),
        workload=WorkloadTrust(spiffe_id="spiffe://guardian/exec", namespace="guardian",
                               service_account="exec", image_digest="sha256:" + "b" * 64,
                               runtime_profile="restricted", cert_valid=True, not_revoked=True),
        machine=MachineTrust(secure_boot=True, tpm_attested=True, measured_boot=True,
                             ima_ok=True, approved_firmware=True, not_quarantined=True),
        software=SoftwareTrust(approved_repo=True, commit="abc123", build_verified=True,
                               sbom_present=True, provenance_valid=True, signature_valid=True,
                               approved_builder=True, deps_approved=True,
                               policy_connector_digest_ok=True),
        target=TargetTrust(ownership_verified=True, environment=environment,
                           resolved_addresses=("203.0.113.5",), dns_unchanged=True,
                           not_third_party=True),
        evidence=EvidenceTrust(service_available=True, append_ok=True, attestation_generated=True,
                               trace_id="t-1", case_id=str(uuid4()), shadow_received=True),
    )


def test_empty_context_fails_every_root():
    report = RootsOfTrust().verify(TrustContext(), environment="staging")
    assert not report.allow
    assert set(report.failed_roots()) == set(ALL_ROOTS)


def test_full_context_passes():
    report = RootsOfTrust().verify(_full_context(), environment="staging")
    assert report.allow, report.reasons()


@pytest.mark.parametrize("root", list(Root))
def test_each_root_is_independently_required(root):
    # Knock out exactly one root's evidence; only that root should fail.
    ctx = _full_context()
    broken = ctx.model_copy(update={root.value: type(getattr(ctx, root.value))()})
    report = RootsOfTrust().verify(broken, environment="staging")
    assert not report.allow
    assert report.failed_roots() == [root]


def test_production_requires_two_distinct_reviewers():
    # A single approver is enough for staging but NOT for production.
    staging_ok = RootsOfTrust().verify(_full_context(production=False), environment="staging")
    assert staging_ok.allow
    prod_one = _full_context(environment="production", production=False)  # only 1 approver
    report = RootsOfTrust().verify(prod_one, environment="production")
    assert not report.allow
    assert Root.HUMAN in report.failed_roots()


def test_self_review_is_rejected():
    ctx = _full_context()
    bad = ctx.model_copy(update={"human": _full_human().model_copy(
        update={"requester": "ciso", "approvers": ("ciso",)})})
    report = RootsOfTrust().verify(bad, environment="staging")
    assert not report.allow
    assert any("self_review" in r for r in report.reasons())


def test_required_subset_only_checks_those_roots():
    ctx = TrustContext(human=_full_human())  # only human populated
    report = RootsOfTrust().verify(ctx, environment="staging", required=frozenset({Root.HUMAN}))
    assert report.allow


def test_require_roots_posture(monkeypatch):
    monkeypatch.delenv("GUARDIAN_REQUIRE_ROOTS", raising=False)
    monkeypatch.setenv("GUARDIAN_ENV", "development")
    assert require_roots() is False
    monkeypatch.setenv("GUARDIAN_ENV", "production")
    assert require_roots() is True
    monkeypatch.setenv("GUARDIAN_ENV", "development")
    monkeypatch.setenv("GUARDIAN_REQUIRE_ROOTS", "1")
    assert require_roots() is True
