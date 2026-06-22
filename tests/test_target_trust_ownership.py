"""Bridge: the real ownership verifier populates the six-roots target root."""

from __future__ import annotations

from core.roots_of_trust import Root, RootsOfTrust
from core.trust_producers import build_trust_context, target_trust_from_ownership
from ownership import OwnershipVerifier, dns_challenge_record

DOMAIN = "app.invisable.io"
TOKEN = "tok123"
ADDR = ("203.0.113.5",)


def _verifier() -> OwnershipVerifier:
    return OwnershipVerifier(
        expected_dns_token={DOMAIN: TOKEN},
        allowed_repo_owners={"invisable"},
        dns_resolver=lambda d: [dns_challenge_record(TOKEN)] if d == DOMAIN else [],
        github_resolver=lambda repo: "invisable" if repo.startswith("github.com/invisable/") else None,
        ttl_seconds=3600,
    )


def _target_root_ok(ctx) -> bool:
    return RootsOfTrust().verify(ctx, environment="staging",
                                 required=frozenset({Root.TARGET})).allow


def test_owned_domain_with_unchanged_dns_passes_target_root():
    ev = _verifier().verify("domain", DOMAIN)
    assert ev is not None
    tgt = target_trust_from_ownership(ev, environment="staging",
                                      resolved_addresses=ADDR, authorised_addresses=ADDR)
    assert _target_root_ok(build_trust_context(target=tgt))


def test_owned_repo_passes_ownership_half():
    ev = _verifier().verify("repo", "github.com/invisable/app")
    tgt = target_trust_from_ownership(ev, environment="staging",
                                      resolved_addresses=ADDR, authorised_addresses=ADDR)
    assert tgt.ownership_verified and tgt.not_third_party


def test_unowned_target_fails_target_root():
    ev = _verifier().verify("domain", "attacker.example")  # not owned -> None
    assert ev is None
    tgt = target_trust_from_ownership(ev, environment="staging",
                                      resolved_addresses=ADDR, authorised_addresses=ADDR)
    report = RootsOfTrust().verify(build_trust_context(target=tgt), environment="staging",
                                   required=frozenset({Root.TARGET}))
    assert not report.allow
    assert any("ownership_verified" in r for r in report.reasons())


def test_post_authorisation_dns_change_fails_target_root():
    ev = _verifier().verify("domain", DOMAIN)
    tgt = target_trust_from_ownership(ev, environment="staging",
                                      resolved_addresses=("203.0.113.9",),  # changed
                                      authorised_addresses=ADDR)
    report = RootsOfTrust().verify(build_trust_context(target=tgt), environment="staging",
                                   required=frozenset({Root.TARGET}))
    assert not report.allow
    assert any("dns_unchanged" in r for r in report.reasons())


def test_no_baseline_is_fail_closed_on_dns():
    ev = _verifier().verify("domain", DOMAIN)
    tgt = target_trust_from_ownership(ev, environment="staging", resolved_addresses=ADDR)
    # ownership proven, but with no authorised baseline dns_unchanged stays False (fail closed)
    assert tgt.ownership_verified and not tgt.dns_unchanged
