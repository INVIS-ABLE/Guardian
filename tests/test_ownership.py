"""Live, expiring, fail-closed ownership verification (blueprint area 2)."""

from __future__ import annotations

from ownership import OwnershipVerifier, ProofMethod, dns_challenge_record


def _dns(records: dict[str, list[str]]):
    return lambda domain: records.get(domain, [])


def _gh(owners: dict[str, str]):
    return lambda repo: owners.get(repo)


# --- domain (DNS-TXT) ----------------------------------------------------------------------

def test_domain_verified_when_challenge_token_published():
    v = OwnershipVerifier(
        expected_dns_token={"app.invisable.io": "tok123"},
        dns_resolver=_dns({"app.invisable.io": [dns_challenge_record("tok123")]}),
    )
    ev = v.verify("domain", "app.invisable.io")
    assert ev is not None
    assert ev.method is ProofMethod.DNS_TXT
    assert v("domain", "app.invisable.io") is True


def test_domain_fails_closed_without_resolver():
    v = OwnershipVerifier(expected_dns_token={"app.invisable.io": "tok123"})
    assert v("domain", "app.invisable.io") is False


def test_domain_fails_closed_without_expected_token():
    v = OwnershipVerifier(dns_resolver=_dns({"x.io": [dns_challenge_record("whatever")]}))
    assert v("domain", "x.io") is False


def test_domain_fails_closed_on_wrong_or_missing_record():
    v = OwnershipVerifier(
        expected_dns_token={"app.invisable.io": "tok123"},
        dns_resolver=_dns({"app.invisable.io": ["guardian-verification=OTHER"]}),
    )
    assert v("domain", "app.invisable.io") is False


def test_resolver_error_is_not_success():
    def boom(_domain):
        raise RuntimeError("dns down")

    v = OwnershipVerifier(expected_dns_token={"a.io": "t"}, dns_resolver=boom)
    assert v("domain", "a.io") is False


# --- repo (GitHub-App) ---------------------------------------------------------------------

def test_repo_verified_for_allowlisted_owner():
    v = OwnershipVerifier(
        allowed_repo_owners={"INVIS-ABLE"},
        github_resolver=_gh({"INVIS-ABLE/Guardian": "INVIS-ABLE"}),
    )
    assert v("repo", "INVIS-ABLE/Guardian") is True


def test_repo_fails_closed_for_unlisted_owner():
    v = OwnershipVerifier(
        allowed_repo_owners={"INVIS-ABLE"},
        github_resolver=_gh({"someone/Guardian": "someone"}),
    )
    assert v("repo", "someone/Guardian") is False


def test_unknown_kind_fails_closed():
    v = OwnershipVerifier(
        expected_dns_token={"a.io": "t"}, dns_resolver=_dns({"a.io": ["guardian-verification=t"]})
    )
    assert v("bucket", "a.io") is False


# --- expiry / freshness --------------------------------------------------------------------

def test_evidence_expires_and_triggers_reresolution():
    calls = {"n": 0}

    def counting_resolver(domain):
        calls["n"] += 1
        return [dns_challenge_record("t")]

    v = OwnershipVerifier(
        expected_dns_token={"a.io": "t"}, dns_resolver=counting_resolver, ttl_seconds=100,
    )
    # First call resolves and caches; a call inside the window reuses the cache.
    assert v.verify("domain", "a.io", now=1_000) is not None
    assert v.verify("domain", "a.io", now=1_050) is not None
    assert calls["n"] == 1
    # Past the TTL it must re-resolve.
    assert v.verify("domain", "a.io", now=1_200) is not None
    assert calls["n"] == 2


def test_default_ttl_zero_reresolves_every_call():
    calls = {"n": 0}

    def counting_resolver(domain):
        calls["n"] += 1
        return [dns_challenge_record("t")]

    v = OwnershipVerifier(expected_dns_token={"a.io": "t"}, dns_resolver=counting_resolver)
    v("domain", "a.io")
    v("domain", "a.io")
    assert calls["n"] == 2  # verified immediately before each use


def test_failure_is_audited_and_not_cached():
    class _Audit:
        def __init__(self):
            self.entries = []

        def record(self, action, *, actor, scope=None, decision="allowed", detail=None):
            self.entries.append({"action": action, "decision": decision, "scope": scope})

    audit = _Audit()
    v = OwnershipVerifier(expected_dns_token={"a.io": "t"}, audit=audit)  # no resolver -> fail
    assert v("domain", "a.io") is False
    assert ("domain", "a.io") not in v._cache
    assert audit.entries and audit.entries[0]["decision"] == "denied"


# --- integration with Guardrails -----------------------------------------------------------

def test_guardrails_uses_verifier_for_production_ownership():
    from pathlib import Path

    from core.guardrails import Guardrails
    from core.scope import Scope

    scope = Scope(
        path=Path("invisable-prod.yaml"),
        raw={
            "asset": "invisable-prod",
            "environment": "production",
            "owner": "INVIS-ABLE",
            "allowed_repos": ["INVIS-ABLE/Guardian"],
        },
    )
    verifier = OwnershipVerifier(
        allowed_repo_owners={"INVIS-ABLE"},
        github_resolver=_gh({"INVIS-ABLE/Guardian": "INVIS-ABLE"}),
    )
    gr = Guardrails(scope=scope, ownership_verifier=verifier)
    # The verifier proves ownership; without it, production fails closed (scope != proof).
    assert gr._verify_ownership("repo", "INVIS-ABLE/Guardian") is True

    gr_no_verifier = Guardrails(scope=scope)
    assert gr_no_verifier._verify_ownership("repo", "INVIS-ABLE/Guardian") is False
