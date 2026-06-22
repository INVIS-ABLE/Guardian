# Ownership Verification (area 2)

A scope file declares *intent* — which assets a run may touch. It is **not proof of ownership**.
`ownership/` provides the proof: a live, expiring, fail-closed verifier that re-proves control of
a domain or repo and drops straight into `Guardrails.ownership_verifier`.

## Why a separate verifier

`core/guardrails.py` already fails closed for production when no verifier is configured —
scope-file membership is explicitly *not* accepted as ownership proof there. This module is the
authoritative verifier you inject so production targets can actually be authorised, and so even
non-production proof is real rather than assumed.

## Proof methods

| Kind | Method | What is checked |
| ---- | ------ | --------------- |
| domain | DNS-TXT | An injected DNS resolver must return `guardian-verification=<token>` for the domain. |
| repo | GitHub-App | An injected GitHub resolver must report an owning login on the allowlist. |

Resolvers are **injected callables** — no DNS or GitHub client is imported here, so the policy
core stays dependency-free and the resolvers can be wired to dnspython / PyGithub (or a mock) in
deployment.

```python
from ownership import OwnershipVerifier, dns_challenge_record

verifier = OwnershipVerifier(
    expected_dns_token={"app.invisable.io": "tok123"},
    dns_resolver=dnspython_txt_lookup,            # domain -> [TXT records]
    allowed_repo_owners={"INVIS-ABLE"},
    github_resolver=github_app_owner_lookup,      # repo -> owning login | None
)
guardrails = Guardrails(scope=scope, ownership_verifier=verifier)

# The record the domain owner must publish:
dns_challenge_record("tok123")   # -> "guardian-verification=tok123"
```

## Fail-closed, and verified *immediately before use*

Every path that isn't a positive, fresh proof returns "not owned":

- no resolver configured, no expected token, or an empty owner allowlist,
- an unknown `kind`,
- a resolver that raises (a DNS/GitHub outage is never read as success),
- a token/owner mismatch.

Proof **expires**. With the default `ttl_seconds=0` the verifier re-resolves on *every* call, so
ownership is proven immediately before the sensitive action — never inferred from a months-old
check. A positive proof may be cached for `ttl_seconds > 0` to bound resolver load; once the
window lapses the next call re-resolves. Failures are never cached, and are audited
(`ownership:unverified:<kind>`, `decision="denied"`) when an audit log is supplied.

## Tests

`tests/test_ownership.py` — DNS-TXT success + every fail-closed branch; repo allowlist
accept/reject; unknown kind; resolver error; TTL caching vs. re-resolution; default TTL=0
re-proves each call; failure audited and not cached; and an end-to-end `Guardrails` check
showing production ownership succeeds only with the verifier (and fails closed without it).
