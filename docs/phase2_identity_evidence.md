# Phase 2 — Identity & Evidence

Blueprint areas 4 (secrets), 5/9 (immutable evidence + attestation), 7 (dashboard identity).
In-process, tested implementations with lazy adapters for the real services.

## Evidence system of record (`attestation/`)

The local hash-chained JSONL (`core/audit.py`) is a **cache**. The authoritative system of
record is an append-only, **hash-chained AND signed** store in a separate trust boundary —
immudb in deployment.

- `InMemoryEvidenceStore` — verifiable chain + signature (dev/tests).
- `ImmudbEvidenceStore` — lazy adapter to immudb.
- `SystemOfRecord` — writes to the authoritative store **and** the cache; verification runs
  against the store, so **deleting the local cache cannot destroy the evidence**
  (bulletproof test #10 — proven by `test_deleting_local_cache_does_not_lose_authoritative_evidence`).
- Signing: **Ed25519** by default (non-repudiable), HMAC-SHA256 fallback when `cryptography`
  is unavailable. Artifact/release signing and pipeline attestation are done by **cosign** and
  **in-toto/witness** in deployment (area 9).

## Short-lived credentials (`identity/credentials.py`)

Guardian receives **short-lived, per-workflow** credentials — never long-lived tokens.

- `InMemoryCredentialBroker` — issues credentials with a TTL; a credential past expiry or
  revoked is refused; `MAX_TTL_SECONDS` is a hard ceiling so long-lived creds cannot exist.
- `OpenBaoBroker` — lazy adapter to OpenBao dynamic secrets.
- Tests: redeem-then-expire, no-long-lived (TTL ceiling), revocation, wrong-secret.

## Dashboard identity (`identity/oidc.py`)

The dashboard is **never exposed directly**. In deployment **oauth2-proxy** (OIDC via
Keycloak / Entra ID) authenticates the user and injects identity headers; this module turns
those **trusted** headers into a `Principal` and enforces role checks.

- `principal_from_headers(..., trust_forwarded_headers=...)` — refuses (fail closed) when the
  headers are untrusted (no proxy) or no identity is present.
- `require_roles(principal, required)` — `Forbidden` unless the principal holds a required role.
- The forwarded headers are only trusted behind the proxy on a private network — never from a
  directly-exposed port (`docker-compose.yml` keeps the dashboard off public ports; area 7).

## Acceptance-gate movement

| Capability | Before | Now |
| ---------- | ------ | --- |
| Audit — immutable + signed evidence; local deletion can't erase it | 🟡 (hash chain cache) | 🟡→ system-of-record + Ed25519 signatures shipped; immudb wiring pending |
| Secrets — short-lived, no long-lived tokens | ⬜ | 🟡 broker contract enforced (TTL ceiling, expiry, revoke); OpenBao wiring pending |
| Identity — OIDC + role checks for the dashboard/APIs | 🟡 (crypto sessions) | 🟡 principal + role enforcement shipped; oauth2-proxy/Keycloak wiring pending |

Bulletproof tests covered here: **#10 deleting local logs does not delete authoritative
evidence** ✅; foundations for **#11 (fail closed if evidence backend unavailable)** and the
secrets/identity rows.

## Next

Wire the deployment services (immudb, OpenBao, oauth2-proxy/Keycloak) per
`docs/architecture/components.yaml`, then add cosign/witness attestation in CI (area 9).
