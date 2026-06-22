# Tenant & Authorised-Target Model

*Phase 0 deliverable. This document specifies the model implemented in
`core/tenancy.py` and tested in `tests/test_tenancy.py`.*

## Why

Guardian's legitimacy rule today is "the target is on the INVISABLE allowlist".
For a vendor-neutral control plane that rule must generalise to:

> A target is legitimate **only** when a **current, non-revoked, signed
> authorisation grant**, belonging to the **requesting tenant**, covers the exact
> **asset + capability + environment** of the request.

This preserves rules 1, 3, 4, 12 and 19 of the platform charter (default deny; no
unauthorised scanning; explicit authorisation evidence; fail closed on uncertainty;
tenant isolation).

## Entities

### Tenant (`core.tenancy.Tenant`)

The unit of isolation — an operator or customer. Every identifier and every grant
belongs to exactly one tenant.

| Field | Meaning |
|-------|---------|
| `tenant_id` | Stable id. INVISABLE's is the reserved `"invisable"`. |
| `legal_name` | Display / contractual name. |
| `deployment_mode` | `DeploymentMode` (drives egress/residency — see DEPLOYMENT_MODES.md). |
| `region`, `data_residency` | Where this tenant's data may live. |
| `encryption_profile`, `retention_policy` | Per-tenant crypto / retention. |
| `administrators` | Identities that may issue grants for the tenant. |
| `status` | `active` / `suspended` / `archived`. Non-active ⇒ deny. |

INVISABLE is preserved as the **built-in first tenant** (`INVISABLE_TENANT`), always
present in a `TenantRegistry`.

### AuthorisationGrant (`core.tenancy.AuthorisationGrant`)

The generalisation of the allowlist. The **only** thing that makes a target
legitimate.

| Field | Meaning |
|-------|---------|
| `grant_id`, `tenant_id` | Identity + owning tenant (isolation is structural). |
| `asset_ids` | Assets this grant authorises (must be non-empty). |
| `authorising_identity` | Who issued it (a tenant administrator). |
| `authority_basis` | `AuthorityBasis` — how authority was established. |
| `evidence` | Reference/digest of the proof (DNS token, repo-install id, contract ref…). |
| `permitted_capabilities` | Allowed capabilities (`"*"` = all-not-prohibited). |
| `prohibited_capabilities` | Always wins over permitted. |
| `environments` | Allowed environments (e.g. `staging`). |
| `test_window` | Optional `(start, end)` epoch window. |
| `issued_at`, `expires_at` | Lifetime. Expiry ⇒ deny. |
| `revocation_status` | `active` / `revoked`. Revoked ⇒ deny. |
| `signature` | Detached signature over `signing_payload()`. |

### AuthorityBasis

`verified_ownership`, `dns_challenge`, `repo_installation`, `cloud_account`,
`signed_declaration`, `contract_reference`, `delegated_admin`. The basis is never
sufficient on its own — it must be backed by recorded `evidence`.

## The decision function

```python
authorise_target(grants, *, tenant_id, asset_id, capability, environment,
                 now=None, verify_key=None, require_signature=False,
                 tenants=None) -> GrantDecision
```

Pure (no I/O), so it is trivially testable and sits cleanly in front of the policy
gate. It returns a fail-closed `GrantDecision` (default **denied**). A request is
authorised only when a single grant satisfies **all** of:

1. `grant.tenant_id == tenant_id` — cross-tenant grants never match.
2. `asset_id in grant.asset_ids`.
3. `grant.is_active(now)` — not revoked, not expired, inside any test window.
4. `environment in grant.environments`.
5. `grant.permits(capability)` — permitted and not prohibited.
6. If a key is supplied (or `require_signature`), the signature verifies.

If a registry is supplied, the tenant must exist and be `active`. Denials carry the
closest near-miss reason so operators can fix the grant, not guess.

### Worked example

```python
from core.tenancy import AuthorisationGrant, AuthorityBasis, authorise_target

grant = AuthorisationGrant(
    grant_id="acme-2026-q3",
    tenant_id="acme",
    asset_ids=("acme-staging",),
    authorising_identity="admin@acme.example",
    authority_basis=AuthorityBasis.DNS_CHALLENGE,
    evidence="dns-token:abc123",
    permitted_capabilities=frozenset({"static_code", "dependency"}),
    environments=frozenset({"staging"}),
    expires_at=now + 86_400,
).signed(private_key_hex)

decision = authorise_target(
    [grant], tenant_id="acme", asset_id="acme-staging",
    capability="static_code", environment="staging", verify_key=public_key_hex,
)
assert decision.allowed
```

## Properties guaranteed by tests

`tests/test_tenancy.py` pins, among others:

- A grant for tenant A never authorises tenant B (even for an identical asset id).
- Empty/unknown/suspended tenant ⇒ deny.
- Missing, expired, revoked, or out-of-window grant ⇒ deny.
- Asset mismatch, capability not permitted, environment mismatch ⇒ deny.
- `prohibited_capabilities` beats a `"*"` wildcard.
- Signature required-but-missing, key-absent, or tampered grant ⇒ deny.
- A pre-tenancy scope file resolves to the founding INVISABLE tenant.

## Relationship to existing components

- **Scope** (`core/scope.py`) gains a backward-compatible `tenant` accessor
  (defaults to `invisable`); `SCOPE_SCHEMA.yaml` gains an optional `tenant:` field.
- **Policy gate / roots of trust** are *not yet* wired to this model — that is the
  next, separately-reviewable step (see INVISABLE_TO_MULTI_TENANT_MIGRATION.md). The
  intended placement is: `authorise_target()` runs **before** `policy_gate.decide()`,
  so target legitimacy is established before action policy is evaluated.
- **Ownership verifier** remains the live proof mechanism; a successful proof is one
  acceptable form of `evidence` backing a grant of basis `verified_ownership`.

## Non-goals (deliberately deferred)

Persistence/storage of grants, a grant-issuance API, per-tenant key management, and
wiring into the live enforcement path are out of scope for this first change. The
model is pure and additive so those can land incrementally without rework.
