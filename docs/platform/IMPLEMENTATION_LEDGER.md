# Platform Implementation Ledger

What has actually been **built, tested, and merged** for the universal-platform
programme. Claims here are only made for code that exists and passes tests.

## Shipped

### Tenant-neutral domain model + authorised-target grants
- **Decision:** D-0001, D-0002 (DECISION_LOG.md).
- **Code:** `core/tenancy.py` — `Tenant`, `AuthorisationGrant`, `GrantDecision`,
  `TenantRegistry`, `authorise_target()`, enums (`DeploymentMode`, `TenantStatus`,
  `AuthorityBasis`, `RevocationStatus`), built-in `INVISABLE_TENANT`.
- **Integration:** `Scope.tenant` accessor (`core/scope.py`); optional `tenant:`
  field in `SCOPE_SCHEMA.yaml`. **Not** on the enforcement path.
- **Licence:** First-party Guardian code. No third-party dependency added.
- **Egress / secrets:** None. Pure in-memory model; no I/O, no network.
- **Tenant data accessed:** None (model only).
- **Evidence:** Grants are signable via `core.signing` (Ed25519 / HMAC fallback),
  consistent with `connectors/contract.py` and `attestation/`.
- **Tests:** `tests/test_tenancy.py` — 22 tests: tenant isolation, missing/expired/
  revoked/out-of-window authorisation, asset & environment mismatch, capability
  escalation, prohibited-beats-wildcard, signature required/missing/tampered,
  INVISABLE default. Full suite green (no regressions).
- **Feature flag:** Not required (additive, off the enforcement path).
- **Risks:** Model could drift from enforcement if Phase B lags — tracked here.
- **Rollback:** Delete the module, test, accessor, and schema field. Lossless.
- **Owner:** Platform architecture. **Review date:** at Phase B start.

### Tenant-aware policy enforcement (Phase B, feature-flagged)
- **Decision:** D-0004 (DECISION_LOG.md).
- **Code:** `core/policy_gate.py` — `_tenancy_enforced()` (flag `GUARDIAN_TENANCY_ENFORCE`,
  default off), `_tenant_denies()`, `evaluate()` refactored to apply tenant
  authorisation as an outer AND over `_evaluate_core()` (the unchanged OPA/embedded
  path). `PolicyInput` gains inert `tenant_id` (default `invisable`), `capability`,
  `asset_id`, `grants`, `verify_grant_key`.
- **Integration:** scope tenant threaded into `PolicyInput` at both construction
  sites (`core/guardrails.py`, `core/brain/orchestrator.py`).
- **Parity:** tenant check lives **outside** `decide()`, so `policies/opa/guardian.rego`
  and the OPA/embedded parity test are untouched.
- **Tests:** `tests/test_policy_tenancy.py` — inert-by-default, allow-with-grant,
  deny-without-grant, cross-tenant denial, missing-capability, capability escalation,
  non-target action, AND-composition with the action policy, and signature
  enforcement. Full suite green.
- **Feature flag:** `GUARDIAN_TENANCY_ENFORCE` (default off).
- **Rollback:** unset the flag (instant) or revert the additions. Lossless.
- **Owner:** Platform architecture. **Review date:** at Phase C start.

### Data-plane tenant scoping (Phase C, additive)
- **Decision:** D-0005 (DECISION_LOG.md).
- **Code:** `tenant_id` on `ActionRequest` (bound into `canonical_request`),
  `EvidenceItem`, `Finding`, and `TargetTrust` (empty tenant fails the target root).
  `ownership/verifier.py` generalised to per-tenant DNS/repo config with a
  `(kind, target, tenant)` cache key; `OwnershipEvidence` carries `tenant`.
- **Defaults:** every new field defaults to `invisable`, so existing callers/tests and
  stored shapes are unchanged.
- **Tests:** `tests/test_tenant_isolation.py` — per-tenant ownership config & cache
  isolation, unconfigured-tenant fail-closed, target-root tenant requirement, signed
  authorisation bound to tenant (cross-tenant replay rejected), evidence/finding
  tenant fields. Full suite green.
- **Rollback:** remove the fields and the verifier's tenant maps/cache key. Lossless.
- **Owner:** Platform architecture. **Review date:** at Phase D start.

### Phase 0 platform documentation
- `docs/platform/`: README, CURRENT_STATE_ASSESSMENT, GUARDIAN_UNIVERSAL_PRODUCT_VISION,
  TENANT_AND_AUTHORISED_TARGET_MODEL, INVISABLE_TO_MULTI_TENANT_MIGRATION,
  DEPLOYMENT_MODES, DECISION_LOG, IMPLEMENTATION_LEDGER.

## Planned (not yet built — do not claim as done)

| Item | Phase | Tracked in |
|------|-------|-----------|
| ~~Wire `authorise_target()` ahead of the policy gate (feature-flagged)~~ | B | ✅ shipped (D-0004) |
| `tenant_id` on `PolicyInput` ✅ / `ActionRequest` ✅ / `EvidenceItem` ✅ | B–C | ✅ shipped (D-0005) |
| Tenant dimension on the target root of trust | C | ✅ shipped (D-0005) |
| Generalise `ownership/verifier.py` maps to tenant-scoped | C | ✅ shipped (D-0005) |
| Cross-tenant isolation tests (ownership cache / evidence / signed auth) | C | ✅ shipped (D-0005) |
| Cross-tenant **telemetry/memory** partition tests | D | migration doc |
| `tenant:` column in asset/test-account registries | D | migration doc |
| Grant issuance + persistence + revocation API | D | migration doc |
| `tenants/invisable.yaml` explicit profile | E | migration doc |
| Candidate-catalogue evaluation + build/buy/adapt/reject matrix | — | D-0003 |
| Signed plugin registry + sandbox profiles + untrusted-output gateway | — | vision doc |

## Test commands

```bash
uv sync --extra dev
uv run pytest tests/test_tenancy.py -q          # the new foundation
uv run pytest tests/ -q                          # full suite
python -m core.inventory --write                 # refresh the repo inventory report
```
