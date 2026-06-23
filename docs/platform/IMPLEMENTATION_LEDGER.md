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

### Candidate repository catalogue (research framework)
- **Decision:** D-0003 superseded (DECISION_LOG.md) — catalogue framework now shipped.
- **Artifacts:** `research/repositories/` — `catalogue.yaml` (217 candidates),
  `decisions.yaml`, `licences.yaml`, `security_review.yaml`, `data_flows.yaml`,
  `generate.py` (deterministic generator), README. Narrative:
  `docs/platform/COMPETITOR_AND_OPEN_SOURCE_LANDSCAPE.md` and
  `BUILD_BUY_ADAPT_REJECT_MATRIX.md`.
- **Honesty:** live numeric metadata is marked `pending_live_discovery` with a
  reproducible `gh` command — never fabricated. Decisions are architectural.
- **Tests:** `tests/test_repository_catalogue.py` — well-formedness, decision/category
  present, metadata-pending, offensive tools never adopted, single policy authority
  (OPA) preserved.

### Durable grant store + registry tenant column (Phase D, additive)
- **Decision:** D-0007 (DECISION_LOG.md).
- **Code:** `core/grants.py` (`GrantStore`: JSON load/save, `issue`/`revoke`/
  `active_grants`/`authorise`, all fail-closed and tenant-isolated);
  `AuthorisationGrant.to_dict()/from_dict()`; `tenant` column on `scope/assets.yaml`
  and `scope/test_accounts.yaml`; `core/scope.py` enforces scope↔asset tenant match.
- **Defaults:** registry tenant defaults to `invisable`, so existing scopes are valid.
- **Tests:** `tests/test_grants.py` (issue/persist/load/revoke/authorise round-trip,
  signature survives serialisation, duplicate-id rejected, tenant isolation, default
  deny, malformed-store fail-closed) and `tests/test_scope.py` (cross-tenant asset
  reference denied). Full suite green.
- **Rollback:** remove the module, (de)serialisers, scope check, and registry columns.
- **Owner:** Platform architecture. **Review date:** at Phase D-2 (issuance API/UI).

### Phase 0 platform documentation
- `docs/platform/`: README, CURRENT_STATE_ASSESSMENT, GUARDIAN_UNIVERSAL_PRODUCT_VISION,
  TENANT_AND_AUTHORISED_TARGET_MODEL, INVISABLE_TO_MULTI_TENANT_MIGRATION,
  DEPLOYMENT_MODES, COMPETITOR_AND_OPEN_SOURCE_LANDSCAPE, BUILD_BUY_ADAPT_REJECT_MATRIX,
  DECISION_LOG, IMPLEMENTATION_LEDGER.

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
