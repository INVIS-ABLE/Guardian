# INVISABLE → Multi-Tenant Migration

*Phase 0 deliverable. How Guardian becomes tenant-aware while INVISABLE keeps
working with zero behaviour change.*

## Principle

**Generalise, never remove.** INVISABLE's protections become the behaviour of one
concrete, built-in tenant. Every step is additive, default-deny preserving, and
reversible. At no point does an INVISABLE deployment lose a control or change its
runtime behaviour without an explicit, separate decision.

## Backward-compatibility contract

1. A scope file with **no `tenant:` key resolves to `invisable`** (`Scope.tenant`,
   `core/tenancy.INVISABLE_TENANT_ID`). Existing scope files are untouched and valid.
2. `INVISABLE_TENANT` is always present in a `TenantRegistry`.
3. Existing registries (`scope/assets.yaml`, `scope/test_accounts.yaml`) are treated
   as belonging to the INVISABLE tenant until/unless a `tenant:` column is added.
4. The new model is **not yet** on the enforcement path; turning it on is a later,
   separately-reviewed, feature-flagged step.

## Phased plan

### Phase A — model (this PR) ✅
- `core/tenancy.py`: `Tenant`, `AuthorisationGrant`, `authorise_target()`, registry,
  built-in INVISABLE tenant.
- `Scope.tenant` accessor + optional `tenant:` schema field.
- `tests/test_tenancy.py` (22 tests). No enforcement change.

### Phase B — tenant-aware enforcement (shipped, feature-flagged) ✅
- `PolicyInput` gains `tenant_id` (defaults to the scope's tenant via
  `Scope.tenant`), plus `capability`, `asset_id`, `grants`, `verify_grant_key`.
- `evaluate()` applies `authorise_target()` as an **outer AND** over the action
  policy (`_tenant_denies()` → `_evaluate_core()`): target legitimacy first, action
  policy second. It lives outside `decide()`, so OPA/embedded parity is untouched.
- Flag: `GUARDIAN_TENANCY_ENFORCE` (default `false`); when off, behaviour is exactly
  today's. (See D-0004.)
- *Deferred to Phase C:* the tenant dimension on the target root in
  `core/roots_of_trust.py` (ownership verified *for this tenant's* authorising
  identity).

### Phase C — data-plane tenant scoping (shipped, additive) ✅
- `tenant_id` added to `ActionRequest` (bound into `canonical_request`, so a signed
  capability cannot be replayed cross-tenant), `EvidenceItem`, `Finding`, and
  `TargetTrust` (empty tenant fails the target root of trust). (See D-0005.)
- `ownership/verifier.py` generalised to `tenant → {domain: token}` /
  `tenant → {owners}` with a `(kind, target, tenant)` cache key; flat maps belong to
  the configured tenant, unconfigured tenants fail closed.
- Cross-tenant isolation tests in `tests/test_tenant_isolation.py`.
- *Deferred to Phase D:* tenant-partitioning of memory/telemetry/RAG collections and
  their leakage tests (needs the storage layer, not just the contracts).

### Phase D — registries & onboarding (in progress)
- ✅ `tenant:` column added to `scope/assets.yaml` and `scope/test_accounts.yaml`
  (default `invisable`); `core/scope.py` enforces scope↔asset tenant matching.
- ✅ Grant persistence + issuance + revocation via `core/grants.py` (`GrantStore`).
  Issuance requires the signing key (no self-granted authority); signatures persist
  and re-verify; lookups are tenant-isolated. (See D-0007.)
- *Remaining (D-2):* tenant-administrator onboarding API/UI; grant issuance surface;
  tenant-partitioned memory/telemetry/RAG and their leakage tests.

### Phase E — INVISABLE as an explicit profile (shipped) ✅
- `tenants/invisable.yaml` captures INVISABLE as a first-class tenant config; loaded by
  `core/tenancy.load_tenant` / `load_tenant_registry` into a `TenantRegistry`. The
  in-code `INVISABLE_TENANT` default is retained (and always seeded) so pre-tenancy
  scopes are unaffected. (See D-0008.)
- ✅ The loaded registry is now wired into the policy edge: when enforcement is on,
  `PolicyInput.tenants` (or the cached `tenants/` load) is passed to `authorise_target`,
  so a suspended/archived/unknown tenant is rejected end-to-end. (See D-0009.)

## Rollback

Each phase is independently revertible:
- Phase A is pure/additive — deleting `core/tenancy.py` and the `Scope.tenant`
  accessor restores the prior state; no data migration occurred.
- Phases B–E are feature-flagged; setting the flag off restores single-tenant
  behaviour. Registry columns default to `invisable`, so removing them is lossless
  for the INVISABLE tenant.

## Invariants that must never regress

- Default deny; production needs human approval; single policy decision point.
- Fail closed on policy/identity/signature/evidence/target/scope uncertainty.
- No cross-tenant identifier, cache, telemetry, or evidence access.
- Safeguarding/privacy controls remain enforced for every tenant.

These are covered by existing tests plus the new tenancy tests; Phase B onward adds
explicit cross-tenant isolation tests before enforcement is enabled.
