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

### Phase B — tenant-aware enforcement (next, feature-flagged)
- Add `tenant_id` to `PolicyInput` (`core/policy_gate.py`), defaulting to the scope's
  tenant. Place `authorise_target()` **before** `decide()`: target legitimacy first,
  action policy second.
- Add a tenant dimension to the target root in `core/roots_of_trust.py` (ownership is
  verified *for this tenant's* authorising identity).
- Flag: `guardian.tenancy.enforce` (default `false`); when off, behaviour is exactly
  today's.

### Phase C — data-plane tenant scoping
- Add `tenant_id` to `ActionRequest` (`connectors/contract.py`) and `EvidenceItem`
  (`core/evidence/models.py`); tenant-scope evidence storage and RAG collections.
- Generalise `ownership/verifier.py` maps to `tenant → {domain: token}` /
  `tenant → {owners}`.
- Tenant-partition memory/telemetry; add cross-tenant leakage tests.

### Phase D — registries & onboarding
- Add a `tenant:` column to asset/test-account registries (default `invisable`).
- Grant issuance + persistence; tenant administrator onboarding; revocation/expiry.

### Phase E — INVISABLE as an explicit profile
- Ship `tenants/invisable.yaml` capturing INVISABLE as a first-class tenant config and
  deployment profile, replacing the implicit default with an explicit, auditable one.

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
