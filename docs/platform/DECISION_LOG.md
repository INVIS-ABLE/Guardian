# Platform Decision Log

Reversible, attributable record of universal-platform decisions. Newest first.
Each decision records: context, decision, rationale, and how to reverse it.

---

## D-0008 — INVISABLE becomes an explicit tenant profile (Phase E)
- **Date:** 2026-06-23
- **Context:** INVISABLE was the *implicit* default tenant (a code constant). The
  migration's Phase E calls for replacing the implicit default with an explicit,
  auditable, version-controlled record.
- **Decision:** Add `tenants/invisable.yaml` (a first-class tenant profile) and
  `core/tenancy.load_tenant` / `tenant_from_dict` / `load_tenant_registry` to build a
  `TenantRegistry` from YAML profiles. The built-in `INVISABLE_TENANT` is always
  seeded; a committed profile for it wins. Malformed/missing profiles fail closed.
- **Rationale:** Makes the founding tenant auditable and lets additional tenants be
  declared as data, not code — without changing the in-code default that keeps
  pre-tenancy scopes working.
- **Reverse:** Delete `tenants/invisable.yaml`, the three loader functions, and the
  test. The in-code `INVISABLE_TENANT` default remains, so nothing breaks.

## D-0007 — Durable, signed grant store + registry tenant column (Phase D)
- **Date:** 2026-06-23
- **Context:** Grants were in-memory only (Phase A). Tenant authority needs a managed,
  revocable, persistent record; and the asset registry had no tenant column, so scope
  ↔ asset tenant matching could not be enforced.
- **Decision:** Add `AuthorisationGrant.to_dict()/from_dict()` round-trip and
  `core/grants.py` (`GrantStore`: JSON persistence, `issue` [requires signing key],
  `revoke`, `active_grants`, tenant-isolated `authorise`). Add a `tenant` column
  (default `invisable`) to `scope/assets.yaml` and `scope/test_accounts.yaml`, and
  enforce in `core/scope.py` that a scope may only target an asset owned by its own
  tenant (cross-tenant reference → `ScopeError`).
- **Rationale:** Makes authority durable and revocable without weakening any control:
  empty/missing/malformed store ⇒ deny; issuance needs the key (no self-granted
  authority); signatures persist and re-verify; lookups are tenant-isolated. The
  registry default `invisable` keeps every existing scope valid.
- **Reverse:** Delete `core/grants.py`, the (de)serialisers, the scope cross-check, and
  the registry `tenant:` columns. Defaults are `invisable`; no data migration occurred.

## D-0005 — Tenant-scope the data plane additively, defaulting to INVISABLE (Phase C)
- **Date:** 2026-06-23
- **Context:** Evidence, findings, connector authorisations, the target root of trust,
  and the ownership verifier were single-owner. Tenant isolation needs a tenant
  dimension on each, without breaking existing callers/tests.
- **Decision:** Add `tenant_id` (default `invisable`) to `ActionRequest`
  (`connectors/contract.py`, **bound into `canonical_request`** so a signed capability
  cannot be replayed cross-tenant), `EvidenceItem` and `Finding`
  (`core/evidence/models.py`), and `TargetTrust` (`core/roots_of_trust.py`, with an
  empty tenant failing the target root). Generalise `ownership/verifier.py` to
  per-tenant DNS/repo config and a `(kind, target, tenant)` cache key; the flat maps
  belong to the configured tenant and an unconfigured tenant fails closed.
- **Rationale:** Isolation must be structural at the data layer, not just the policy
  layer. Non-empty defaults keep every existing construction valid; the signature
  binding and per-tenant cache close concrete cross-tenant replay/leak paths.
- **Reverse:** Remove the added fields and the verifier's tenant maps/cache key (revert
  to the 2-tuple). Defaults are `invisable`, so no stored data needs migration.

## D-0004 — Tenant authorisation is an outer AND over the policy gate (Phase B)
- **Date:** 2026-06-22
- **Context:** The action policy (`core/policy_gate.decide`) is mirrored exactly by
  `policies/opa/guardian.rego`, and a CI job enforces OPA/embedded parity. Tenant
  authorisation must not disturb that parity.
- **Decision:** Enforce tenant target-authorisation in `evaluate()` as an **outer
  AND** (`_tenant_denies()` runs `core.tenancy.authorise_target` *before/around* the
  action decision), gated by `GUARDIAN_TENANCY_ENFORCE` (default **off**). It lives
  outside `decide()`, so the Rego mirror and parity test are untouched. `PolicyInput`
  gains inert `tenant_id` (default `invisable`), `capability`, `asset_id`, `grants`,
  `verify_grant_key`. Scope's tenant is threaded into both `PolicyInput` construction
  sites (`core/guardrails.py`, `core/brain/orchestrator.py`).
- **Rationale:** Keeps the single action-policy authority and its OPA twin intact;
  adds tenant legitimacy as a strictly-additive gate; default-off preserves INVISABLE
  behaviour exactly. A request must satisfy **both** gates — tenancy never *grants*
  what the action policy denies.
- **Reverse:** Unset the flag (instant, full revert to prior behaviour) or remove
  `_tenant_denies`/`_tenancy_enforced`, the new `PolicyInput` fields, and the two
  `tenant_id=` lines. No data migration occurred.

## D-0006 — Ship the candidate catalogue as a framework with pending live metadata
- **Date:** 2026-06-23
- **Context:** D-0003 deferred the ~200-repo evaluation for lack of live metadata.
  The architectural decisions, however, do not need live metadata — they follow from
  each project's category and purpose.
- **Decision:** Ship `research/repositories/` (217 candidates) with **decisions made**
  and **numeric metadata explicitly marked `pending_live_discovery`** plus reproducible
  `gh` commands. Decisions are generated deterministically (`generate.py`) and guarded
  by `tests/test_repository_catalogue.py`. Supersedes D-0003.
- **Rationale:** Honours "do not fabricate metadata" while still delivering the
  actionable build/buy/adapt/reject judgement the brief asks for. The test pins the
  safety-critical invariants (no offensive tool adopted; OPA remains sole authority).
- **Reverse:** Delete `research/repositories/`, the two narrative docs, and the test.

## D-0003 — Defer the candidate-catalogue evaluation to a follow-up
- **Date:** 2026-06-22
- **Context:** The master prompt lists ~200 candidate repositories to evaluate
  (`research/repositories/*`). A credible evaluation requires live GitHub metadata
  and per-repo licence/security review.
- **Decision:** Do **not** fabricate catalogue metadata. Ship the tenant foundation
  first; produce `research/repositories/` and the build/buy/adapt/reject matrix in a
  dedicated follow-up with real metadata-first discovery.
- **Rationale:** Rule: "Do not fabricate metadata when network access is
  unavailable." Foundations before tools. A wrong matrix is worse than an absent one.
- **Reverse:** N/A (deferral). Tracked in README.md and IMPLEMENTATION_LEDGER.md.

## D-0002 — `Scope.tenant` defaults to INVISABLE; `tenant:` is optional
- **Date:** 2026-06-22
- **Context:** Existing scope files carry no tenant. `SCOPE_SCHEMA.yaml` sets
  `additionalProperties: false`, so an unknown key would fail validation.
- **Decision:** Add an **optional** `tenant:` field to the schema and a
  `Scope.tenant` accessor defaulting to `invisable`.
- **Rationale:** Backward compatibility (D-0001 principle). Pre-tenancy files stay
  valid and resolve to the founding tenant; multi-tenant files declare a tenant.
- **Reverse:** Remove the `tenant:` schema property and the accessor; no data
  migration occurred.

## D-0001 — Introduce a tenant-neutral domain model as the first foundation
- **Date:** 2026-06-22
- **Context:** INVISABLE is hard-coded as the single implicit owner across scope,
  ownership, policy, evidence, and config (see CURRENT_STATE_ASSESSMENT.md). This
  blocks serving any other organisation and offers no structural cross-tenant
  isolation.
- **Decision:** Build `core/tenancy.py` (`Tenant`, `AuthorisationGrant`,
  `authorise_target()`, `TenantRegistry`, built-in `INVISABLE_TENANT`) as a **pure,
  additive, fail-closed** model — **not** yet on the enforcement path. Generalise,
  never remove.
- **Rationale:** "Implement foundations before adding many tools." The tenant +
  authorised-target model is the dependency for every later step (plugins, adapters,
  findings federation). Keeping it pure and off the enforcement path makes it small,
  reviewable, and reversible.
- **Reverse:** Delete `core/tenancy.py`, `tests/test_tenancy.py`, the `Scope.tenant`
  accessor, and the schema field. No runtime behaviour changed, so removal is lossless.
