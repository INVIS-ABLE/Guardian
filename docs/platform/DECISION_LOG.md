# Platform Decision Log

Reversible, attributable record of universal-platform decisions. Newest first.
Each decision records: context, decision, rationale, and how to reverse it.

---

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
