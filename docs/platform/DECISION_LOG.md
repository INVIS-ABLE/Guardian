# Platform Decision Log

Reversible, attributable record of universal-platform decisions. Newest first.
Each decision records: context, decision, rationale, and how to reverse it.

---

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
