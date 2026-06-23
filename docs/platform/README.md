# Guardian Universal Platform — `docs/platform/`

This directory holds the strategic and architectural work that evolves Guardian
from **internal INVISABLE tooling** into a **vendor-neutral, tenant-aware security,
safeguarding, evidence, and authorised-defence control plane** — without removing
any existing protection. INVISABLE is preserved as the founding organisation and
**first built-in tenant**.

## Guiding constraints (non-negotiable)

Every change in this programme upholds Guardian's existing posture:

1. **Default deny.** Anything not explicitly authorised is denied.
2. **No action without authenticated identity.**
3. **No scan without an authorised target and valid scope.**
4. **No third-party testing without explicit, current, verifiable authorisation.**
5. **No hack-back, persistence, stealth, credential theft, or destructive testing.**
6. **Humans approve production changes; no agent grants itself authority.**
7. **Uncertainty fails closed** (policy, identity, signature, evidence, target, scope).
8. **Tenant isolation** — no cross-tenant data leakage.

Guardian generalises INVISABLE's protections; it never relaxes them.

## Document index

| Document | Status | Purpose |
|----------|--------|---------|
| [CURRENT_STATE_ASSESSMENT.md](CURRENT_STATE_ASSESSMENT.md) | ✅ written | Honest map of what Guardian already is, with file citations. |
| [GUARDIAN_UNIVERSAL_PRODUCT_VISION.md](GUARDIAN_UNIVERSAL_PRODUCT_VISION.md) | ✅ written | The vendor-neutral control-plane vision and product boundary. |
| [TENANT_AND_AUTHORISED_TARGET_MODEL.md](TENANT_AND_AUTHORISED_TARGET_MODEL.md) | ✅ written | The tenant + authorisation-grant model (implemented in `core/tenancy.py`). |
| [INVISABLE_TO_MULTI_TENANT_MIGRATION.md](INVISABLE_TO_MULTI_TENANT_MIGRATION.md) | ✅ written | How INVISABLE becomes the first tenant with zero behaviour change. |
| [DEPLOYMENT_MODES.md](DEPLOYMENT_MODES.md) | ✅ written | Self-hosted, SaaS, private, dedicated, air-gapped, hybrid. |
| [DECISION_LOG.md](DECISION_LOG.md) | ✅ living | Reversible, attributable record of platform decisions. |
| [IMPLEMENTATION_LEDGER.md](IMPLEMENTATION_LEDGER.md) | ✅ living | What has actually been built, tested, and merged. |
| COMPETITOR_AND_OPEN_SOURCE_LANDSCAPE.md | ⏳ follow-up | Catalogue evaluation (`research/repositories/`). |
| CAPABILITY_GAP_ANALYSIS.md | ⏳ follow-up | What candidates do better / what Guardian lacks. |
| BUILD_BUY_ADAPT_REJECT_MATRIX.md | ⏳ follow-up | Per-candidate integration decision. |
| INTEGRATION_PRIORITY_ROADMAP.md | ⏳ follow-up | Sequenced integration plan. |
| COMMERCIALISATION_AND_OPEN_SOURCE_OPTIONS.md | ⏳ follow-up | Licensing / distribution analysis. |
| DATA_CLASSIFICATION_AND_RESIDENCY.md | ⏳ follow-up | Extends `docs/governance/DATA_CLASSIFICATION.md` per tenant. |
| PLUGIN_ECOSYSTEM_DESIGN.md | ⏳ follow-up | Signed plugin model. |

`⏳ follow-up` items are intentionally deferred so this first change stays small,
reviewable, and tested. They are tracked in [DECISION_LOG.md](DECISION_LOG.md) and
the [IMPLEMENTATION_LEDGER.md](IMPLEMENTATION_LEDGER.md) — not silently dropped.

## What this PR actually ships

This is the **first foundation stone**, not the whole platform:

- `core/tenancy.py` — the `Tenant` and `AuthorisationGrant` model with a pure,
  fail-closed `authorise_target()` chokepoint, plus the built-in INVISABLE tenant.
- A backward-compatible `Scope.tenant` accessor and an optional `tenant:` scope
  field — pre-tenancy scope files resolve to INVISABLE unchanged.
- `tests/test_tenancy.py` — 22 tests covering tenant isolation, missing/expired/
  revoked authorisation, target mismatch, capability escalation, environment
  mismatch, and signature failure.
- These platform documents.

Nothing here is wired into the enforcement path yet — that is a separate,
reviewable step (see the migration doc's phased plan). The model is additive and
fully reversible.
