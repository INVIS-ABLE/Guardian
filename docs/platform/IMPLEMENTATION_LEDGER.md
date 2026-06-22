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

### Phase 0 platform documentation
- `docs/platform/`: README, CURRENT_STATE_ASSESSMENT, GUARDIAN_UNIVERSAL_PRODUCT_VISION,
  TENANT_AND_AUTHORISED_TARGET_MODEL, INVISABLE_TO_MULTI_TENANT_MIGRATION,
  DEPLOYMENT_MODES, DECISION_LOG, IMPLEMENTATION_LEDGER.

## Planned (not yet built — do not claim as done)

| Item | Phase | Tracked in |
|------|-------|-----------|
| Wire `authorise_target()` ahead of `policy_gate.decide()` (feature-flagged) | B | migration doc |
| `tenant_id` on `PolicyInput`, `ActionRequest`, `EvidenceItem` | B–C | migration doc |
| Tenant dimension on the target root of trust | B | migration doc |
| Generalise `ownership/verifier.py` maps to tenant-scoped | C | migration doc |
| Cross-tenant leakage tests (cache/telemetry/evidence) | C | migration doc |
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
