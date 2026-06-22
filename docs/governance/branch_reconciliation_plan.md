# Branch reconciliation plan

> Canonical tip and divergence are recorded in `reconciliation_baseline.md`.
> Classifications follow the Merge Governor charter.

## Classification of every branch with unique work vs `main`

| Branch | Unique commits | Classification | Reason / action |
| --- | --- | --- | --- |
| `claude/confident-planck-9t1rfs` | 1 (`d51c6ed`) | **KEEP** | Wave 0 repository-truth baseline. Additive, LOW risk. Already merged to legacy via #48; **port forward to `main`** via `steward/57`-adjacent reconciliation PR. |
| `claude/laughing-ptolemy-zfeiiu` (legacy) | 3 | KEEP (subset) | Unique content = the same Wave 0 work + merge commits. Reconcile Wave 0 into `main`; then retire after owner approval. |
| `claude/exciting-goldberg-udmve1` | 1 | **UNKNOWN_REQUIRES_HUMAN** | Inspect content before action; not yet classified. Likely superseded by later `main` merges — confirm by content diff. |
| `claude/fix-main-ci-rego-zizmor` | 1 | **UNKNOWN_REQUIRES_HUMAN** | CI/zizmor fix; touches `.github/**` (security-sensitive). Requires supply-chain + security review before any merge. |
| `claude/twin-ci-gate` | 2 | **KEEP** (open PR #52) | Ambient blast-radius gate; already an open PR to `main`. Governed through the normal PR gates, not the steward. |

All other branches in `branch_inventory.yaml` show **0 unique commits** vs `main`
(cherry-pick aware) — their work is already integrated. They are **retirement
candidates** (`branch_retirement.yaml`), pending owner approval to delete.

## Dependency order for reconciliation

Following the Governor default DAG, constrained to the work actually outstanding:

1. **Governance & branch control** — this baseline PR (`steward/57`).
2. **Wave 0 forward-port** — bring the repository-truth inventory onto `main` so later
   waves build on a verified base. Additive; no security-control change.
3. **`fix-main-ci-rego-zizmor`** — CI/policy fix; security review required (touches
   `.github/**` and `policies/**`). Only after independent review.
4. Normal worker PRs (#52, #55) proceed through their own gates.

## Conflicting files to watch when porting Wave 0 onto `main`

`main` advanced after Wave 0 branched. The Wave 0 edits touch shared files that may have
moved on `main`:

- `docs/architecture/components.yaml` — Wave 0 adds the `repo_inventory` component;
  `main` may have added components. Re-apply additively; keep one-owner-per-function.
- `docs/tooling_catalogue.md`, `README.md` — Wave 0 appends links; re-apply at tail.
- `pyproject.toml` — `main` has 3 lines Wave 0 lacked; merge, do not overwrite.

The forward-port re-runs `python -m core.inventory --write` against the merged tree so
the committed `reports/audit/current_state.json` reflects `main`'s actual registries
(it will differ from the legacy snapshot — that is correct and expected).

## Tests required after each integration

`pytest -q` (full suite) + `ruff check .` + the governor's own
`tests/test_repository_governor.py`. For any branch touching `.github/**`,
`policies/**`, `core/policy_gate.py`, crypto, identity or evidence: the full security
suite and **independent human review** before merge.

## Expected final topology

`main` carries all reconciled work; the legacy branch and fully-merged `claude/*`
branches are retired (owner-approved); GitHub default is changed to `main`
(owner-approved); future branches are cut from `main` with canonical names.

## Rejected / deferred

None rejected yet. `exciting-goldberg-udmve1` and `fix-main-ci-rego-zizmor` are deferred
pending content inspection and (for the latter) security review — not discarded.
