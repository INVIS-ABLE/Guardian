# Guardian — Live Repository State (Final Structure, PR 1)

> **Generated, point-in-time discovery snapshot.** This is *evidence*, not the governance
> source of truth. Authoritative governance state lives in `docs/governance/`
> (`branch_inventory.yaml`, `merge_ledger.yaml`, `branch_retirement.yaml`, …). Drift is
> expected the moment it is written, because the repository is under active parallel work.

- **Observed at:** `2026-06-23T01:49:16Z`
- **Canonical branch:** `main`
- **`main` tip:** `fadc3a980a6310ffa340c3cb3f189a92dd04776b`
- **GitHub default branch (live):** `claude/laughing-ptolemy-zfeiiu` — **not `main`** (owner must move it; Phase C)
- **`main` protected:** no ruleset yet (owner action)
- **Branches observed:** 54 (local fetch basis; GitHub listed 57 at 01:43Z — minor flux)

## Headline findings

1. **Wrong-base enforcement was report-only.** The governor's `check_pr_base` (base must be
   `main`) existed but never failed CI. **This PR makes it blocking** via a dedicated
   `--fail-on-checks pr_base_not_canonical` gate in `.github/workflows/repository-governor.yml`,
   decoupled from default-branch state and from lower-severity hygiene findings — so it is safe
   to require *now*, while the GitHub default branch is still being moved to `main`.
2. **The GitHub default branch is still the legacy branch.** Until the owner runs
   `gh repo edit --default-branch main`, new PRs created from the GitHub UI default to the
   legacy base and will (now) fail the blocking governor step — which is the intended forcing
   function, but the durable fix is the owner moving the default.
3. **One wholesale legacy→main PR is open (#99).** Its head is the entire legacy default branch
   targeting `main`, which violates rule 3.2 ("no wholesale legacy merges"). Flagged for the
   owner/steward; not actioned here.

## Branch classification (see `branch_content_graph.yaml` for per-branch SHAs)

| Class | Count | Meaning |
|---|---|---|
| `canonical` | 1 | `main` |
| `active-worker` | 1 | head of an open PR into `main` (`claude/keen-euler-4t9vo7` #101, `wave3/execution-job-bridge` #103) |
| `human-decision-required` | 1 | `claude/laughing-ptolemy-zfeiiu` — current GitHub default; retire only after default moves |
| `unsafe` | 1 | `claude/fix-main-ci-rego-zizmor` — unique HIGH-risk OPA/rego change, needs human security review |
| `reconcile` | 2 | branches with unique non-merge commits not yet represented in `main` (`claude/keen-bohr-eqhtrq`, `claude/model-gateway`) — investigate before retiring |
| `retirement-candidate` | 48 | 0 unique non-merge commits vs `main` (content recoverable from `main` by recorded SHA) |

## Open PRs into `main` (01:43Z)

- **#103** `wave3/execution-job-bridge` — Wave 3 execution-job seam (draft)
- **#101** `claude/keen-euler-4t9vo7` — Wave 3 sovereign systems (draft)
- **#99** `claude/laughing-ptolemy-zfeiiu` — wholesale legacy→main (draft; **rule 3.2 violation**)

## What this PR changes (PR 1 — no functional moves)

- `scripts/repository_governor.py`: adds `--fail-on-checks` (blocking subset of checks by name,
  severity-independent) + `blocking_findings()` helper. Detection-only; still never merges,
  changes settings, or deletes.
- `.github/workflows/repository-governor.yml`: adds a **blocking** "Enforce canonical PR base"
  step (PR events only). The existing report-only artifact step is unchanged.
- `tests/test_repository_governor.py`: 4 tests for the blocking behavior (blocks wrong base,
  passes `main`, stays report-only without the flag, filters by check name).
- `reports/final_structure/`: this discovery snapshot + `branch_content_graph.yaml`.

## Deferred (by design)

- **Owner actions:** move default branch to `main`; apply the `main` ruleset; retire legacy.
- **Default-branch-drift blocking:** intentionally **not** enabled — it would fail every PR
  until the owner moves the default. Activate it (add `default_branch_not_main` to the blocking
  set) *after* the default is `main`.
- **`runtime_call_graph.md` / `resource_risk_inventory.yaml`:** belong to the edge/runtime
  workstream (PRs 5–11) and are deferred to keep PR 1 focused on governance with no functional
  moves.
