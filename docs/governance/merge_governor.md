# Guardian Merge Governor & Repository Steward

> Status: active. This document is the operating charter for repository governance.
> It complements (does not replace) the security governance under `docs/governance/`.

Guardian protects vulnerable people and security-sensitive systems. Repository
governance is treated as a **production security control**: separation of duties,
independent review, fail-closed gates, and honest capability claims apply to the repo
itself, exactly as Guardian enforces them on protected systems.

## Canonical branch policy

- **`main` is the sole canonical integration and release branch.** All work merges into
  `main` through a pull request. Direct pushes to `main` are prohibited.
- **`claude/laughing-ptolemy-zfeiiu` is a legacy branch requiring reconciliation.** Even
  though GitHub currently marks it as the default branch, no new feature work targets it.
  Changing the GitHub default to `main` is **owner-approval-gated** (see issue #57).
- New branches are cut from current `main`:
  - workers: `agent/<area>/<issue>-<short-description>`
  - steward: `steward/<issue>-<short-description>`

## What the steward may do autonomously

Inventory branches/PRs; produce reconciliation reports; create reconciliation branches,
issues, PR comments and non-sensitive labels; rebase/merge `main` into worker branches
when safe; resolve straightforward non-security conflicts; run tests/scanners; author
governance scripts, workflows and docs; close clearly-superseded duplicate PRs after
documenting why.

## What requires explicit human owner approval

Changing the default branch; changing branch protection / rulesets; deleting branches
with unique commits; **merging changes to authorization, approvals, ownership
verification, cryptography, secrets, evidence, policy, execution boundaries or
production infrastructure**; merging with fewer than the required independent reviews;
overriding a failed/missing required check; force-pushing or rewriting shared history;
rotating signing keys; changing the meaning of a security invariant; production
deployment; relaxing a security tool; publishing a release; making public
capability/competitor-superiority claims.

**No agent review counts as the required independent human review for a
security-sensitive change.**

## PR risk classification

| Risk | Examples | Minimum gate |
| --- | --- | --- |
| LOW | typo, non-security docs, test-fixture cleanup, internal refactor | CI green; 1 independent review where required; no unresolved threads |
| MEDIUM | new connector adapter, dependency update, dashboard/telemetry change | LOW + security scans green + integration tests + rollback notes |
| HIGH | authz, ownership, approvals, secrets, crypto, audit/evidence, network policy, isolation, AI tool execution, workflow permissions, prod infra | all checks green; **2 independent human reviews**; CODEOWNERS; threat-model update; negative + property + integration tests; security-impact statement; rollback; no self-approval |
| CRITICAL | signing keys, root of trust, Shadow Guardian, break-glass, evidence deletion/retention, default-deny policy, prod deploy authority, anything enabling unverified-target execution | HIGH + explicit repository-owner approval + independent security review + staged deploy + failure injection + recovery test + post-merge monitoring |

## Required merge gates (summary)

Base is `main`; branch fresh / rebased; no hidden out-of-scope changes; required
independent human reviews present; author has not self-approved; all review threads
resolved; format/lint/type/unit/property/policy/contract/integration tests pass where
applicable; security scans (CodeQL, Semgrep, Bandit, Gitleaks, Trivy, OSV, pip-audit,
Checkov, zizmor/actionlint, OPA tests, SBOM/provenance/signature) pass and are
**blocking** — never hidden behind `|| true`, `continue-on-error: true`, or a bare
`except: pass`. New dependencies: recorded reason, licence reviewed, version/digest
pinned, SBOM updated. Documentation claims match the capability registry and evidence.

## Governance file map

| File | Purpose |
| --- | --- |
| `docs/governance/merge_governor.md` | this charter |
| `docs/governance/branch_inventory.yaml` | snapshot of every branch vs `main` |
| `docs/governance/reconciliation_baseline.md` | immutable baseline SHAs + facts |
| `docs/governance/branch_reconciliation_plan.md` | classification + integration order |
| `docs/governance/worker_registry.yaml` | one bounded objective per worker |
| `docs/governance/path_ownership.yaml` | high-risk path → owner matrix |
| `docs/governance/merge_queue.yaml` | dependency-ordered merge DAG |
| `docs/governance/merge_ledger.yaml` | append-only record of merges |
| `docs/governance/branch_retirement.yaml` | retirement candidates + final SHAs |
| `docs/governance/emergency_freeze.md` | freeze triggers + procedure |
| `.github/CODEOWNERS` | review routing (proposal until owners named) |
| `.github/pull_request_template.md` | risk + gate checklist on every PR |
| `.github/ISSUE_TEMPLATE/*` | worker-task + security-governance intake |
| `.github/workflows/repository-governor.yml` | non-merging watchdog |
| `scripts/repository_governor.py` | the checks the watchdog runs |
| `tests/test_repository_governor.py` | tests for the governor |

## The governor never merges

The watchdog and the steward never auto-merge. The governor may upload an audit
artifact, comment on a PR, add a steward label, or open/update one deduplicated
governance issue — nothing more. Merges remain a human, review-gated act.
