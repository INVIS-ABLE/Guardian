# Guardian Final Consolidation Plan (§3/§5/§6)

_Generated 2026-06-23T02:24:37Z · verified against `main` @ `d9377c4d8cb3a3c10931d8540a56d98415ff33a8`._

## Headline

The consolidation is **substantially complete and gated on one owner action** (default
branch → `main`, see `reports/consolidation/live_state.md`). Of the remote branches:

| Classification | Count | Disposition |
| --- | --- | --- |
| ALREADY_IN_MAIN | 56 | Retirement candidates (after default flip) — 0 unique content vs `main` |
| CONFLICTING_SECURITY_MODEL | 2 | **Human security review required** — do not auto-merge |
| HUMAN_DECISION_REQUIRED | 1 | Lab-isolation review required (Group E) |
| SUPERSEDED | 1 | Owner-rejected (PR #103) — retire, do not recreate |

There are **0 open PRs** and **no second integration branch**. The legitimate platform
work (governance, Waves 0–2 typed contracts + router fabric, plus other sessions'
reasoning/identity/twin/citadel/endpoint/sovereign work) is already merged into `main`.

## Why no wholesale forward-port PRs were created

Per §4/§6/§9 the steward does **not** auto-forward-port security-critical work and does
**not** act as a human reviewer. Every branch with unique content is already in `main`,
owner-rejected, or **security-sensitive and therefore blocked on human review**:

- **`claude/fix-main-ci-rego-zizmor`** — OPA reference monitor change. `main`'s policy CI
  is green, so **likely SUPERSEDED**; a human must confirm before closing. *Critical → two
  independent reviews.*
- **`steward/forward-port-citadel-waves`** — 5 commits of **key custody, threshold/quorum
  custody, cryptographic agility, transparency fabric**. *Critical → two human reviews +
  owner approval* before forward-port. Tracked, not merged.
- **`claude/keen-euler-4t9vo7`** — Group E **lab/proof systems** (fuzzing, crypto proofs,
  malware lab, chaos). Must pass **lab-isolation review** (§5 Group E) before forward-port.

## Consolidation order status (§5)

- **Group A (governance):** in `main`.
- **Group B/C (authority + execution):** in `main`; the citadel crypto waves are the one
  authority gap awaiting human review.
- **Group D (awareness/adaptive):** in `main`.
- **Group E (lab/proof):** `keen-euler` awaits isolation review.
- **Group F (catalogue):** in `main`.
- **Group G (edge/app):** not started — safe to begin after the default flip.

## Next actions

1. **Owner:** flip default branch → `main` (unblocks retirement + acceptance §12/§14).
2. **Owner/reviewers:** human review of the 3 security-sensitive branches; close
   `fix-main-ci-rego-zizmor` if confirmed superseded.
3. **Steward (post-flip):** retire the 56 ALREADY_IN_MAIN branches + owner-rejected
   `wave3/execution-job-bridge`, then run the §14 acceptance test.
