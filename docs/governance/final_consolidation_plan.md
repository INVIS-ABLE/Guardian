# Guardian Final Consolidation Plan (§3/§5/§6)

_Generated 2026-06-23T02:23:02Z · verified against `main` @ `df4d3e355def7ea27f81b864b11ddb1688f9f835`._

## Headline

The consolidation is **substantially complete and gated on one owner action** (default
branch → `main`, see `reports/consolidation/live_state.md`). Of **60 remote branches**:

| Classification | Count | Disposition |
| --- | --- | --- |
| ALREADY_IN_MAIN | 56 | Retirement candidates (after default flip) — 0 unique content vs `main` |
| CONFLICTING_SECURITY_MODEL | 2 | **Human security review required** — do not auto-merge |
| HUMAN_DECISION_REQUIRED | 1 | Lab-isolation review required (Group E) |
| SUPERSEDED | 1 | Owner-rejected (PR #103) — retire, do not recreate |

There are **0 open PRs** and **no second integration branch**. The legitimate platform
work (governance, Waves 0–2 typed contracts + router fabric, plus other sessions'
reasoning/identity/twin/citadel/endpoint work) is already merged into `main`.

## Why no wholesale forward-port PRs were created

Per §4/§6/§9, the steward does **not** auto-forward-port security-critical work and does
**not** act as a human reviewer. Every branch with unique content is either already in
`main`, owner-rejected, or **security-sensitive and therefore blocked on human review**:

- **`claude/fix-main-ci-rego-zizmor`** — changes the OPA reference monitor
  (`policies/opa/guardian.rego`, `opa-policy.yml`). `main`'s policy CI is currently green,
  so this is **likely SUPERSEDED**; a human must confirm before closing. *Critical → two
  independent reviews; no self-approval.*
- **`steward/forward-port-citadel-waves`** — 5 commits of **key custody, threshold/quorum
  custody, cryptographic agility, transparency fabric**. Legitimate unique work, but
  *critical key-custody/crypto* → **two human reviews + repository-owner approval** before
  forward-port. Left as a tracked branch, not merged.
- **`claude/keen-euler-4t9vo7`** — Group E **lab/proof systems** (fuzzing farm, crypto
  proofs, malware lab, chaos sim). Must pass **lab-isolation review** (technically incapable
  of reaching production assets, §5 Group E) before forward-port.

## Consolidation order status (§5)

- **Group A (governance):** present in `main` (merge governor, CODEOWNERS, charter, retirement manifest).
- **Group B/C (authority + execution):** present (OPA gate, roots-of-trust, signed one-use
  capabilities, guarded executor, typed `ExecutionJob`, health-aware resolver). The citadel
  crypto waves (key custody/quorum/agility) on `steward/forward-port-citadel-waves` are the
  one **authority gap awaiting human review**.
- **Group D (awareness/adaptive):** present (event fabric/CaseEvent, twin, identity graph,
  threat hunting, competing hypotheses).
- **Group E (lab/proof):** the `keen-euler` lab systems await isolation review.
- **Group F (catalogue):** present (repository catalogue, schemas, capability registry).
- **Group G (edge/app):** not started — safe to begin once the default flip removes ambiguity.

## Next actions

1. **Owner:** flip default branch → `main` (unblocks retirement + acceptance).
2. **Owner/reviewers:** human review of the 3 security-sensitive branches above; close
   `fix-main-ci-rego-zizmor` if confirmed superseded, schedule reviews for citadel + lab.
3. **Steward (post-flip):** retire the 56 ALREADY_IN_MAIN branches + the owner-rejected
   `wave3/execution-job-bridge` using the recorded SHAs, then run the §14 acceptance test.
