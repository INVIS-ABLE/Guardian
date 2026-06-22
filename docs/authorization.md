# Guardian Authorization — Central Policy Gate

Implements acceptance-gate **#1 (Authorisation)** and **#10 (Testing)** from the hardening
blueprint: one central, policy-backed `authorize()` decides every action; there is **no
`allow_production` escape parameter**; and property tests prove no input combination
bypasses the guardrails.

## One decision, one authority

```
connector / agent / simulator
        │  authorize(mode, action, domain?, repo?, test_account?, commit?, workflow_run?)
        ▼
core.guardrails.Guardrails.authorize()
        │  builds PolicyInput(actor, action, mode, environment, target, ownership,
        │                     approvals, scope lists, commit, workflow_run)
        ▼
core.policy_gate.evaluate()
        ├── OPA (policies/opa/guardian.rego)   ← when GUARDIAN_USE_OPA=1 and `opa` present
        └── embedded mirror (decide())          ← otherwise; identical rules
        ▼
PolicyDecision(allow, denies)  →  allow: proceed | deny: audit + raise GuardrailViolation
```

Connectors/agents/simulators **never** decide authorization themselves — they call
`authorize()`. The embedded evaluator and the Rego are kept identical so enforcement holds
before OPA is deployed and CI/`conftest` can test the same policy.

The embedded mirror is a **testing oracle, not a production authority**. `evaluate()`
keys off Guardian's deployment posture (`GUARDIAN_ENV`): in `development`/`ci` the mirror
may decide (and in `ci`, when OPA is present, the two must agree); in `staging`/`production`
OPA is **mandatory** and its absence means **deny** — there is no silent fallback.

## The rules (default deny)

1. Globally/scope **blocked actions** are never permitted (8 blocked actions; a scope
   cannot re-enable them).
2. **Mode** must be in the scope's `allowed_modes`.
3. **Ownership** of any named domain/repo must be verified (DNS-TXT / GitHub-App). Ownership
   evidence **expires** — a check from months ago is not permanent authority.
4. Only **registered test accounts** — never real users.
5. **Approval-gated** actions need a *valid (unexpired)* recorded approval.
6. **Production** needs **two distinct, unexpired** `production_scan` approvers (two-person
   rule). This replaces the removed `allow_production` flag.

## Approvals

`core.guardrails.Approval` is action-bound, can be `commit`/`workflow_run`-bound, and
**expires** (`expires_at`). Production needs ≥ `PRODUCTION_MIN_REVIEWERS` (2) *distinct*
approvers. The full durable, signal-based two-reviewer flow lives in the planned Temporal
workflow (blueprint area 3); the policy here enforces the invariant regardless of source.

## Audited denials

Every **denied** action is written to the tamper-evident audit log
(`authorize:deny:<action>`, `decision="denied"`, with the policy reasons) — not just
actions that ran (acceptance-gate: audit allowed, denied, failed and cancelled).

## Testing it

- `tests/test_policy_gate.py` — unit tests of every rule.
- `tests/test_authorization_properties.py` — Hypothesis proofs: blocked actions are never
  allowed; production always needs two distinct unexpired approvers; gated actions always
  need a valid approval — across generated input combinations.
- `tests/test_guardrails.py` — asserts **no `allow_production` parameter exists**.
- `policies/opa/guardian_test.rego` — `opa test` / `conftest` validation of the Rego.

```bash
pytest tests/test_policy_gate.py tests/test_authorization_properties.py tests/test_guardrails.py
opa test policies/opa            # when the opa binary is installed
GUARDIAN_USE_OPA=1 pytest        # run enforcement through OPA instead of the mirror
```

## Where this sits in the blueprint

This is the keystone of **area 1 (Policy & authorisation)**. Ownership verification (area 2,
PyGithub/dnspython), durable two-reviewer approval (area 3, Temporal), immutable audit
(area 5, immudb/witness) and the rest plug into this single decision point. See
[hardening_roadmap.md](hardening_roadmap.md).
