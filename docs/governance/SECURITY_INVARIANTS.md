# Security Invariants

Properties that must hold at all times. Each maps to enforcement and a test. An invariant
without an automated check is a gap to close.

## Enforced now

| Invariant | Enforcement | Test |
| --------- | ----------- | ---- |
| No action runs without passing the one central `authorize()` | `core/policy_gate.py`, `core/guardrails.py` | `tests/test_policy_gate.py`, `tests/test_guardrails.py` |
| No `allow_production` escape parameter exists | `Guardrails.authorize` signature | `test_authorize_has_no_allow_production_parameter` |
| Blocked actions are never permitted by any input combination | policy gate | `tests/test_authorization_properties.py` |
| Production needs two distinct, unexpired `production_scan` approvers | policy gate | `test_production_*` |
| An approval bound to a commit/workflow/target is invalid elsewhere | policy gate | `test_commit_bound_approval_*` |
| Scope-file membership is NOT ownership proof in production | `Guardrails._verify_ownership` (fail-closed) | `test_production_ownership_fails_closed_without_verifier` |
| Denied actions are audited, not just successful ones | `Guardrails._audit_denial` | manual + audit chain |
| Only registered test accounts are ever used | policy gate | `test_non_test_account_*` |
| Crypto: no plaintext passwords, keys not stored beside data, no tokens in localStorage | `security/crypto/*` + `cryptoPolicyChecker` | `security/crypto/__tests__/*` |
| Privacy: Guardian never decrypts/reads private content, holds keys, or trains on user data | privacy invariants are globally blocked actions in `core/policy_gate.py` + `policies/opa/guardian.rego` | `tests/test_privacy_invariants.py` |

## The "bulletproof" acceptance tests (target state)

Guardian reaches high assurance only when all hold (status tracked in
[../hardening_roadmap.md](../hardening_roadmap.md)):

1. A fully compromised model cannot execute an unapproved action.
2. A compromised connector cannot reach an unapproved destination.
3. A malicious repository cannot inject instructions into trusted memory.
4. One compromised reviewer cannot authorise production.  ✅ (two-person rule)
5. A valid approval copied to another commit is rejected.  ✅ (commit binding)
6. A stale DNS / GitHub ownership proof is rejected.  🟡 (expiry modelled; real verifier pending)
7. A replayed Temporal signal is rejected.
8. An unsigned or incorrectly attested image cannot run.
9. A mutated policy bundle cannot load.
10. Deleting local logs does not delete the authoritative evidence.  🟡 (immudb pending)
11. OPA / OpenBao / immudb failure causes sensitive operations to stop (fail closed).
12. A compromised staging environment cannot administer production Guardian.
13. No model, scanner or log receives unnecessary real-user data.
14. Every production change is traceable to source, build, scans, policy, reviewers, deploy.
15. A full clean-environment restoration succeeds from documented backups.
16. An independent security team cannot bypass the controls during an authorised pentest.

Each unchecked item has an owner and a target phase in the roadmap.
