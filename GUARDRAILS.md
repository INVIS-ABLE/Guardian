# Guardian Guardrails — Mandatory Control Gates

These gates are **non-negotiable**. They are enforced in code (`core/guardrails.py`),
in scope validation (`core/scope.py`), and in CI. A run that cannot satisfy every
applicable gate is **refused** — it does not "degrade gracefully" into a riskier mode.

---

## 1. Scope gates (who/what may be touched)

| Gate                         | Rule                                                                 |
| ---------------------------- | ------------------------------------------------------------------- |
| Whitelisted domains only     | Targets must match `allowed_domains` in the active scope file.      |
| Whitelisted repos only       | Repo actions must match `allowed_repos`.                            |
| Staging by default           | `environment: staging` unless an approved production scope is used. |
| DNS / repo ownership check   | Ownership is verified before any active test (`core/scope.py`).     |
| Test accounts only           | Only accounts in `scope/test_accounts.yaml` may be used.            |
| No real user data            | Production datastores and PII are never read or exported.           |

## 2. Behaviour gates (what may be done)

The following are **always blocked**, in every mode, in every scope:

- `third_party_scan` — scanning anything not INVISABLE-owned
- `real_user_data_access`
- `credential_theft`
- `stealth` — evasion of detection/logging
- `persistence` — leaving any foothold
- `exploit_deployment`
- `hack_back`
- `destructive_testing`

## 3. Approval gates (human-in-the-loop)

These actions are refused unless an explicit, recorded **human approval** exists for the
specific run (see `core/guardrails.py::ApprovalGate` and the Human Approval Agent):

- `production_scan`
- `high_volume_test`
- `account_locking_test`
- `data_export_test`
- `admin_permission_test`

## 4. Change-management gates

| Gate                              | Rule                                                            |
| --------------------------------- | -------------------------------------------------------------- |
| All code changes are pull requests | No direct pushes to protected branches; no production self-modification. |
| Feature-flag deploys only          | Approved fixes ship behind a flag, never as a silent live change.|
| Automatic rollback                 | If post-deploy safety checks fail, the change is rolled back.   |
| Every action logged                | Tamper-evident audit log (`core/audit.py`); logs are evidence. |

---

## How a gate decision is made

```
load scope ──▶ verify ownership ──▶ check mode is allowed ──▶ check action not blocked
   │                                                              │
   └────────────── any failure ──▶ REFUSE + log ◀────────────────┘
                                        │
                        action in approval_required?
                                        │
                                yes ──▶ require recorded approval ──▶ else REFUSE
```

**One central path.** Connectors, agents, and simulators never decide authorization
themselves — they call a single `authorize()`, which asks the central policy
(`core/policy_gate.py`, mirrored by `policies/opa/guardian.rego`) for one decision.
There is **no `allow_production` escape parameter**: production requires two distinct,
unexpired `production_scan` approvers. Denied actions are audited too. See
[docs/authorization.md](docs/authorization.md).

```python
gate = Guardrails(scope, approvals=[...])
gate.authorize(                      # the ONLY authorization call sites use
    mode=mode,                       # mode in scope.allowed_modes
    action=action,                   # not blocked; valid approval if gated
    domain=target_domain,            # ownership verified (expires)
    repo=target_repo,
    test_account=account,            # registered test account only
)  # → allow, or audit("denied") + raise GuardrailViolation
```

---

## Default-deny posture

- Unknown target → **deny**
- Unknown mode → **deny**
- Missing/invalid scope file → **deny**
- Missing approval for an approval-gated action → **deny**
- Ambiguity about ownership → **deny**

When in doubt, Guardian stops and asks a human. That is the intended behaviour.
