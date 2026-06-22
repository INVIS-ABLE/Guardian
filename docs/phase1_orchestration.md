# Phase 1 — Durable Orchestration (Temporal state machine)

Blueprint area 3. A restart-safe security-workflow state machine with two-reviewer
approvals, replay protection, risk tiers, budgets, kill switches, and a **last-moment policy
re-check before execution**. Temporal makes it durable in deployment; the in-process engine
(`orchestration/`) enforces the same invariants and is fully testable without a cluster.

## Workflow states (monotonic, forward-only)

```
CREATED → SCOPED → THREAT_MODELLED → SCANNED → PATCH_PROPOSED → TESTED
        → AWAITING_APPROVAL → APPROVED → EXECUTING → DEPLOYED → MONITORING → DONE
                   │                │
                   └── DENIED ◀─────┘   (refusal off-ramp)
   any non-terminal ── CANCELLED         (operator stop)
                       EXECUTING/MONITORING ── ROLLED_BACK
```

- **Monotonic:** no transition moves backward; illegal transitions raise `IllegalTransition`.
- **Terminal is terminal:** `DONE`/`ROLLED_BACK`/`DENIED`/`CANCELLED` cannot be left — a
  cancelled or denied workflow can never resume into execution.

## Invariants enforced (with tests)

| Invariant | Where | Test |
| --------- | ----- | ---- |
| Production pauses for **two distinct** authenticated reviewers | `ApprovalLedger.satisfied_for_production` | `test_production_*` |
| A **replayed** approval signal (reused nonce) is rejected | `ApprovalLedger.submit` | `test_replayed_nonce_rejected` |
| An approval can't move between commits/runs (bound) | `ApprovalLedger.submit` | `test_signal_bound_to_workflow_run` |
| The policy gate is **re-asked immediately before execution** | `SecurityWorkflowEngine.execute` | `test_policy_reasked_before_execution_denies` |
| A **denied** workflow never reaches EXECUTING | engine + state machine | `test_policy_reasked_*`, `test_budget_*` |
| A **cancelled** workflow cannot resume | `WorkflowMachine` | `test_cancelled_is_terminal_*` |
| A **kill switch** (global/env/tenant) halts work | `KillSwitch` | `test_kill_switch_halts_execution` |
| Per-workflow **budgets** bound runaway work | `WorkflowBudget` | `test_budget_exceeded_*` |
| Every step + decision is **audited** (allowed and denied) | `SecurityWorkflowEngine._audit` | — |

## The two-gate approval model

1. **Workflow approval** — distinct human reviewers signal the `ApprovalLedger`. Risk tier
   sets the minimum count (`LOW`=0 … `HIGH`/`CRITICAL`=2); production forces ≥2 distinct.
2. **Policy authorization** — `execute()` calls the central `core.guardrails.authorize()`
   **again**, right before running. A capability that has since expired, been revoked, or had
   its commit changed is refused at the last moment (the workflow transitions to `DENIED`).

Both must pass. This realises the blueprint's rule: *"pause until two distinct authenticated
reviewers approve, then ask OPA again immediately before execution."*

## Temporal backend

`orchestration/temporal_backend.py` lazily detects the `temporalio` SDK. In deployment the
same machine/engine run as a Temporal workflow that blocks on a `production_approval` signal
and a `kill` signal. Until then the in-process engine is the reference behaviour — identical
invariants, no cluster required. Enable with the `brain`/orchestration extras + a Temporal
service (see `docs/architecture/components.yaml`, `durable_orchestration`).

## Maps to the acceptance gate

- **Approvals:** two distinct, bound, expiring approvals → ✅ enforced here + in the policy.
- **Bulletproof tests:** *one compromised reviewer cannot authorise production* (✅),
  *a replayed Temporal signal is rejected* (✅), *a valid approval copied to another commit is
  rejected* (✅ via binding), *denied/cancelled workflows never execute* (✅).
