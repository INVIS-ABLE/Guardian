# Guardian Brain

> **A brain, not a supermodel.** Guardian does not train a model from scratch. It
> *stitches proven pieces together* into one controlled, auditable system: the 17
> agents, the tool router, the guardrails, the policy gates, memory, and the
> evaluation harness — coordinated by a small, explicit orchestrator.

```
                          ┌──────────────────────────────────────────┐
                          │              GuardianBrain                │
                          │  (core/brain.py — controlled workflow)    │
                          └───────────────┬──────────────────────────┘
        plan → scope_verify → threat_model │ → detect → simulate → monitor
                                           │ → patch → test → evidence
                                           ▼ → [HUMAN APPROVAL] → learn
   ┌────────────┬──────────────┬───────────┴───────────┬─────────────────┐
   ▼            ▼              ▼                       ▼                 ▼
 agents      ToolRouter     Guardrails + OPA        Memory (RAG)     Evaluation
 (17)        (core/router)  (core/guardrails,       (core/memory)    (eval/)
                            core/opa, NeMo rails)
```

## The pipeline

The Brain runs the README workflow as an ordered, gated state machine
(`core/brain.py::WORKFLOW`):

```
Detect → Simulate → Analyse → Patch proposal → Test → Evidence
       → Human approval → (deploy safely) → Monitor → Learn
```

Each node:

1. **Policy-gates** the work first. Detect/simulate stages map to a scope *mode*; the
   Brain evaluates the central policy (`core/policy_gate.py`) before invoking the agent. A mode that
   is not in the active scope is **refused** (default-deny) — e.g. `runtime_monitoring`
   is refused under the staging scope that does not allow it.
2. **Runs the agent** (`agents/`), which decides and delegates real work to the router.
3. **Writes outcomes to memory** (detect/simulate/threat_model/evidence stages) so the
   Brain learns across runs.
4. **Audits** every transition to the tamper-evident log.

### The human-in-the-loop hard stop

The `approval` node is a **hard boundary**. Nothing in a `deploy` stage runs until a
human approval is recorded — the Brain *skips* those stages and halts with
`AWAITING HUMAN APPROVAL`. This cannot be disabled from config.

```bash
# Dry-run the whole workflow over a scope (safe by default):
guardian brain scope/invisable-staging.yaml

# Supply a recorded approval (still gated, still audited):
guardian brain scope/invisable-staging.yaml --approve production_scan \
  --approver ciso --ticket OPS-123
```

## Tool router (`core/router.py`)

Agents *decide*; the router *acts*. Every connector/simulator call funnels through one
chokepoint that pre-authorises on the tool's declared `mode`/`action`, honours dry-run,
audits the call, and returns a uniform `RouteResult`. Capabilities are the stable
vocabulary (`static_code`, `secrets`, `dast`, `privacy_simulation`, …); the concrete
tool behind each can change without touching agents.

```bash
guardian capabilities      # list capability -> tool mappings
```

Refusals are **returned, not raised** — the Brain records them and continues, fail-closed
for that step.

## Policy gates — defence in depth (`core/policy_gate.py`, `policies/`)

Three layers must agree on "defensive-only":

| Layer | Where | Role |
| ----- | ----- | ---- |
| Central authority | `core/policy_gate.py` + `policies/opa/guardian.rego` | The ONE `evaluate()` authority; default-deny, fail-closed. In-process mirror of the Rego, delegating to the `opa` binary when `GUARDIAN_USE_OPA=1`. Two-person rule + expiring, bound approvals for production. |
| Guardrails wrapper | `core/guardrails.py` | Every connector/agent/simulator routes through `authorize()`, which builds a `PolicyInput` and asks the central authority. |
| NeMo Guardrails | `policies/guardrails/nemo/` | Conversational rails on the reasoning model: it reasons defensively or refuses. |

```bash
guardian policy scope/invisable-staging.yaml --action credential_audit --mode credential_audit
GUARDIAN_USE_OPA=1 opa test policies/opa -v    # when the OPA binary is installed
```

## Memory / RAG (`core/memory.py`)

Controlled long-term memory: pluggable backends (Qdrant/pgvector/Chroma in production)
with an always-available, JSONL-persisted in-memory fallback so retrieval works offline
and in CI. **Safe by design** — collections are whitelisted, and text *and*
sensitively-named metadata are scrubbed before storage, so memory can never become an
exfiltration channel or a store of real user data.

## Evaluation (`eval/`)

Guardian's behaviour is tested, not assumed: **DeepEval** (deterministic, offline
behavioural assertions — gates, router, scrubbing), **Promptfoo** (refusal/red-team
against the reasoning model), and **Ragas** (memory retrieval quality). See
[`eval/README.md`](../../eval/README.md).

## What the Brain still will not do

Everything in [GUARDRAILS.md](../GUARDRAILS.md) holds: no third-party targeting, no
hack-back, no credential theft, no real-user data, no uncontrolled/stealth scans, no
direct production deploys, no bypassing human approval. The Brain coordinates — it does
not widen the blast radius.
