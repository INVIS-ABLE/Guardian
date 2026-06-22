# Reasoning graph + durable workflow (`core/brain`)

Build-order step 4 replaces the fixed linear loop with a **bounded reasoning graph**
(LangGraph) wrapped in a **durable case workflow** (Temporal), both operating over the
typed `GuardianCaseState` from step 1.

```
Temporal: durable case + approval workflow   (temporal_workflow.py)
        │  owns retries, suspension, crash-replay, the human-approval signal
        ▼
LangGraph: bounded reasoning graph            (graph.py + nodes.py)
        │  intake → scope gate → plan → collect → analyse → challenge → adjudicate
        ▼
Typed deltas applied to immutable GuardianCaseState   (state.py)
```

## Why the split

- **LangGraph** owns the bounded reasoning *within* a phase: nodes return typed
  `CaseStateDelta`s, a reducer applies them to a new immutable state (no shared mutable
  blackboard), conditional edges branch, and a step cap turns a runaway graph into a
  recorded HALT instead of an open-ended loop.
- **Temporal** owns the durable orchestration *around* it: it runs the graph inside
  activities (so the deterministic workflow body never imports LangGraph or calls
  models), suspends on a human approval via a signal, and resumes deterministically
  from event history after a crash.

The case crosses the activity boundary as a JSON-safe dict
(`GuardianCaseState.model_dump(mode="json")`), so no custom Temporal converter is needed.

## Phases

1. **Investigation graph** (`run_investigation`): intake → **scope/identity gate** →
   plan → collect → analyse → challenge → adjudicate. The scope gate is deterministic
   and **fails closed** — unverified ownership halts the case and nothing downstream
   runs. It ends at `AWAITING_APPROVAL` (a grounded finding) or `COMPLETED` (abstained:
   "insufficient evidence" is a first-class outcome).
2. **Human approval** — the Temporal workflow suspends until an `approve("approved")`
   signal arrives. A model never grants this; a rejection leaves the case un-executed.
3. **Execution graph** (`run_execution`): controlled execution → observe → learn. Only
   ever reached after approval.

## Failure taxonomy (`failures.py`)

Each failure class maps to an explicit behaviour (§12), so the graph fails closed where
it must instead of skipping a failed node and continuing:

| Failure class | Behaviour |
|---|---|
| scope / identity / ownership / policy | **halt** |
| evidence collector | retry, then mark an evidence gap |
| specialist model | approved fallback or abstain |
| memory unavailable | continue without retrieval (**development only**; else halt) |
| audit / evidence backend | **halt** |
| verification | reject the proposed action |
| approval backend | **halt** |
| observability | halt for high-risk work, else degrade |

## Status

The graph is real and tested end-to-end (happy path, fail-closed scope halt, budget
exhaustion, step-cap halt, abstention, post-approval execution, the Temporal activity
boundary). The collectors/analysers are still thin — wiring the model gateway
(`core/ai`) and real scanners into these typed nodes, and standing up a Temporal worker
deployment, are later build-order steps. The legacy `GuardianBrain` orchestrator remains
in place and unchanged until the graph fully supersedes it.
