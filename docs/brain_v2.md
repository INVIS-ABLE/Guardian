# Guardian Brain V2 — Cognition Architecture

> **Going deeper than [`brain.md`](brain.md).** The V1 Brain is an ordered, dependency-free
> state machine over a shared mutable blackboard — the *controls came before the intelligence*,
> which is the right order. V2 makes the intelligence real: a durable, bounded, replayable
> reasoning system that can investigate, correlate, test, patch and plan recovery almost
> entirely on its own — while remaining **powerless to exceed its authority**.

## The one design line

> Guardian may become **highly autonomous in investigation**, correlation, testing, patch
> preparation and recovery *planning*. **Production execution, key access, identity changes
> and irreversible containment stay behind deterministic policy (OPA) + bound human approval.**

Said another way, and enforced as a test invariant
([`tests/test_brain_tools_manifest.py`](../tests/test_brain_tools_manifest.py)):

```
Cognition proposes.  Authority disposes.  No cognitive tool can grant authority.
```

This is what lets us add a lot of intelligence without building a self-authorising machine.
Every tool below sits *underneath* the existing reference monitor
([`core/policy_gate.py`](../core/policy_gate.py) + [`policies/opa/guardian.rego`](../policies/opa/guardian.rego)),
not beside it.

## The shape

```
Temporal ── durable case & approval workflow (survives restarts, safe pending approvals)
   │
   ▼
LangGraph ── bounded reasoning graph (branches, parallel specialists, interrupts, replay)
   │
   ├──────────────┬──────────────────────────────────────────────┐
   ▼              ▼                                                ▼
Deterministic   AI reasoning                                  Typed contracts
controls        (LiteLLM gateway → routed models → retrieval)  (PydanticAI state deltas)
OPA / identity / scope / Z3 plan-feasibility
   │                                                                │
   └──────────────┬─────────────────────────────────────────────────
                  ▼
        Typed Tool Gateway (MCP behind a capability proxy → one-use tokens)
                  │
        Isolated scanners & connectors (gVisor / Cilium, deny-egress)
                  │
                  ▼
        Evidence graph → independent verification → human approval → controlled execution
```

One owner per responsibility — **do not** stack CrewAI/AutoGen/Semantic-Kernel beside this:

| Responsibility | Owner |
| -------------- | ----- |
| Durability / retries / pending approvals | **Temporal** |
| Bounded cognition (the graph) | **LangGraph** |
| Typed agent contracts | **PydanticAI** |
| Controlled model access | **LiteLLM** |
| Authority (allow/deny) | **OPA** (unchanged keystone) |

## The 20 cognitive tools

The authoritative, machine-checked list is
[`architecture/brain_tools.yaml`](architecture/brain_tools.yaml). Summary by category:

### Executive reasoning & orchestration — the nervous system
| # | Tool | What it gives Guardian |
| - | ---- | ---------------------- |
| 1 | **LangGraph** | The inner cognitive graph: branching investigations, parallel specialists, human interrupts, checkpoints, replanning, bounded loops. |
| 2 | **Temporal** | The durable outer workflow: investigations survive restarts, approvals stay safely pending, activities retry, history replays. *(Also tracked in `components.yaml::durable_orchestration`.)* |
| 3 | **PydanticAI** | Typed agent inputs/outputs/dependencies — every node returns a *validated object*, not arbitrary prose or an untyped dict. |
| 4 | **LiteLLM** | One controlled model gateway (routing, budgets, provenance). Agents never call providers directly. |

### Tool use, structured generation & self-improvement
| # | Tool | What it gives Guardian |
| - | ---- | ---------------------- |
| 5 | **MCP Python SDK** | A standard tool/resource protocol — wrapped behind a Guardian *capability proxy*, never arbitrary command-line access. |
| 6 | **Outlines** | Schema-constrained generation so output is structurally valid (plans, findings, tool calls). Valid ≠ true — still verified against evidence. |
| 7 | **DSPy** | *Offline* optimisation of prompts/programs against the eval datasets. Never auto-deploys; promotion is via signed prompt manifest. |
| 8 | **Langfuse** | Self-hosted tracing, prompt/version management, evals, latency and token-cost visibility — *why* an agent concluded what it did. |

### Temporal memory & security knowledge
| # | Tool | What it gives Guardian |
| - | ---- | ---------------------- |
| 9 | **Graphiti** | A time-aware knowledge graph of how assets/identities/findings/incidents change, with provenance preserved. |
| 10 | **Neo4j GraphRAG** | Graph-based retrieval over repos/services/identities/APIs/vulns/data-flows — *connected* evidence, not text similarity. |
| 11 | **NetworkX** | Deterministic graph algorithms: attack paths, shortest paths, blast radius, critical nodes. |
| 12 | **Z3** | A solver that **proves a plan is internally feasible** (permissions, capacity, exclusivity) before it runs. |
| 13 | **DuckDB** | Fast, deterministic SQL over logs/SARIF/SBOM/scanner output — factual computation instead of asking a model to count. |

### Deep code & application understanding
| # | Tool | What it gives Guardian |
| - | ---- | ---------------------- |
| 14 | **Tree-sitter** | Robust multi-language parse to syntax trees — functions, imports, routes, symbols, structural diffs. |
| 15 | **Joern** | Code-property graphs (syntax + control flow + data flow) for taint and authorisation-path analysis. |
| 16 | **OpenHands** | A disposable-sandbox software engineer: reproduce, patch, run tests; prepares branches/PRs — **never deploys**. |

### Assurance, adversarial testing & formal proof
| # | Tool | What it gives Guardian |
| - | ---- | ---------------------- |
| 17 | **Hypothesis** | Property-based generation of approval/identity/timestamp/envelope combinations to find bypasses. *(Already used: [`tests/test_authorization_properties.py`](../tests/test_authorization_properties.py).)* |
| 18 | **TLA+ / TLC** | Formal model checking of workflow invariants — concurrency, duplicate signals, replay, approval-state transitions. |
| 19 | **PyRIT** | Adaptive, multi-turn adversarial campaigns against Guardian's own models and agents. |
| 20 | **garak** | Repeatable LLM vulnerability scanning — prompt injection, data leakage, unsafe-behaviour probes. |

PyRIT and garak overlap deliberately: garak gives **broad repeatable** scanning, PyRIT gives
**adaptive** campaigns. With Hypothesis (structured inputs) and TLA+ (state transitions), the
Brain is attacked from four directions before any release.

## Three levels of code intelligence

```
Tree-sitter   →  fast structure & symbol understanding
   ↓
Joern         →  security data-flow & control-flow understanding
   ↓
OpenHands     →  sandboxed reproduction, patching and test execution
```

Backed by a persistent **code map** per repo (files → routes → auth checks → crypto ops →
secret access → trust boundaries → data classifications), updated per-commit. That is what lets
the Brain say *"this PR changed the session-token validator; three routes depend on it; one
handles health data; the new validator no longer verifies the intended audience"* — genuine
security intelligence rather than scanner aggregation.

## A model proposes, Z3 proves, OPA authorises

Three distinct gates, never collapsed into one:

```
LiteLLM-routed model  →  proposes a plan / patch / containment
        ↓
Z3                    →  proves the plan is internally POSSIBLE
                         (capacity ≥ threshold, ≥2 workers remain, evidence store reachable,
                          identity can't revoke itself, no unapproved production capability)
        ↓
OPA                   →  decides whether it is AUTHORISED
        ↓
Human approval        →  binds the exact action/target/commit/policy-digest (for sensitive acts)
```

A model never decides whether it has authority to proceed.

## Make Guardian as clever as its tools — the Tool Intelligence Package

Connecting 20 tools does not make the Brain clever. Each tool ships a package so the Brain
understands its **epistemic limits**, not just its command syntax:

```
tools/<tool>/
├── manifest.yaml          # capability, image digest, schemas, limits, network/fs posture
├── capability.py          # the typed capability the router can issue a one-use token for
├── input_schema.py / output_schema.py
├── planner_guidance.md    # what it CAN and CANNOT answer
├── parser.py / normaliser.py
├── verifier.py            # how to corroborate the result, and with which other tool
├── failure_modes.py / cost_model.py / privacy_rules.py
├── evaluation_cases/
└── adapter.py
```

Each manifest tells the planner: *what question this answers, what it cannot answer, false-positive
patterns, failure modes, required permissions/network, runtime/cost, whether the result is
deterministic, how fresh it must be, and which independent tool corroborates it.* Example: Joern
answers "can untrusted input reach a sensitive operation?" but **does not** answer "is the
vulnerable route publicly reachable?" — and is corroborated by Tree-sitter, Semgrep and a
targeted test.

## The cognitive loop

```
1  trigger → 2 verify actor/scope/ownership/environment → 3 build case
4  query asset & temporal knowledge graphs → 5 identify evidence gaps
6  generate ≥3 investigation plans (minimal / deep / privacy-preserving)
7  score plans (evidence gain, risk, privacy exposure, time, cost, reversibility, availability)
8  Z3 validates plan constraints → 9 OPA authorises evidence collection
10 execute tools via capability-bound MCP adapters → 11 normalise into the evidence graph
12 correlate (DuckDB + graph algorithms) → 13 generate competing hypotheses
14 sceptic + alternative-explanation agents → 15 pick falsification tests → 16 safe cyber-range tests
17 adjudicate findings from evidence → 18 generate response/patch options → 19 verify each independently
20 prepare strongest verified recommendation/PR → 21 await required approval
22 revalidate the entire action envelope → 23 execute the exact authorised action
24 observe → 25 auto-rollback if safety conditions fail → 26 promote only verified lessons to memory
```

The planner must produce **at least three** strategies — minimal, deep, privacy-preserving — and
a *deterministic* scorer selects the one giving sufficient confidence with the smallest safe
footprint. The Brain does not default to the most aggressive plan.

## Autonomy levels

### Fully autonomous (within verified owned scope)
Inventory assets · analyse commits · correlate/dedupe findings · triage · build threat models &
attack paths · search logs (redacted) · reproduce in isolation · generate tests · produce patch
branches · run CI + security evals · open **draft** PRs · create DefectDojo findings · draft
incident reports · recommend containment · monitor whether a fix worked · close false positives
with evidence · maintain the digital twin · flag stale controls / missing evidence.

### Conditionally autonomous (only with prior policy-defined authority, expiry + auto-rollback)
Pause a compromised CI workflow · quarantine an untrusted image digest · revoke a specific
short-lived service credential · isolate a single staging pod · disable a compromised
non-production integration · roll back a failed staging/canary release · apply a temporary,
narrowly scoped block · raise rate-limiting during a confirmed attack · freeze a suspicious
deployment. Every such action is narrowly scoped, reversible, time-limited, independently
verified, immutably audited, and **cannot expand its own scope**.

### Never autonomous
Deploy to production · grant itself permissions · change its own OPA policies · add tools to its
allowlist · alter root signing keys · disable immutable auditing · delete evidence · access
private-message decryption keys · decrypt INVISABLE conversations · change legal/retention policy
· disable safeguarding controls · promote its own model output directly into trusted memory ·
target anything outside verified INVISABLE scope.

> This does not make Guardian weak. It makes Guardian **compromise-resistant**: owning one
> cognitive tool, or one specialist agent, does not buy you the control plane.

## Priority implementation waves

The `wave` field in [`brain_tools.yaml`](architecture/brain_tools.yaml) is authoritative.

1. **Wave 1 — a real nervous system:** LangGraph, Temporal, PydanticAI, LiteLLM, MCP capability
   proxy, Outlines. *Outcome:* durable cases, bounded reasoning, typed outputs, controlled calls.
2. **Wave 2 — knowledge & deduction:** Langfuse, Graphiti, Neo4j GraphRAG, NetworkX, Z3, DuckDB.
   *Outcome:* relationships, attack paths, plan constraints, evidence-grounded explanations.
3. **Wave 3 — engineering capability:** Tree-sitter, Joern, OpenHands, DSPy. *Outcome:* structural
   + data-flow code understanding, sandboxed reproduction and tested fixes.
4. **Wave 4 — try relentlessly to break it:** Hypothesis, TLA+/TLC, PyRIT, garak. *Outcome:* every
   Brain release faces generated edge cases, formal state checking and adversarial model testing.

## Prerequisite fixes (do these before more autonomy)

These existing V1 defects are tracked in [`hardening_roadmap.md`](hardening_roadmap.md) and must
land before the agents become more autonomous:

- `core/brain.py::build_policy_input` defaults `ownership_verified=True` — should default
  **False** and require target/repo/commit/workflow/ownership-evidence-id + expiry.
- The approval node returns `auto_approve`, but the Brain reads `approved` — so a supplied
  approval can never actually approve a run; replace with a signed Temporal signal / LangGraph
  interrupt carrying a bound `ApprovalSignal`.
- The embedded policy mirror is used whenever OPA is absent — it must be a **testing oracle**,
  not a production authority: dev = embedded ok; CI = embedded and OPA must match; staging = OPA
  required; production = remote/pinned OPA, absence ⇒ **deny**.
- Memory must **fail closed** in production if the approved backend (Qdrant) is unavailable —
  never silently drop to local JSONL.

## The Brain V2 release gate

Do not call the Brain operationally autonomous until **all** hold:

1. Every conclusion identifies supporting evidence objects (≥95% of material factual claims).
2. Every tool call is authorised, typed, bounded by a one-use capability, and replayable.
3. Critical failures **halt** dependent stages instead of being silently skipped.
4. The model cannot alter scope, identity, policy or approvals.
5. Untrusted repository/log/web content can never become an instruction.
6. Model output cannot enter trusted memory automatically.
7. No production approval is reusable across targets or commits.
8. No private-message content reaches a model.
9. The Brain can explicitly report **"insufficient evidence."**
10. An independent verifier can reconstruct every decision (full replay).
11. A model/provider failure cannot cause an unsafe fallback.
12. Patch proposals pass *independent* verification (the generator is not the sole reviewer).
13. Model/prompt/memory changes pass mandatory regression evals (no improving one metric while
    materially worsening safety, privacy or false-positive rate).
14. Compromising one specialist agent does not compromise the control plane.

> The strongest Guardian is not the one with the most agents. It is the one that can collect
> evidence, reason across the whole INVISABLE ecosystem, challenge its own conclusions, create
> verified fixes, learn only from approved outcomes — and remain powerless to exceed its authority.
