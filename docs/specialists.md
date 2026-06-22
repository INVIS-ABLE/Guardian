# Priority specialist agents (`agents/specialists`)

Build-order step 6 turns the first four agents from thin stubs into **real bounded
specialists**. Each has the contract the roadmap requires (§6): a typed task, an approved
evidence view, a model-routing class, abstention rules, a hard iteration bound, a
deterministic verifier — and **no ability to approve or execute** its own recommendations
(`can_approve = can_execute = False`).

They reason through the model gateway (`core/ai`) and act only through the tool gateway
(`core/tools`). Inputs and outputs are typed (`SpecialistTask` → `SpecialistResult`), and
contributions come back as a `CaseStateDelta` — never mutated global state.

| Specialist | Domain | Model class | What it does |
|---|---|---|---|
| `ScopeController` | command | **none** (deterministic) | Verifies scope/identity/ownership; emits a typed policy decision. A model never decides authority — a failed check is a hard `fail` (halt). |
| `CodeArchitectureAnalyst` | analysis | `REASONING` | Runs `static_code_scan` via the tool gateway → typed `TOOL_OUTPUT` evidence → interprets it with a strong-reasoning model → forms a hypothesis **grounded** in that evidence. |
| `EvidenceAdjudicator` | verification | `REVIEW` (advisory) | Evidence-led verdict, **never majority vote**: a hypothesis is established only if grounded, contradiction-free and asset-bound; otherwise it abstains. A judge model may add a note but cannot change the verdict. |
| `PatchReviewer` | verification | `REVIEW` | Independent patch verification: abstains if the reviewer's model family equals the **producer's** (the patch model is never its own sole reviewer), then runs deterministic completeness checks (rollback plan, residual risk, traceability). |

## Safety properties (and how they're enforced)

- **A model never decides authority** — `ScopeController.work_class is None`; it is pure
  deterministic logic.
- **Abstention is first-class** — every specialist returns `verdict="abstain"` when it
  lacks grounded evidence, the model is unavailable (fail closed, §12), or the model
  output trips the output firewall (`high_risk`).
- **Grounding is verified deterministically** — a hypothesis/finding is only emitted when
  a deterministic check confirms it cites real evidence.
- **Independent verification** — `PatchReviewer` enforces a different model family from the
  patch producer; the adjudicator's judge opinion is advisory only.
- **No self-approval / self-execution** — encoded as class invariants and asserted in
  tests; specialists return typed results for the human/Temporal approval gate.

## Status

The four specialists are implemented and tested (`tests/test_specialists.py`). Wiring them
into the reasoning-graph nodes (so the graph's collect/analyse/adjudicate steps delegate to
them) and expanding the remaining specialist domains are later build-order steps. The legacy
17-stub registry is untouched.
