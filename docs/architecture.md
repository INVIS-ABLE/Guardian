# Guardian Architecture

```
                         ┌────────────────────────────────────────────┐
                         │                 ECC command centre          │
                         │      (orchestration / workflow engine)       │
                         └───────────────┬──────────────────────────────┘
                                         │ plans & sequences
        ┌────────────────────────────────┼────────────────────────────────┐
        ▼                                ▼                                ▼
  Guardian agents               core (enforcement)                  connectors
  (17 ECC agents)        ┌───────────────────────────┐         (tool wrappers)
  planner, scope,        │ config · scope · guardrails │   codeql · semgrep ·
  threat model,    ◀────▶│ evidence · audit            │◀──▶ gitleaks · trivy ·
  code review, …         └───────────────────────────┘         zap · repo_scanner
        │                          ▲        ▲                          │
        ▼                          │        │                          ▼
   simulators ───────────────────┘        └──────────────────  external tools
   (defensive abuse library)                                    (staging only)
```

## Layers

1. **ECC command centre** — orchestrates workflows; picks agents/modes from the active
   scope. (This repo provides the agent/connector/simulator building blocks ECC drives.)

2. **Guardian agents** (`agents/`) — 17 bounded, auditable agents (see [agents.md](agents.md)).
   Agents *orchestrate*; they never bypass `core` guardrails.

3. **core** (`core/`) — the enforcement layer. **Everything** routes through here:
   - `config.py` — loads `guardian.config.yaml` (safe defaults).
   - `scope.py` — loads/validates scope files; ownership + registry membership.
   - `guardrails.py` — the mandatory control gates (default-deny, fail-closed).
   - `evidence.py` — the `SimulatorResult` contract + report generator (secret-scrubbed).
   - `audit.py` — hash-chained, tamper-evident audit log.

4. **connectors** (`connectors/`) — dry-run-aware wrappers around CodeQL, Semgrep,
   Gitleaks, Trivy, ZAP, plus the `RepoScanner` aggregator. Each gate-checks before running.

5. **simulators** (`simulators/`) — defensive abuse scenarios against *owned* staging +
   *test* accounts only. Each emits the mandatory evidence contract.

## Data & safety flow

```
scope file ─▶ core.scope.load_scope ─▶ schema + registry validation
                                          │
agent/connector/simulator ─▶ core.guardrails.authorize() ─▶ allow | REFUSE+log
                                          │ allow
                                          ▼
                                   action (dry-run by default)
                                          │
                                          ▼
                          core.evidence.write_report  +  core.audit.record
```

## RAG memory & models

Configured in `guardian.config.yaml`: a reasoning model (Claude/GPT-compatible), an
optional local model for private/offline analysis, and a vector DB (Qdrant by default)
holding repos, policies, threat models, app docs, support flows, and safeguarding rules.
The Learning Memory agent writes outcomes back so Guardian improves over time.

## The defensive simulator library

MVP ships **privacy_leak**, **banned_user_return**, **moderator_abuse**. The remaining
library (account takeover, credential-stuffing, password-spray, scraper, API-abuse,
bot-swarm, fake-user, harassment-wave, grooming-risk, staff-permission-abuse,
health-data-exposure, data-breach-response, upload-abuse, report-system-abuse,
recovery/rollback, supply-chain-tamper) is declared in `simulators.PLANNED` and added
incrementally, each following the same `BaseSimulator` contract.
