# INVISABLE Guardian

**An AI-assisted, defensive-only security & safeguarding immune system for INVISABLE-owned assets.**

Guardian detects weaknesses, simulates attacks against *owned* staging systems and test
accounts, analyses the results, proposes patches, gathers evidence, and routes everything
through **human approval** before anything reaches production.

```
Detect → Simulate → Analyse → Patch proposal → Test → Evidence → Human approval → Deploy safely → Monitor → Learn
```

> Guardian is a **defensive** system built to protect vulnerable users. It strengthens
> INVISABLE systems, preserves evidence, reduces harm, and supports safe development.
> It must **never** become an uncontrolled offensive tool. See [GUARDRAILS.md](GUARDRAILS.md).

---

## Non-negotiable boundaries

Guardian will **never**:

- Target third-party assets (only whitelisted INVISABLE-owned domains/repos)
- Perform hack-back or retaliate against attackers
- Steal credentials or access real user data
- Deploy payloads/exploits to anyone
- Run uncontrolled / stealth / persistent scans
- Make production changes without explicit human approval
- Self-modify production directly (all changes are pull requests)

Every action is scoped, logged, and gated. The full control matrix is in
[GUARDRAILS.md](GUARDRAILS.md) and enforced in code by `core/guardrails.py`.

---

## Repository layout

```
/                       root config, policies, CI workflows
├── core/               config loader, scope engine, guardrails, evidence, audit log
├── agents/             the 17 Guardian ECC agents (orchestration layer)
├── connectors/         thin, dry-run-aware wrappers around security tools
├── simulators/         defensive abuse/attack simulators (owned staging only)
├── policies/           security-standard mappings + malware defence library
├── scope/              asset registry, scope files, test-account registry
├── reports/            generated evidence reports + templates
├── tests/              unit tests for guardrails, scope, simulators
├── playwright/         safeguarding user-journey tests
├── zap/                OWASP ZAP Automation Framework plans
├── semgrep/            Semgrep rule configuration
├── codeql/             CodeQL configuration
├── trivy/              Trivy configuration
├── gitleaks/           Gitleaks configuration
├── dashboard/          Guardian status dashboard (FastAPI)
├── docs/               architecture, agent and workflow docs
└── .github/workflows/  CodeQL, Semgrep, Gitleaks, Trivy, Guardian CI
```

---

## Quick start

```bash
# 1. Install Python tooling
pip install -e ".[dev]"

# 2. Validate scope + guardrails against a scope file (dry run, no scanning)
python -m core.guardrails check scope/invisable-staging.yaml

# 3. List available simulators
python -m simulators list

# 4. Run a simulator against owned staging (dry run by default)
python -m simulators run privacy_leak --scope scope/invisable-staging.yaml --dry-run

# 5. Bring up the local stack (dashboard + vector DB + monitoring)
docker compose up -d

# 6. Open the Guardian dashboard
open http://localhost:8080
```

By default everything runs in **dry-run** mode against **staging**. Real execution and
any production-touching action requires an approved scope plus the Human Approval gate.

---

## The MVP

The first build target ships:

| Capability                | Where                                              |
| ------------------------- | -------------------------------------------------- |
| Asset registry            | `scope/assets.yaml`                                |
| Scope file + schema       | `scope/invisable-staging.yaml`, `SCOPE_SCHEMA.yaml`|
| Test account registry     | `scope/test_accounts.yaml`                         |
| GitHub repo scanner       | `connectors/repo_scanner.py`                       |
| CodeQL integration        | `connectors/codeql.py`, `.github/workflows/codeql.yml` |
| Semgrep integration       | `connectors/semgrep.py`, `semgrep/semgrep.yml`     |
| Gitleaks integration      | `connectors/gitleaks.py`, `gitleaks/.gitleaks.toml`|
| Trivy integration         | `connectors/trivy.py`, `trivy/trivy.yaml`          |
| ZAP Automation Framework  | `connectors/zap.py`, `zap/staging-baseline.yaml`   |
| Playwright safeguarding   | `playwright/safeguarding.spec.ts`                  |
| Report generator          | `core/evidence.py`, `reports/templates/`           |
| Human approval PR workflow| `.github/workflows/guardian-ci.yml`, [SECURITY_POLICY.md](SECURITY_POLICY.md) |
| Guardian dashboard        | `dashboard/app.py`                                 |

---

## Security standards mapped

OWASP **WSTG**, **ASVS 5.0**, **SAMM**, **MASVS/MASTG**; **NIST SSDF**; **SLSA**;
**MITRE ATT&CK** (defensive behaviour mapping only). See
[`policies/security_standards.md`](policies/security_standards.md).

---

## Documentation

- [SECURITY_POLICY.md](SECURITY_POLICY.md) — disclosure, self-healing workflow, approval
- [GUARDRAILS.md](GUARDRAILS.md) — the mandatory control gates
- [docs/architecture.md](docs/architecture.md) — system architecture
- [docs/agents.md](docs/agents.md) — the 17 Guardian agents
- [docs/workflow.md](docs/workflow.md) — self-healing workflow detail
- [docs/self_healing_stack.md](docs/self_healing_stack.md) — recommended tools/frameworks per self-healing layer
- [docs/credential_audit_tools.md](docs/credential_audit_tools.md) — hashcat/John/Hydra, authorised defensive use only
- [docs/tooling_catalogue.md](docs/tooling_catalogue.md) — every tool Guardian orchestrates, with upstream sources
- [docs/tool_independence.md](docs/tool_independence.md) — defensive vendor/pin + detection-learning plan
- [policies/mobile_guardian_modules.yaml](policies/mobile_guardian_modules.yaml) — mobile/PWA defence modules (MASVS/MASTG)
- **Encryption & hashing layer** — [security/README.md](security/README.md),
  [docs/crypto_architecture.md](docs/crypto_architecture.md),
  [docs/crypto_security_policy.md](docs/crypto_security_policy.md),
  [docs/crypto_threat_model.md](docs/crypto_threat_model.md),
  [docs/crypto_test_plan.md](docs/crypto_test_plan.md)

---

## License & use

Internal INVISABLE defensive security tooling. Authorised for use **only** against
INVISABLE-owned assets listed in an approved scope file.
