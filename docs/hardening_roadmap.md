# Guardian Hardening Roadmap (12 areas → 10/10 acceptance gate)

Tracks the production-hardening blueprint. **Status key:** ✅ done · 🟡 in progress ·
⬜ planned. The keystone (central OPA-backed authorization) is done; everything else
plugs into that single decision point.

## "Fix before stitching anything else"

| Item | Status | Notes |
| ---- | ------ | ----- |
| Central OPA-backed `authorize()`, no `allow_production` escape | ✅ | `core/policy_gate.py` + `policies/opa/guardian.rego`; property-tested |
| Approvals bound to commit/workflow/target (not just action name) | ✅ | policy gate binding + tests |
| Scope-file membership not accepted as ownership proof in production | ✅ | `Guardrails._verify_ownership` fail-closed; test |
| Replace default Grafana password; close exposed internal ports; no `latest` | ✅ | `docker-compose.yml` (version-pinned, private network, fail-closed Grafana pw) |
| Governance docs skeleton | ✅ | `docs/governance/` (14 docs) |
| Remove every `\|\| true` / security `continue-on-error`; make security jobs blocking | ✅ | `.github/workflows/*` jobs blocking; ruff/bandit/pip-audit/zizmor + Semgrep/Trivy/CodeQL/Gitleaks all gate; `persist-credentials: false` |
| Pin every Action to a full commit SHA | 🟡 | `renovate.json` (`helpers:pinGitHubActionDigests`) pins on first Renovate PR; zizmor enforces a pinned ref now |
| Pin every container by digest (sha256) | 🟡 | `renovate.json` (`docker:pinDigests`); zizmor `unpinned-images` enforced |
| Protected `main`; ruleset (2 reviews, CODEOWNERS, signed commits, no force-push) | ⬜ | repo settings (admin action) |
| Production GitHub Environment with required reviewers, no self-review/admin bypass | ⬜ | repo settings |
| Register Guardian as a least-privilege GitHub App | ⬜ | area 2 |

## The 12 integration areas

| # | Area | Upstream | Status | Where |
| - | ---- | -------- | ------ | ----- |
| 1 | Policy & authorisation | OPA, conftest | ✅ keystone | `core/policy_gate.py`, `policies/opa/*.rego`, `docs/authorization.md` |
| 2 | Ownership verification | PyGithub, dnspython | 🟡 | live, expiring, fail-closed verifier shipped (`ownership/`): DNS-TXT challenge + GitHub-App owner proof via injected resolvers, re-resolves immediately before use (TTL-bounded), drops into `Guardrails.ownership_verifier`; concrete dnspython/PyGithub resolver wiring pending |
| 3 | Durable workflows & approvals | Temporal + sdk-python | 🟡 | state machine + engine shipped (`orchestration/`): monotonic states, two-reviewer approvals, replay protection, kill switches, budgets, **re-ask policy before execute**; Temporal cluster wiring pending |
| 4 | Secrets & keys | OpenBao, SOPS | 🟡 | short-lived credential broker shipped (`identity/credentials.py`: TTL ceiling, expiry, revoke); OpenBao + SOPS wiring pending |
| 5 | Immutable audit & evidence | immudb, in-toto/witness, cosign | 🟡 | system-of-record + Ed25519-signed attestations shipped (`attestation/`); local deletion can't erase evidence; immudb + cosign/witness wiring pending |
| 6 | Findings management | DefectDojo | 🟡 | risk-based prioritisation shipped (`supplychain/sbom.py`: KEV/EPSS/exposure/reachability + OpenVEX); DefectDojo ledger wiring pending |
| 7 | Dashboard identity | oauth2-proxy (OIDC) | 🟡 | principal + role enforcement shipped (`identity/oidc.py`); internal ports closed; oauth2-proxy/Keycloak wiring pending |
| 7b | Egress control | Cilium + egress gateway | 🟡 | default-deny egress policy shipped (`isolation/egress.py`: blocks metadata/private/loopback, allowlist); Cilium gateway wiring pending |
| 8 | Sandbox & runtime detection | gVisor (runsc), Falco | 🟡 | sandbox profile + run-spec validation shipped (`isolation/sandbox.py`); gVisor/Falco runtime wiring pending |
| 9 | Build provenance | actions/attest, cosign, witness | 🟡 | admission verify + provenance signing shipped (`supplychain/`): digest-pinned+signed+provenance+SBOM, fail-closed; cosign/witness CI wiring pending |
| 10 | Mandatory CI gates | dependency-review, scorecard, zizmor, pip-audit, bandit | 🟡 | zizmor + pip-audit + bandit blocking now; dependency-review + scorecard pending |
| 11 | High-assurance testing | hypothesis, schemathesis, uv, renovate | 🟡 | hypothesis property tests done; uv lockfile + schemathesis next |
| 21 | Reversible containment | deterministic adapter | 🟡 | reversible-only allowlist + deterministic param validation + audit shipped (`containment/`); concrete IdP/Cilium/Harbor adapters pending |
| 19 | Detection-as-code | SigmaHQ/sigma | 🟡 | ATT&CK-mapped rules + engine shipped (`detection/`): per-rule positive/negative tests, recommends reversible containment (still gated); Sigma export to Wazuh/Loki pending |
| 23 | Chaos & fail-closed | LitmusChaos | 🟡 | control-plane health + fail-closed gate shipped (`resilience/`): OPA/OpenBao/immudb/Temporal down ⇒ sensitive actions refused + audited; chaos-cluster injection pending |
| 26 | Backup & recovery | restic, Velero | 🟡 | WORM backups + restore drill shipped (`recovery/`): integrity-verified, tamper-refusing restore, audit-chain re-verification with measured RPO/RTO; restic/Velero wiring pending |
| 12 | Observability & alerting | OTel (py + collector), Tempo, Alertmanager | 🟡 | correlation/trace IDs + nested spans (`observability/trace.py`, contextvar-propagated) and severity-routed, deduplicated alerting carrying the correlation id (`observability/alerts.py`, allowlist routing, injected sinks — no network by default); OTel exporter + Tempo/Alertmanager wiring pending |

## 10/10 acceptance gate

| Capability | Status | Evidence |
| ---------- | ------ | -------- |
| Authorisation — one central path, no `allow_production` | ✅ | `core/policy_gate.py`; `tests/test_guardrails.py::test_authorize_has_no_allow_production_parameter` |
| Approvals — two distinct people, action/commit/workflow-bound, expire | 🟡 | policy enforces 2-distinct + expiry; durable signal flow (Temporal) pending |
| Ownership — verified immediately before sensitive execution | 🟡 | live re-resolving verifier shipped (`ownership/`, `tests/test_ownership.py`): TTL=0 re-proves every call, fail-closed; dnspython/PyGithub resolver wiring pending |
| Audit — allowed/denied/failed/cancelled, immutable + signed | 🟡 | denials audited in hash chain; immudb + attestations pending |
| Secrets — none long-lived in Git/.env/compose | ⬜ | OpenBao/SOPS pending |
| CI — all security jobs block; Actions by SHA; containers by digest | ⬜ | next PR |
| Supply chain — SBOM + provenance + verified signature per release | ⬜ | cosign/witness pending |
| Isolation — sandboxed, rootless, read-only input, egress allowlist | ⬜ | gVisor/Falco pending |
| Identity — OIDC, role checks, TLS, secure sessions | 🟡 | crypto layer (cookies/tokens) done; oauth2-proxy pending |
| Testing — property tests prove no bypass | ✅ | `tests/test_authorization_properties.py` |
| Monitoring — trace IDs; routed alerts | 🟡 | correlation/trace IDs + spans and severity-routed dedup alerts shipped (`observability/`, `tests/test_observability.py`); OTel exporter + Tempo/Alertmanager wiring pending |
| Recovery — backups, restore, key rotation, audit verification exercised | 🟡 | WORM backup/restore drill re-verifies the audit hash chain (`recovery/`, `tests/test_recovery.py`); fail-closed on control-plane outage (`resilience/`); key rotation + restic/Velero wiring pending |
| Validation — independent review + authorised pentest | ⬜ | pre-production |

## Sequencing

1. **This PR:** area 1 keystone + property tests (✅).
2. **Next:** "fix before stitching" CI hardening — make security jobs blocking, pin Actions
   by SHA, pin containers by digest, close internal ports, Grafana password (area 10 + infra).
3. Ownership verifier (area 2), then Temporal two-reviewer durability (area 3).
4. immudb + witness/cosign attestations (areas 5, 9); DefectDojo (6); oauth2-proxy (7).
5. gVisor/Falco isolation (8); OTel/Tempo/Alertmanager (12); uv lockfile + schemathesis (11).
