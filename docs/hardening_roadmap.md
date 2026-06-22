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
| Remove every `\|\| true` / security `continue-on-error`; make security jobs blocking | ⬜ | Now unblocked (code scanning enabled, findings clean). Next PR. |
| Pin every Action to a full commit SHA | ⬜ | Next PR (resolve + pin all `uses:` refs) |
| Pin every container by digest (sha256) | 🟡 | version tags pinned now; digest-pin after registry/Harbor mirror (area 8) |
| Protected `main`; ruleset (2 reviews, CODEOWNERS, signed commits, no force-push) | ⬜ | repo settings (admin action) |
| Production GitHub Environment with required reviewers, no self-review/admin bypass | ⬜ | repo settings |
| Register Guardian as a least-privilege GitHub App | ⬜ | area 2 |

## The 12 integration areas

| # | Area | Upstream | Status | Where |
| - | ---- | -------- | ------ | ----- |
| 1 | Policy & authorisation | OPA, conftest | ✅ keystone | `core/policy_gate.py`, `policies/opa/*.rego`, `docs/authorization.md` |
| 2 | Ownership verification | PyGithub, dnspython | ⬜ | inject a real verifier into `Guardrails.ownership_verifier`; expiring evidence |
| 3 | Durable workflows & approvals | Temporal + sdk-python | ⬜ | two-reviewer signal flow, re-ask OPA before execute |
| 4 | Secrets & keys | OpenBao, SOPS | ⬜ | short-lived per-workflow creds; encrypt in-Git config |
| 5 | Immutable audit & evidence | immudb, in-toto/witness, cosign | 🟡 | denials already audited (hash chain); immudb + signed attestations next |
| 6 | Findings management | DefectDojo | ⬜ | unified findings ledger; Guardian orchestrates, doesn't re-home findings |
| 7 | Dashboard identity | oauth2-proxy (OIDC) | ⬜ | proxy in front of FastAPI; internal services off public ports |
| 8 | Sandbox & runtime detection | gVisor (runsc), Falco | ⬜ | scanners rootless, read-only input, egress allowlist |
| 9 | Build provenance | actions/attest, cosign, witness | ⬜ | SBOM + provenance + signature; verify by digest before deploy |
| 10 | Mandatory CI gates | dependency-review, scorecard, zizmor, pip-audit, bandit | ⬜ | required, blocking checks |
| 11 | High-assurance testing | hypothesis, schemathesis, uv, renovate | 🟡 | hypothesis property tests done; uv lockfile + schemathesis next |
| 12 | Observability & alerting | OTel (py + collector), Tempo, Alertmanager | ⬜ | trace IDs across policy decisions/workflows; routed alerts |

## 10/10 acceptance gate

| Capability | Status | Evidence |
| ---------- | ------ | -------- |
| Authorisation — one central path, no `allow_production` | ✅ | `core/policy_gate.py`; `tests/test_guardrails.py::test_authorize_has_no_allow_production_parameter` |
| Approvals — two distinct people, action/commit/workflow-bound, expire | 🟡 | policy enforces 2-distinct + expiry; durable signal flow (Temporal) pending |
| Ownership — verified immediately before sensitive execution | ⬜ | verifier hook present; PyGithub/dnspython impl pending |
| Audit — allowed/denied/failed/cancelled, immutable + signed | 🟡 | denials audited in hash chain; immudb + attestations pending |
| Secrets — none long-lived in Git/.env/compose | ⬜ | OpenBao/SOPS pending |
| CI — all security jobs block; Actions by SHA; containers by digest | ⬜ | next PR |
| Supply chain — SBOM + provenance + verified signature per release | ⬜ | cosign/witness pending |
| Isolation — sandboxed, rootless, read-only input, egress allowlist | ⬜ | gVisor/Falco pending |
| Identity — OIDC, role checks, TLS, secure sessions | 🟡 | crypto layer (cookies/tokens) done; oauth2-proxy pending |
| Testing — property tests prove no bypass | ✅ | `tests/test_authorization_properties.py` |
| Monitoring — trace IDs; routed alerts | ⬜ | OTel/Alertmanager pending |
| Recovery — backups, restore, key rotation, audit verification exercised | ⬜ | pending |
| Validation — independent review + authorised pentest | ⬜ | pre-production |

## Sequencing

1. **This PR:** area 1 keystone + property tests (✅).
2. **Next:** "fix before stitching" CI hardening — make security jobs blocking, pin Actions
   by SHA, pin containers by digest, close internal ports, Grafana password (area 10 + infra).
3. Ownership verifier (area 2), then Temporal two-reviewer durability (area 3).
4. immudb + witness/cosign attestations (areas 5, 9); DefectDojo (6); oauth2-proxy (7).
5. gVisor/Falco isolation (8); OTel/Tempo/Alertmanager (12); uv lockfile + schemathesis (11).
