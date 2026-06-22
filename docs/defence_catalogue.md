# Guardian defensive bolt-on catalogue

Guardian is a **control plane, not a code dump.** Every upstream project is connected through
a tightly controlled adapter, a pinned package, an immutable container digest, or a full
GitHub Action commit SHA — never vendored wholesale. The strength comes not from the number
of tools but from Guardian being **technically unable to bypass its own policy, identity,
containment, and evidence controls.**

> Layered, not duplicated: **one** edge gateway, **one** WAF ruleset, **one** identity
> authority, **one** policy engine, **one** findings ledger. Extra scanners may cross-check
> results; extra *control planes* would weaken accountability, not strengthen it.

## Five outcomes

The architecture enforces a chain: **Prevent → Detect → Contain → Prove → Recover.**

| Outcome | Question it answers | Authoritative owners (see [components.yaml](architecture/components.yaml)) |
| ------- | ------------------- | -------------------------------------------------------------------------- |
| **Prevent** | Can a bad action even start? | edge gateway (Envoy) + WAF (Coraza/CRS), Cilium deny-by-default, OPA policy, Keycloak/OpenFGA identity, OpenBao secrets |
| **Detect** | Did something unexpected happen? | Falco, Suricata, Zeek, CrowdSec, Wazuh SIEM, OpenTelemetry |
| **Contain** | Can it be stopped and isolated? | Tetragon runtime enforcement, gVisor sandbox, deny egress, short-lived identities |
| **Prove** | Can we show exactly what happened? | immudb evidence, cosign/witness attestations, DefectDojo findings, Dependency-Track |
| **Recover** | Can we restore and verify? | restic / pgBackRest / Velero, with mandatory restore tests |

Guardian's existing CodeQL, Semgrep, Gitleaks, Trivy, ZAP, and Playwright integrations are
kept and **surrounded** by these layers, not replaced.

## One authority per function

The authoritative selection — and the alternatives that may cross-check but must **never**
run as a second authority — is the machine-readable single source of truth in
[`architecture/components.yaml`](architecture/components.yaml) (`authoritative_choices`),
enforced by `tests/test_components_manifest.py`:

- An alternative under `not_as_second_authority` can never also be an authoritative component.
- Each `selected` owner must be a real listed component.

Example locked decisions: **Envoy** gateway (HAProxy/Caddy/NGINX internal only) · **Coraza**
WAF (not ModSecurity) · **Cilium** network policy (not Calico/Antrea) · **Gatekeeper** k8s
admission (not Kyverno) · **Keycloak** identity · **OPA** policy · **OpenBao** secrets ·
**Temporal** workflow · **gVisor** isolation · **Wazuh** SIEM · **DefectDojo** findings ·
**Dependency-Track** components · **immudb** evidence · **DFIR-IRIS** IR cases · **OTel +
Prometheus/Loki/Tempo/Grafana** observability.

## The connector contract

Every bolt-on sits behind **one common interface** ([`connectors/contract.py`](../connectors/contract.py)):

```python
class GuardianConnector(Protocol):
    def inventory(self) -> ConnectorInventory: ...
    def validate_configuration(self) -> ValidationResult: ...
    def calculate_plan(self, request: ActionRequest) -> ExecutionPlan: ...
    def required_permissions(self) -> list[Permission]: ...
    def required_approvals(self) -> ApprovalPolicy: ...
    def execute(self, authorization: SignedAuthorization) -> ExecutionResult: ...
    def collect_evidence(self) -> EvidenceBundle: ...
    def cleanup(self) -> CleanupResult: ...
```

The contract makes the dangerous things **structurally impossible** (enforced and tested in
`tests/test_connector_contract.py`):

- **No raw command strings.** `command`/`shell`/`script`/`exec`/`eval` args are rejected, as
  are typed args containing shell metacharacters. Connectors use *enumerated actions*, *typed
  args*, and *fixed executable paths*.
- **Targets are allowlisted** (exact / subdomain / subpath match only).
- **`execute()` requires a `SignedAuthorization`** that is present, unexpired, and bound to
  the request — mirroring the production approval model in `core/policy_gate.py`.
- **Evidence is mandatory; cleanup always runs** (failure/cancel/timeout destroys the env).

## The AI-agent boundary

The model **recommends**; the central policy **decides**. Every AI-generated action becomes a
typed request independently evaluated by the one authority. The boundary is machine-readable
in [`policies/agent_boundary.yaml`](../policies/agent_boundary.yaml) and enforced:

| The model **may** | The model **may not** | Enforcement |
| ----------------- | --------------------- | ----------- |
| recommend actions, assemble plans, classify findings, draft patches, explain evidence | expand scope, change policy, disable logging, merge its own security patch, resolve its own finding, unrestricted secret access, arbitrary command execution | **globally blocked actions** (`core/policy_gate.py` + Rego), tested in `tests/test_agent_boundary.py` |
| | approve production | two-person human rule (`core/policy_gate.py`) |
| | execute outside a connector | the connector contract above |

## The order to stitch this together

Phases map to [`hardening_roadmap.md`](hardening_roadmap.md):

- **Phase 0 — close existing gaps:** protected `main`, one central `authorize()`, blocking CI
  security checks, Actions pinned to SHAs / images to digests, no exposed internal ports. ✅
  (largely landed — see the roadmap for live status).
- **Phase 1 — perimeter & authority:** Envoy, Coraza/CRS, Cilium, Keycloak/oauth2-proxy, OPA/
  Conftest/Gatekeeper, OpenBao/SOPS/External-Secrets, SPIRE/cert-manager/step-ca, ownership verification.
- **Phase 2 — contained execution:** Temporal, gVisor, Tetragon, Falco, Suricata/Zeek,
  CrowdSec, deny-by-default egress, per-job short-lived identities.
- **Phase 3 — software & evidence:** Syft, Grype/OSV, Dependency-Track, DefectDojo, cosign,
  witness/in-toto, immudb, immutable object storage.
- **Phase 4 — operations & response:** Wazuh, Velociraptor, OpenTelemetry, Prometheus/
  Alertmanager/Loki/Tempo, DFIR-IRIS, OpenCTI/MISP, restic/pgBackRest/Velero, IR/DR drills.
- **Phase 5 — specialist capability:** cloud posture, fuzzing, malware analysis, AI-agent
  security evaluation, chaos engineering, formal compliance evidence mapping.

## Final production gate

Guardian refuses production status unless it can **prove** all of the following — these are
the "bulletproof" acceptance tests tracked in
[`governance/SECURITY_INVARIANTS.md`](governance/SECURITY_INVARIANTS.md):

1. Every action passed OPA. 2. Ownership freshly verified. 3. Exact commit/artifact approved.
4. Two distinct reviewers approved sensitive production work. 5. Execution image signed +
digest-pinned. 6. Scanner ran isolated. 7. Network restricted to the authorised target.
8. Secrets short-lived. 9. Allowed/denied actions immutably recorded. 10. Findings reached
DefectDojo. 11. Component risks reached Dependency-Track. 12. Runtime activity reached the
SIEM. 13. Evidence/reports signed. 14. Backups verified. 15. A successful restore test exists.
16. Guardian itself passed independent security testing.

> A backup that has never been restored successfully is not a valid backup; a control without
> an automated check is a gap, not a guarantee.
