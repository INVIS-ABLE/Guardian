# Guardian Target Production Stack

The full defensive architecture Guardian is built toward, by trust zone. The authoritative,
machine-readable list is [`components.yaml`](components.yaml) (validated by
`tests/test_components_manifest.py`). **One authoritative owner per function** — we do not
add overlapping platforms to inflate the count.

## Principles

- **One reference monitor.** Every action passes the central OPA-backed `authorize()`
  (already in place: `core/policy_gate.py`). Nothing executes around it.
- **Private by default, deny egress by default.** Only the edge gateway is reachable; the
  management plane is separate from the systems Guardian protects (blueprint area 5).
- **Pinned + signed.** Images by sha256 digest, Actions by full commit SHA; artifacts signed
  (cosign) and attested (witness), verified before run.
- **Evidence is immutable.** immudb + signed attestations are the system of record; the local
  hash chain is a cache.

## By trust zone

```
                 Internet
                     │
        ┌────────────▼─────────────┐   edge (DMZ)
        │ Envoy Gateway → Coraza/CRS│   oauth2-proxy (OIDC) in front of the dashboard
        └────────────┬─────────────┘
                     │ authenticated, WAF-filtered
        ┌────────────▼───────────────────────────────┐  management plane (isolated)
        │  OPA (authority) · Temporal (durable wf)    │
        │  Gatekeeper (k8s admission)                 │
        └───────┬───────────────────────┬────────────┘
        identity│                        │execution (sandboxed)
   Keycloak/OIDC, OpenFGA, SPIRE,        gVisor + Cilium/Tetragon, default-deny egress
   cert-manager/step-ca, OpenBao,        scanners run rootless, read-only input,
   SOPS, external-secrets                ephemeral workspace, destroyed after each job
        │                                        │
        ├── evidence ──► immudb · cosign · witness · restic (WORM backups)
        ├── findings ──► DefectDojo · Dependency-Track
        ├── detection ─► Falco · Suricata · Zeek · CrowdSec · Wazuh · Velociraptor · IRIS
        └── telemetry ─► OpenTelemetry Collector → Prometheus/Loki/Tempo → Alertmanager
```

## Component → roadmap → phase

Each component maps to a hardening-roadmap area and an adoption phase (see
[`../hardening_roadmap.md`](../hardening_roadmap.md) and the construction order). Summary:

| Zone | Components | Phase |
| ---- | ---------- | ----- |
| Edge | Envoy Gateway, Coraza, CRS, oauth2-proxy | 2–3 |
| Authority | **OPA (present)**, Gatekeeper, Temporal | 1 |
| Identity/PKI/secrets | Keycloak, OpenFGA, SPIRE, cert-manager, step-ca, OpenBao, SOPS, external-secrets | 2 |
| Execution isolation | gVisor, Cilium, Tetragon | 3 |
| Evidence | immudb, cosign, witness, restic | 2 / 4 / 6 |
| Findings | DefectDojo, Dependency-Track | 4 |
| Detection/IR/forensics | Falco, Suricata, Zeek, CrowdSec, Wazuh, Velociraptor, IRIS | 6 |
| Observability | OpenTelemetry Collector | 6 |

## What exists today vs planned

- **Present:** the authority layer — OPA policy + embedded mirror (`core/policy_gate.py`,
  `policies/opa/guardian.rego`), the tamper-evident audit cache (`core/audit.py`), the
  crypto layer (`security/crypto/`), and the local monitoring stack (Prometheus/Grafana/Loki,
  now private-by-default).
- **Planned:** everything else, sequenced by phase. `components.yaml` tracks `status`
  (`present`/`planned`) so the manifest is an honest, checkable inventory rather than a wish
  list. Each component is added with its pinning, network and egress posture from day one.

## Adoption order (recap)

1. **Phase 1 — Authority:** OPA (done) → Temporal state machine → Gatekeeper.
2. **Phase 2 — Identity & evidence:** Keycloak/oauth2-proxy/OpenFGA/SPIRE, cert-manager/step-ca,
   OpenBao/SOPS/external-secrets, immudb/witness/cosign.
3. **Phase 3 — Isolation:** gVisor, Cilium/Tetragon, Envoy+Coraza+CRS, default-deny egress.
4. **Phase 4 — Supply-chain trust:** DefectDojo, Dependency-Track, cosign/witness verification.
5. **Phase 6 — Detection & resilience:** Falco/Suricata/Zeek/CrowdSec/Wazuh/Velociraptor/IRIS,
   OTel, restic recovery drills.
