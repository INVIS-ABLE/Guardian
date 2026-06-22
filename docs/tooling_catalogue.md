# Guardian Tooling Catalogue

Canonical upstream sources for the tools Guardian orchestrates, with their role and the
Guardian connector/config that drives them. Guardian uses these **defensively**, only
against INVISABLE-owned assets within an approved scope.

## Core scanning & runtime stack

| Tool | Role in Guardian | Guardian wiring | Upstream |
| ---- | ---------------- | --------------- | -------- |
| **CodeQL** | Static code security (SAST) | `connectors/codeql.py`, `.github/workflows/codeql.yml`, `codeql/codeql-config.yml` | https://github.com/github/codeql |
| **Semgrep** | Static code security (SAST) | `connectors/semgrep.py`, `semgrep/semgrep.yml`, `.github/workflows/semgrep.yml` | https://github.com/semgrep/semgrep |
| **Gitleaks** | Secrets detection | `connectors/gitleaks.py`, `gitleaks/.gitleaks.toml`, `.github/workflows/gitleaks.yml` | https://github.com/gitleaks/gitleaks |
| **TruffleHog** | Secrets detection (verified secrets) | Secrets Agent (planned connector) | https://github.com/trufflesecurity/trufflehog |
| **OWASP ZAP** | Dynamic app/API testing (DAST) | `connectors/zap.py`, `zap/staging-baseline.yaml`, `.github/workflows/zap-staging.yml` | https://github.com/zaproxy/zaproxy |
| **Trivy** | Vuln/misconfig/secret scan (fs, container, IaC, repo) | `connectors/trivy.py`, `trivy/trivy.yaml`, `.github/workflows/trivy.yml` | https://github.com/aquasecurity/trivy |
| **Checkov** | IaC misconfiguration scanning | Dependency/IaC Agent (config-gated) | https://github.com/bridgecrewio/checkov |
| **Falco** | Runtime threat detection | Runtime Monitoring Agent → `policies/malware_defence_library.yaml` | https://github.com/falcosecurity/falco |
| **Wazuh** | SIEM / XDR monitoring | Runtime Monitoring Agent | https://github.com/wazuh/wazuh |
| **CrowdSec** | Behavioural detection & blocking | Runtime Monitoring Agent | https://github.com/crowdsecurity/crowdsec |

## Dependency & supply chain

| Tool | Role | Upstream |
| ---- | ---- | -------- |
| OSV-Scanner | Dependency vulnerability scanning | https://github.com/google/osv-scanner |
| Syft | SBOM generation | https://github.com/anchore/syft |
| Grype | SBOM vulnerability scanning | https://github.com/anchore/grype |
| Sigstore Cosign | Artifact signing / provenance | https://github.com/sigstore/cosign |
| Dependabot | Dependency updates | https://github.com/dependabot |
| Renovate | Dependency updates | https://github.com/renovatebot/renovate |

## Infra / cloud / container

| Tool | Role | Upstream |
| ---- | ---- | -------- |
| Terrascan | IaC scanning | https://github.com/tenable/terrascan |
| KICS | IaC scanning | https://github.com/Checkmarx/kics |
| kube-bench | Kubernetes CIS benchmark | https://github.com/aquasecurity/kube-bench |
| kube-hunter | Kubernetes pen-test (lab only) | https://github.com/aquasecurity/kube-hunter |

## Dynamic / API / browser testing

| Tool | Role | Upstream |
| ---- | ---- | -------- |
| Schemathesis | OpenAPI fuzz testing | https://github.com/schemathesis/schemathesis |
| Dredd | API contract testing | https://github.com/apiaryio/dredd |
| Newman | Postman CLI runner | https://github.com/postmanlabs/newman |
| Playwright | Browser / user-journey testing | https://github.com/microsoft/playwright |

## Monitoring & incident response

| Tool | Role | Upstream |
| ---- | ---- | -------- |
| Prometheus | Metrics | https://github.com/prometheus/prometheus |
| Grafana | Dashboards | https://github.com/grafana/grafana |
| Loki | Logs | https://github.com/grafana/loki |
| OpenTelemetry | Tracing / telemetry | https://github.com/open-telemetry/opentelemetry-collector |
| Sentry | Application errors | https://github.com/getsentry/sentry |

## Credential-audit (authorised defensive use only)

See [credential_audit_tools.md](credential_audit_tools.md) for the strict guardrails.

| Tool | Role | Upstream |
| ---- | ---- | -------- |
| hashcat | Password-policy strength audit (synthetic corpus) | https://github.com/hashcat/hashcat |
| John the Ripper | Password-policy strength audit (synthetic corpus) | https://github.com/openwall/john |
| THC Hydra | Online login-defence resilience (owned staging, test accounts) | https://github.com/vanhauser-thc/thc-hydra |

---

> Inclusion here authorises a tool only within Guardian's guardrails: owned assets only,
> test accounts only, no third-party scanning, dry-run by default, and human approval for
> high-impact actions. See [../GUARDRAILS.md](../GUARDRAILS.md).
