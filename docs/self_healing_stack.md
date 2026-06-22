# Self-Healing Stack — Recommended Tools per Layer

The [self-healing workflow](workflow.md) (Detect → … → Human approval → Deploy safely →
Monitor → Roll back) is engine-agnostic. This is the recommended tool/framework per layer,
mapped to where it plugs into Guardian. **Two invariants override every choice below:** no
silent production change (all fixes are pull requests), and human approval before deploy.

| Layer | Recommended tools / frameworks | Guardian touchpoint |
| ----- | ------------------------------ | ------------------- |
| **Agent repair brain** | Claude Code, GitHub Copilot Agents, OpenAI Codex-style agents | Patch Proposal + Code Review agents (`agents/`); reasoning model in `guardian.config.yaml` |
| **Workflow engine** | Temporal or Dapr Workflows | ECC orchestration of the agent/connector/simulator steps |
| **Automated code remediation** | OpenRewrite, Semgrep Autofix, CodeQL autofix (where available) | Patch Proposal agent generates the patch branch + regression tests |
| **GitOps deployment** | Argo CD or Flux CD | Deploy step — applies only an approved, merged change |
| **Progressive deployment** | Argo Rollouts, Flagger | `self_healing.deploy.feature_flag_required` — canary/flagged rollout |
| **Policy-as-code** | Open Policy Agent (OPA), Kyverno | Externalises guardrails as admission/policy gates alongside `core/guardrails.py` |
| **Supply-chain proof** | SLSA, Sigstore/Cosign, Syft, Grype | Dependency agent; provenance/signing before deploy |
| **Test orchestration** | GitHub Actions, Playwright, ZAP Automation, Trivy, Gitleaks | Test Runner agent + `.github/workflows/` test gate |
| **Runtime monitoring** | OpenTelemetry, Prometheus, Grafana, Loki, Sentry, Wazuh, Falco | Runtime Monitoring agent; `guardian.config.yaml::monitoring` |
| **Safe rollback** | Argo Rollouts, feature flags, Git revert automation | `self_healing.deploy.auto_rollback_on_safety_failure` |

## Upstream sources

| Tool | Layer | Upstream |
| ---- | ----- | -------- |
| OpenRewrite | Automated code remediation | https://github.com/openrewrite/rewrite |
| Temporal | Workflow engine | https://github.com/temporalio/temporal |
| Dapr | Workflow engine | https://github.com/dapr/dapr |
| Argo CD | GitOps deployment | https://github.com/argoproj/argo-cd |
| Argo Rollouts | Progressive deploy / safe rollback | https://github.com/argoproj/argo-rollouts |
| Flux (flux2) | GitOps deployment | https://github.com/fluxcd/flux2 |
| Flagger | Progressive deploy | https://github.com/fluxcd/flagger |
| Open Policy Agent (OPA) | Policy-as-code | https://github.com/open-policy-agent/opa |
| Kyverno | Policy-as-code | https://github.com/kyverno/kyverno |

Semgrep/CodeQL autofix, the test-orchestration tools, the supply-chain tools (SLSA,
Cosign, Syft, Grype), and the runtime-monitoring tools are listed with their upstream
sources in [tooling_catalogue.md](tooling_catalogue.md).

## How the layers gate each other

```
repair brain ─▶ code remediation ─▶ PR (draft) ─▶ test orchestration ─▶ policy-as-code
     │                                                                        │
     └──────────────── all must pass ────────────────────────────────────────┘
                                   │
                          HUMAN APPROVAL (required)
                                   │
                    GitOps deploy ─▶ progressive rollout (feature flag)
                                   │
                          runtime monitoring
                                   │
                 safety check fails? ──▶ safe rollback (automatic)
```

## Notes on safe defaults

- **Policy-as-code is additive, not a replacement.** OPA/Kyverno enforce guardrails at the
  cluster/admission boundary; `core/guardrails.py` still enforces them in Guardian itself.
  Defence in depth — neither layer is trusted alone.
- **The repair brain proposes; it never deploys.** Agent autofixes land as draft PRs and
  pass the full test gate before a human can approve. See [GUARDRAILS.md](../GUARDRAILS.md).
- **Progressive + rollback are paired.** A flagged/canary rollout is only safe if rollback
  is automatic on a failed post-deploy safety check; Guardian requires both together.
- **Supply-chain proof gates deploy.** Unsigned builds / missing provenance / SBOM drift
  block the merge (see `policies/malware_defence_library.yaml::supply_chain`).
