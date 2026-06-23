"""Deterministically generate research/repositories/*.yaml from the candidate list.

Live numeric metadata (default branch, evaluated commit, latest release, archived
status, exact licence) requires GitHub API access which is not available in this
environment. Those fields are emitted as `pending_live_discovery` with a reproducible
`gh` command, per the prompt's rule: do not fabricate metadata.

The *decision* fields ARE filled: integration posture is an architectural judgement
the platform lead is empowered to make from the repo's category and purpose.
"""
from __future__ import annotations


# (category_key, default_posture, default_isolation, candidates[(url, decision?, rationale?)])
# decision/rationale override the category default when set.
CATEGORIES = {
    "A_agentic_security": dict(
        title="Agentic-security / autonomous offensive systems",
        default_decision="reference",
        default_option="research_reference",
        isolation="ephemeral_sandbox",
        note="Autonomous offensive capability is high-risk. Guardian is the control "
             "plane; these are studied for architecture/validation ideas, never enabled "
             "as unrestricted attack workflows (charter rules 5,6,7).",
        items=[
            ("https://github.com/INVIS-ABLE/Guardian", "self", "This repository."),
            ("https://github.com/usestrix/strix", None, None),
            ("https://github.com/ruvnet/agentic-security", None, None),
            ("https://github.com/agenticsorg/agentic-security", None, None),
            ("https://github.com/Be-Secure/BeSSAAIAgent", None, None),
            ("https://github.com/codexstar69/bug-hunter", "reject",
             "Autonomous bug-hunting; uncontrolled offensive path, low maturity signal."),
            ("https://github.com/aica-iwg/aica-agent", None, None),
            ("https://github.com/FunnyWolf/agentic-soc-platform", None, None),
            ("https://github.com/beenuar/AiSOC", None, None),
            ("https://github.com/vxcontrol/pentagi", "reject",
             "Autonomous pentest agent; offensive, cannot be enabled within charter."),
            ("https://github.com/KeygraphHQ/shannon", None, None),
            ("https://github.com/pensarai/apex", None, None),
            ("https://github.com/GH05TCREW/pentestagent", "reject",
             "Autonomous pentest agent; offensive."),
            ("https://github.com/GreyDGL/PentestGPT", "reference",
             "Influential reference for LLM pentest reasoning; study only, never wire in."),
            ("https://github.com/bugbasesecurity/pentest-copilot", None, None),
            ("https://github.com/Armur-Ai/Pentest-Swarm-AI", "reject",
             "Multi-agent offensive swarm; uncontrolled offensive path."),
            ("https://github.com/0x4m4/hexstrike-ai", "reject",
             "Autonomous offensive tooling; reject."),
            ("https://github.com/aliasrobotics/CAI", None, None),
            ("https://github.com/visa/visa-vulnerability-agentic-harness", "reference",
             "Vendor harness; useful architecture reference for agentic vuln validation."),
            ("https://github.com/anthropics/defending-code-reference-harness", "reference",
             "Defensive reference harness; aligns with Guardian's adversarial-validation idea."),
            ("https://github.com/anthropics/claude-code-security-review", "adapt",
             "Defensive AI code review; candidate eval/benchmark + adapter for PR review."),
            ("https://github.com/OWASP/appsec-agent", "reference", None),
            ("https://github.com/Agent-Field/sec-af", None, None),
            ("https://github.com/samugit83/redamon", None, None),
            ("https://github.com/xalgord/xalgorix", None, None),
            ("https://github.com/PentesterFlow/agent", None, None),
            ("https://github.com/ahmetdrak/drakben", None, None),
            ("https://github.com/AgentSecOps/SecOpsAgentKit", None, None),
            ("https://github.com/junistaurelien/Agentic-RemediateBot", None, None),
            ("https://github.com/0xSteph/pentest-ai-agents", "reject",
             "Offensive agent collection."),
            ("https://github.com/hardenedlinux/agentic-ai-pentest", "reference", None),
            ("https://github.com/OWASP/secure-agent-playbook", "reference",
             "Playbook/standard; informs Guardian's agent-boundary docs."),
            ("https://github.com/fortify/skills", "reference", None),
        ],
    ),
    "B_agent_governance_mcp": dict(
        title="Agent governance / control planes / MCP security / agent firewalls",
        default_decision="benchmark",
        default_option="benchmark_or_compare",
        isolation="n/a",
        note="Compared directly against Guardian's router, policy gate, capability "
             "boundary and MCP exposure. Guardian must not create a second, conflicting "
             "control authority — these inform, they do not replace the policy gate.",
        items=[
            ("https://github.com/microsoft/agent-governance-toolkit", "reference", None),
            ("https://github.com/cordum-io/cordum", None, None),
            ("https://github.com/WhitzardAgent/AgentGuard", None, None),
            ("https://github.com/luckyPipewrench/pipelock", None, None),
            ("https://github.com/elliot35/deterministic-agent-control-protocol", "reference",
             "Deterministic control protocol; compare with policy_gate/connector contract."),
            ("https://github.com/veritasfuji-japan/veritas_os", None, None),
            ("https://github.com/GoPlusSecurity/agentguard", None, None),
            ("https://github.com/getagentseal/agentseal", None, None),
            ("https://github.com/garagon/aguara", None, None),
            ("https://github.com/elliotllliu/agent-shield", None, None),
            ("https://github.com/sattyamjjain/agent-audit-kit", None, None),
            ("https://github.com/DaoyuanLi2816/mcp-fence", None, None),
            ("https://github.com/ressl/mcpwn", None, None),
            ("https://github.com/ressl/mcp-firewall", None, None),
            ("https://github.com/invariantlabs-ai/mcp-scan", "adapt",
             "MCP server scanning / tool-poisoning detection; candidate adapter for the "
             "MCP-broker hardening path."),
            ("https://github.com/sinewaveai/agent-security-scanner-mcp", None, None),
            ("https://github.com/GT-Projects256/mcpguard", None, None),
            ("https://github.com/deconvolute-labs/deconvolute", None, None),
            ("https://github.com/mcpware/IntentProbe", None, None),
            ("https://github.com/Viprasol-Tech/tripwire", None, None),
            ("https://github.com/loplop-h/mcpguard", None, None),
            ("https://github.com/jakeefr/mcp-sentinel", None, None),
            ("https://github.com/go-authgate/agent-scanner", None, None),
            ("https://github.com/panguard-ai/panguard-ai", None, None),
            ("https://github.com/jnMetaCode/shellward", None, None),
        ],
    ),
    "C_ai_model_eval": dict(
        title="AI / LLM / model / agent security evaluation",
        default_decision="adapt",
        default_option="eval_harness_adapter",
        isolation="ephemeral_worker",
        note="Aligns with eval/ and the untrusted-output gateway. Strong candidates to "
             "INTEGRATE as red-team / model-risk evaluators behind adapters.",
        items=[
            ("https://github.com/NVIDIA/garak", "adapt",
             "LLM vulnerability scanner; integrate as a model red-team eval adapter."),
            ("https://github.com/microsoft/PyRIT", "adapt",
             "Risk-identification toolkit; eval-harness adapter for adversarial probing."),
            ("https://github.com/meta-llama/PurpleLlama", "adapt", None),
            ("https://github.com/promptfoo/promptfoo", "retain",
             "Already in eval/ (promptfooconfig.yaml). Keep as the prompt-eval authority."),
            ("https://github.com/Giskard-AI/giskard", "reference", None),
            ("https://github.com/confident-ai/deepeval", "retain",
             "Already an eval dependency-group tool. Keep."),
            ("https://github.com/explodinggradients/ragas", "retain",
             "Already an eval dependency-group tool. Keep (dev-only)."),
            ("https://github.com/protectai/llm-guard", "adapt",
             "Input/output guardrail; candidate for the model I/O firewall."),
            ("https://github.com/protectai/modelscan", "adapt",
             "Model serialization-attack scanner; supply-chain admission for models."),
            ("https://github.com/protectai/nbdefense", "reference", None),
            ("https://github.com/protectai/vulnhuntr", "reference", None),
            ("https://github.com/protectai/rebuff", "reference", None),
            ("https://github.com/whylabs/langkit", "reference", None),
            ("https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks",
             "benchmark", "Cybersecurity benchmark; use as a test fixture."),
            ("https://github.com/SEC-bench/SEC-bench", "benchmark", None),
            ("https://github.com/regaan/basilisk", None, None),
            ("https://github.com/ProjectRecon/awesome-ai-agents-security", "reference",
             "Curated discovery list."),
            ("https://github.com/LLMSecurity/awesome-agent-skills-security", "reference",
             "Curated discovery list."),
        ],
    ),
    "D_sast_sca_dast": dict(
        title="SAST / semantic code analysis / secrets / SCA / SBOM / DAST",
        default_decision="adapt",
        default_option="connector_adapter",
        isolation="ephemeral_worker_egress_controlled",
        note="The core scanner-connector layer. Scope-constrained, rate-limited, never "
             "pointed at arbitrary internet assets. Several already wrapped by Guardian.",
        items=[
            ("https://github.com/semgrep/semgrep", "retain", "Already a Guardian connector."),
            ("https://github.com/semgrep/semgrep-rules", "adopt", "Ruleset (review licence per-rule)."),
            ("https://github.com/github/codeql", "retain", "Already integrated (CodeQL workflow)."),
            ("https://github.com/github/codeql-action", "retain", None),
            ("https://github.com/gitleaks/gitleaks", "retain", "Already a Guardian connector."),
            ("https://github.com/trufflesecurity/trufflehog", "adapt", None),
            ("https://github.com/Yelp/detect-secrets", "reference", None),
            ("https://github.com/aquasecurity/trivy", "retain", "Already a Guardian connector."),
            ("https://github.com/anchore/grype", "adapt", None),
            ("https://github.com/anchore/syft", "adapt", "SBOM generation; supply-chain."),
            ("https://github.com/google/osv-scanner", "retain", "Enabled in config (osv)."),
            ("https://github.com/dependency-check/DependencyCheck", "reference", None),
            ("https://github.com/owasp-dep-scan/dep-scan", "reference", None),
            ("https://github.com/zaproxy/zaproxy", "retain", "Already a Guardian connector (ZAP)."),
            ("https://github.com/projectdiscovery/nuclei", "adapt",
             "Template scanner; scope-constrained adapter only."),
            ("https://github.com/projectdiscovery/nuclei-templates", "adopt", None),
            ("https://github.com/projectdiscovery/httpx", "adapt", None),
            ("https://github.com/projectdiscovery/subfinder", "defer",
             "Subdomain discovery; only against owned/authorised assets."),
            ("https://github.com/bridgecrewio/checkov", "adapt", "IaC scan (config has checkov)."),
            ("https://github.com/tenable/terrascan", "reference", None),
            ("https://github.com/kubescape/kubescape", "adapt", None),
            ("https://github.com/aquasecurity/kube-bench", "adapt", None),
            ("https://github.com/aquasecurity/kube-hunter", "defer",
             "Active k8s probing; authorised targets only."),
            ("https://github.com/bearer/bearer", "reference", None),
            ("https://github.com/SonarSource/sonarqube", "reference",
             "Commercial-tier features; licence review required before any use."),
            ("https://github.com/greenbone/openvas-scanner", "isolate",
             "Network vuln scanner; isolated service, scope-constrained, never arbitrary."),
            ("https://github.com/greenbone/gvmd", "isolate", None),
            ("https://github.com/prowler-cloud/prowler", "adapt", "Cloud posture; CSPM adapter."),
            ("https://github.com/MobSF/Mobile-Security-Framework-MobSF", "adapt",
             "Mobile security (MASVS/MASTG align)."),
        ],
    ),
    "E_runtime_detection": dict(
        title="Runtime security / EDR / cloud workload / detection engineering",
        default_decision="adapt",
        default_option="observe_only_adapter",
        isolation="isolated_service",
        note="Begin in observe-only / recommend-only mode. Automated containment needs "
             "separate approval, blast-radius limits, rollback, tested runbooks.",
        items=[
            ("https://github.com/falcosecurity/falco", "adapt", "Runtime detection (config has falco, off)."),
            ("https://github.com/falcosecurity/falcosidekick", "adapt", None),
            ("https://github.com/aquasecurity/tracee", "reference", None),
            ("https://github.com/cilium/tetragon", "adapt", None),
            ("https://github.com/wazuh/wazuh", "adapt", "SIEM/XDR; observe-only adapter (config has wazuh)."),
            ("https://github.com/wazuh/wazuh-docker", "reference", None),
            ("https://github.com/utmstack/UTMStack", "reference", None),
            ("https://github.com/fleetdm/fleet", "adapt", None),
            ("https://github.com/osquery/osquery", "adapt", "Endpoint telemetry (endpoint fabric)."),
            ("https://github.com/Velocidex/velociraptor", "adapt", "DFIR; IR adapter."),
            ("https://github.com/crowdsecurity/crowdsec", "reference", None),
            ("https://github.com/Security-Onion-Solutions/securityonion", "reference", None),
            ("https://github.com/SigmaHQ/sigma", "adopt", "Detection-rule format; adopt as detection content."),
            ("https://github.com/SigmaHQ/sigma-cli", "adapt", None),
            ("https://github.com/VirusTotal/yara", "adopt", "Signature format; malware-defence library."),
            ("https://github.com/mitre-attack/attack-stix-data", "adopt", "ATT&CK data (already mapped)."),
            ("https://github.com/mitre-attack/attack-navigator", "reference", None),
        ],
    ),
    "F_vulnmgmt_aspm_siem_soar_ti": dict(
        title="Vuln mgmt / ASPM / ASM / findings correlation / SIEM / SOAR / TI",
        default_decision="federate",
        default_option="federation_adapter",
        isolation="isolated_service",
        note="Guardian owns the CANONICAL finding (CanonicalFinding contract); these "
             "federate as sources/sinks. Avoid conflicting sources of truth.",
        items=[
            ("https://github.com/DefectDojo/django-DefectDojo", "federate",
             "Mature ASPM; candidate findings sink/federation. Guardian stays canonical."),
            ("https://github.com/infobyte/faraday", "reference", None),
            ("https://github.com/SecurityUniversalOrg/SecuSphere", "reference", None),
            ("https://github.com/Patrowl/PatrowlManager", "reference", None),
            ("https://github.com/Patrowl/PatrowlEngines", "reference", None),
            ("https://github.com/oasm-platform/open-asm", "reference", None),
            ("https://github.com/yyhuni/xingrin", "reference", None),
            ("https://github.com/1N3/AttackSurfaceManagement", "reject",
             "Offensive ASM tooling; uncontrolled internet scanning."),
            ("https://github.com/Shuffle/Shuffle", "reference", "SOAR; compare with orchestration/."),
            ("https://github.com/TheHive-Project/TheHive", "federate", "Case management; IR federation."),
            ("https://github.com/TheHive-Project/Cortex", "adapt", None),
            ("https://github.com/MISP/MISP", "adapt", "Threat-intel platform; TI adapter (STIX/TAXII)."),
            ("https://github.com/OpenCTI-Platform/opencti", "adapt", "CTI; STIX-native adapter."),
            ("https://github.com/dfir-iris/iris-web", "reference", None),
            ("https://github.com/Yeti-Platform/yeti", "reference", None),
            ("https://github.com/intelowlproject/IntelOwl", "adapt", None),
        ],
    ),
    "G_policy_identity_secrets_privacy": dict(
        title="Policy engines / authz / identity / workload identity / secrets / privacy",
        default_decision="reference",
        default_option="compare_no_second_authority",
        isolation="n/a",
        note="OPA is already Guardian's policy authority. Do NOT create multiple "
             "contradictory decision authorities; identity/secrets/privacy components "
             "are adopted where they fill a real gap.",
        items=[
            ("https://github.com/open-policy-agent/opa", "retain",
             "Guardian's external policy authority (policies/opa). Keep."),
            ("https://github.com/open-policy-agent/gatekeeper", "reference", None),
            ("https://github.com/kyverno/kyverno", "reference", None),
            ("https://github.com/cedar-policy/cedar", "reference",
             "Alternative policy lang; do not introduce a second authority."),
            ("https://github.com/cerbos/cerbos", "reference", None),
            ("https://github.com/openfga/openfga", "reference",
             "Relationship authz; candidate for tenant RBAC graph (future, single authority)."),
            ("https://github.com/permitio/opal", "reference", None),
            ("https://github.com/spiffe/spiffe", "adopt", "Workload identity (roots_of_trust workload)."),
            ("https://github.com/spiffe/spire", "adopt", "SPIFFE runtime; aligns with WorkloadTrust."),
            ("https://github.com/openbao/openbao", "adopt", "Secrets/KMS (key management plan)."),
            ("https://github.com/keycloak/keycloak", "reference", "IdP option (OIDC already supported)."),
            ("https://github.com/zitadel/zitadel", "reference", None),
            ("https://github.com/oauth2-proxy/oauth2-proxy", "retain",
             "Already referenced by identity/oidc.py header model."),
            ("https://github.com/microsoft/presidio", "adopt",
             "PII detection/redaction; privacy fabric + telemetry redaction."),
            ("https://github.com/openmined/PySyft", "defer", None),
            ("https://github.com/smallstep/certificates", "reference", None),
        ],
    ),
    "H_supplychain_signing_provenance": dict(
        title="Supply-chain security / signatures / provenance / SBOM / secure builds",
        default_decision="adopt",
        default_option="supply_chain_integration",
        isolation="n/a",
        note="Guardian must verify what it runs, know its origin and contents, and "
             "preserve the attestation chain. Aligns with attestation/ + supplychain/.",
        items=[
            ("https://github.com/sigstore/cosign", "adopt", "Artifact/image signing (admission)."),
            ("https://github.com/sigstore/rekor", "adopt", "Transparency log."),
            ("https://github.com/sigstore/fulcio", "reference", None),
            ("https://github.com/in-toto/in-toto", "adopt", "Pipeline attestation (provenance)."),
            ("https://github.com/theupdateframework/python-tuf", "reference", None),
            ("https://github.com/slsa-framework/slsa", "adopt", "Provenance framework (already referenced)."),
            ("https://github.com/slsa-framework/slsa-github-generator", "adopt", None),
            ("https://github.com/ossf/scorecard", "adapt", "Repo health scoring for candidate review."),
            ("https://github.com/oss-review-toolkit/ort", "adapt", "Licence/dependency compliance automation."),
            ("https://github.com/aboutcode-org/scancode-toolkit", "adapt", "Licence scanning."),
            ("https://github.com/CycloneDX/cyclonedx-cli", "adopt", "SBOM format tooling."),
            ("https://github.com/spdx/tools-python", "adopt", "SPDX SBOM tooling."),
            ("https://github.com/chainguard-dev/melange", "reference", None),
            ("https://github.com/chainguard-dev/apko", "reference", None),
        ],
    ),
    "I_sandbox_isolation": dict(
        title="Sandboxing / isolation / container runtimes / safe execution",
        default_decision="adopt",
        default_option="isolation_tier",
        isolation="self",
        note="Choose isolation tier by tool risk. High-risk active testing must not "
             "share the Guardian control-plane trust zone (isolation/).",
        items=[
            ("https://github.com/firecracker-microvm/firecracker", "adopt",
             "MicroVM; highest-risk worker isolation tier."),
            ("https://github.com/google/gvisor", "adopt", "Syscall-sandbox tier."),
            ("https://github.com/kata-containers/kata-containers", "reference", None),
            ("https://github.com/containers/bubblewrap", "adopt", "Lightweight sandbox tier."),
            ("https://github.com/seccomp/libseccomp", "adopt", "Syscall filtering (security_context)."),
            ("https://github.com/opencontainers/runc", "reference", None),
            ("https://github.com/containerd/containerd", "reference", None),
        ],
    ),
    "J_orchestration_gitops": dict(
        title="Workflow orchestration / GitOps / deployment / release control",
        default_decision="reference",
        default_option="compare_release_control",
        isolation="n/a",
        note="Temporal is already Guardian's durable workflow engine. Check each "
             "project's CURRENT licence — public source != OSI/commercially compatible.",
        items=[
            ("https://github.com/argoproj/argo-cd", "adopt", "GitOps deploy (controlled response)."),
            ("https://github.com/argoproj/argo-workflows", "reference", None),
            ("https://github.com/fluxcd/flux2", "reference", None),
            ("https://github.com/temporalio/temporal", "retain",
             "Already Guardian's durable workflow backend."),
            ("https://github.com/StackStorm/st2", "reference", None),
            ("https://github.com/apache/airflow", "reference", None),
            ("https://github.com/PrefectHQ/prefect", "reference", None),
            ("https://github.com/windmill-labs/windmill", "defer", "Licence review required."),
            ("https://github.com/n8n-io/n8n", "defer",
             "Sustainable-use licence — NOT OSI; commercial-use review required before any use."),
        ],
    ),
    "K_telemetry_observability_audit": dict(
        title="Telemetry / observability / audit / operational evidence",
        default_decision="adopt",
        default_option="observability_integration",
        isolation="n/a",
        note="Telemetry must be privacy-filtered, tenant-scoped, tamper-evident where "
             "required, and incapable of leaking secrets or protected data.",
        items=[
            ("https://github.com/open-telemetry/opentelemetry-collector", "retain",
             "OTel already enabled in config."),
            ("https://github.com/open-telemetry/opentelemetry-collector-contrib", "adopt", None),
            ("https://github.com/open-telemetry/opentelemetry-python", "retain", None),
            ("https://github.com/prometheus/prometheus", "retain", "Already in config/monitoring."),
            ("https://github.com/grafana/grafana", "retain", "Already in config."),
            ("https://github.com/grafana/loki", "retain", "Already in config (redaction required)."),
            ("https://github.com/grafana/tempo", "adopt", None),
            ("https://github.com/jaegertracing/jaeger", "reference", None),
            ("https://github.com/getsentry/sentry", "reference", "Config has sentry (off)."),
            ("https://github.com/openobserve/openobserve", "reference", None),
            ("https://github.com/langfuse/langfuse", "adapt",
             "LLM observability; tenant-scoped + redacted, candidate for Brain tracing."),
        ],
    ),
    "L_standards_formats_sim": dict(
        title="Standards / data formats / threat models / cyber simulation",
        default_decision="adopt",
        default_option="open_format",
        isolation="n/a",
        note="Adopt open formats over bespoke coupling. Adversary-emulation systems are "
             "high-risk: controlled simulation / isolated cyber-range only.",
        items=[
            ("https://github.com/oasis-open/cti-stix2-json-schemas", "adopt", "STIX2 schemas."),
            ("https://github.com/oasis-open/cti-pattern-validator", "adopt", None),
            ("https://github.com/mitre-attack/attack-stix-data", "adopt", "ATT&CK (already mapped)."),
            ("https://github.com/mitre-attack/attack-navigator", "reference", None),
            ("https://github.com/mitre/caldera", "isolate",
             "Adversary emulation; HIGH RISK — isolated authorised cyber-range only."),
            ("https://github.com/CycloneDX/specification", "adopt", "SBOM format."),
            ("https://github.com/oasis-tcs/sarif-spec", "adopt", "SARIF — canonical findings interchange."),
            ("https://github.com/OWASP/ASVS", "adopt", "Already mapped."),
            ("https://github.com/OWASP/wstg", "adopt", "Already mapped."),
            ("https://github.com/OWASP/samm", "adopt", "Already mapped."),
            ("https://github.com/OWASP/masvs", "adopt", "Already mapped."),
            ("https://github.com/OWASP/mastg", "adopt", "Already mapped."),
        ],
    ),
    "M_curated_discovery": dict(
        title="Curated discovery lists / live GitHub topic surfaces",
        default_decision="reference",
        default_option="discovery_only",
        isolation="n/a",
        note="Use only to DISCOVER candidates; independently verify every linked project.",
        items=[
            ("https://github.com/raphabot/awesome-cybersecurity-agentic-ai", None, None),
            ("https://github.com/ottosulin/awesome-ai-security", None, None),
            ("https://github.com/AmanPriyanshu/Awesome-AI-For-Security", None, None),
            ("https://github.com/ProjectRecon/awesome-ai-agents-security", None, None),
            ("https://github.com/LLMSecurity/awesome-agent-skills-security", None, None),
            ("https://github.com/Escape-Technologies/awesome-attack-surface-management", None, None),
            ("https://github.com/rezmoss/awesome-security-pipeline", None, None),
            ("https://github.com/bureado/awesome-software-supply-chain-security", None, None),
            ("https://github.com/cybersader/awesome-siem", None, None),
            ("https://github.com/punkpeye/awesome-mcp-servers", None, None),
        ],
    ),
}


def owner_repo(url: str) -> tuple[str, str]:
    parts = url.replace("https://github.com/", "").split("/")
    owner = parts[0] if parts else ""
    repo = parts[1] if len(parts) > 1 else ""
    return owner, repo


DISCOVERY_CMD = "gh repo view {owner}/{repo} --json name,owner,defaultBranchRef,isArchived,licenseInfo,latestRelease,pushedAt,stargazerCount"

HEADER = """# research/repositories/{fname}
# GENERATED by scratchpad/gen_catalogue.py — do not edit by hand; regenerate.
#
# LIMITATION: GitHub API / network access was not available when this was produced.
# Quantitative metadata (default_branch, evaluated_commit, latest_release, archived,
# exact licence, dependency/model licences, maintenance signals) is therefore marked
# `pending_live_discovery: true` with a reproducible discovery command. Per the
# platform charter, metadata is never fabricated. The DECISION fields are architectural
# judgements made from each project's category and purpose, and are actionable now.
"""


def gen_catalogue() -> str:
    out = [HEADER.format(fname="catalogue.yaml"), "schema_version: 1", "candidates:"]
    for key, cat in CATEGORIES.items():
        out.append(f"  # --- {cat['title']} ---")
        for url, decision, rationale in cat["items"]:
            owner, repo = owner_repo(url)
            dec = decision or cat["default_decision"]
            out.append(f"  - name: {repo or owner}")
            out.append(f"    url: {url}")
            out.append(f"    category: {key}")
            out.append(f"    owner: {owner}")
            out.append(f"    repo: {repo}")
            out.append(f"    provisional_decision: {dec}")
            out.append(f"    integration_option: {cat['default_option']}")
            out.append(f"    isolation_tier: {cat['isolation']}")
            if rationale:
                out.append(f"    rationale: {yaml_str(rationale)}")
            out.append("    live_metadata:")
            out.append("      pending_live_discovery: true")
            out.append(f"      discovery_cmd: {yaml_str(DISCOVERY_CMD.format(owner=owner, repo=repo))}")
    return "\n".join(out) + "\n"


def yaml_str(s: str) -> str:
    return '"' + s.replace('"', "'") + '"'


def gen_decisions() -> str:
    out = [HEADER.format(fname="decisions.yaml"), "schema_version: 1",
           "# Decision vocabulary: retain | adopt | adapt | integrate | federate | "
           "isolate | benchmark | reference | defer | reject | self",
           "category_defaults:"]
    for key, cat in CATEGORIES.items():
        out.append(f"  {key}:")
        out.append(f"    title: {yaml_str(cat['title'])}")
        out.append(f"    default_decision: {cat['default_decision']}")
        out.append(f"    integration_option: {cat['default_option']}")
        out.append(f"    isolation_tier: {cat['isolation']}")
        out.append(f"    note: {yaml_str(cat['note'])}")
    out.append("overrides:  # candidates whose decision differs from the category default")
    for key, cat in CATEGORIES.items():
        for url, decision, rationale in cat["items"]:
            if decision is None:
                continue
            owner, repo = owner_repo(url)
            out.append(f"  - name: {repo or owner}")
            out.append(f"    category: {key}")
            out.append(f"    decision: {decision}")
            if rationale:
                out.append(f"    rationale: {yaml_str(rationale)}")
    return "\n".join(out) + "\n"


def _li(s: str) -> str:
    """A YAML list item, always quoted so embedded ': ' never starts a mapping."""
    return "  - " + yaml_str(s)


def gen_licences() -> str:
    out = [HEADER.format(fname="licences.yaml"), "schema_version: 1",
           "# Per the charter: a permissive top-level licence does NOT mean every",
           "# dependency, model, ruleset, dataset, or image is commercially safe.",
           "policy:",
           _li("All licences must be confirmed by live discovery before integration."),
           _li("n8n, windmill, sonarqube: KNOWN non-OSI or commercial-tier concerns — "
               "legal review required before any commercial use (flagged, not fabricated)."),
           _li("rulesets/templates (semgrep-rules, nuclei-templates) reviewed per-rule."),
           _li("models/datasets reviewed via model cards + dataset licences separately."),
           "candidates_pending_licence_confirmation: true",
           "discovery_cmd: \"gh repo view <owner>/<repo> --json licenseInfo,name\""]
    return "\n".join(out) + "\n"


def gen_security_review() -> str:
    out = [HEADER.format(fname="security_review.yaml"), "schema_version: 1",
           "quarantine_procedure:",
           _li("metadata-first; no cloning during discovery."),
           _li("no install scripts, git hooks, submodules, containers, binaries, "
               "Makefiles, tests, or builds until quarantine review passes."),
           _li("any later execution only in an ephemeral sandbox (isolation/)."),
           _li("pin to reviewed releases, commits, checksums, container digests."),
           "category_controls:"]
    for key, cat in CATEGORIES.items():
        out.append(f"  {key}: {{ isolation_tier: {cat['isolation']}, "
                   f"default_decision: {cat['default_decision']} }}")
    out.append("high_risk_flags:")
    out.append(_li("category A offensive agents: reject/reference; never enable attack workflows."))
    out.append(_li("mitre/caldera, openvas, kube-hunter, subfinder, nuclei: active/offensive — "
                   "scope-constrained, authorised targets only, isolated tier."))
    return "\n".join(out) + "\n"


def gen_data_flows() -> str:
    out = [HEADER.format(fname="data_flows.yaml"), "schema_version: 1",
           "# Egress/telemetry posture per category. Default-deny egress; sensitive,",
           "# safeguarding, PII, and secret data never leave the tenant boundary unless",
           "# an explicit data policy authorises it (charter rule 14).",
           "principles:",
           _li("external model providers are opt-in per tenant; never see PRIVACY_FORBIDDEN."),
           _li("air-gapped/hybrid: workers return only schema-validated findings + signed "
               "evidence digests; raw target data and secrets stay inside the customer boundary."),
           "category_egress:"]
    egress = {
        "C_ai_model_eval": "may call model providers — gate via AI gateway + redaction",
        "D_sast_sca_dast": "no egress beyond the authorised target; results only",
        "E_runtime_detection": "telemetry inbound; redact before storage",
        "F_vulnmgmt_aspm_siem_soar_ti": "TI feeds in/out; STIX/TAXII, tenant-scoped",
        "K_telemetry_observability_audit": "internal only; privacy-filtered, tenant-scoped",
    }
    for key, cat in CATEGORIES.items():
        out.append(f"  {key}: {yaml_str(egress.get(key, 'default-deny egress; no phone-home permitted'))}")
    return "\n".join(out) + "\n"


FILES = {
    "catalogue.yaml": gen_catalogue,
    "decisions.yaml": gen_decisions,
    "licences.yaml": gen_licences,
    "security_review.yaml": gen_security_review,
    "data_flows.yaml": gen_data_flows,
}

if __name__ == "__main__":
    import os
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    os.makedirs(target, exist_ok=True)
    for fname, fn in FILES.items():
        with open(os.path.join(target, fname), "w", encoding="utf-8") as fh:
            fh.write(fn())
    n = sum(len(c["items"]) for c in CATEGORIES.values())
    print(f"wrote {len(FILES)} files; {n} candidates across {len(CATEGORIES)} categories")
