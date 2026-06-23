# Candidate repository catalogue

Machine-readable evaluation of the ~200 external projects in the Guardian
universal-platform brief. This is a **research and candidate catalogue, not a
mandatory installation list** — nothing here is integrated by virtue of appearing.

## Honest limitation (no fabricated metadata)

GitHub API / network access was **not available** when this catalogue was produced.
Per the platform charter ("Do not fabricate metadata when network access is
unavailable"), quantitative fields — default branch, evaluated commit, latest
release, archived status, exact licence, dependency/model/dataset licences, and
maintenance signals — are **not invented**. Each candidate carries:

```yaml
live_metadata:
  pending_live_discovery: true
  discovery_cmd: "gh repo view <owner>/<repo> --json name,owner,defaultBranchRef,isArchived,licenseInfo,latestRelease,pushedAt,stargazerCount"
```

Run the discovery commands (or `gh search repos …` from the brief) to populate them
before any integration. The **decision** fields, by contrast, are architectural
judgements made from each project's category and purpose and are actionable now.

## Files

| File | Contents |
|------|----------|
| `catalogue.yaml` | All 217 candidates: owner/repo, category, provisional decision, integration option, isolation tier, rationale (where notable), and the pending live-metadata block. |
| `decisions.yaml` | Per-category default decision + integration posture + rationale, and the per-candidate overrides that differ from their category default. |
| `licences.yaml` | Licence-review policy and known commercial/non-OSI flags (n8n, windmill, sonarqube) requiring legal review. |
| `security_review.yaml` | Quarantine procedure, per-category isolation tier, and high-risk (offensive/active) flags. |
| `data_flows.yaml` | Egress/telemetry posture per category (default-deny egress; protected data never leaves the tenant boundary). |
| `generate.py` | Deterministic generator. Edit decisions here and regenerate — do not hand-edit the YAML. |

## Regenerate

```bash
uv run python research/repositories/generate.py
```

## Decision vocabulary

`retain` (keep Guardian's existing component) · `adopt` (use directly) · `adapt`
(wrap behind the connector contract) · `integrate` · `federate` (external system of
record, Guardian stays canonical) · `isolate` (run as an isolated/sandboxed service) ·
`benchmark` (test fixture) · `reference` (architecture/research only) · `defer` ·
`reject` · `self` (this repo).

## Headline judgements

- **Offensive autonomous agents (category A)** — mostly `reference`/`reject`.
  Guardian is the control plane; unrestricted attack workflows are never enabled.
- **Standard scanners (category D)** — `adapt`/`retain`. Several (Semgrep, CodeQL,
  Trivy, ZAP, OSV) are already Guardian connectors; new ones sit behind the same
  contract, scope-constrained and rate-limited.
- **Policy engines (category G)** — OPA is `retain`ed as the single authority; Cedar/
  Cerbos/OpenFGA are `reference` only to avoid a second, conflicting decision point.
- **Open formats & supply-chain (H, L)** — `adopt` (SARIF, CycloneDX, SPDX, STIX,
  cosign, in-toto, SLSA) over bespoke coupling.
- **Findings/SIEM/SOAR/TI (F)** — `federate`; Guardian owns the CanonicalFinding.
- **Adversary emulation (CALDERA), OpenVAS, kube-hunter, nuclei, subfinder** —
  high-risk/active: `isolate`, authorised targets only, isolated tier.

See `docs/platform/BUILD_BUY_ADAPT_REJECT_MATRIX.md` and
`docs/platform/COMPETITOR_AND_OPEN_SOURCE_LANDSCAPE.md` for the narrative.
