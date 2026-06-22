# Phase 4 — Supply-Chain Trust & Verification

Blueprint areas 8/9 (admission + provenance) and 17 (risk-based prioritisation). Nothing
deploys unless it is digest-pinned, signed, provenanced, and SBOM-attested — verified
**fail-closed**. Harbor, Dependency-Track, cosign, sigstore/policy-controller, and
in-toto/witness are the deployment systems; `supplychain/` is the in-process decision layer.

## Admission verification (`supplychain/admission.py`)

`verify_artifact(bundle, policy)` refuses an image/release unless:

- **digest-pinned** (`@sha256:<64hex>`) — a movable tag is rejected;
- **signed** with a valid signature whose **identity is on the allowlist** (cosign cert
  identity / OIDC workflow subject);
- accompanied by **provenance** whose `subject_digest` matches the image;
- accompanied by an **SBOM**;
- **not expired**.

Missing signature/provenance/SBOM material → **deny** (fail closed). Tested: signed+pinned
admitted; tag-only refused; missing provenance fails closed; forged signature refused;
untrusted identity refused; provenance/image digest mismatch refused; missing SBOM refused;
expired attestation refused.

## Build provenance (`supplychain/provenance.py`)

A SLSA-style statement binding the artifact digest to the source repo, commit, builder, and
materials; signed/verified with the attestation signer (Ed25519/HMAC). In CI, cosign signs and
in-toto/witness attest each stage (scan → policy → approval → build → deploy).

## Risk-based prioritisation (`supplychain/sbom.py`)

Don't prioritise by raw CVSS. `prioritise(vuln, ctx, vex)` combines:

- severity/CVSS, **CISA KEV** (known-exploited boost), **EPSS** probability,
- **internet exposure**, **runtime reachability** (is the component actually loaded?),
- **user-safety impact**, compensating controls,
- and **OpenVEX exploitability** — `is_exploitable()` treats `not_affected`/`fixed` as not
  exploitable ("package present" ≠ "exploitable in this product"), strongly de-prioritising
  unreachable/cleared findings.

It outputs a score → tier → **remediation SLA** (critical 1d / high 7d / medium 30d / low 90d).

## Maps to the acceptance gate / bulletproof tests

- **#8 an unsigned or incorrectly attested image cannot run** ✅ (admission fail-closed).
- **Supply chain row** — every release has SBOM + provenance + verified signature ✅
  (contract shipped; cosign/witness wiring in CI is the deployment step).

## Deployment wiring

Harbor (private registry, digest-only deploy, signature/attestation admission),
Dependency-Track (continuous SBOM), cosign + sigstore/policy-controller (admission), TUF
(secure policy/rule/tool updates), GUAC (supply-chain graph) — per
`docs/architecture/components.yaml`. `actions/attest` + cosign generate signed provenance in
CI; `verify_artifact` gates deploys.
