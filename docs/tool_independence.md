# Tool Independence & Learning — Defensive Plan

Captures the agreed approach to "build our own / don't rely on them" for the tools Guardian
orchestrates. **Defensive boundary (non-negotiable):** Guardian must not become an
offensive tool. We do **not** fork tools to remove their controls, retain offensive
capability, or train a model to perform attacks. We pursue independence and learning only on
the *detection and defence* side.

> Confirmed directions: **vendor & pin**, **extract detection rules**, **teach model
> detection**. (Selected via the Guardian planning question.)

## 1. Vendor & pin (supply-chain resilience)

Goal: Guardian keeps working if an upstream disappears or is compromised — without changing
tool behaviour or stripping guardrails.

- Exact-pin every tool/library version (already enforced for crypto libs by the policy
  checker; extend to scanners via lockfiles + pinned action SHAs).
- Mirror release artifacts to an internal registry; record provenance (SLSA) and verify
  signatures (Sigstore/Cosign) before use.
- Generate an SBOM (Syft) and scan it (Grype/Trivy/OSV) on every bump.
- Bumps go through review + scanning; no `latest`, no floating ranges.

## 2. Extract detection rules (reduce reliance on the binaries for logic)

Goal: own the *detection logic* so our coverage survives a tool being unavailable.

- Maintain Guardian's own Semgrep ruleset (`semgrep/semgrep.yml`) and the crypto-policy
  checker (`security/crypto/cryptoPolicyChecker.ts`) as first-party detections.
- Curate Gitleaks rules (`gitleaks/.gitleaks.toml`) and ATT&CK-mapped detections in
  `policies/security_standards.md` + `policies/malware_defence_library.yaml`.
- These are **detections**, not exploits: they describe what an attack looks like so we can
  catch and contain it on owned systems.

## 3. Teach the model detection (Learning Memory)

Goal: the model gets better at *catching* techniques, never at performing them.

- The Learning Memory agent stores **defensive** outcomes in RAG memory: detection
  signatures, containment results, ATT&CK **defensive** mappings, false-positive feedback.
- Training/eval data is detection-and-response oriented (e.g. "signal X ⇒ technique Y ⇒
  containment Z"), drawn from owned-staging simulations and approved docs — never real user
  data and never attack execution traces meant to reproduce an attack.
- Evaluation (DeepEval/Promptfoo/Ragas) measures detection quality and safe refusal, not
  offensive capability.

## Explicitly out of scope

- Forking credential-crackers/brute-forcers (hashcat/Hydra/John) into bespoke offensive
  tools, or removing their guardrails.
- Training any model to perform attacks, evade detection, or target third parties.
- Anything that conflicts with Guardian's non-negotiable defensive principle
  (see [../GUARDRAILS.md](../GUARDRAILS.md)).
