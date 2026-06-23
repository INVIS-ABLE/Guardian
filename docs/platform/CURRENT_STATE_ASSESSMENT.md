# Guardian — Current State Assessment

*Phase 0 deliverable. An evidence-based map of what Guardian already is, before any
universal-platform change. All claims cite files in this repository.*

## 1. What Guardian is today

Guardian is a **defensive-only, human-gated AI security & safeguarding control
plane** for INVISABLE-owned assets. Its spine is:

```
Detect → Simulate → Analyse → Patch proposal → Test → Evidence → Human approval → Deploy → Monitor → Learn
```

It is already a *control plane*, not a pile of scripts: every tool runs behind a
single chain of authority, dry-run by default, scope-bound, and fail-closed
(`README.md`, `GUARDRAILS.md`).

### Authoritative branch

This assessment was produced on `claude/keen-bohr-eqhtrq`, which descends from the
merged mainline (latest merges include endpoint intelligence fabric, data lineage &
privacy graph, the six roots of trust, and the ambient PR blast-radius twin gate —
see `git log`). No older branch supersedes it.

## 2. Strengths (what Guardian already does well)

| Capability | Where | Note |
|-----------|-------|------|
| Single policy decision point | `core/policy_gate.py` | One `decide()` authority mirroring `policies/opa/*.rego`; 28 globally blocked actions; production needs 2 distinct, unexpired reviewers. |
| Connector contract | `connectors/contract.py` | No raw commands, no shell metacharacters, enumerated actions, fixed binaries, signed execution authorisations. |
| Live, expiring ownership proof | `ownership/verifier.py` | Re-proves DNS-TXT / GitHub-App ownership immediately before use; fails closed. |
| Six roots of trust | `core/roots_of_trust.py` | Human, workload, machine, software, target, evidence — all must hold. |
| Tamper-evident evidence | `attestation/evidence_store.py`, `core/evidence/models.py` | Hash-chained, signed attestations; classification + trust-level lattice; privacy-forbidden classes never reach a model. |
| Short-lived identity | `identity/credentials.py` | 1-hour TTL ceiling; no long-lived tokens. |
| Safeguarding as first-class | `simulators/`, `playwright/safeguarding.spec.ts`, `policies/privacy_invariants.yaml` | Abuse/privacy simulators on owned staging only; "protector, never reader". |
| Default-deny scope | `core/scope.py`, `SCOPE_SCHEMA.yaml` | Validated scope files; cross-checked asset & test-account registries. |
| Supply-chain posture | `supplychain/`, `core/signing.py`, `attestation/` | SBOM/provenance/admission; Ed25519 with HMAC fallback. |
| Human-gated self-healing | `guardian.config.yaml`, `.github/workflows/` | Draft PRs only; `require_human_approval` cannot be disabled. |

## 3. The core limitation: a single implicit owner

Guardian assumes **exactly one owner — INVISABLE — everywhere**. Ownership is
implicit in schema language, defaults, and registries rather than modelled as a
first-class boundary. Concrete coupling points:

| Location | Hard-coded assumption |
|----------|----------------------|
| `core/scope.py:45` | `owner` defaults to `"INVISABLE"`. |
| `SCOPE_SCHEMA.yaml` | "INVISABLE-owned assets" language; no tenant field. |
| `scope/assets.yaml`, `scope/test_accounts.yaml` | Only INVISABLE assets/accounts; no tenant column. |
| `ownership/verifier.py:34-35` | Flat `expected_dns_token` / `allowed_repo_owners`; no tenant scoping. |
| `core/policy_gate.py` (`PolicyInput`) | No tenant field; approval counts are global. |
| `core/roots_of_trust.py` | Roots apply to one estate; no tenant dimension. |
| `connectors/contract.py` (`ActionRequest`) | No tenant field. |
| `core/evidence/models.py` (`EvidenceItem`) | Asset refs carry no tenant. |
| `guardian.config.yaml:24-31` | RAG collections are INVISABLE-scoped. |

None of this is *wrong* for INVISABLE — but it blocks serving charities, SMEs,
enterprises, public-sector, and MSSP customers, and it provides no structural
guarantee against cross-tenant leakage.

## 4. Gaps relative to a universal control plane

- **No tenant boundary** as a typed, enforced concept. *(addressed first — see
  `core/tenancy.py` and the migration doc.)*
- **No generalised authorisation grant** — "the target is legitimate" is currently
  "the target is on the INVISABLE allowlist", not a tenant-scoped, expiring,
  signed, revocable grant.
- **No deployment-mode model** (self-hosted vs SaaS vs air-gapped) driving egress
  and residency policy.
- **No signed plugin/connector marketplace model** (connectors are first-party).
- **No per-tenant data residency / model-provider policy.**
- **No external-findings federation contract** (Guardian owns findings today; it
  does not yet decide *canonical-vs-federated* for DefectDojo/Faraday-class tools).

## 5. Posture to preserve at all costs

Any generalisation must keep: default-deny, human approval of production, the
single policy decision point, fail-closed on uncertainty, tamper-evident evidence,
the connector contract's structural safety, and the safeguarding/privacy controls.
These are the product, not legacy baggage.

## 6. Conclusion

Guardian is a mature, well-bounded single-tenant control plane. The highest-leverage
first move is **not** adding tools — it is introducing the **tenant + authorised-
target model** so every existing protection becomes tenant-aware. That is the
foundation this programme builds first; everything else (plugin SDK, scanner
adapters, findings federation) depends on it.
