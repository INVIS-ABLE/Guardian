# Guardian Universal — Product Vision

*Phase 0 deliverable.*

## One sentence

Guardian is the **trusted control plane that governs security, safeguarding,
evidence, and authorised cyber-defence** — owning identity, authorisation, policy,
approval, evidence, and learning — while external scanners, runtimes, and AI agents
remain **replaceable and subordinate** behind it.

## Who it serves

INVISABLE remains the founding organisation and a protected tenant. Guardian
generalises to serve: charities and vulnerable-user services, startups/SMEs,
enterprises, public-sector and regulated organisations, security and software teams,
MSSPs, and self-hosted / air-gapped / cloud / multi-tenant SaaS customers.

## What Guardian always owns (the control plane)

Guardian is authoritative for, and never delegates:

- tenant identity & isolation
- target ownership & authorisation (`core/tenancy.py`)
- asset scope (`core/scope.py`)
- agent & service identity
- tool capability boundaries (`connectors/contract.py`)
- policy decisions (`core/policy_gate.py`) and approval gates
- evidence integrity (`attestation/`, `core/evidence/`)
- safeguarding & privacy (`policies/privacy_invariants.yaml`, `simulators/`)
- secret handling, remediation/release authority, rollback, audit, learning.

## What stays external and replaceable

Scanners (Semgrep, CodeQL, Trivy, ZAP, Nuclei…), runtimes (Falco, Tetragon…),
findings backends (DefectDojo, Faraday…), policy engines (OPA/Cedar as *evaluators*,
never as competing authorities), sandboxes, and AI/agent models. Each sits behind the
connector contract and a signed execution plan. **Guardian must always be able to
replace any external worker.**

## Product boundary (the line we will not cross)

- Guardian is **never** an unrestricted offensive platform. Every target is owned or
  explicitly, verifiably authorised.
- No public interface exposes unrestricted shell or arbitrary tool execution.
- No AI agent grants itself authority or merges/deploys its own production changes.
- No external scanner bypasses Guardian's policy decision point.
- Uncertainty fails closed.

## Architecture (target)

```
Operator / Customer
  → Guardian API & Console
  → Tenant Identity + Authorised-Target Registry      (core/tenancy.py)
  → Policy Decision & Approval Plane                   (core/policy_gate.py)
  → Signed Execution Plan
  → Risk-tiered isolated worker / external adapter     (connectors/, isolation/)
  → Untrusted Output Gateway → schema validation, normalisation, dedup
  → Evidence, Provenance, Attestation, Audit           (attestation/, core/evidence/)
  → Adversarial + Safeguarding/Privacy analysis        (simulators/, policies/)
  → Remediation proposal → Digital-twin/staging         (twin/)
  → Human approval → GitOps / controlled response
  → Runtime monitoring + recovery + learning           (detection/, recovery/)
```

This mirrors the existing Brain flow (`core/brain.py`) with two additions: a tenant
+ authorised-target registry at the front, and an explicit untrusted-output gateway.

## Differentiators

1. **Safeguarding as a first-class, configurable capability** — vulnerable adults,
   children, health/disability, financial vulnerability, domestic-abuse and
   harassment risk, fraud/social-engineering, privacy/consent, accessibility, and
   human escalation. A generic enterprise refactor must never erase this.
2. **Evidence integrity by construction** — tamper-evident, attributable records for
   every material decision.
3. **Human authority is structural**, not advisory — the model recommends; policy
   decides; humans approve production.
4. **Authorised-only by design** — the authorisation grant makes "is this target
   legitimate?" a typed, expiring, signed, tenant-scoped question.

## How we get there

Foundations before tools. Sequence (subject to evidence):

1. **Tenant-neutral domain model + authorised-target grants** ← *this PR.*
2. Wire `authorise_target()` ahead of the policy gate (tenant-aware enforcement).
3. Canonical connector contract carries `tenant_id`; evidence carries `tenant_id`.
4. Signed plugin registry + sandbox profiles + untrusted-output gateway.
5. First low-risk scanner adapters; findings federation decision.
6. Adversarial validation, dynamic testing, runtime monitoring, controlled response.

Each step is feature-flagged, additive, reversible, and tested before the next.
