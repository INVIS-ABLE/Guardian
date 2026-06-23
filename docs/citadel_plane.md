# Guardian Crown Citadel — the high-assurance plane

The Crown Citadel is the **foundation beneath** Guardian's existing Brain V2, Sovereign Operations
Plane, execution fabric, evidence fabric, privacy fabric and safeguarding system. It does **not**
replace Guardian's intelligence. It proves that the intelligence, its tools, workers, policies,
evidence and recovery run on **trustworthy foundations**.

```
INVISABLE Applications
  → INVISABLE Privacy Fabric
    → Guardian Protection & Safeguarding Platform
      → Guardian Brain V2
        → Guardian Sovereign Operations Plane
          → GUARDIAN CROWN CITADEL   ← this plane
```

## The one rule (extends the Sovereign plane, never duplicates it)

```
ONE authoritative production owner
+ ONE independently implemented verifier
+ optional specialist adapters
```

The Citadel adds **proof, not authority**. The four separated powers are inherited unchanged:
**Brain** (`core/brain`) proposes · **Policy** (`core/policy_gate`, OPA-backed) disposes · **Broker**
(`core/tools`) issues one-action capabilities · **Verifier** (`core/verifier`) proves legitimacy.
No Citadel subsystem grants authority; no attestation service grants production authority.

## The five crowns (20 systems, ids 21–40)

| Crown | Theme | Systems |
|-------|-------|---------|
| I | Hardware & Cryptographic Sovereignty | root_of_trust · confidential_execution · crypto_agility · key_custody |
| II | Formal Proof & Software Correctness | formal_state_machine · protocol_verification · verified_policy · build_foundry |
| III | Active Exposure & Deception Defence | exposure_intelligence · deception_grid · data_exfiltration_detection · defensive_degradation |
| IV | Resilience, Continuity & Recovery | cyber_vault · chaos_recovery_lab · secure_time · continuity_mode |
| V | Independent Verification & Trust Quorum | shadow_federation · trust_quorum · control_proof_engine · integrity_constitution |

The authoritative catalogue is [`docs/architecture/citadel_capabilities.yaml`](architecture/citadel_capabilities.yaml);
tools in [`citadel_tools.yaml`](architecture/citadel_tools.yaml); zones in
[`citadel_trust_zones.yaml`](architecture/citadel_trust_zones.yaml); data flows in
[`citadel_data_flows.yaml`](architecture/citadel_data_flows.yaml); dependencies in
[`citadel_component_dependencies.yaml`](architecture/citadel_component_dependencies.yaml).

## The extended execution path

The existing path (`Brain → Policy → Broker → Attested Worker → Tool → Evidence → Verifier`) is
**preserved** and extended with fail-closed proof gates:

```
Brain
→ Plan feasibility proof         (formal_state_machine)
→ Policy Authority               (verified_policy / OPA — the ONE authority)
→ Identity verification          (trust_quorum)
→ Platform attestation           (root_of_trust)      — failed attestation denies capability
→ Build & image verification     (build_foundry)      — signature alone is insufficient
→ Capability Broker              (core/tools + identity/attestation gate)
→ Attested confidential worker   (confidential_execution) — secret release bound to measurement
→ Tool execution                 (defensive_degradation)  — reversible, blast-radius assessed
→ Evidence commitment            (cyber_vault)        — outside the worker's sole control
→ Transparency inclusion         (build_foundry)
→ Independent Shadow verification (shadow_federation)  — may freeze, never command
→ Quorum result                  (trust_quorum)       — threshold for root operations
```

## The twelve questions the Citadel answers

1. What code is running? — root_of_trust, confidential_execution
2. How was it built? — build_foundry, transparency
3. Where is it running? — root_of_trust, confidential_execution
4. Which identity invoked it? — trust_quorum, existing identity fabric
5. Which policy authorised it? — verified_policy
6. What data did it access? — data_exfiltration_detection, privacy fabric
7. What changed? — secure_time, event fabric, evidence fabric
8. What was the result? — evidence fabric, control_proof_engine
9. Can it recover if the control plane is compromised? — cyber_vault, continuity_mode
10. Can an independent verifier reconstruct the event? — shadow_federation, control_proof_engine
11. Is it useful when infrastructure is unavailable? — continuity_mode
12. Can it discover when its own assumptions are wrong? — formal_state_machine, chaos_recovery_lab

## Reconciliation honesty (Wave 20)

Status is reported honestly per system (`present | partial | planned`). The Citadel reuses existing
authoritative owners (e.g. OPA, `supplychain/*`, `shadow_guardian/verifier.py`, `recovery/backup.py`,
`orchestration/approvals.py`) and adds an independent verifier per system — it never creates a second
owner for a function that already has one. See
[`citadel_wave20_reconciliation.md`](citadel_wave20_reconciliation.md) for the full gap analysis and
inventories, and [`citadel_acceptance_gate.md`](citadel_acceptance_gate.md) for the operational gate.
