# Guardian Sovereign Operations Plane

> **The phase after [`brain_v2.md`](brain_v2.md).** Brain V2 gave Guardian a real nervous system
> — a model gateway ([`core/ai/`](../core/ai)), a bounded reasoning graph
> ([`core/brain/`](../core/brain)), typed evidence ([`core/evidence/`](../core/evidence)),
> a one-use capability broker ([`core/tools/`](../core/tools)), and an independent verifier
> ([`core/verifier.py`](../core/verifier.py)). The Sovereign plane gives Guardian **complete
> situational awareness, deeper reasoning, a controlled experimentation laboratory, and
> brokered operational power** — without ever becoming a self-authorising machine.

## The one rule about "full power"

> **Do not give the AI permanent administrator credentials simply because it sits behind strong
> firewalls.** That is one catastrophic failure point. The strongest design is not "an AI with
> root." It is *an AI that knows nearly everything relevant, can test almost anything safely, but
> can touch production only through short-lived cryptographic capabilities.*

Give Guardian:

- **Full analytical visibility** into security metadata.
- **Full execution freedom inside disposable cyber ranges.**
- **Full permission to prepare** code, tests, detections and recovery plans.
- **Temporary, one-action production capabilities** issued only after policy checks.
- **Automatic authority only** for narrowly scoped, reversible actions.

Enforced as a test invariant
([`tests/test_sovereign_capabilities_manifest.py`](../tests/test_sovereign_capabilities_manifest.py)):
**no capability system grants itself authority**, and **anything reaching approval-bound
production requires human approval**.

## The four separated powers

Do not place one huge Brain directly above every system. Use four powers, each a **distinct
module** so one compromise is not total compromise:

| Power | Can… | Module (today) |
| ----- | ---- | -------------- |
| **Guardian Brain** | reason and propose | [`core/brain/`](../core/brain) |
| **Guardian Policy Authority** | approve or deny | [`core/policy_gate.py`](../core/policy_gate.py) + `policies/opa/` |
| **Guardian Capability Broker** | issue one-action credentials | [`core/tools/`](../core/tools) (capability + executor) |
| **Guardian Verifier** | prove whether everything was legitimate | [`core/verifier.py`](../core/verifier.py) |

```
All approved security telemetry
        │
        ▼
  Event & evidence fabric
        │
  ┌─────┴───────────┐
  ▼                 ▼
Live digital twin   Historical timeline
  └──────┬──────────┘
         ▼
 Guardian reasoning council  ──► hypotheses & plans
         ▼
 Cyber range / proof / fuzzing lab  ──► verified conclusions
         ▼
 Capability-based response broker   ──► reversible action only
         ▼
 Independent Shadow verifier
```

## The 20 capability systems

The authoritative, machine-checked list is
[`architecture/sovereign_capabilities.yaml`](architecture/sovereign_capabilities.yaml).

### Wave 1 — Omniscience (total awareness)
| # | System | Gives Guardian |
| - | ------ | -------------- |
| 1 | **Live cyber digital twin** (Cartography / CloudQuery) — *[first slice implemented](digital_twin.md)* | a continuously-updated graph of every repo/service/identity/cloud/k8s/key/dependency/data-class — answer instantly *"what is affected if this is compromised?"* |
| 2 | **Identity & permission attack graph** (BloodHound) — *[first slice implemented](identity_graph.md)* | effective + transitive permissions, escalation paths, dormant privilege, separation-of-duties breaks |
| 3 | **Data lineage & privacy graph** (DataHub / OpenLineage) — *[first slice implemented](data_lineage.md)* | field-level lineage + classification propagation — detect *"a new integration moves a health field outside its approved boundary"* |
| 4 | **Endpoint intelligence fabric** (osquery / Fleet) — *[first slice implemented](endpoint_fabric.md)* | structured OS state via **signed, reviewed query packs only** — never model-generated commands |
| 5 | **Real-time security event fabric** (ClickHouse / Redpanda) — *[first slice implemented](event_fabric.md)* | Guardian's nervous system: OPA/Temporal/GitHub/identity/Cilium/Falco/build/model events in one durable stream + analytical store |
| 6 | **Forensic timeline reconstruction** (Timesketch) — *[first slice implemented](forensic_timeline.md)* | automatic chronologies so the Brain reasons from *sequence*, not isolated alerts |

### Wave 2 — Intelligence (deeper reasoning)
| # | System | Gives Guardian |
| - | ------ | -------------- |
| 7 | **Evidence & competing-hypothesis engine** — *[first slice implemented](reasoning.md)* | every case holds rival hypotheses with supporting/contradicting/missing evidence + falsification tests; it seeks *disproof* of its preferred theory |
| 8 | **Causal root-cause engine** — *[first slice implemented](reasoning.md)* | counterfactual reasoning to separate first-event / root-cause / enabling-conditions / amplifiers / symptoms |
| 9 | **Multi-model reasoning council** — *[first slice implemented](reasoning.md#9--multi-model-reasoning-council)* | planner · sceptic · alt-hypothesis · attack-path · privacy · adjudicator roles across model families — adjudication, **not majority vote** |
| 10 | **Confidence calibration & abstention** — *[first slice implemented](reasoning.md)* | learns whether 90%-confidence is right ~90% of the time; lowers it or says *"insufficient evidence"* |
| 11 | **Autonomous threat-hunting engine** — *[first slice implemented](reasoning.md#11--autonomous-threat-hunting-engine)* | continuous read-only, budgeted, tenant-isolated, privacy-filtered hunts; a validated hunt becomes a **permanent detection** |
| 12 | **Predictive attack-path forecasting** (NetworkX over the twin) — *[first slice implemented](digital_twin.md#cross-domain-federation--attack-path-forecasting)* | evaluates PRs & infra changes *before* deploy — not after a scanner finds the exposure |

### Wave 3 — Proof & controlled experimentation
| # | System | Gives Guardian |
| - | ------ | -------------- |
| 13 | **Continuous adversary-emulation lab** (CALDERA / Atomic Red Team / Stratus) — *[first slice implemented](adversary_emulation.md)* | did prevention block it? did an independent sensor detect it? was evidence preserved? — **lab only**, every bypass → regression test |
| 14 | **Continuous fuzzing farm** (ClusterFuzzLite / AFL++ / Atheris / Jazzer) — *[first slice implemented](fuzzing_farm.md)* | fuzz crypto envelopes, attachments, tokens, parsers, evidence formats |
| 15 | **Cryptographic protocol proof lab** (Tamarin / Verifpal / ProVerif) — *[first slice implemented](crypto_proof_lab.md)* | review the crypto **system** — device/key/group/forward-secrecy/recovery flows — never plaintext |
| 16 | **Binary & malware analysis lab** (Ghidra / angr / CAPE / YARA) — *[first slice implemented](malware_lab.md)* | Tier-3 isolated RE: no prod route, disposable VMs, full pcap, **human approval to import unknown artifacts** |
| 17 | **Digital-twin chaos & recovery simulator** — *[first slice implemented](chaos_recovery.md)* | failure scenarios against the **cloned** twin; compare predicted vs actual impact to learn which controls actually work |

### Wave 4 — Brokered operational power
| # | System | Gives Guardian |
| - | ------ | -------------- |
| 18 | **Autonomous remediation factory** | reproduce → patch → failing+passing tests → SBOM/provenance → **draft PR**; merge & production stay approval-bound |
| 19 | **Reversible response broker** | a *separate* service that verifies identity/ownership/OPA/signed-capability/blast-radius/rollback before any reversible action — everything expires or rolls back |
| 20 | **Confidential execution & Shadow Guardian** (Confidential Containers) | sensitive workers in TEEs; a separate-credential Shadow recomputes decisions and can **freeze capability issuance** — but never take over production |

## The five autonomy levels

| Level | Name | Guardian may, autonomously… |
| ----- | ---- | --------------------------- |
| 1 | **Awareness** | inventory, correlate, map, monitor |
| 2 | **Investigation** | open cases, run read-only queries, gather evidence, test hypotheses, conclude |
| 3 | **Engineering** | reproduce weaknesses, generate patches/detections/tests, open **draft** PRs |
| 4 | **Reversible defence** | quarantine / pause / isolate / revoke **narrowly-scoped, short-lived** objects under prior policy, with auto-rollback |
| 5 | **Approval-bound production** | prepare everything, **wait for required approvals**, revalidate the entire state, execute exactly the signed plan |

Levels 1–3 are read/prepare and run freely within verified owned scope. Level 4 runs only with
**prior policy-defined authority, strict expiry and automatic rollback** — every action is
narrowly scoped, reversible, time-limited, independently verified, immutably audited, and
**cannot expand its own scope**. Level 5 never proceeds without a human.

## Permanently prohibited

Guardian can **never** independently: give itself permissions · change its own policies · add new
tools · disable evidence · access private-content keys · bypass approval · widen scope · target
third parties · convert temporary authority into permanent authority. *(Enumerated and tested in
the catalogue's `never_autonomous` list.)*

## What to feed Guardian — and what never to

**Feed it** continuously-updated, structured security context: source + commit history, IaC &
manifests, SBOMs & dependency graphs, build provenance & signatures, cloud/k8s inventories,
IAM/RBAC/relationship permissions, API & event schemas, network/DNS flows, runtime & endpoint
telemetry, WAF/IDS/abuse signals, certificate & key *metadata*, threat-intel feeds, incident
timelines, findings & accepted risks, data classifications & lineage, privacy/safeguarding
requirements, recovery procedures & test outcomes, and human decisions + their eventual correctness.

**Never feed it:** private-message plaintext · conversation decryption keys · unredacted patient
records · universal recovery material · raw sensitive data merely because it might improve a model.
This is the existing Privacy Fabric principle — Guardian protects the cryptographic system while
remaining structurally **outside** private content
([`privacy_fabric/`](privacy_fabric/README.md), and the Verifier's enforced boundary).

## Build order (after the current roadmap)

The `wave` field in [`sovereign_capabilities.yaml`](architecture/sovereign_capabilities.yaml) is
authoritative.

1. **Wave 1 — Omniscience:** digital twin · identity graph · data-lineage graph · endpoint fabric ·
   event lake · forensic timelines.
2. **Wave 2 — Intelligence:** hypothesis engine · causal engine · multi-model council ·
   calibration · threat hunting · predictive attack-path analysis.
3. **Wave 3 — Proof & experimentation:** adversary-emulation range · fuzzing farm · crypto-proof
   lab · binary/malware lab · chaos & recovery simulations.
4. **Wave 4 — Operational power:** remediation factory · reversible response broker · confidential
   workers + Shadow Guardian.

## Sovereign acceptance gate

Built this way, Guardian becomes the continuously-learning, independently-verified security nervous
system for every INVISABLE application — with enormous practical power, but where compromising one
model, one agent or one capability system never equals total organisational compromise. Do not
declare the Sovereign plane live until:

1. Every operational action flows Brain → Policy → Broker → Verifier (no shortcut).
2. No capability system can grant itself authority (tested).
3. Production is reachable only via short-lived, single-use capabilities issued after policy checks.
4. Level-4 actions are all narrowly scoped, reversible, expiring and auto-rolled-back.
5. The Shadow Guardian can freeze capability issuance but never assume production power.
6. Private-message plaintext and decryption keys never enter any system here.
7. Every decision and result is independently reconstructable from immutable evidence.
