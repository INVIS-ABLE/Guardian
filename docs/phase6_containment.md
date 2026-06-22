# Phase 6 — Reversible Containment

Blueprint area 21. Guardian's *respond* half. Guardian may **recommend** containment, but
**no AI-generated command executes** — every order passes a deterministic adapter that
validates each parameter against a fixed schema. Automatic containment is restricted to a
small allowlist of **pre-approved, reversible** operations.

## The allowlist (`containment/actions.py`)

Reversible only, each with a confidence threshold, blast-radius cap, default TTL
(containment **auto-expires**), human-approval flag, and a documented rollback:

`revoke_token` · `disable_service_account` · `isolate_pod`* · `remove_workload_from_service`
· `block_indicator_temporarily` · `disable_feature_flag` · `pause_workflow` ·
`quarantine_image_digest` · `freeze_deployment`* · `force_reauthentication`
(*human-approval required).

An action **not** in this catalogue can never run — there is no free-form path.

## The deterministic adapter (`containment/adapter.py`)

`issue(request)` enforces, in order, and **audits the outcome (issued / rejected / denied)**:

1. action is on the **reversible allowlist** (else reject — no AI-invented commands);
2. **every parameter validated** — exact target, evidence reference, confidence ∈ [0,1];
3. **confidence ≥ the action's threshold**;
4. **blast radius ≤ the action's cap**;
5. **human approval token** present for high-impact actions;
6. **central policy** permits it (injected `policy_check`, OPA-backed in deployment);
7. issue an order with an **exact target, expiry (TTL-capped), and rollback procedure**;
8. track it so it can be **rolled back** and **auto-expires**.

Each order carries the controls the blueprint requires: exact target · expiry · rollback ·
max blast radius · confidence threshold · evidence link · policy decision · immutable audit.

## Tested invariants (8)

- a reversible action issues with rollback + expiry;
- an **unknown / raw-command action is refused** (`rm -rf …`, `delete_production_database`);
- **every parameter is validated** (missing target/evidence, out-of-range confidence,
  below-threshold confidence, over-cap blast radius, high-impact without approval);
- high-impact actions **require approval**;
- **policy denial** is enforced and audited;
- **rollback** works and **TTL auto-expiry** deactivates orders;
- requested TTL is **capped** at the action default;
- **rejected orders are audited** (Guardian records what it refused to do).

## Maps to the blueprint

- Area 21: *"No AI-generated containment command should execute without a deterministic
  adapter validating every parameter."* ✅
- Feeds from detection (the malware defence library `respond:` actions, runtime monitoring)
  and routes through the same `authorize()` policy + tamper-evident audit as everything else.

## Deployment wiring

The `policy_check` hook is backed by OPA; orders drive concrete adapters (revoke at the IdP /
OpenBao, isolate via Cilium network policy, quarantine a digest at Harbor, freeze a Temporal
deployment). Detection inputs come from Falco/Suricata/Wazuh/Sigma (Phase 6 detection-as-code).
