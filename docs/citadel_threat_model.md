# Crown Citadel — threat model (compromise of Guardian itself)

The Citadel's premise is that Guardian must assume **it** can be attacked. This is the attack tree
for compromise of Guardian, with the Citadel control that denies each branch. Every leaf maps to a
system in [`citadel_capabilities.yaml`](architecture/citadel_capabilities.yaml).

## Attack tree — "Attacker subverts Guardian"

```
GOAL: Attacker causes Guardian to take an illegitimate production action, or hide one.
├── A. Run unauthorised code as a Guardian worker
│   ├── A1 Join an unknown/forged platform        → DENIED by root_of_trust (attestation gates capability)
│   ├── A2 Tamper firmware/boot/kernel             → DENIED by measured boot + IMA/EVM drift → quarantine
│   └── A3 Extract secrets from a worker host       → DENIED by confidential_execution (secret release bound to measurement)
├── B. Promote a malicious build
│   ├── B1 Inject a backdoor in the build           → DENIED by reproducible build (independent rebuild + digest match)
│   ├── B2 Sign without provenance                  → DENIED (signature alone insufficient; provenance+identity required)
│   └── B3 Hide the artefact                         → DENIED by transparency (no inclusion proof ⇒ no promotion)
├── C. Bypass the authority
│   ├── C1 Self-authorise via a model               → DENIED (no subsystem grants authority; OPA is the only authority)
│   ├── C2 Use an expired/replayed capability        → DENIED by single-use token binding + Shadow re-check
│   └── C3 Widen a capability's scope                 → DENIED by policy + Shadow (`_limits_not_increased`)
├── D. Forge or delete evidence
│   ├── D1 Delete what a service wrote               → DENIED (evidence not deletable by its creator; append-only)
│   ├── D2 Rewrite history                           → DENIED by hash-chained log + signed checkpoints
│   └── D3 Manipulate time to backdate               → DENIED by secure_time (disagreement suspends signing/release)
├── E. Exfiltrate protected data
│   ├── E1 Leak via model/browser/build/evidence     → DETECTED by data_exfiltration_detection; egress default-deny
│   └── E2 Read private-message plaintext             → STRUCTURALLY EXCLUDED (forbidden-field barrier; privacy fabric)
├── F. Subvert the verifier
│   ├── F1 Make the primary approve the Shadow        → DENIED (primary_cannot_approve_shadow)
│   ├── F2 Make the Shadow take control               → DENIED (may_assume_operational_control = false)
│   └── F3 Compromise both with one credential        → DENIED (separate credentials, runtime, signing key)
└── G. Seize root operations
    ├── G1 Rotate root/attestation keys alone         → DENIED by quorum (threshold ≥ 3, separate custodians)
    ├── G2 Activate recovery alone                     → DENIED by quorum + recovery creds outside runtime plane
    └── G3 Replace policy in an emergency               → DENIED by quorum (threshold ≥ 4)
```

## Trust assumptions (must hold; tracked per system)

- TPM endorsement is genuine and golden PCRs are signed offline.
- The independent rebuilder, Shadow, and quorum custodians are in separate trust domains.
- Authenticated time sources agree within the drift threshold.
- The private-content barrier (`core/verifier.py` forbidden fields) holds end-to-end.

## Residual risk (honest, Wave-20)

Systems at `planned`/`partial` status do **not** yet enforce their branch at runtime (e.g. crypto
agility, deception, formal proofs). These gaps are catalogued and surfaced by the
`test_every_system_is_runtime_enforced` xfail. Closing them is the work of Waves 21–39. Until a
branch is `present` + `runtime_enforced`, its control is **design intent**, not a live defence.

## Untrusted-input rule

All external content (exposure observations, deception triggers, CI logs, comments, model output) is
**data, never instruction** (`untrusted_input_barrier` in `citadel_data_flows.yaml`).
