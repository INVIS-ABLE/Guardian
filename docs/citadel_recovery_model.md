# Crown Citadel — recovery model (loss of Guardian itself)

The companion to the [threat model](citadel_threat_model.md): if Guardian's control plane is
compromised or lost, how is it restored to a **proven-good** state? Recovery is incomplete until
**evidence integrity AND identity integrity** both pass (invariant 30).

## Recovery tree — "Restore Guardian to a trustworthy state"

```
GOAL: Restore Guardian after compromise/loss with proof it is trustworthy again.
├── 1. Detect & contain
│   ├── 1a Shadow detects divergence                  → freeze capability issuance (one-way latch)
│   └── 1b Enter continuity mode                       → local policy/model/evidence queue; fail-closed
├── 2. Recover state from the cyber vault
│   ├── 2a Select last VERIFIED snapshot               → recovery/drill.py integrity + malware scan must pass
│   ├── 2b Restore from isolated plane                 → separate identity + network; no normal-runtime write access
│   └── 2c Reject any tampered recovery point           → BackupManager.restore raises on digest mismatch
├── 3. Re-establish roots
│   ├── 3a Re-enrol attestation root (quorum ≥ 3)       → separate custodians, recorded ceremony
│   ├── 3b Rotate root/release/evidence signing (quorum) → recovery creds drawn from outside the runtime plane
│   └── 3c Rebuild transparency state                    → verify against the independent log
├── 4. Prove identity & evidence integrity
│   ├── 4a Verify evidence hash chain + checkpoints      → core/verifier.py consistency/inclusion
│   └── 4b Verify identity/key transparency               → detect_silent_key_replacement clean
├── 5. Reconcile & exit continuity
│   ├── 5a Replay deferred events into durable plane      → continuity reconcile_on_exit
│   └── 5b Confirm no invariant was weakened in continuity → scope/policy/evidence/approval/privacy intact
└── 6. Clear the freeze (quorum)
    └── 6a Sovereign-Root quorum clears Shadow latch       → primary cannot clear its own freeze
```

## Recovery-path inventory (current)

| Capability | Owner (present) | Verifier | Gap to close |
|------------|-----------------|----------|--------------|
| Immutable backup | `recovery/backup.py` (WORM + SHA-256) | `recovery/drill.py` | isolated identity/network plane (Wave 36) |
| Restore drill (RPO/RTO) | `recovery/drill.py` | audit chain | malware scan + automated cadence |
| Control-plane health | `resilience/health.py` | — | continuity local-policy cache (Wave 37) |
| Local-model continuity | `core/ai/routing.py` | — | local evidence queue reconciliation |
| Key-transparency recovery | `core/verifier.py` | independent monitor | attestation-root re-enrol ceremony |

## Recovery objectives

- **RPO/RTO**: measured by `recovery/drill.py`; per-class targets recorded in `configs/citadel/cyber-vault.yaml`.
- **Recovery credentials**: live **outside** the normal runtime plane (invariant 18), offline-held.
- **Recovery evidence**: never written solely by the system being recovered (invariant 19).

## Exercises (Wave 36–39 acceptance)

Catastrophic control-plane loss · compromised worker · corrupted build · transparency-log split-view
· crypto-rotation · clock-manipulation. Each must pass before the
[acceptance gate](citadel_acceptance_gate.md) declares the Citadel operational.
