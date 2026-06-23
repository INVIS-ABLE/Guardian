# Crown Citadel — wave status

Honest delivery tracker for the Citadel waves (docs/citadel_plane.md, citadel_acceptance_gate.md).
A wave is **delivered** only when its acceptance criteria pass with tests. Anything not yet built is
**planned** — never marked done prematurely.

| Wave | Scope | Status | Evidence |
|------|-------|--------|----------|
| 20 | Citadel reconciliation — manifests, configs, invariant tests | **delivered** | `docs/citadel_*`, `docs/architecture/citadel_*.yaml`, `configs/citadel/*`, `tests/test_citadel_*` (49 tests) |
| 21 | Hardware root of trust | **delivered** | `citadel/root_of_trust/` + `tests/test_citadel_root_of_trust.py` (see below) |
| 22 | Confidential worker fabric | **delivered** | `citadel/confidential/` + `tests/test_citadel_confidential.py` (see below) |
| 23 | Cryptographic agility | **delivered** | `citadel/crypto_agility/` + `tests/test_citadel_crypto_agility_runtime.py` |
| 24 | Key custody & ceremonies | planned | — |
| 25 | Formal state-machine proof | planned | — |
| 26 | Protocol proof laboratory | planned | — |
| 27 | Verified policy pipeline | partial | OPA + `core/policy_gate.py` parity (`tests/test_opa_parity.py`) |
| 28 | Reproducible build foundry | partial | `supplychain/*` (admission/provenance/sbom) |
| 29 | Transparency fabric | planned | — |
| 30 | Exposure intelligence | partial | `ownership/verifier.py`, `core/twin` |
| 31 | Deception grid | planned | — |
| 32 | Data-protection & exfiltration | partial | `isolation/egress.py`, gitleaks |
| 33 | Device & endpoint integrity | partial | folded into Wave 21 platform inventory |
| 34 | Fraud & abuse graph | planned | — |
| 35 | Privacy-preserving analytics | planned | — |
| 36 | Immutable cyber vault | partial | `recovery/backup.py`, `recovery/drill.py` |
| 37 | Chaos & continuity | partial | `core/twin`, `resilience/health.py` |
| 38 | Secure time, Shadow & quorum | partial | `shadow_guardian/verifier.py`, `orchestration/approvals.py` |
| 39 | Citadel final acceptance | planned | gated by `docs/citadel_acceptance_gate.md` |

## Wave 21 — Hardware root of trust (delivered)

`citadel/root_of_trust/` builds the fabric around the existing authoritative owner
`core/machine_attestation.py` (reused, not duplicated) and adds the **independent verifier**:

- **Platform identity + inventory** (`schemas.py`, `inventory.py`) — the source of truth for which
  platforms are approved; an unknown platform is never attested.
- **Enrolment / revocation** (`enrolment.py`, `revocation.py`) — bind a platform to approved
  inventory; quarantine (reversible) and revoke (permanent).
- **Collectors** (`measured_boot.py`, `ima.py`, `tpm.py`, `keylime.py`) — measured/Secure Boot PCRs,
  IMA/EVM runtime state, signed TPM quotes, and the Keylime client seam (with a `SoftwareTpm` /
  `StaticKeylimeClient` stand-in so the full signature path is exercised offline).
- **Independent verifier + gate** (`verifier.py`) — re-derives the verdict, cross-checks the
  authoritative owner (divergence fails closed), owns nonce issuance + one-shot consumption
  (anti-replay) and freshness, and on drift emits a durable `guardian.boot.drift` event, opens a
  case, and quarantines the platform. Its output maps to `core.roots_of_trust.MachineTrust`, which
  the existing capability broker already enforces.
- **PWA Platform Integrity** (`integrity_view.py` + `dashboard/app.py` `/api/platform-integrity`).

**Acceptance (all tested in `tests/test_citadel_root_of_trust.py`):** an unknown platform cannot
pass the machine root (no production capability); attestation evidence (a content-addressable
digest) attaches to execution; drift creates a durable event **and** a case and quarantines the
platform. The independent verifier agrees with the authoritative owner.

## Wave 22 — Confidential worker fabric (delivered)

`citadel/confidential/` builds on `isolation.sandbox` (the worker-isolation owner, reused) and
Wave 21's platform attestation:

- **Profiles** (`profiles.py`) — six worker classes mapped to the strict sandbox posture plus
  confidential-compute requirements (attestation, measured/signed image, ephemerality, externally
  committed evidence). Confidential classes require attestation; sandbox classes do not.
- **Workload attestation** (`attestation.py`) — combines the Wave 21 platform attestation with a
  canonical, content-addressable **workload measurement** (image + class + config).
- **Attestation-bound secret release** (`secret_release.py`) — a secret is sealed to one exact
  workload measurement and released only against a passing attestation that matches it.
- **Runtimes** (`confidential_containers.py` CoCo/Kata owner; `gramine.py`, `enarx.py` specialist
  adapters) — launch / attest / destroy, ephemeral by construction.
- **Independent verifier** (`verifier.py`) — commits worker evidence to an independent sink
  (outside the worker's control) and verifies worker destruction (no worker outlives its job).

**Acceptance (tested in `tests/test_citadel_confidential.py`):** failed attestation prevents secret
release; release is tied to the exact workload measurement; sensitive worker evidence is
independently committed; worker destruction is verified.
