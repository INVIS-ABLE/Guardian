# The six roots of trust

Before any sensitive capability is issued, Guardian independently verifies **six roots of
trust** (target architecture §5). Failing any required root denies issuance — fail closed.
This is the "are we even allowed to act?" gate that sits *in front of* the one-use
capability token (`core/tools/capability.py`), enforced in the issuance path
(`core/tools/executor.py`) and implemented in `core/roots_of_trust.py`.

```
request ─▶ resolve signed manifest ─▶ human approval ─▶ SIX ROOTS OF TRUST ─▶ issue one-use
                                                          (fail closed)          capability
```

## The roots

| Root | Independently verifies (evidence model) |
| ---- | --------------------------------------- |
| **human** | authenticated · phishing-resistant · active (not suspended) · role · requester ≠ approver (no self-review) · valid, unexpired, **envelope-bound** approval · **two distinct reviewers for production** |
| **workload** | SPIFFE id · namespace · service account · image digest · runtime profile · valid cert · not revoked |
| **machine** | Secure Boot · TPM attestation · measured boot · IMA · approved firmware · not quarantined |
| **software** | approved repo · commit · verified build · SBOM · provenance · signature · approved builder · approved deps · policy+connector digest |
| **target** | fresh ownership evidence · environment · resolved addresses · no post-authorisation DNS change · not third-party |
| **evidence** | evidence service available · immutable append OK · attestation generated · trace + case ids · **Shadow verification received the event** |

Every field is a **positive assertion that defaults to its fail-closed value**, so an
empty or partially-populated `TrustContext` fails: absence of proof is not proof
(`test_empty_context_fails_every_root`). Each root is checked independently — knocking out
any one root's evidence fails only that root (`test_each_root_is_independently_required`).

## Posture (fail closed)

`require_roots()` makes the gate mandatory in `staging`/`production` (or when
`GUARDIAN_REQUIRE_ROOTS=1`) — exactly like signed manifests and the policy gate. In a
`development` posture without an explicit gate, the roots are not enforced, preserving local
ergonomics. When enforced, a **missing** trust context is itself a refusal
(`ROOTS_OF_TRUST_FAILED`), not a pass.

## Relationship to the rest of the authority stack

The roots sit alongside the existing authority components, each owning one concern:

- **policy gate** (`core/policy_gate.py`) — *may this action happen at all?* (OPA-backed)
- **roots of trust** (`core/roots_of_trust.py`) — *are all six trust anchors verified?*
- **capability token** (`core/tools/capability.py`) — *one-use, bound permission to run it*
- **Shadow Guardian** (`shadow_guardian/`) — *independent re-check; freeze on divergence*

A capability that satisfies policy but lacks a verified machine/workload/evidence anchor is
refused before any token is minted.

## Producing a TrustContext from real evidence

The gate verifies a `TrustContext`; `core/trust_producers.py` *builds* one from the concrete
evidence Guardian already has, so the roots are populated from facts — not hand-set booleans:

| Root | Producer | Real source |
| ---- | -------- | ----------- |
| human | `human_trust_from(principal, approvals, …)` | `identity.oidc.Principal` + `core.guardrails.Approval` (validity + envelope binding) |
| workload | `workload_trust_from(credential, …)` | `identity.credentials.Credential.valid()` |
| evidence | `evidence_trust_from(receipt, …)` | a real `core.evidence.store.EvidenceReceipt` from an immutable append |
| machine | `machine_trust_from(report)` | verified TPM/Keylime attestation result |
| software | `software_trust_from(report)` | verified SBOM/provenance/signature result |
| target | `target_trust_from_ownership(evidence, …)` | the live `ownership.OwnershipVerifier` (DNS-TXT challenge / GitHub-App installation) + a DNS-change check against the authorised address baseline |

Each producer is **fail closed**: a field is asserted only when its evidence supports it
(`tests/test_trust_producers.py` — an expired credential fails the workload root, an unbound
approval fails the human envelope-binding, a missing receipt fails the evidence root, etc.).
The machine/software/target producers are the integration points for the attestation,
provenance, and ownership systems; until those land, an incomplete report keeps the root
negative rather than assuming trust.

