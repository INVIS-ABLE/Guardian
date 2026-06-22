# ADR 0002 — Key transparency & the Guardian Verifier

- **Status:** Accepted (verifier reference implemented; production directory pending)
- **Date:** 2026-06-22
- **Deciders:** platform eng (owner), cryptography specialist, privacy counsel
- **Realises:** Privacy Fabric **Epic 3** ([../epics.md](../epics.md))

## Context

End-to-end encryption (ADR 0001) is weakened if a malicious or compromised server can
secretly substitute a user's identity key. We need users (and an independent monitor) to be
able to **detect** silent key replacement, without weakening the privacy boundary that keeps
Guardian out of plaintext.

## Decision

Operate an **append-only, verifiable key directory**:

- Append-only log of public key leaves *(identity, device, public key, epoch, recovery)*.
- **Inclusion** and **consistency** proofs; client-side verification.
- **Signed checkpoints** (Ed25519 in production) stored **outside** the messaging service.
- Key-change notifications; device-specific key history; **no silent key replacement** — a
  device's key changes only via a leaf explicitly flagged `recovery`, which is displayed to
  contacts.
- **Independent monitors**, including the **Guardian Verifier**.

### The Guardian Verifier

Implemented in [`core/verifier.py`](../../../core/verifier.py) (tested in
`tests/test_verifier.py`). It checks:

- **Checkpoint signature** + that the signed root matches the recomputed root at that size.
- **Consistency** — a later log must extend an earlier checkpoint (append-only; no history rewrite).
- **Inclusion** — a given leaf is in the log.
- **Silent key replacement** — a device key changing without a `recovery` leaf raises
  `silent_key_replacement:<identity>/<device>`.

`monitor()` returns a `VerifierReport(ok, size, root, alerts)`.

### Boundary (enforced)

The Verifier ingests **public data only**. It has no method to read message plaintext, media,
or private/conversation keys, and it **rejects** any leaf carrying such fields
(`VerifierBoundaryError`). This matches `guardian_verifier` in
[`policies/privacy_invariants.yaml`](../../../policies/privacy_invariants.yaml): it reads
inclusion/consistency proofs, signed checkpoints, and device key history — and never private
content or keys.

## Consequences

- **Positive:** silent identity-key substitution is detectable by clients *and* an
  independent Guardian monitor; Guardian gains a real privacy-protective role without ever
  touching plaintext.
- **Signing:** checkpoints are signed via [`core/signing.py`](../../../core/signing.py),
  which uses **Ed25519** when the `cryptography` backend is functional and falls back to a
  deterministic HMAC only where it is not (CI/offline), selected by a runtime self-test. The
  primitive is swappable; the verification logic is fixed. The same module signs connector
  execution authorizations (see below).
- **Pending:** checkpoints must be stored **outside** the messaging service, backed by a real
  verifiable-log/transparency backend, with **>1 independent monitor** beyond the Guardian Verifier.
- **Guardian impact:** the Verifier is Guardian's single privacy-adjacent active role; all
  other privacy "must never" actions remain globally blocked.
