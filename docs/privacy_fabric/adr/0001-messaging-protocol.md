# ADR 0001 — Messaging protocol selection (Signal vs MLS)

- **Status:** Proposed (awaiting professional cryptographer sign-off — Privacy Fabric Epic 2)
- **Date:** 2026-06-22
- **Deciders:** cryptography specialist (owner), platform eng, privacy counsel
- **Context source:** [../messaging_crypto.md](../messaging_crypto.md)

## Context

INVISABLE Life / Chat needs end-to-end encrypted 1:1 chats, large private groups, and
group calls. Per Rule 0 (**do not invent message encryption**), we integrate established,
peer-reviewed specifications only. We must pick a protocol per conversation type and pin a
versioned suite, with **no silent downgrade** between conversation types.

## Decision

| Conversation type | Protocol | Rationale |
| ----------------- | -------- | --------- |
| Private 1:1 chat | **Signal Protocol** — X3DH/**PQXDH** + Double Ratchet + Sesame | Forward secrecy + post-compromise security; per-device sessions; async prekeys; post-quantum initial agreement |
| Large private groups | **MLS (RFC 9420)** | Designed for async encrypted groups from 2 to thousands; efficient tree-based membership/key updates vs sender-key |
| Group call media | **SFrame (RFC 9605)** over WebRTC; call keys via MLS | SFU forwards media with routing metadata only, never decrypting |

A versioned cryptographic abstraction pins, per type: protocol suite · cipher suite · key
lifecycle · device lifecycle · migration procedure · backward-compatibility period. Selection
is server-asserted but **client-verified**; a conversation never silently downgrades.

## Open decision items (block "Accepted")

1. **libsignal adoption** — the official implementation is **AGPL-3.0** and unsupported for
   use outside Signal with APIs that may change. Requires: licensing review, a pinned
   compatibility layer, and a maintenance plan. Alternative: an independently reviewed
   Signal Protocol implementation.
2. **MLS implementation** choice + cipher-suite selection (incl. post-quantum posture).
3. **1:1 ↔ group migration** and emergency key/device **revocation** procedures.
4. Interop boundary between Signal (1:1) and MLS (groups) — explicitly *not* casually mixed.

## Consequences

- **Positive:** Signal-level guarantees per type; group efficiency from MLS; calls stay E2EE
  end to end; clear, reviewable suite definitions.
- **Negative / risk:** two protocol stacks to maintain; libsignal licensing/maintenance
  overhead; migration complexity.
- **Guardian impact:** none on plaintext — Guardian never holds keys or reads content
  (enforced by `policies/privacy_invariants.yaml`). Guardian's only role here is the
  **Verifier** over key transparency — see [ADR 0002](0002-key-transparency.md).

## Status tracking

This ADR realises Privacy Fabric **Epic 2** ([../epics.md](../epics.md)). It stays *Proposed*
until a professional cryptographer signs off the open items above.
