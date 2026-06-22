# Crypto Architecture, Implementation Plan & Package Choices

Privacy-first architecture for INVISABLE Guardian + PWA. **No custom cryptography** — only
established, audited libraries. Every decision below is deliberate and reviewable.

## Principles

1. Established libraries only (argon2, libsodium, jose). Never roll our own primitive.
2. Defence in depth: hashing, AEAD, envelope keys, hardened sessions, tamper-evident audit.
3. Keys live apart from data (envelope encryption; KEK in a KMS/secret store).
4. The client holds message/E2EE keys; the server only relays ciphertext.
5. Everything is verified by the Guardian crypto-policy checker (module 9) in CI.

## Module map

| # | Module | Primitive / library | Decision |
| - | ------ | ------------------- | -------- |
| 1 | passwordHashing | Argon2id (`argon2`) | OWASP first choice; m=64MiB,t=3,p=1; unique salt; optional pepper. |
| 2 | sessionSecurity | `cookie` + hardened defaults | HttpOnly+Secure+SameSite=Strict, `__Host-` prefix, 256-bit opaque id. |
| 3 | tokenRotation | `jose` JWT + opaque refresh | 10-min access tokens; refresh rotation with reuse detection; step-up reauth. |
| 4 | keyManagement | XChaCha20-Poly1305 (libsodium) | DEK wrapped by KEK; KEK from KMS/env, never beside data. |
| 5 | fieldEncryption | XChaCha20-Poly1305 AEAD | Per-field nonce; AAD binds `table:record:field` (no cut-and-paste). |
| 6 | encryptedExports | secretstream + Argon2id / sealed box | Passphrase or recipient-key; chunked AEAD for large exports. |
| 7 | e2eeMessaging | libsodium `crypto_box` (baseline) / libsignal | Authenticated E2EE; libsignal for Double-Ratchet forward secrecy. |
| 8 | auditLogIntegrity | SHA-256 hash chain + Ed25519 | Tamper-evident admin log; optional non-repudiation signatures. |
| 9 | cryptoPolicyChecker | static analysis | Verifies all crypto rules; fails CI on high/critical. |

## Data-at-rest flow (sensitive profile/health field)

```
plaintext field ──▶ fieldEncryption.encryptField(DEK, value, {table,record,field})
                         │ AEAD (XChaCha20-Poly1305), AAD = context
                         ▼
                   { nonce, ct }  ── stored in the record
DEK ──▶ keyManagement.wrapDek(KEK) ──▶ { kekId, nonce, ct }  ── stored as the wrapped key
KEK ── lives in KMS / secret store, NEVER in the database
```

Decrypt reverses it: resolve KEK (KMS) → unwrap DEK → AEAD-decrypt the field with matching
context. A wrong record/field/context fails authentication.

## Auth flow (login → access → refresh → step-up)

```
login (password=Argon2id verify; prefer passkey/TOTP MFA over SMS)
  └▶ set __Host- session cookie (HttpOnly, Secure, SameSite=Strict)
  └▶ issue 10-min access JWT (jose, HS256 pinned) with amr + auth_time
  └▶ issue refresh token (opaque; only SHA-256 hash stored), family started
access expires ──▶ rotateRefreshToken() ──▶ new access + new refresh (old invalidated)
   replay of a rotated token ──▶ ReuseDetected ──▶ whole family revoked
sensitive action ──▶ requiresReauth(auth_time) ? force reauth : proceed
```

## Implementation plan (phased)

- **Phase 1 (this PR):** modules 1–9 implemented + 42 tests + the policy checker + CI.
  Flagship working modules: password hashing (1) and the policy checker (9).
- **Phase 2:** integrate into the PWA/app — wire `keyManagement` to a real KMS (AWS KMS /
  Vault), add WebAuthn/passkey registration, and run the policy checker against the app repo.
- **Phase 3:** enable libsignal for E2EE; add key-rotation jobs and re-wrap tooling.
- **Phase 4:** field-encryption migration tooling + envelope re-encryption on KEK rotation.

## Package choices

See [`../security/README.md`](../security/README.md) for the pinned versions and rationale.
All crypto libraries are exact-pinned and scanned (Trivy/OSV in CI); the policy checker
enforces pinning.
