# Crypto Security Policy

Mandatory rules for cryptography across INVISABLE Guardian and the PWA. The Guardian
crypto-policy checker (`security/crypto/cryptoPolicyChecker.ts`) enforces the verifiable
ones in CI; the rest are review gates.

## Rules

1. **No custom cryptography.** Use argon2, libsodium, jose only. New primitives require
   security review and an established library.
2. **No plaintext passwords.** Argon2id only, unique per-hash salt, OWASP parameters,
   optional server-side pepper kept in a secret store.
3. **No fast hashes for passwords.** MD5/SHA-1/SHA-256 must never hash passwords. (SHA-256
   is allowed for integrity, e.g. the audit chain and hashing high-entropy refresh tokens.)
4. **No auth tokens in localStorage.** Sessions use HttpOnly+Secure+SameSite cookies;
   access tokens are short-lived and delivered via that flow.
5. **No secrets committed to the repo.** Enforced by Gitleaks/TruffleHog + the checker.
6. **No sensitive data cached by the PWA service worker.** No auth/health/profile responses
   in the cache.
7. **No private health/disability data in logs.**
8. **No encryption keys stored beside encrypted records.** Envelope encryption; KEK in a
   KMS/secret store.
9. **All sensitive exports encrypted.** Use `encryptedExports`; never emit raw sensitive data.
10. **All admin access logged** with tamper-evident integrity (`auditLogIntegrity`).
11. **All crypto libraries pinned and scanned.** Exact versions; bumps reviewed + scanned.

## OWASP Password Storage compliance

- Algorithm: **Argon2id** (memory-hard, side-channel resistant).
- Parameters: m=65536 KiB (64 MiB), t=3, p=1 (≥ OWASP minimums), tunable + upgrade-on-login.
- **Unique salt** per hash (library-generated CSPRNG, stored in the PHC string).
- **Slow, memory-hard** — never a fast hash.
- Plaintext is never stored or logged.

## Authentication policy

- **Prefer passkeys (WebAuthn) and authenticator (TOTP) MFA over SMS** (SIM-swap risk).
  Tokens record the methods used in the `amr` claim.
- Sessions: `__Host-` cookie, HttpOnly, Secure, SameSite=Strict, short max-age.
- Access tokens: ≤ 10 min, algorithm-pinned (HS256), bound to a session id (`sid`).
- Refresh tokens: opaque, hashed at rest, **rotated** on every use, with **reuse detection**
  that revokes the whole token family on replay.
- **Sensitive actions require reauthentication** (`requiresReauth` on `auth_time`).

## Key management policy

- DEKs are random 256-bit keys; wrapped by a KEK before storage.
- The KEK lives in a separate trust boundary (KMS / Vault / cloud KMS), never in the DB.
- Key rotation re-wraps DEKs under the new KEK; data does not need re-encrypting unless a
  DEK is rotated.

## Incident handling

- On suspected token theft: refresh-token reuse detection auto-revokes the family.
- On suspected key compromise: rotate the KEK, re-wrap DEKs, and (if a DEK leaked) re-encrypt
  affected fields and force reauth.
- On audit tampering: `auditLogIntegrity.verify()` fails → treat as a security incident.
