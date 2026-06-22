# INVISABLE Security — Encryption & Hashing Layer

Privacy-first cryptography for INVISABLE Guardian and the INVISABLE PWA. **Established
libraries only — no custom cryptography.** Every crypto decision is documented in
[`../docs/crypto_architecture.md`](../docs/crypto_architecture.md) and the sibling docs.

## Repo structure

```
security/
├── package.json            exact-pinned crypto deps (no ^/~)
├── tsconfig.json           strict TS
├── vitest.config.ts        test runner
└── crypto/
    ├── _sodium.ts          shared libsodium (WASM) loader
    ├── passwordHashing.ts      (1) Argon2id password hashing
    ├── sessionSecurity.ts      (2) HttpOnly/Secure/SameSite + __Host- cookies
    ├── tokenRotation.ts        (3) short-lived JWT access + refresh rotation + reuse detection
    ├── keyManagement.ts        (4) envelope encryption (DEK wrapped by KEK; keys kept apart)
    ├── fieldEncryption.ts      (5) AEAD field-level encryption (profile/health data)
    ├── encryptedExports.ts     (6) encrypted backup/export (passphrase or recipient key)
    ├── e2eeMessaging.ts        (7) optional E2EE (libsodium baseline; libsignal path)
    ├── auditLogIntegrity.ts    (8) tamper-evident admin audit log (hash chain + Ed25519)
    ├── cryptoPolicyChecker.ts  (9) Guardian crypto-policy checker (static verifier)
    └── __tests__/              one test file per module (42 tests)
```

## Package choices (and why)

| Need | Package (pinned) | Why |
| ---- | ---------------- | --- |
| Password hashing | `argon2` 0.41.1 | node binding to the PHC reference Argon2; OWASP's first choice (Argon2id). |
| AEAD / KDF / boxes / signatures | `libsodium-wrappers-sumo` 0.7.15 | Audited libsodium (jedisct1) as WASM — same code in Node and the PWA. |
| Access tokens | `jose` 5.9.6 | Modern, audited JWS/JWT; algorithm pinning prevents alg-confusion. |
| Cookies | `cookie` 1.0.2 | RFC 6265 serialization; we layer hardened defaults on top. |
| Optional Signal E2EE | `@signalapp/libsignal-client` 0.62.0 | Official X3DH + Double Ratchet for full forward secrecy. |

Crypto libraries are **exact-pinned**; the policy checker (module 9) fails CI if a `^`/`~`
range sneaks in. Bumps go through review + scanning.

## Run

```bash
cd security
npm install
npm test            # vitest — 42 tests across all 9 modules
npm run typecheck   # tsc --noEmit
npm run crypto:check  # run the Guardian crypto-policy checker over the repo
```

## Hard rules (enforced here)

- No custom crypto; established libraries only.
- No plaintext passwords; Argon2id with unique salts.
- No encryption keys stored beside encrypted data (envelope encryption).
- No auth tokens in localStorage; HttpOnly/Secure/SameSite cookies + short-lived tokens.
- Passkeys/authenticator MFA preferred over SMS (see `tokenRotation` `amr` claims).
- Sensitive actions require reauthentication (`requiresReauth`).
- All sensitive exports encrypted; admin access logged with tamper-evidence.
