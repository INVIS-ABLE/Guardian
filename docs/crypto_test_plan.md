# Crypto Test Plan

Every module ships a vitest suite (`security/crypto/__tests__`). 42 tests today. Run:

```bash
cd security && npm test
```

## Coverage per module

| Module | Tests assert |
| ------ | ------------ |
| passwordHashing (1) | Argon2id PHC output; plaintext never present; verify true/false; **unique salt** (same input ⇒ different hash); refuses non-Argon2id material; rehash detection; empty/oversized rejected; pepper. |
| sessionSecurity (2) | HttpOnly+Secure+SameSite+`__Host-` (no Domain); refuses insecure `__Host-`; 256-bit ids; clear cookie; config auditor. |
| tokenRotation (3) | issue/verify access JWT; wrong secret rejected; step-up reauth on stale auth_time; short-secret rejected; refresh rotation; **reuse detection revokes family**; unknown token rejected. |
| keyManagement (4) | wrap/unwrap round-trip; raw DEK absent from blob; wrong KEK fails; EnvKeyProvider missing/loads. |
| fieldEncryption (5) | round-trip; **AAD context binding** stops cut-and-paste; tamper detection; unique nonce. |
| encryptedExports (6) | passphrase round-trip with no plaintext; wrong passphrase fails; recipient round-trip + wrong recipient fails; empty export. |
| e2eeMessaging (7) | authenticated round-trip; wrong recipient fails; sealed-sender; documents no-forward-secrecy baseline. |
| auditLogIntegrity (8) | intact chain verifies; tampering detected; Ed25519 sign/verify + forged key rejected. |
| cryptoPolicyChecker (9) | flags all violation classes in a bad repo; passes a clean pinned repo; every finding has a user-safety impact. |

## Negative / adversarial cases (must stay covered)

- Decryption with wrong key / wrong context / tampered ciphertext **must throw**.
- Verifying a password against a SHA-256 value **must return false** (no accidental accept).
- Replaying a rotated refresh token **must raise `ReuseDetectedError`** and revoke the family.
- The policy checker **must fail CI** (exit 1) on any high/critical finding.

## CI

`.github/workflows/crypto.yml` runs, on changes under `security/`:

1. `npm ci` (uses the committed lockfile — reproducible, pinned).
2. `npm run typecheck`.
3. `npm test` (vitest).
4. `npm run crypto:check` (Guardian crypto-policy checker over the repo; fails on high/critical).

## Future test work

- Property-based tests (fast-check) for encode/decode round-trips.
- Known-answer/interop vectors for E2EE against libsignal once enabled.
- Coverage thresholds and mutation testing for the policy checker rules.
