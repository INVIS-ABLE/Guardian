# Key Management Plan

> Status: draft — owner TBD. Part of Guardian governance (docs/governance/).

Key hierarchy, rotation, ceremonies (blueprint area 14).

- Hardware-backed root (HSM/KMS/TPM); offline root signing
- Separate signing / encryption / authentication keys; per-environment hierarchies
- Envelope encryption (security/crypto/keyManagement.ts); automatic rotation; versioning
- Threshold/multi-party control for root ops; recovery-key separation
- Compromise playbook; rotation + simulated-compromise tests
