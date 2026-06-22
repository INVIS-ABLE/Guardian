# Model Risk Register

> Status: draft — owner TBD. Part of Guardian governance (docs/governance/).

AI model risks and controls (blueprint areas 3, 10–12).

- | ID | Risk | Control |
- | M-001 | Prompt injection (direct/indirect) | model gateway + untrusted-output handling + PyRIT tests |
- | M-002 | Data exfiltration via outputs | DLP redaction + egress gateway |
- | M-003 | Memory poisoning | RAG quarantine + promotion flow (area 10) |
- | M-004 | Unsafe provider fallback | no silent fallback; allowlists |
