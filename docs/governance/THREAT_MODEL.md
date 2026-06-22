# System Threat Model

> Status: draft — owner TBD. Part of Guardian governance (docs/governance/).

STRIDE + agentic (OWASP Agentic) + safeguarding threat model for Guardian.

- Assets & trust boundaries (see TRUST_BOUNDARIES.md)
- Adversaries: external attacker, malicious insider, compromised model/connector, malicious repo content, supply-chain attacker
- Agentic risks: prompt injection (direct/indirect), tool abuse, privilege escalation, memory poisoning, data exfiltration
- Component models: crypto layer → ../crypto_threat_model.md; safeguarding → SAFEGUARDING (area 28)
- Mitigations map to core/policy_gate.py, security/crypto, and the hardening roadmap
