# Guardian Governance

Administrative governance for INVISABLE Guardian (blueprint area 27). These documents are
living artifacts; each has an owner and a review cadence (see SECURITY_TESTING_CALENDAR.md).

| Document | Purpose |
| -------- | ------- |
| [THREAT_MODEL.md](THREAT_MODEL.md) | System threat model (links crypto + safeguarding models) |
| [TRUST_BOUNDARIES.md](TRUST_BOUNDARIES.md) | Management plane vs protected systems; data flows |
| [DATA_CLASSIFICATION.md](DATA_CLASSIFICATION.md) | Data classes and handling rules |
| [ASSET_CRITICALITY.md](ASSET_CRITICALITY.md) | Asset importance for prioritisation |
| [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) | Properties that must always hold + bulletproof gate |
| [RISK_REGISTER.md](RISK_REGISTER.md) | Tracked risks, owners, mitigations |
| [CONTROL_OWNERS.md](CONTROL_OWNERS.md) | Who owns each control |
| [EXCEPTION_PROCESS.md](EXCEPTION_PROCESS.md) | How exceptions are requested, approved, expired |
| [KEY_MANAGEMENT_PLAN.md](KEY_MANAGEMENT_PLAN.md) | Key hierarchy, rotation, ceremonies |
| [INCIDENT_RESPONSE_PLAN.md](INCIDENT_RESPONSE_PLAN.md) | IR roles, severities, runbooks |
| [DISASTER_RECOVERY_PLAN.md](DISASTER_RECOVERY_PLAN.md) | RPO/RTO, restore procedures |
| [MODEL_RISK_REGISTER.md](MODEL_RISK_REGISTER.md) | AI model risks (injection, exfiltration, etc.) |
| [VENDOR_RISK_REGISTER.md](VENDOR_RISK_REGISTER.md) | Third-party/service risks |
| [SECURITY_TESTING_CALENDAR.md](SECURITY_TESTING_CALENDAR.md) | Cadence of tests, drills, reviews |

Each exception requires an owner, justification, compensating controls, expiry, review date,
evidence, and an approver other than the requester. See EXCEPTION_PROCESS.md.
