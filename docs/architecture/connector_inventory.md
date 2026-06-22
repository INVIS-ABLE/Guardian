# Guardian connector inventory

Connectors registered in `connectors.REGISTRY`. Each is a dry-run-aware wrapper that
drives an external security tool through the typed `GuardianConnector` contract
(enumerated actions, allowlisted targets, signed-authorization execution).
Enforced by `tests/test_repo_inventory.py`.

| name | class | binary | mode | trust zone | actions |
| --- | --- | --- | --- | --- | --- |
| `codeql` | CodeQLConnector | `codeql` | code_review | execution | analyze |
| `gitleaks` | GitleaksConnector | `gitleaks` | secrets_scan | execution | detect |
| `hashcat` | HashcatConnector | `hashcat` | credential_audit | execution | credential_audit |
| `hydra` | HydraConnector | `hydra` | credential_audit | execution | high_volume_test |
| `john` | JohnConnector | `john` | credential_audit | execution | credential_audit |
| `semgrep` | SemgrepConnector | `semgrep` | code_review | execution | scan |
| `trivy` | TrivyConnector | `trivy` | dependency_scan | execution | scan |
| `zap` | ZapConnector | `zap.sh` | zap_scan | execution | baseline |

## Simulators

Defensive abuse simulators registered in `simulators.REGISTRY`.

| name | class | mode |
| --- | --- | --- |
| `banned_user_return` | BannedUserReturnSimulator | abuse_simulation |
| `moderator_abuse` | ModeratorAbuseSimulator | abuse_simulation |
| `privacy_leak` | PrivacyLeakSimulator | privacy_leakage |
