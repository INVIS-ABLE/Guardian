# Security Standards Mapping

Guardian's checks are anchored to recognised standards so findings are traceable and
audit-friendly. Mappings are intentionally pragmatic for the MVP and expand over time.

## Application security

| Standard            | Use in Guardian                                                      |
| ------------------- | ------------------------------------------------------------------- |
| OWASP **WSTG**      | Test-case catalogue for the API Security + ZAP connectors.          |
| OWASP **ASVS 5.0**  | Verification requirements asserted by Auth/RBAC and Privacy agents. |
| OWASP **SAMM**      | Maturity model for the SAMM-aligned roadmap of Guardian itself.     |
| OWASP **MASVS/MASTG** | Mobile verification (future mobile connector).                    |

## Secure development & supply chain

| Standard        | Use in Guardian                                                          |
| --------------- | ----------------------------------------------------------------------- |
| **NIST SSDF**   | Maps the self-healing workflow (PR + tests + evidence) to SSDF tasks.   |
| **SLSA**        | Provenance/signing targets for build artifacts (Syft/Grype + Cosign).  |

## Defensive behaviour mapping

| Standard            | Use in Guardian                                                     |
| ------------------- | ------------------------------------------------------------------ |
| **MITRE ATT&CK**    | Detection signals in the malware defence library are tagged to ATT&CK techniques for *defensive* mapping only — never to operate offensively. |

### Example ATT&CK → defence mapping (illustrative)

| ATT&CK technique                         | Guardian detection (library key)        | Defensive response            |
| ---------------------------------------- | --------------------------------------- | ----------------------------- |
| T1486 Data Encrypted for Impact          | `ransomware.abnormal_file_encryption`   | isolate_host, trigger_backup_lock |
| T1490 Inhibit System Recovery            | `ransomware.backup_deletion_attempt`    | trigger_backup_lock, alert_admin |
| T1539 Steal Web Session Cookie           | `infostealer.session_export_attempt`    | revoke_tokens, enforce_mfa    |
| T1505.003 Web Shell                      | `web_shell.server_side_command_execution` | quarantine_file, disable_upload_path |
| T1499 Endpoint Denial of Service (abuse) | `scraper_or_botnet.distributed_request_bursts` | rate_limit, challenge   |
| T1195 Supply Chain Compromise            | `supply_chain.unsigned_build`           | block_merge, require_provenance |

> ATT&CK is used **strictly** to understand and defend against adversary behaviour on
> INVISABLE-owned systems. Guardian never executes offensive techniques.
