# Guardian capability inventory

Capabilities are the stable vocabulary the Brain and agents speak. Two registries
exist today and are preserved through Wave 0:

1. **Router capabilities** (`core/router.py` `CAPABILITY_MAP`) — the legacy
   capability→tool routing the CLI and agents already use.
2. **Signed tool-manifest capabilities** (`core/tools/registry.py`
   `default_registry()`) — pinned, signed manifests with one-use capability tokens.

The Final Power-Up capability vocabulary (`code.sast`, `secret.scan`, …) is the
target; it will be mapped onto these via compatibility adapters in later waves so
existing names keep working. Enforced by `tests/test_repo_inventory.py`.

## Router capabilities

| capability | kind | tool |
| --- | --- | --- |
| `api_security` | connector | `zap` |
| `banned_user_simulation` | simulator | `banned_user_return` |
| `codeql` | connector | `codeql` |
| `container` | connector | `trivy` |
| `dast` | connector | `zap` |
| `dependency` | connector | `trivy` |
| `login_resilience` | connector | `hydra` |
| `moderator_abuse_simulation` | simulator | `moderator_abuse` |
| `password_strength` | connector | `hashcat` |
| `privacy_simulation` | simulator | `privacy_leak` |
| `secrets` | connector | `gitleaks` |
| `static_code` | connector | `semgrep` |

## Signed tool-manifest capabilities

| capability | tool | environments | approval | network |
| --- | --- | --- | --- | --- |
| `code_analysis` | `codeql` | development, staging | False | deny_all |
| `container_scan` | `trivy` | development, staging | False | deny_all |
| `dast` | `zap` | staging | False | egress_allowlist |
| `dependency_scan` | `trivy` | development, staging | False | deny_all |
| `login_resilience` | `hydra` | staging | True | egress_allowlist |
| `password_strength` | `hashcat` | staging | True | deny_all |
| `secrets_scan` | `gitleaks` | development, staging | False | deny_all |
| `static_code_scan` | `semgrep` | development, staging | False | deny_all |
