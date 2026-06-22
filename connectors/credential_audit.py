"""Credential-audit connectors — AUTHORISED DEFENSIVE USE ONLY.

These wrap well-known credential-strength / login-resilience tools so Guardian can
*defensively* verify INVISABLE auth controls:

  * hashcat / John the Ripper — audit PASSWORD-POLICY STRENGTH against a SYNTHETIC test
    corpus (or owned, consented test hashes). Used to confirm that weak/breached
    passwords are rejected and that the policy resists offline cracking. NEVER run
    against real user password hashes or third-party data.
  * THC Hydra — validate ONLINE LOGIN DEFENCES (rate limiting, lockout, MFA) on OWNED
    staging using TEST accounts only, to confirm credential-stuffing / password-spray
    are contained. This is a high-volume, account-locking action and is therefore
    forced through the human-approval gate.

Hard boundaries (enforced by core.guardrails + this module):
  - owned domains/repos only (assert_owned)
  - registered test accounts only (assert_test_account) — never real users
  - real_user_data_access stays globally blocked; these tools never touch real creds
  - credential_audit and the high-volume/lockout actions require recorded human approval
  - dry-run by default

Upstream tools (references):
  - hashcat:           https://github.com/hashcat/hashcat
  - John the Ripper:   https://github.com/openwall/john
  - THC Hydra:         https://github.com/vanhauser-thc/thc-hydra
"""

from __future__ import annotations

from typing import Any

from .base import BaseConnector, ConnectorResult


class _PasswordPolicyAuditConnector(BaseConnector):
    """Shared base for offline password-strength auditing (hashcat / john).

    Operates only on a SYNTHETIC/consented test corpus of hashes. Requires the
    ``credential_audit`` mode and a recorded human approval (the ``credential_audit``
    action is globally approval-gated). Refuses if no explicit synthetic corpus is given.
    """

    mode = "credential_audit"
    action = "credential_audit"

    def run(self, *, repo: str | None = None, target: str | None = None, **kwargs: Any) -> ConnectorResult:
        corpus = kwargs.get("hash_corpus")
        if not corpus:
            raise PermissionError(
                f"{self.tool}: a synthetic/consented 'hash_corpus' is required. "
                "Guardian never audits real user password hashes."
            )
        if kwargs.get("synthetic") is not True:
            raise PermissionError(
                f"{self.tool}: refusing — set synthetic=True to confirm the corpus contains "
                "no real user data. Only synthetic/consented test hashes may be audited."
            )
        return super().run(repo=repo, target=target, **kwargs)


class HashcatConnector(_PasswordPolicyAuditConnector):
    """hashcat — offline password-policy strength audit (synthetic corpus only)."""

    tool = "hashcat"
    binary = "hashcat"

    def build_command(self, *, repo: str | None = None, target: str | None = None, **kwargs: Any) -> list[str]:
        corpus = kwargs["hash_corpus"]
        hash_mode = str(kwargs.get("hash_mode", "1400"))  # e.g. 1400 = sha256
        wordlist = kwargs.get("wordlist", "policy-audit/weak-and-breached.txt")
        return [
            self.binary,
            "-m", hash_mode,
            "-a", "0",                 # straight wordlist (policy audit, not exhaustive)
            "--potfile-disable",       # do not persist recovered material
            "--quiet",
            corpus,
            wordlist,
        ]

    def parse(self, result: ConnectorResult) -> ConnectorResult:
        # Report only counts/policy verdicts — never the cracked plaintext itself.
        cracked = sum(1 for line in result.stdout.splitlines() if ":" in line)
        result.findings.append(
            {"metric": "weak_passwords_cracked_in_audit", "count": cracked,
             "verdict": "policy_too_weak" if cracked else "policy_resisted_audit"}
        )
        result.note = "Password-policy audit (synthetic corpus). Plaintext not recorded."
        return result


class JohnConnector(_PasswordPolicyAuditConnector):
    """John the Ripper — offline password-policy strength audit (synthetic corpus only)."""

    tool = "john"
    binary = "john"

    def build_command(self, *, repo: str | None = None, target: str | None = None, **kwargs: Any) -> list[str]:
        corpus = kwargs["hash_corpus"]
        wordlist = kwargs.get("wordlist", "policy-audit/weak-and-breached.txt")
        fmt = kwargs.get("format")
        cmd = [self.binary, f"--wordlist={wordlist}"]
        if fmt:
            cmd.append(f"--format={fmt}")
        cmd.append(corpus)
        return cmd

    def parse(self, result: ConnectorResult) -> ConnectorResult:
        result.note = "Password-policy audit (synthetic corpus). Use 'john --show' offline; plaintext not recorded here."
        return result


class HydraConnector(BaseConnector):
    """THC Hydra — validate ONLINE login defences on OWNED staging with TEST accounts.

    Confirms rate limiting / lockout / MFA contain credential-stuffing and password-spray.
    This is a high-volume, account-locking action: it requires a recorded human approval
    (``high_volume_test`` and ``account_locking_test`` are approval-gated) and an in-scope
    owned target plus a registered test account.
    """

    tool = "hydra"
    binary = "hydra"
    mode = "credential_audit"
    # Map to the approval-gated, high-impact action labels so the human gate is enforced.
    action = "high_volume_test"

    def run(self, *, repo: str | None = None, target: str | None = None, **kwargs: Any) -> ConnectorResult:
        if target is None:
            target = self.scope.allowed_domains[0] if self.scope.allowed_domains else None
        if target is None:
            raise PermissionError("hydra requires an in-scope owned target domain; none available.")
        test_account = kwargs.get("test_account")
        if not test_account:
            raise PermissionError(
                "hydra: a registered test_account is required — Guardian never targets real users."
            )
        # Enforce both approval-gated actions implied by an online login-resilience test.
        self.guardrails.assert_approved("account_locking_test")
        self.guardrails.assert_test_account(test_account)
        return super().run(repo=repo, target=target, **kwargs)

    def build_command(self, *, repo: str | None = None, target: str | None = None, **kwargs: Any) -> list[str]:
        test_account = kwargs["test_account"]
        wordlist = kwargs.get("wordlist", "policy-audit/spray-candidates.txt")
        service = kwargs.get("service", "https-post-form")
        path = kwargs.get("form_path", "/api/auth/login:username=^USER^&password=^PASS^:F=invalid")
        # Controlled: low task count + small wordlist so the test stays within rate limits
        # and demonstrably trips the defence rather than causing uncontrolled load.
        tasks = str(kwargs.get("tasks", 4))
        return [
            self.binary,
            "-l", test_account,
            "-P", wordlist,
            "-t", tasks,
            "-f",                       # stop on first success (we expect lockout first)
            f"{target}",
            service,
            path,
        ]

    def parse(self, result: ConnectorResult) -> ConnectorResult:
        result.note = (
            "Login-defence validation on owned staging with a test account. "
            "Expectation: rate limiting/lockout/MFA stop the attempt — that is a PASS."
        )
        return result
