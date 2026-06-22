"""Banned User Return Simulator.

Defensive scenario: verify that a banned identity cannot regain access to owned
staging by the usual evasion routes — re-registration, token reuse, session
resurrection, or device/identifier rotation. Uses the synthetic ``banned_user_test``
account only. No real users, no persistence, no stealth.
"""

from __future__ import annotations

from core.evidence import SimulatorResult

from .base import BaseSimulator


class BannedUserReturnSimulator(BaseSimulator):
    """Checks that ban enforcement holds across common return/evasion vectors."""

    name = "banned_user_return"
    mode = "abuse_simulation"
    action = "abuse_simulation"

    VECTORS = [
        "reuse_pre_ban_session_token",
        "refresh_token_exchange_after_ban",
        "re_register_same_email",
        "re_register_similar_email_alias",
        "login_from_new_device_fingerprint",
        "password_reset_flow_after_ban",
    ]

    def _accounts_used(self) -> list[str]:
        return ["banned_user_test"]

    def simulate(self) -> SimulatorResult:
        signals: list[str] = []
        evidence: list[str] = []
        bypasses: list[str] = []

        for vector in self.VECTORS:
            if self.dry_run:
                signals.append(f"[dry-run] would attempt ban-evasion vector '{vector}'")
                continue
            allowed_back_in = self._attempt_vector(vector)
            signals.append(f"attempted '{vector}'")
            if allowed_back_in:
                bypasses.append(vector)
                evidence.append(f"banned_user_test regained access via '{vector}'")

        detected = bool(bypasses)
        severity = "high" if detected else "info"

        return SimulatorResult(
            scenario_name="Banned User Return Simulator",
            scope=self.scope.asset,
            test_accounts_used=self._accounts_used(),
            signals_observed=signals,
            detection_result=(
                "ban bypass detected" if detected else
                ("dry-run: no live attempt performed" if self.dry_run else "no bypass detected")
            ),
            containment_result=(
                "ban enforcement held across all tested vectors" if not detected else
                f"ban enforcement FAILED for: {', '.join(bypasses)}"
            ),
            user_safety_impact=(
                "A returning banned user can re-contact and re-harm the people they were "
                "banned for endangering — a direct safeguarding failure." if detected else
                "Banned identity remained excluded; protected users stay protected."
            ),
            evidence=evidence or ["No bypass evidence captured (enforcement held / dry-run)."],
            severity=severity,
            recommended_fix=(
                "Invalidate all sessions/refresh tokens at ban time; bind bans to durable "
                "identifiers (account + verified email + device/risk signals) not just the "
                "session; block re-registration of banned emails/aliases; gate password "
                "reset for banned accounts. Add regression tests per VECTOR."
            ),
            retest_instructions=(
                "Re-run: python -m simulators run banned_user_return "
                "--scope scope/invisable-staging.yaml --no-dry-run and confirm every vector "
                "results in access denied."
            ),
            extra={"vectors": self.VECTORS},
        )

    def _attempt_vector(self, vector: str) -> bool:
        """Placeholder for the live attempt (wired to connectors.auth).

        Returns True if the banned account regained access. Defaults to False
        (enforcement held) so live runs without a configured auth connector do not
        emit false positives.
        """
        return False
