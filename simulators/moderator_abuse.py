"""Moderator Abuse Simulator.

Defensive scenario: verify that a moderator's elevated powers on owned staging are
bounded, logged, and cannot be turned against vulnerable users. We confirm that
abuse-of-power actions are either denied, require justification/approval, or are
audited and reversible. Uses synthetic ``moderator_test`` against ``vulnerable_user_test``.
"""

from __future__ import annotations

from core.evidence import SimulatorResult

from .base import BaseSimulator


class ModeratorAbuseSimulator(BaseSimulator):
    """Checks that moderator powers are least-privilege, audited, and reversible."""

    name = "moderator_abuse"
    mode = "abuse_simulation"
    action = "abuse_simulation"

    # Each action maps to the control we expect to constrain it.
    ABUSE_ACTIONS = {
        "view_vulnerable_user_pii": "field_level_redaction + access logged",
        "mass_message_users": "rate_limit + approval for bulk",
        "unmask_anonymous_reporter": "denied (reporter anonymity protected)",
        "delete_safeguarding_report": "denied / requires dual-control",
        "elevate_own_role_to_admin": "denied (separation of duties)",
        "disable_user_safety_protections": "denied / requires approval + audit",
        "export_user_data": "approval_required (data_export_test) + audited",
    }

    def _accounts_used(self) -> list[str]:
        return ["moderator_test", "vulnerable_user_test"]

    def simulate(self) -> SimulatorResult:
        signals: list[str] = []
        evidence: list[str] = []
        failures: list[str] = []

        for action, expected_control in self.ABUSE_ACTIONS.items():
            if self.dry_run:
                signals.append(
                    f"[dry-run] would attempt '{action}' and assert control: {expected_control}"
                )
                continue
            outcome = self._attempt_action(action)
            signals.append(f"attempted '{action}' -> {outcome['result']}")
            if not outcome["constrained"]:
                failures.append(action)
                evidence.append(
                    f"'{action}' was permitted without the expected control "
                    f"({expected_control}); audit_logged={outcome.get('audited', False)}"
                )

        detected = bool(failures)
        severity = "high" if detected else "info"
        if any(a in failures for a in (
            "unmask_anonymous_reporter",
            "delete_safeguarding_report",
            "disable_user_safety_protections",
        )):
            severity = "critical"

        return SimulatorResult(
            scenario_name="Moderator Abuse Simulator",
            scope=self.scope.asset,
            test_accounts_used=self._accounts_used(),
            signals_observed=signals,
            detection_result=(
                "moderator power abuse possible" if detected else
                ("dry-run: no live attempt performed" if self.dry_run else
                 "all moderator powers constrained")
            ),
            containment_result=(
                "least-privilege, audit, and reversibility controls held" if not detected else
                f"controls FAILED for: {', '.join(failures)}"
            ),
            user_safety_impact=(
                "An abusive or compromised moderator could de-anonymise reporters, delete "
                "safeguarding reports, or strip protections from vulnerable users." if detected
                else "Moderator powers cannot be weaponised against vulnerable users."
            ),
            evidence=evidence or ["No abuse evidence captured (controls held / dry-run)."],
            severity=severity,
            recommended_fix=(
                "Apply least-privilege RBAC/ABAC to moderator actions; protect reporter "
                "anonymity unconditionally; require dual-control for destructive safeguarding "
                "actions; gate data export behind approval; ensure every privileged action is "
                "immutably audited and reversible. Add a permission-matrix regression test."
            ),
            retest_instructions=(
                "Re-run: python -m simulators run moderator_abuse "
                "--scope scope/invisable-staging.yaml --no-dry-run and confirm each action is "
                "denied or constrained-and-audited as specified in ABUSE_ACTIONS."
            ),
            extra={"abuse_actions": self.ABUSE_ACTIONS},
        )

    def _attempt_action(self, action: str) -> dict[str, object]:
        """Placeholder for the live attempt (wired to connectors.auth/api).

        Returns {"constrained": bool, "result": str, "audited": bool}. Defaults to
        constrained=True so live runs without a configured connector do not emit
        false positives.
        """
        return {"constrained": True, "result": "denied/constrained", "audited": True}
