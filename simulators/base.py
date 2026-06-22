"""Base class for Guardian defensive simulators.

A simulator exercises a *defensive* scenario against owned staging systems and test
accounts only. It never attacks third parties, deploys exploits, or persists. Every
simulator routes through the guardrails before doing anything, runs in dry-run by
default, and must emit a complete ``SimulatorResult`` (the mandatory output contract).
"""

from __future__ import annotations

import abc

from core.audit import AuditLog
from core.evidence import SimulatorResult, write_report
from core.guardrails import Guardrails
from core.scope import Scope


class BaseSimulator(abc.ABC):
    """All simulators inherit from this. Subclasses set ``name``/``mode`` and
    implement :meth:`simulate`."""

    #: short machine name, e.g. "privacy_leak"
    name: str = "base"
    #: the scope mode this simulator needs (must be in scope.allowed_modes)
    mode: str = "abuse_simulation"
    #: the guardrail action label for approval/blocking checks
    action: str = "abuse_simulation"

    def __init__(self, scope: Scope, *, dry_run: bool = True, guardrails: Guardrails | None = None):
        self.scope = scope
        self.dry_run = dry_run
        self.guardrails = guardrails or Guardrails(scope=scope)
        self.audit = AuditLog()

    # --- public API ------------------------------------------------------------
    def run(self) -> SimulatorResult:
        """Authorise via guardrails, run the scenario, log, and return the result."""
        # Gate first — refuse before doing anything if not authorised.
        self.guardrails.authorize(mode=self.mode, action=self.action)
        for account in self._accounts_used():
            self.guardrails.assert_test_account(account)

        self.audit.record(
            f"simulator:{self.name}:start",
            actor="abuse_simulation_agent",
            scope=self.scope.asset,
            decision="allowed",
            detail={"dry_run": self.dry_run},
        )

        result = self.simulate()
        result.scope = self.scope.asset

        self.audit.record(
            f"simulator:{self.name}:complete",
            actor="abuse_simulation_agent",
            scope=self.scope.asset,
            decision="allowed",
            detail={
                "severity": result.severity,
                "detection_result": result.detection_result,
                "containment_result": result.containment_result,
                "dry_run": self.dry_run,
            },
        )
        return result

    def run_and_report(self) -> SimulatorResult:
        result = self.run()
        write_report(result)
        return result

    # --- subclass hooks --------------------------------------------------------
    @abc.abstractmethod
    def simulate(self) -> SimulatorResult:
        """Perform the (defensive) scenario and return a SimulatorResult."""

    def _accounts_used(self) -> list[str]:
        """Override to declare which test accounts the scenario touches."""
        return []
