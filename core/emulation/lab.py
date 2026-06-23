"""The adversary-emulation lab harness (Sovereign plane, Wave 3, system #13).

``AdversaryLab`` is the reference monitor for system #13's one hard rule: **emulation runs in
the disposable lab ONLY, never production** (docs/sovereign_ops_plane.md). It refuses to assemble
a report for any environment that is not a recognised range — the same fail-closed posture the
endpoint fabric uses for unsigned packs.

Given the lab's observed results (prevented / detected / evidence-preserved per technique), it:
  * classifies each into a ``Verdict`` (blocked · detected · bypass);
  * **mints a regression test for every gap** — a bypass (neither prevented nor detected) and an
    evidence gap (fired but left no evidence) — so the failure becomes permanent, testable
    knowledge rather than a one-off observation; and
  * reports breadth (coverage) and whether the operation found a bypass (the gate signal).

It executes nothing itself and asserts no authority — it adjudicates results the range produced.
"""

from __future__ import annotations

from typing import Iterable

from .models import (
    EmulationReport,
    RegressionReason,
    RegressionTest,
    TechniqueResult,
)

# Recognised disposable environments. Emulation may run in these and nowhere else — production
# is never a valid target for offensive emulation.
LAB_ENVIRONMENTS = frozenset({"range", "lab", "test", "cyber_range", "ephemeral"})


class EmulationError(ValueError):
    """Raised on structural errors (duplicate technique, empty operation name)."""


class LabOnlyViolation(EmulationError):
    """Raised when emulation is targeted anywhere but the disposable lab — the cardinal rule."""


def _require_lab(environment: str) -> str:
    env = (environment or "").strip().lower()
    if env not in LAB_ENVIRONMENTS:
        raise LabOnlyViolation(
            f"adversary emulation may run in the disposable lab only ({sorted(LAB_ENVIRONMENTS)}); "
            f"refusing to emulate against '{environment}' — emulation never touches production"
        )
    return env


def _regressions_for(result: TechniqueResult) -> list[RegressionTest]:
    """Mint the regression tests a single result warrants (a bypass and/or an evidence gap)."""
    t = result.technique
    out: list[RegressionTest] = []
    if result.is_bypass:
        out.append(RegressionTest(
            technique_id=t.id, technique_name=t.name, tactic=t.tactic,
            reason=RegressionReason.BYPASS,
            requirement=f"{t.id} ({t.name}) must be prevented or detected by an independent sensor",
        ))
    if result.evidence_gap:
        out.append(RegressionTest(
            technique_id=t.id, technique_name=t.name, tactic=t.tactic,
            reason=RegressionReason.EVIDENCE_GAP,
            requirement=f"{t.id} ({t.name}) must preserve forensic evidence when it fires",
        ))
    return out


class AdversaryLab:
    """Assembles an emulation report from lab-observed results, lab-only and fail-closed."""

    def __init__(self, environment: str = "range") -> None:
        self.environment = _require_lab(environment)

    def report(self, operation: str, results: Iterable[TechniqueResult]) -> EmulationReport:
        """Classify results and mint regression tests for every prevention/detection/evidence gap."""
        if not operation or not operation.strip():
            raise EmulationError("operation name must be non-empty")

        materialised = tuple(results)
        seen: set[str] = set()
        for r in materialised:
            if r.technique.id in seen:
                raise EmulationError(f"duplicate technique in operation: {r.technique.id}")
            seen.add(r.technique.id)

        regressions: list[RegressionTest] = []
        for r in materialised:
            regressions.extend(_regressions_for(r))

        return EmulationReport(
            operation=operation, environment=self.environment,
            results=materialised, regression_tests=tuple(regressions),
        )
