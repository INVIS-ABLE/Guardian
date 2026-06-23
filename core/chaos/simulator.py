"""The chaos & recovery simulator engine (Sovereign plane, Wave 3, system #17).

``ChaosSimulator`` adjudicates failure simulations run against a **clone** of the digital twin —
never the production twin. Its one structural rule: it must be told the clone it is operating on,
and it refuses to run against anything that is not declared a clone. For each scenario it compares
the model's predicted blast radius against the actual observed impact and surfaces the
**surprises**:

  * *unpredicted impact* — something broke the twin model did not foresee (a map gap to fix);
  * *overpredicted impact* — a control held where the model feared failure (resilience to bank);

plus RTO breaches. The aggregate **model accuracy** tells Guardian how much to trust the twin's
blast-radius predictions. It injects nothing itself and asserts no authority.
"""

from __future__ import annotations

from typing import Iterable

from .models import ChaosReport, ChaosResult


class ChaosError(ValueError):
    """Raised on structural errors (production target, duplicate scenario)."""


class ProductionTargetRefused(ChaosError):
    """Raised when the simulator is pointed at a production twin instead of a clone."""

# Markers that identify a twin reference as a disposable clone, not production.
_CLONE_MARKERS = ("clone", "shadow", "replica", "ephemeral", "sim")


def _require_clone(clone_of: str) -> str:
    ref = (clone_of or "").strip()
    if not ref:
        raise ChaosError("clone_of must name the twin the clone was taken from")
    if not any(m in ref.lower() for m in _CLONE_MARKERS):
        raise ProductionTargetRefused(
            f"chaos simulations run against a CLONE only; '{ref}' is not marked as a clone "
            f"(expected one of {list(_CLONE_MARKERS)} in the reference) — never inject failures "
            "into the production twin"
        )
    return ref


class ChaosSimulator:
    """Adjudicates chaos results against a declared clone of the twin."""

    def __init__(self, clone_of: str) -> None:
        self.clone_of = _require_clone(clone_of)

    def report(self, run: str, results: Iterable[ChaosResult]) -> ChaosReport:
        """Assemble the chaos report, rejecting duplicate scenarios."""
        if not run or not run.strip():
            raise ChaosError("run name must be non-empty")
        materialised = tuple(results)
        seen: set[str] = set()
        for r in materialised:
            if r.scenario.id in seen:
                raise ChaosError(f"duplicate scenario in run: {r.scenario.id}")
            seen.add(r.scenario.id)
        return ChaosReport(run=run, clone_of=self.clone_of, results=materialised)
