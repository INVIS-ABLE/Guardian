"""Twin-driven chaos & recovery simulation (Sovereign plane, Wave 3, system #17 — real engine).

The first slice of system #17 read a hand-written ``predicted_impact`` from a spec, which is not
a simulation — it is a transcription. This module makes the prediction *real*: it computes both
the predicted and the actual blast radius from the **actual digital twin** (#1,
[`core/twin/`](.)), so a game-day genuinely tests the model and the controls.

For a failure of ``target``:

  * **predicted impact** = ``twin.blast_radius(target)`` — everything the model says a loss of
    ``target`` propagates to, *ignoring* defences.
  * **actual impact** = the same propagation, but a **working security control** (a
    ``SECURITY_CONTROL`` asset with a ``PROTECTS`` edge) acts as a *firebreak*: the asset it
    protects survives and does not propagate the failure onward.
  * **contained_by_controls** = predicted − actual = exactly *"which controls actually worked"*
    — the question the Sovereign doc says this system exists to answer.

A scenario may mark some controls as **degraded** (the chaos injection: *"what if sigstore is
also down?"*); those stop firebreaking, the actual impact grows, and the game-day shows the
control's real value. Recovery timing (RTO) is a genuine observation and stays an input.

Clone-only is reused from [`core/chaos`](../chaos): the run is validated against a clone
reference, never the production twin. This engine reuses ``core.chaos`` vocabulary
(``FailureMode``) rather than redefining it.
"""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict

from core.chaos.models import FailureMode
from core.chaos.simulator import ChaosSimulator  # reused for clone-only validation

from .graph import DigitalTwin, TwinError
from .ingest import load_twin
from .models import RelationKind

SCHEMA_VERSION = 1


class TwinChaosScenario(BaseModel):
    """One failure to simulate against the twin. Predicted/actual impact are COMPUTED, not given."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    id: str
    mode: FailureMode
    target: str                              # the twin asset that fails
    degraded_controls: tuple[str, ...] = ()  # security-control assets that are ALSO down (no firebreak)
    rto_seconds: int | None = None
    rto_objective_seconds: int | None = None


class TwinChaosResult(BaseModel):
    """The computed outcome of one scenario, derived from the real twin graph."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario: TwinChaosScenario
    predicted_impact: tuple[str, ...]        # blast_radius(target), ignoring controls
    actual_impact: tuple[str, ...]           # propagation with working controls as firebreaks
    contained_by_controls: tuple[str, ...]   # predicted − actual: assets the controls saved
    controls_engaged: tuple[str, ...]        # the control assets that actually firebroke the failure

    @property
    def rto_breached(self) -> bool:
        s = self.scenario
        if s.rto_seconds is None or s.rto_objective_seconds is None:
            return False
        return s.rto_seconds > s.rto_objective_seconds

    @property
    def fully_contained(self) -> bool:
        """True when controls absorbed the entire predicted blast (actual impact empty)."""
        return not self.actual_impact


class TwinChaosReport(BaseModel):
    """The outcome of a twin-driven game-day."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run: str
    clone_of: str
    results: tuple[TwinChaosResult, ...]

    @property
    def rto_breaches(self) -> tuple[TwinChaosResult, ...]:
        return tuple(r for r in self.results if r.rto_breached)

    @property
    def uncontained(self) -> tuple[TwinChaosResult, ...]:
        """Scenarios whose failure still reached assets no control contained."""
        return tuple(r for r in self.results if r.actual_impact)

    def controls_that_worked(self) -> dict[str, int]:
        """How many times each security control firebroke a failure across the game-day."""
        out: dict[str, int] = {}
        for r in self.results:
            for c in r.controls_engaged:
                out[c] = out.get(c, 0) + 1
        return out

    @property
    def has_finding(self) -> bool:
        """An RTO breach is a recovery finding — callers gate on this."""
        return bool(self.rto_breaches)


def working_protections(twin: DigitalTwin, degraded: frozenset[str]) -> dict[str, str]:
    """Map ``protected_asset → control`` for every PROTECTS edge whose control is not degraded."""
    out: dict[str, str] = {}
    for rel in twin.relationships():
        if rel.kind is RelationKind.PROTECTS and rel.src not in degraded:
            out.setdefault(rel.dst, rel.src)
    return out


def simulate_failure(
    twin: DigitalTwin, target: str, *, degraded_controls: tuple[str, ...] = ()
) -> TwinChaosResult:
    """Simulate a failure of ``target`` against ``twin`` — predicted & actual impact are computed.

    ``predicted`` is the twin's control-blind blast radius; ``actual`` re-runs the same directed
    propagation but treats every asset shielded by a *working* control as a firebreak (it neither
    fails nor propagates). The difference is the set of assets the controls actually saved.
    """
    if target not in twin:
        raise TwinError(f"unknown twin asset: {target}")

    predicted = set(twin.blast_radius(target).asset_ids())

    degraded = frozenset(degraded_controls)
    protections = working_protections(twin, degraded)  # protected_asset -> control

    actual: set[str] = set()
    engaged: set[str] = set()
    seen = {target}
    queue: deque[str] = deque([target])
    while queue:
        current = queue.popleft()
        for _kind, dst in twin.neighbours(current):
            if dst in seen:
                continue
            seen.add(dst)
            control = protections.get(dst)
            if control is not None:
                # A working control holds this asset up: firebreak — not impacted, no propagation.
                engaged.add(control)
                continue
            actual.add(dst)
            queue.append(dst)

    contained = predicted - actual
    return TwinChaosResult(
        scenario=TwinChaosScenario(id=f"sim:{target}", mode=FailureMode.REGION_OUTAGE, target=target,
                                   degraded_controls=degraded_controls),
        predicted_impact=tuple(sorted(predicted)),
        actual_impact=tuple(sorted(actual)),
        contained_by_controls=tuple(sorted(contained)),
        controls_engaged=tuple(sorted(engaged)),
    )


def run_gameday(
    twin: DigitalTwin, run: str, clone_of: str, scenarios: list[TwinChaosScenario]
) -> TwinChaosReport:
    """Run a game-day of scenarios against a clone of ``twin``. Clone-only is enforced."""
    ChaosSimulator(clone_of=clone_of)  # reuse the clone-only guard (raises on a production ref)
    if not run or not run.strip():
        raise TwinError("run name must be non-empty")

    results: list[TwinChaosResult] = []
    seen: set[str] = set()
    for sc in scenarios:
        if sc.id in seen:
            raise TwinError(f"duplicate scenario in game-day: {sc.id}")
        seen.add(sc.id)
        base = simulate_failure(twin, sc.target, degraded_controls=sc.degraded_controls)
        results.append(base.model_copy(update={"scenario": sc}))
    return TwinChaosReport(run=run, clone_of=clone_of, results=tuple(results))


def build_gameday_from_spec(twin: DigitalTwin, spec: dict[str, Any]) -> TwinChaosReport:
    """Run a game-day from a ``{run, clone_of, scenarios:[...]}`` spec against a loaded twin."""
    scenarios = [TwinChaosScenario(**s) for s in spec.get("scenarios", [])]
    return run_gameday(twin, spec.get("run", "unnamed game-day"), spec.get("clone_of", ""), scenarios)


def load_gameday(twin_path: str | Path, gameday_path: str | Path) -> TwinChaosReport:
    """Load a twin spec and a game-day spec, then run the twin-driven simulation."""
    twin = load_twin(twin_path)
    p = Path(gameday_path)
    if not p.exists():
        raise FileNotFoundError(f"game-day spec not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return build_gameday_from_spec(twin, data)
