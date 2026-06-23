"""Causal root-cause engine — Sovereign system #8.

Correlation is not causation. Given an incident — observed compromised nodes and the sensitive
sink they reached — this engine uses *counterfactual* reasoning over the digital twin
(:mod:`core.twin`) to separate:

  * **first event**      — the observed entry point the chain started from,
  * **root cause**       — the earliest node whose removal would have prevented the incident
                           ("would it still have happened without this?"),
  * **enabling conditions** — the intermediate nodes the chain traversed,
  * **amplifiers**       — nodes that widen the blast radius the most (the choke points),
  * **symptoms**         — what was finally reached (the sink and its last hop).

This produces stronger remediation than patching the alert's immediate symptom: it points at the
link that actually has to be cut. Read-only over the twin — it explains, it never remediates.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from core.twin import DigitalTwin
from core.twin.forecast import chokepoint_ranking


class Counterfactual(BaseModel):
    """Would the incident still occur if ``node`` did not exist?"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node: str
    breaks_chain: bool   # True ⇒ removing this node prevents source reaching the sink


class CausalReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sink: str
    first_event: str | None
    root_cause: str | None
    enabling_conditions: tuple[str, ...]
    amplifiers: tuple[str, ...]
    symptoms: tuple[str, ...]
    counterfactuals: tuple[Counterfactual, ...]


def _path_ids(twin: DigitalTwin, source: str, sink: str) -> list[str] | None:
    steps = twin.attack_path(source, sink)
    if steps is None:
        return None
    return [source, *(s.asset for s in steps)]


def root_cause(twin: DigitalTwin, *, observed: list[str], sink: str) -> CausalReport:
    """Explain how ``observed`` compromised nodes reached ``sink``, causally.

    Picks the observed entry whose shortest path to the sink is shortest as the realised chain,
    then runs counterfactuals along it. ``root_cause`` is the earliest node on the chain whose
    removal severs every observed→sink path (a true necessary link, closest to the source).
    """
    if sink not in twin:
        from core.twin import TwinError

        raise TwinError(f"unknown sink: {sink}")

    # The realised chain: the observed source with the shortest route to the sink.
    chains = [(o, _path_ids(twin, o, sink)) for o in observed if o in twin]
    chains = [(o, p) for o, p in chains if p is not None]
    if not chains:
        return CausalReport(sink=sink, first_event=None, root_cause=None,
                            enabling_conditions=(), amplifiers=(), symptoms=(sink,),
                            counterfactuals=())
    source, path = min(chains, key=lambda c: len(c[1]))
    observed_sources = [o for o, _ in chains]

    # Counterfactual along the chain (exclude the sink itself).
    interior = [n for n in path if n != sink]
    cfs: list[Counterfactual] = []
    root: str | None = None
    for node in interior:
        if node in observed_sources and node == source:
            # The entry itself: removing the attacker's foothold trivially breaks it; record but
            # the *root cause* we want is the earliest enabling node beyond the foothold.
            cfs.append(Counterfactual(node=node, breaks_chain=True))
            continue
        breaks = all(_path_ids(_twin_without(twin, node), s, sink) is None for s in observed_sources)
        cfs.append(Counterfactual(node=node, breaks_chain=breaks))
        if breaks and root is None:
            root = node

    first_event = source
    enabling = tuple(n for n in path[1:-1])           # interior hops, between entry and sink
    symptoms = tuple(path[-2:]) if len(path) >= 2 else (sink,)

    # Amplifiers: the global choke points (most attack paths cut) that lie on/near this incident.
    chokes = chokepoint_ranking(twin, sources=observed_sources, sinks=[sink])
    amplifiers = tuple(c.node for c in chokes[:3])

    return CausalReport(
        sink=sink,
        first_event=first_event,
        root_cause=root,
        enabling_conditions=enabling,
        amplifiers=amplifiers,
        symptoms=symptoms,
        counterfactuals=tuple(cfs),
    )


def _twin_without(twin: DigitalTwin, drop: str) -> DigitalTwin:
    """A copy of the twin with ``drop`` (and its edges) removed — for counterfactuals."""
    from core.twin import DigitalTwin as _T

    clone = _T()
    for a in twin.assets():
        if a.id != drop:
            clone.add_asset(a)
    for r in twin.relationships():
        if r.src != drop and r.dst != drop:
            clone.add_relationship(r)
    return clone
