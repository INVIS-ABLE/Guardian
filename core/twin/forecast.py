"""Predictive attack-path forecasting over the (federated) twin — Sovereign system #12.

Beyond "what is reachable", the most useful defensive question is *which single control, if
placed (or which single node, if it fails), changes the most attack paths to the crown jewels?*
(docs/sovereign_ops_plane.md). This module answers two:

  * :func:`chokepoint_ranking` — for every intermediate node, how many ``source → sink`` attack
    paths are CUT if that node is removed. The top node is where one control (isolate, patch,
    revoke) breaks the most paths — and, equally, the biggest single point of failure.
  * :func:`attack_surface` — the reachable ``source → sink`` pairs themselves.

Deterministic, dependency-free BFS over the existing graph (NetworkX is the production
accelerator for very large graphs; the algorithm here is the point and stays exact + offline).
Read-only: it proposes where a control would help — it never places one.
"""

from __future__ import annotations

from collections import deque
from typing import Iterable

from pydantic import BaseModel, ConfigDict

from .assessment import Severity, _sink_severity
from .graph import DigitalTwin
from .models import AssetKind


def default_sinks(twin: DigitalTwin) -> tuple[str, ...]:
    """Sensitive sinks = assets whose compromise carries real severity (data, keys, stores)."""
    return tuple(
        a.id for a in twin.assets() if _sink_severity(a)[0] != Severity.NONE
    )


def default_sources(twin: DigitalTwin) -> tuple[str, ...]:
    """Entry points = identities with no inbound edge (an attacker's initial foothold)."""
    has_inbound: set[str] = {dst for _, dst in _all_edges(twin)}
    return tuple(
        a.id for a in twin.assets()
        if a.kind == AssetKind.IDENTITY and a.id not in has_inbound
    )


def _all_edges(twin: DigitalTwin) -> list[tuple[str, str]]:
    return [(r.src, r.dst) for r in twin.relationships()]


def _reachable_from(adj: dict[str, list[str]], source: str, *, blocked: str | None = None) -> set[str]:
    if source == blocked:
        return set()
    seen: set[str] = {source}
    q: deque[str] = deque([source])
    while q:
        cur = q.popleft()
        for nxt in adj.get(cur, ()):  # noqa: SIM118
            if nxt == blocked or nxt in seen:
                continue
            seen.add(nxt)
            q.append(nxt)
    return seen


def _adjacency(twin: DigitalTwin) -> dict[str, list[str]]:
    adj: dict[str, list[str]] = {a.id: [] for a in twin.assets()}
    for src, dst in _all_edges(twin):
        adj[src].append(dst)
    return adj


class ChokePoint(BaseModel):
    """A node ranked by how many source→sink attack paths its removal cuts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node: str
    kind: AssetKind
    paths_cut: int            # source→sink pairs that become unreachable without this node
    protects_sinks: tuple[str, ...]  # the sinks newly unreachable when this node is removed


def _reachable_pairs(adj: dict[str, list[str]], sources, sinks, *, blocked=None) -> set[tuple[str, str]]:
    sink_set = set(sinks)
    pairs: set[tuple[str, str]] = set()
    for s in sources:
        if s == blocked:
            continue
        reach = _reachable_from(adj, s, blocked=blocked)
        for t in sink_set & reach:
            if t != s:
                pairs.add((s, t))
    return pairs


def attack_surface(
    twin: DigitalTwin,
    *,
    sources: Iterable[str] | None = None,
    sinks: Iterable[str] | None = None,
) -> tuple[tuple[str, str], ...]:
    """The reachable ``(source, sink)`` attack pairs, sorted."""
    srcs = tuple(sources) if sources is not None else default_sources(twin)
    snks = tuple(sinks) if sinks is not None else default_sinks(twin)
    adj = _adjacency(twin)
    return tuple(sorted(_reachable_pairs(adj, srcs, snks)))


def chokepoint_ranking(
    twin: DigitalTwin,
    *,
    sources: Iterable[str] | None = None,
    sinks: Iterable[str] | None = None,
) -> tuple[ChokePoint, ...]:
    """Rank intermediate nodes by how many source→sink attack paths their removal cuts.

    The top result is where a single control (isolation, patch, credential revocation) breaks
    the most paths to sensitive sinks — and the most dangerous single point of failure.
    """
    srcs = tuple(sources) if sources is not None else default_sources(twin)
    snks = tuple(sinks) if sinks is not None else default_sinks(twin)
    adj = _adjacency(twin)
    by_id = {a.id: a for a in twin.assets()}

    baseline = _reachable_pairs(adj, srcs, snks)
    if not baseline:
        return ()

    src_set, sink_set = set(srcs), set(snks)
    results: list[ChokePoint] = []
    for node in by_id:
        if node in src_set or node in sink_set:
            continue  # a control sits BETWEEN the attacker and the crown jewels
        remaining = _reachable_pairs(adj, srcs, snks, blocked=node)
        cut = baseline - remaining
        if not cut:
            continue
        results.append(ChokePoint(
            node=node, kind=by_id[node].kind,
            paths_cut=len(cut),
            protects_sinks=tuple(sorted({t for _, t in cut})),
        ))
    results.sort(key=lambda c: (-c.paths_cut, c.node))
    return tuple(results)
