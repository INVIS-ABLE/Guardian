"""The digital twin graph + its core queries (Sovereign plane, Wave 1, system #1).

A dependency-free, in-memory typed graph with the two questions the twin exists to answer:

  * ``blast_radius(id)``  — *what is affected if this asset is compromised?* (directed
    reachability over outgoing edges, the direction impact propagates).
  * ``attack_path(a, b)`` — *how could a compromise of A reach B?* (shortest directed path).

In production the twin is populated from Cartography/CloudQuery and persisted in PostgreSQL
(see ``ingest.py``); the in-memory graph here is the always-available read-model, mirroring
the graceful-degradation pattern used across ``core`` (memory, audit). The algorithms are
deterministic BFS so results are stable and explainable.
"""

from __future__ import annotations

from collections import deque
from typing import Iterable, Iterator

from .models import (
    AssetKind,
    AssetNode,
    BlastRadius,
    ImpactedAsset,
    ImpactStep,
    Relationship,
    RelationKind,
)


class TwinError(ValueError):
    """Raised on structural errors (unknown asset, duplicate id)."""


class DigitalTwin:
    """A typed graph of assets + directed, typed relationships.

    Edges point in the direction a compromise propagates, so ``blast_radius`` is a forward
    BFS and ``attack_path`` a shortest-path BFS over the same adjacency.
    """

    def __init__(self) -> None:
        self._assets: dict[str, AssetNode] = {}
        # adjacency: src_id -> list of (relation_kind, dst_id)
        self._out: dict[str, list[tuple[RelationKind, str]]] = {}
        self._edges: list[Relationship] = []

    # --- construction ----------------------------------------------------------
    def add_asset(self, asset: AssetNode) -> None:
        if asset.id in self._assets:
            raise TwinError(f"duplicate asset id: {asset.id}")
        self._assets[asset.id] = asset
        self._out.setdefault(asset.id, [])

    def add_relationship(self, rel: Relationship) -> None:
        if rel.src not in self._assets:
            raise TwinError(f"relationship from unknown asset: {rel.src}")
        if rel.dst not in self._assets:
            raise TwinError(f"relationship to unknown asset: {rel.dst}")
        self._out[rel.src].append((rel.kind, rel.dst))
        self._edges.append(rel)

    # --- accessors -------------------------------------------------------------
    def __contains__(self, asset_id: object) -> bool:
        return asset_id in self._assets

    def __len__(self) -> int:
        return len(self._assets)

    def asset(self, asset_id: str) -> AssetNode:
        try:
            return self._assets[asset_id]
        except KeyError as exc:
            raise TwinError(f"unknown asset: {asset_id}") from exc

    def assets(self) -> Iterator[AssetNode]:
        return iter(self._assets.values())

    def relationships(self) -> tuple[Relationship, ...]:
        return tuple(self._edges)

    def assets_of_kind(self, kind: AssetKind) -> tuple[AssetNode, ...]:
        return tuple(a for a in self._assets.values() if a.kind == kind)

    def neighbours(self, asset_id: str) -> tuple[tuple[RelationKind, str], ...]:
        if asset_id not in self._assets:
            raise TwinError(f"unknown asset: {asset_id}")
        return tuple(self._out[asset_id])

    # --- the two questions the twin exists to answer ---------------------------
    def blast_radius(self, origin: str, *, max_depth: int | None = None) -> BlastRadius:
        """Every asset reachable from ``origin`` over directed edges, with shortest paths.

        Answers "what is affected if ``origin`` is compromised?". The origin itself is not
        included in the impacted set. Deterministic BFS ⇒ each impacted asset carries the
        *shortest* explanatory path (so the result is auditable, not just a set).
        """
        if origin not in self._assets:
            raise TwinError(f"unknown asset: {origin}")

        impacted: list[ImpactedAsset] = []
        seen: set[str] = {origin}
        queue: deque[tuple[str, tuple[ImpactStep, ...]]] = deque([(origin, ())])
        while queue:
            current, path = queue.popleft()
            if max_depth is not None and len(path) >= max_depth:
                continue
            for kind, dst in self._out[current]:
                if dst in seen:
                    continue
                seen.add(dst)
                dst_path = path + (ImpactStep(via=kind, asset=dst),)
                impacted.append(
                    ImpactedAsset(asset=self._assets[dst], distance=len(dst_path), path=dst_path)
                )
                queue.append((dst, dst_path))
        impacted.sort(key=lambda i: (i.distance, i.asset.id))
        return BlastRadius(origin=origin, impacted=tuple(impacted))

    def attack_path(self, source: str, target: str) -> tuple[ImpactStep, ...] | None:
        """Shortest directed path ``source → target``, or ``None`` if unreachable."""
        if source not in self._assets:
            raise TwinError(f"unknown asset: {source}")
        if target not in self._assets:
            raise TwinError(f"unknown asset: {target}")
        if source == target:
            return ()
        seen: set[str] = {source}
        queue: deque[tuple[str, tuple[ImpactStep, ...]]] = deque([(source, ())])
        while queue:
            current, path = queue.popleft()
            for kind, dst in self._out[current]:
                if dst in seen:
                    continue
                step_path = path + (ImpactStep(via=kind, asset=dst),)
                if dst == target:
                    return step_path
                seen.add(dst)
                queue.append((dst, step_path))
        return None

    # --- convenience -----------------------------------------------------------
    def extend(self, assets: Iterable[AssetNode], relationships: Iterable[Relationship]) -> None:
        for a in assets:
            self.add_asset(a)
        for r in relationships:
            self.add_relationship(r)
