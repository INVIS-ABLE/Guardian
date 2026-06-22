"""The data lineage & privacy graph + its core queries (Sovereign plane, Wave 1, system #3).

A dependency-free, in-memory typed graph that answers the data questions from
docs/sovereign_ops_plane.md, deterministically and auditably:

  * ``downstream(f)`` / ``upstream(f)`` — field-level lineage, both directions.
  * ``propagated_classifications(f)``   — a field's true sensitivity = declared ∪ all upstream.
  * ``boundary_violations()``           — data that flowed into a boundary not approved for it
    (the canonical *"a health field moved outside its approved boundary"* detection).
  * ``retention_violations()``          — derived data that would outlive an upstream deletion
    obligation.

Like the digital twin and identity graph, the in-memory graph is the always-available
read-model; production populates it from DataHub / OpenLineage (see ``ingest.py``). All
traversals are BFS, so every finding carries the *shortest* explanatory path.
"""

from __future__ import annotations

from collections import deque
from typing import Iterable, Iterator

from core.evidence.models import Classification

from .models import (
    Boundary,
    BoundaryViolation,
    Field,
    Flow,
    FlowStep,
    LineageNode,
    RetentionViolation,
    peak,
)


class LineageError(ValueError):
    """Raised on structural errors (unknown field/boundary, duplicate id, flow to unknown field)."""


class LineageGraph:
    """A typed graph of fields + boundaries + directed data-flow edges between fields."""

    def __init__(self) -> None:
        self._fields: dict[str, Field] = {}
        self._boundaries: dict[str, Boundary] = {}
        self._out: dict[str, list[tuple[str, str]]] = {}  # src -> [(via, dst)] (downstream)
        self._in: dict[str, list[tuple[str, str]]] = {}   # dst -> [(via, src)] (upstream)
        self._flows: list[Flow] = []

    # --- construction ----------------------------------------------------------
    def add_boundary(self, boundary: Boundary) -> None:
        if boundary.id in self._boundaries:
            raise LineageError(f"duplicate boundary id: {boundary.id}")
        self._boundaries[boundary.id] = boundary

    def add_field(self, field: Field) -> None:
        if field.id in self._fields:
            raise LineageError(f"duplicate field id: {field.id}")
        if field.boundary is not None and field.boundary not in self._boundaries:
            raise LineageError(f"field {field.id} references unknown boundary: {field.boundary}")
        self._fields[field.id] = field
        self._out.setdefault(field.id, [])
        self._in.setdefault(field.id, [])

    def add_flow(self, flow: Flow) -> None:
        if flow.src not in self._fields:
            raise LineageError(f"flow from unknown field: {flow.src}")
        if flow.dst not in self._fields:
            raise LineageError(f"flow to unknown field: {flow.dst}")
        self._out[flow.src].append((flow.via, flow.dst))
        self._in[flow.dst].append((flow.via, flow.src))
        self._flows.append(flow)

    # --- accessors -------------------------------------------------------------
    def __contains__(self, field_id: object) -> bool:
        return field_id in self._fields

    def __len__(self) -> int:
        return len(self._fields)

    def field(self, field_id: str) -> Field:
        try:
            return self._fields[field_id]
        except KeyError as exc:
            raise LineageError(f"unknown field: {field_id}") from exc

    def fields(self) -> Iterator[Field]:
        return iter(self._fields.values())

    def flows(self) -> tuple[Flow, ...]:
        return tuple(self._flows)

    def boundary(self, boundary_id: str) -> Boundary:
        try:
            return self._boundaries[boundary_id]
        except KeyError as exc:
            raise LineageError(f"unknown boundary: {boundary_id}") from exc

    # --- 1) field-level lineage ------------------------------------------------
    def _walk(self, origin: str, adjacency: dict[str, list[tuple[str, str]]]) -> tuple[LineageNode, ...]:
        if origin not in self._fields:
            raise LineageError(f"unknown field: {origin}")
        nodes: list[LineageNode] = []
        seen = {origin}
        queue: deque[tuple[str, tuple[FlowStep, ...]]] = deque([(origin, ())])
        while queue:
            current, path = queue.popleft()
            for via, nxt in adjacency[current]:
                if nxt in seen:
                    continue
                seen.add(nxt)
                nxt_path = path + (FlowStep(via=via, field=nxt),)
                nodes.append(LineageNode(field=self._fields[nxt], distance=len(nxt_path), path=nxt_path))
                queue.append((nxt, nxt_path))
        nodes.sort(key=lambda n: (n.distance, n.field.id))
        return tuple(nodes)

    def downstream(self, field_id: str) -> tuple[LineageNode, ...]:
        """Every field this field's data flows *into*, with shortest paths."""
        return self._walk(field_id, self._out)

    def upstream(self, field_id: str) -> tuple[LineageNode, ...]:
        """Every field this field's data was *derived from*, with shortest paths."""
        return self._walk(field_id, self._in)

    # --- 2) classification propagation -----------------------------------------
    def _propagate(self, field_id: str) -> dict[Classification, str]:
        """Map each classification reaching ``field_id`` (declared ∪ upstream) → nearest source.

        BFS upstream; the field's own declared class maps to itself, and each upstream class
        maps to the nearest field that declared it (first BFS visit = shortest distance).
        """
        if field_id not in self._fields:
            raise LineageError(f"unknown field: {field_id}")
        source: dict[Classification, str] = {}
        own = self._fields[field_id].classification
        source[own] = field_id
        seen = {field_id}
        queue: deque[str] = deque([field_id])
        while queue:
            current = queue.popleft()
            for _via, up in self._in[current]:
                if up in seen:
                    continue
                seen.add(up)
                cls = self._fields[up].classification
                source.setdefault(cls, up)
                queue.append(up)
        return source

    def propagated_classifications(self, field_id: str) -> frozenset[Classification]:
        """A field's true sensitivity: its declared class unioned with every upstream class."""
        return frozenset(self._propagate(field_id))

    def peak_classification(self, field_id: str) -> Classification:
        """The single most-sensitive label that propagates to ``field_id`` (for reporting)."""
        return peak(self.propagated_classifications(field_id))

    # --- 3) processor-boundary violations --------------------------------------
    def boundary_violations(self) -> tuple[BoundaryViolation, ...]:
        """Fields holding propagated data their boundary is not approved for.

        Categorical, not rank-based: a boundary approved for PII but not HEALTH still rejects
        HEALTH. Each violation names the nearest upstream field that introduced the offending
        class — so the report points straight at the integration that moved the data.
        """
        out: list[BoundaryViolation] = []
        for f in self._fields.values():
            if f.boundary is None:
                continue
            approved = self._boundaries[f.boundary].approved
            source = self._propagate(f.id)
            for cls, introduced_by in sorted(source.items(), key=lambda kv: kv[0].value):
                if cls not in approved:
                    out.append(BoundaryViolation(
                        field=f.id, boundary=f.boundary,
                        offending=cls, introduced_by=introduced_by,
                    ))
        out.sort(key=lambda v: (v.field, v.offending.value))
        return tuple(out)

    # --- 4) retention / deletion-obligation propagation ------------------------
    def retention_violations(self) -> tuple[RetentionViolation, ...]:
        """Fields that would retain data longer than an upstream deletion obligation allows.

        A deletion deadline propagates downstream: derived data may not outlive the strictest
        (smallest ``retention_days``) obligation of any field it descends from. A field with no
        obligation of its own (``None``) violates if *any* upstream field imposes one.
        """
        out: list[RetentionViolation] = []
        for f in self._fields.values():
            obligation: int | None = None
            source = ""
            for node in self.upstream(f.id):
                up = node.field
                if up.retention_days is None:
                    continue
                if obligation is None or up.retention_days < obligation:
                    obligation = up.retention_days
                    source = up.id
            if obligation is None:
                continue
            if f.retention_days is None or f.retention_days > obligation:
                out.append(RetentionViolation(
                    field=f.id, declared_days=f.retention_days,
                    obligation_days=obligation, source=source,
                ))
        out.sort(key=lambda v: v.field)
        return tuple(out)

    # --- convenience -----------------------------------------------------------
    def extend(self, boundaries: Iterable[Boundary], fields: Iterable[Field],
               flows: Iterable[Flow]) -> None:
        for b in boundaries:
            self.add_boundary(b)
        for f in fields:
            self.add_field(f)
        for fl in flows:
            self.add_flow(fl)
