"""The identity & permission attack graph + its core queries (Sovereign plane, Wave 1, #2).

A dependency-free, in-memory typed graph that answers the four identity questions from
docs/sovereign_ops_plane.md, deterministically and auditably:

  * ``effective_permissions(p)``     — what ``p`` can do once membership is followed to closure.
  * ``escalation_paths(p)``          — how ``p`` could acquire rights it does not already hold.
  * ``dormant_privileges(...)``      — privileged principals that have gone quiet.
  * ``separation_of_duties_breaks()``— one principal holding two duties policy keeps apart.

Like the digital twin, the in-memory graph is the always-available read-model; production
populates it from BloodHound / cloud IAM (see ``ingest.py``). All traversals are BFS, so
results are stable and every finding carries the *shortest* explanatory path.
"""

from __future__ import annotations

from collections import deque
from datetime import date
from typing import Iterable, Iterator

from .models import (
    ESCALATION_EDGES,
    INHERITANCE_EDGES,
    DormantPrincipal,
    DutyConflict,
    EdgeKind,
    EffectivePermission,
    EscalationPath,
    Grant,
    IdentityEdge,
    Principal,
    PrincipalKind,
    PrivilegeStep,
    SoDBreak,
)

# Groups and roles are grant *containers*, not actors: they have no "last active" and
# perform no duties, so dormant-privilege and separation-of-duties checks skip them.
_CONTAINER_KINDS = frozenset({PrincipalKind.GROUP, PrincipalKind.ROLE})


class IdentityError(ValueError):
    """Raised on structural errors (unknown principal, duplicate id, grant to unknown holder)."""


class IdentityGraph:
    """A typed graph of principals + directed control edges + the grants each holder owns."""

    def __init__(self) -> None:
        self._principals: dict[str, Principal] = {}
        # adjacency: src_id -> list of (edge_kind, dst_id)
        self._out: dict[str, list[tuple[EdgeKind, str]]] = {}
        self._grants: dict[str, list[Grant]] = {}
        self._edges: list[IdentityEdge] = []

    # --- construction ----------------------------------------------------------
    def add_principal(self, principal: Principal) -> None:
        if principal.id in self._principals:
            raise IdentityError(f"duplicate principal id: {principal.id}")
        self._principals[principal.id] = principal
        self._out.setdefault(principal.id, [])
        self._grants.setdefault(principal.id, [])

    def add_edge(self, edge: IdentityEdge) -> None:
        if edge.src not in self._principals:
            raise IdentityError(f"edge from unknown principal: {edge.src}")
        if edge.dst not in self._principals:
            raise IdentityError(f"edge to unknown principal: {edge.dst}")
        self._out[edge.src].append((edge.kind, edge.dst))
        self._edges.append(edge)

    def add_grant(self, grant: Grant) -> None:
        if grant.holder not in self._principals:
            raise IdentityError(f"grant held by unknown principal: {grant.holder}")
        self._grants[grant.holder].append(grant)

    # --- accessors -------------------------------------------------------------
    def __contains__(self, principal_id: object) -> bool:
        return principal_id in self._principals

    def __len__(self) -> int:
        return len(self._principals)

    def principal(self, principal_id: str) -> Principal:
        try:
            return self._principals[principal_id]
        except KeyError as exc:
            raise IdentityError(f"unknown principal: {principal_id}") from exc

    def principals(self) -> Iterator[Principal]:
        return iter(self._principals.values())

    def grants_of(self, holder: str) -> tuple[Grant, ...]:
        if holder not in self._principals:
            raise IdentityError(f"unknown principal: {holder}")
        return tuple(self._grants[holder])

    # --- internals -------------------------------------------------------------
    def _reach(self, origin: str, kinds: frozenset[EdgeKind]) -> dict[str, tuple[PrivilegeStep, ...]]:
        """BFS over edges whose kind is in ``kinds``; principal id -> shortest path (excl. origin)."""
        reached: dict[str, tuple[PrivilegeStep, ...]] = {}
        seen = {origin}
        queue: deque[tuple[str, tuple[PrivilegeStep, ...]]] = deque([(origin, ())])
        while queue:
            current, path = queue.popleft()
            for kind, dst in self._out[current]:
                if kind not in kinds or dst in seen:
                    continue
                seen.add(dst)
                dst_path = path + (PrivilegeStep(via=kind, principal=dst),)
                reached[dst] = dst_path
                queue.append((dst, dst_path))
        return reached

    def _grants_as_permissions(self, holder: str, *, inherited: bool) -> list[EffectivePermission]:
        return [
            EffectivePermission(
                action=g.action, resource=g.resource, via=holder,
                inherited=inherited, duty=g.duty, sensitive=g.sensitive,
            )
            for g in self._grants[holder]
        ]

    # --- 1) effective + transitive permissions ---------------------------------
    def effective_permissions(self, principal_id: str) -> tuple[EffectivePermission, ...]:
        """Every action/resource ``principal_id`` can exercise *today*.

        Its own grants plus the grants of every group/role reachable by inheritance
        (``MEMBER_OF``) — escalation edges are deliberately NOT followed, because assuming a
        role or rewriting a grant is an *action*, not a right already held. Deterministic and
        deduplicated by (action, resource, via).
        """
        if principal_id not in self._principals:
            raise IdentityError(f"unknown principal: {principal_id}")

        perms: list[EffectivePermission] = self._grants_as_permissions(principal_id, inherited=False)
        for holder in self._reach(principal_id, INHERITANCE_EDGES):
            perms.extend(self._grants_as_permissions(holder, inherited=True))

        seen: set[tuple[str, str, str]] = set()
        unique: list[EffectivePermission] = []
        for p in perms:
            key = (p.action, p.resource, p.via)
            if key not in seen:
                seen.add(key)
                unique.append(p)
        unique.sort(key=lambda p: (p.action, p.resource, p.via))
        return tuple(unique)

    def _effective_pairs(self, principal_id: str) -> set[tuple[str, str]]:
        return {(p.action, p.resource) for p in self.effective_permissions(principal_id)}

    # --- 2) privilege-escalation paths -----------------------------------------
    def escalation_paths(self, principal_id: str, *, max_depth: int | None = None
                         ) -> tuple[EscalationPath, ...]:
        """Routes by which ``principal_id`` could acquire rights beyond its effective set.

        BFS over *all* control edges (inheritance + escalation). A principal reachable only
        by following at least one escalation edge can yield grants the origin does not already
        hold; we report the shortest such route and exactly the permissions it would gain. A
        principal reachable by pure inheritance contributes nothing new (its grants are
        already in the effective set), so it is naturally excluded.
        """
        if principal_id not in self._principals:
            raise IdentityError(f"unknown principal: {principal_id}")

        baseline = self._effective_pairs(principal_id)
        all_edges = INHERITANCE_EDGES | ESCALATION_EDGES
        results: list[EscalationPath] = []
        seen = {principal_id}
        queue: deque[tuple[str, tuple[PrivilegeStep, ...], bool]] = deque([(principal_id, (), False)])
        while queue:
            current, path, escalated = queue.popleft()
            if max_depth is not None and len(path) >= max_depth:
                continue
            for kind, dst in self._out[current]:
                if kind not in all_edges or dst in seen:
                    continue
                seen.add(dst)
                dst_path = path + (PrivilegeStep(via=kind, principal=dst),)
                dst_escalated = escalated or kind in ESCALATION_EDGES
                queue.append((dst, dst_path, dst_escalated))
                if not dst_escalated:
                    continue  # pure-inheritance reach — already in the effective set
                gained = tuple(
                    p for p in self.effective_permissions(dst)
                    if (p.action, p.resource) not in baseline
                )
                if gained:
                    results.append(EscalationPath(
                        origin=principal_id, target=dst, path=dst_path,
                        gained=gained, uses_escalation=True,
                    ))
        results.sort(key=lambda e: (len(e.path), e.target))
        return tuple(results)

    # --- 3) dormant privilege --------------------------------------------------
    def dormant_privileges(self, *, as_of: date, idle_days: int,
                           sensitive_only: bool = False) -> tuple[DormantPrincipal, ...]:
        """Principals that hold standing permissions but have been quiet for ``idle_days``+.

        Groups and roles are not actors, so they are skipped — only humans, service accounts
        and machines carry a meaningful "last active". A principal with no observed activity
        (``last_active is None``) is treated as dormant: unverified standing access.
        """
        if idle_days < 0:
            raise IdentityError("idle_days must be non-negative")

        out: list[DormantPrincipal] = []
        for p in self._principals.values():
            if p.kind in _CONTAINER_KINDS:
                continue
            perms = self.effective_permissions(p.id)
            if not perms:
                continue
            has_sensitive = any(x.sensitive for x in perms)
            if sensitive_only and not has_sensitive:
                continue
            if p.last_active is None:
                idle: int | None = None
            else:
                idle = (as_of - p.last_active).days
                if idle < idle_days:
                    continue
            out.append(DormantPrincipal(
                principal=p, idle_days=idle, permissions=len(perms), sensitive=has_sensitive,
            ))
        out.sort(key=lambda d: (d.idle_days is not None, -(d.idle_days or 0), d.principal.id))
        return tuple(out)

    # --- 4) separation-of-duties breaks ----------------------------------------
    def separation_of_duties_breaks(self, conflicts: Iterable[DutyConflict]
                                    ) -> tuple[SoDBreak, ...]:
        """Principals whose *effective* permissions span both sides of a conflicting-duty pair.

        Only human/service/machine principals are checked (a group/role is a grant container,
        not an actor that "performs" duties).
        """
        conflict_list = list(conflicts)
        out: list[SoDBreak] = []
        for p in self._principals.values():
            if p.kind in _CONTAINER_KINDS:
                continue
            duties: dict[str, str] = {}
            for perm in self.effective_permissions(p.id):
                if perm.duty is not None and perm.duty not in duties:
                    duties[perm.duty] = perm.action
            for c in conflict_list:
                if c.a in duties and c.b in duties:
                    out.append(SoDBreak(
                        principal=p.id, conflict=c,
                        action_a=duties[c.a], action_b=duties[c.b],
                    ))
        out.sort(key=lambda b: (b.principal, b.conflict.name))
        return tuple(out)

    # --- convenience -----------------------------------------------------------
    def extend(self, principals: Iterable[Principal], edges: Iterable[IdentityEdge],
               grants: Iterable[Grant]) -> None:
        for p in principals:
            self.add_principal(p)
        for e in edges:
            self.add_edge(e)
        for g in grants:
            self.add_grant(g)
