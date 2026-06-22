"""Tests for the identity & permission attack graph (Sovereign plane, Wave 1, system #2)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from core.identity_graph import (
    DutyConflict,
    Grant,
    IdentityEdge,
    IdentityError,
    IdentityGraph,
    Principal,
    PrincipalKind,
    build_from_spec,
    from_bloodhound,
    load_graph,
)

SAMPLE = Path(__file__).resolve().parent.parent / "identity_graph" / "invisable-identity-sample.yaml"


# --- models --------------------------------------------------------------------
def test_principal_rejects_empty_id():
    with pytest.raises(ValueError):
        Principal(id="  ", kind=PrincipalKind.HUMAN, name="x")


def test_grant_rejects_empty_action():
    with pytest.raises(ValueError):
        Grant(holder="role:x", action="  ", resource="r")


def test_duty_conflict_rejects_empty():
    with pytest.raises(ValueError):
        DutyConflict(name="c", a="author", b="  ")


# --- graph construction --------------------------------------------------------
def test_edge_to_unknown_principal_is_refused():
    g = IdentityGraph()
    g.add_principal(Principal(id="a", kind=PrincipalKind.HUMAN, name="a"))
    with pytest.raises(IdentityError):
        g.add_edge(IdentityEdge(src="a", dst="ghost", kind="member_of"))


def test_grant_to_unknown_holder_is_refused():
    g = IdentityGraph()
    with pytest.raises(IdentityError):
        g.add_grant(Grant(holder="ghost", action="read"))


def test_duplicate_principal_is_refused():
    g = IdentityGraph()
    g.add_principal(Principal(id="a", kind=PrincipalKind.ROLE, name="a"))
    with pytest.raises(IdentityError):
        g.add_principal(Principal(id="a", kind=PrincipalKind.ROLE, name="a2"))


# --- the four questions the graph answers --------------------------------------
@pytest.fixture()
def graph() -> IdentityGraph:
    return load_graph(SAMPLE)


def test_effective_permissions_follow_membership_not_escalation(graph):
    perms = graph.effective_permissions("id:human-dev")
    pairs = {(p.action, p.resource) for p in perms}
    # Inherited write via engineers → repo-writer.
    assert ("write", "repo:guardian") in pairs
    # approve_release is reachable ONLY by assuming a role — NOT an effective permission.
    assert ("approve_release", "repo:guardian") not in pairs
    # And it is correctly marked inherited, sourced from the role that holds it.
    write = next(p for p in perms if p.action == "write")
    assert write.inherited is True
    assert write.via == "role:repo-writer"
    assert write.duty == "author"


def test_effective_permissions_dedup_and_direct_flag():
    g = build_from_spec({
        "principals": [
            {"id": "p", "kind": "human", "name": "p"},
            {"id": "r", "kind": "role", "name": "r"},
        ],
        "edges": [{"src": "p", "dst": "r", "kind": "member_of"}],
        "grants": [
            {"holder": "p", "action": "read", "resource": "x"},
            {"holder": "r", "action": "read", "resource": "x"},  # same pair, different holder
        ],
    })
    perms = g.effective_permissions("p")
    # Two holders of the same (action, resource) are distinct provenance, both retained.
    assert len(perms) == 2
    assert {p.inherited for p in perms} == {True, False}


def test_escalation_path_gains_approve_release(graph):
    paths = graph.escalation_paths("id:human-dev")
    assert len(paths) == 1
    ep = paths[0]
    assert ep.target == "role:release-admin"
    assert [s.via.value for s in ep.path] == ["can_assume"]
    assert ep.uses_escalation is True
    gained = {(g.action, g.resource) for g in ep.gained}
    assert gained == {("approve_release", "repo:guardian")}


def test_pure_membership_yields_no_escalation():
    # release-bot reaches everything by membership only — nothing to *escalate* to.
    graph = load_graph(SAMPLE)
    assert graph.escalation_paths("id:release-bot") == ()


def test_dormant_privilege_flags_quiet_sensitive_principal(graph):
    dormant = graph.dormant_privileges(as_of=date(2026, 6, 22), idle_days=30)
    ids = {d.principal.id for d in dormant}
    # Legacy deploy bot went quiet in Feb but still holds a sensitive deploy grant.
    assert "id:old-deploy" in ids
    # Recently-active principals are not dormant; roles/groups are never actors.
    assert "id:ci-token" not in ids
    assert "role:deployer" not in ids
    old = next(d for d in dormant if d.principal.id == "id:old-deploy")
    assert old.sensitive is True
    assert old.idle_days is not None and old.idle_days > 30


def test_dormant_sensitive_only_filter(graph):
    # human-dev holds only a non-sensitive write; with sensitive_only it must not appear,
    # even at idle_days=0 (which would otherwise flag every principal).
    dormant = graph.dormant_privileges(as_of=date(2026, 6, 22), idle_days=0, sensitive_only=True)
    ids = {d.principal.id for d in dormant}
    assert "id:human-dev" not in ids
    assert "id:old-deploy" in ids


def test_never_active_principal_is_dormant():
    g = build_from_spec({
        "principals": [{"id": "p", "kind": "service_account", "name": "p"}],  # no last_active
        "grants": [{"holder": "p", "action": "deploy"}],
    })
    dormant = g.dormant_privileges(as_of=date(2026, 6, 22), idle_days=30)
    assert len(dormant) == 1
    assert dormant[0].idle_days is None


def test_separation_of_duties_break_on_release_bot(graph):
    conflicts = [DutyConflict(name="release author/approver", a="author", b="approve")]
    breaks = graph.separation_of_duties_breaks(conflicts)
    assert len(breaks) == 1
    brk = breaks[0]
    assert brk.principal == "id:release-bot"
    assert brk.action_a == "write"
    assert brk.action_b == "approve_release"


def test_no_sod_break_when_duties_held_separately(graph):
    # human-dev holds only the author duty effectively (approve needs escalation) → no break.
    conflicts = [DutyConflict(name="release author/approver", a="author", b="approve")]
    breaking_principals = {b.principal for b in graph.separation_of_duties_breaks(conflicts)}
    assert "id:human-dev" not in breaking_principals


# --- error handling ------------------------------------------------------------
def test_unknown_principal_raises(graph):
    with pytest.raises(IdentityError):
        graph.effective_permissions("nope")
    with pytest.raises(IdentityError):
        graph.escalation_paths("nope")


def test_negative_idle_days_raises(graph):
    with pytest.raises(IdentityError):
        graph.dormant_privileges(as_of=date(2026, 6, 22), idle_days=-1)


# --- ingestion seam ------------------------------------------------------------
def test_from_bloodhound_fails_closed():
    # Until wired, the production source must raise rather than return an empty graph.
    with pytest.raises(NotImplementedError):
        from_bloodhound()


def test_load_graph_missing_file():
    with pytest.raises(FileNotFoundError):
        load_graph(Path("/no/such/identity.yaml"))
