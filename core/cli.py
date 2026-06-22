"""Unified Guardian CLI (entry point: ``guardian``).

Thin wrapper that exposes scope/guardrail checks and simulator runs. Safe by
default: dry-run is on unless ``--no-dry-run`` is passed *and* the scope/approvals
permit live execution.
"""

from __future__ import annotations

import click

from . import VERSION
from .audit import AuditLog
from .guardrails import check_scope
from .scope import load_scope


@click.group()
@click.version_option(VERSION, prog_name="guardian")
def main() -> None:
    """INVISABLE Guardian — defensive-only security & safeguarding immune system."""


@main.command("check-scope")
@click.argument("scope_file", type=click.Path(exists=True))
def check_scope_cmd(scope_file: str) -> None:
    """Validate a scope file and print guardrail notes."""
    scope = load_scope(scope_file)
    click.echo(f"Scope OK: {scope.asset} ({scope.environment})")
    for note in check_scope(scope) or ["No warnings."]:
        click.echo(f"  {note}")
    AuditLog().record("check_scope", actor="cli", scope=scope.asset, decision="allowed")


@main.command("audit-verify")
def audit_verify_cmd() -> None:
    """Verify the tamper-evident audit log chain."""
    ok = AuditLog().verify()
    click.echo("audit chain: OK" if ok else "audit chain: TAMPERED")
    raise SystemExit(0 if ok else 1)


@main.command("simulators")
def simulators_cmd() -> None:
    """List available simulators."""
    from simulators import REGISTRY

    for name, cls in sorted(REGISTRY.items()):
        click.echo(f"{name:28s} {cls.__doc__ or ''}".rstrip())


@main.command("agents")
def agents_cmd() -> None:
    """List the Guardian Brain agents."""
    from agents import REGISTRY

    for name, cls in sorted(REGISTRY.items()):
        click.echo(f"{name:20s} {cls.summary}")


@main.command("capabilities")
def capabilities_cmd() -> None:
    """List tool-router capabilities (capability -> tool)."""
    from .router import CAPABILITY_MAP

    for cap, (kind, tool) in sorted(CAPABILITY_MAP.items()):
        click.echo(f"{cap:28s} {kind:10s} {tool}")


@main.command("policy")
@click.argument("scope_file", type=click.Path(exists=True))
@click.option("--action", required=True, help="Action to authorise (e.g. code_review).")
@click.option("--mode", required=True, help="Scope mode requested (e.g. code_review).")
@click.option("--approve", multiple=True, help="Recorded approval action(s).")
def policy_cmd(scope_file: str, action: str, mode: str, approve: tuple[str, ...]) -> None:
    """Evaluate the central authorization policy for an action against a scope (fail-closed)."""
    from .brain import build_policy_input
    from .policy_gate import ApprovalLite, evaluate

    scope = load_scope(scope_file)
    approvals = [ApprovalLite(action=a, approver="cli-user") for a in approve]
    decision = evaluate(build_policy_input(scope, action=action, mode=mode, approvals=approvals))
    click.echo("decision: ALLOW" if decision.allow else "decision: DENY")
    for reason in decision.denies:
        click.echo(f"  - {reason}")
    raise SystemExit(0 if decision.allow else 1)


@main.command("brain")
@click.argument("scope_file", type=click.Path(exists=True))
@click.option("--no-dry-run", is_flag=True, help="Permit live execution (still gated).")
@click.option("--approve", multiple=True,
              help="Record a human approval action (e.g. production_scan).")
@click.option("--approver", default="cli-user", help="Who approved (for the audit log).")
@click.option("--ticket", default="local-run", help="Approval evidence reference.")
def brain_cmd(scope_file: str, no_dry_run: bool, approve: tuple[str, ...],
              approver: str, ticket: str) -> None:
    """Run the Guardian Brain workflow over a scope (dry-run by default)."""
    from .brain import GuardianBrain
    from .guardrails import Approval

    scope = load_scope(scope_file)
    approvals = [Approval(action=a, approver=approver, ticket=ticket) for a in approve]
    brain = GuardianBrain(scope, dry_run=not no_dry_run, approvals=approvals)
    run = brain.run()
    click.echo(run.summary())
    for s in run.stages:
        marker = {"ok": "✓", "refused": "✗", "skipped": "·", "halted": "!"}.get(s.status, "?")
        line = f"  {marker} [{s.stage}] {s.agent}"
        if s.note:
            line += f" — {s.note}"
        click.echo(line)
    AuditLog().record("brain", actor="cli", scope=scope.asset, decision="allowed",
                      detail={"approved": run.approved, "halted_at": run.halted_at})


@main.command("twin-blast")
@click.argument("spec_file", type=click.Path(exists=True))
@click.argument("asset_id")
@click.option("--max-depth", type=int, default=None, help="Limit propagation depth.")
def twin_blast_cmd(spec_file: str, asset_id: str, max_depth: int | None) -> None:
    """Digital twin: what is affected if ASSET_ID is compromised?"""
    from .twin import load_twin

    twin = load_twin(spec_file)
    radius = twin.blast_radius(asset_id, max_depth=max_depth)
    origin = twin.asset(asset_id)
    click.echo(f"Blast radius of {origin.kind.value} '{origin.name}' ({asset_id}):")
    if not radius.impacted:
        click.echo("  (no downstream assets — isolated)")
    for item in radius.impacted:
        trail = " → ".join(f"{s.via.value}:{s.asset}" for s in item.path)
        click.echo(f"  [{item.distance}] {item.asset.kind.value:16s} {item.asset.id}   ({trail})")
    AuditLog().record("twin-blast", actor="cli", scope=asset_id, decision="allowed",
                      detail={"impacted": len(radius.impacted)})


@main.command("twin-path")
@click.argument("spec_file", type=click.Path(exists=True))
@click.argument("source")
@click.argument("target")
def twin_path_cmd(spec_file: str, source: str, target: str) -> None:
    """Digital twin: shortest attack path SOURCE → TARGET."""
    from .twin import load_twin

    twin = load_twin(spec_file)
    path = twin.attack_path(source, target)
    if path is None:
        click.echo(f"No path from {source} to {target}.")
        raise SystemExit(1)
    trail = source + "".join(f" → {s.via.value} → {s.asset}" for s in path)
    click.echo(trail)
    AuditLog().record("twin-path", actor="cli", scope=f"{source}->{target}",
                      decision="allowed", detail={"hops": len(path)})


@main.command("twin-assess")
@click.argument("spec_file", type=click.Path(exists=True))
@click.option("--changed", required=True,
              help="Comma-separated asset ids the change touches (e.g. repo:guardian,svc:x).")
@click.option("--fail-on", default="high", show_default=True,
              help="Severity that fails the gate: low|medium|high|critical.")
@click.option("--max-depth", type=int, default=None, help="Limit propagation depth.")
def twin_assess_cmd(spec_file: str, changed: str, fail_on: str, max_depth: int | None) -> None:
    """Digital twin: PR-time blast-radius gate for a set of changed assets.

    Exits non-zero (gating CI) when a changed asset's compromise would reach a sink at or
    above the --fail-on severity. Read-only analysis — it proposes a verdict, authorises nothing.
    """
    from .twin import Severity, assess_change, load_twin

    threshold = Severity.from_label(fail_on)
    twin = load_twin(spec_file)
    ids = [c.strip() for c in changed.split(",") if c.strip()]
    result = assess_change(twin, ids, max_depth=max_depth)

    for a in result.assessments:
        click.echo(f"{a.origin.id} ({a.origin.kind.value}): {a.severity.label.upper()} "
                   f"— {a.impacted_count} impacted, {len(a.hits)} sensitive")
        for h in a.hits:
            trail = " → ".join(f"{s.via.value}:{s.asset}" for s in h.path)
            click.echo(f"    [{h.severity.label:8s}] {h.reason}  ({trail})")
    breached = result.breaches(threshold)
    click.echo(f"\nblast-radius gate: {result.severity.label.upper()} "
               f"(fail-on={threshold.label}) → {'FAIL' if breached else 'PASS'}")
    AuditLog().record("twin-assess", actor="cli", scope=changed,
                      decision="denied" if breached else "allowed",
                      detail={"severity": result.severity.label, "fail_on": threshold.label})
    raise SystemExit(1 if breached else 0)


@main.command("id-perms")
@click.argument("spec_file", type=click.Path(exists=True))
@click.argument("principal_id")
def id_perms_cmd(spec_file: str, principal_id: str) -> None:
    """Identity graph: effective + transitive permissions of PRINCIPAL_ID."""
    from .identity_graph import load_graph

    graph = load_graph(spec_file)
    who = graph.principal(principal_id)
    perms = graph.effective_permissions(principal_id)
    click.echo(f"Effective permissions of {who.kind.value} '{who.name}' ({principal_id}):")
    if not perms:
        click.echo("  (no permissions)")
    for p in perms:
        src = "direct" if not p.inherited else f"via {p.via}"
        tags = (" [sensitive]" if p.sensitive else "") + (f" [{p.duty}]" if p.duty else "")
        click.echo(f"  {p.action:16s} {p.resource:24s} ({src}){tags}")
    AuditLog().record("id-perms", actor="cli", scope=principal_id, decision="allowed",
                      detail={"permissions": len(perms)})


@main.command("id-escalate")
@click.argument("spec_file", type=click.Path(exists=True))
@click.argument("principal_id")
@click.option("--max-depth", type=int, default=None, help="Limit escalation path length.")
def id_escalate_cmd(spec_file: str, principal_id: str, max_depth: int | None) -> None:
    """Identity graph: privilege-escalation paths open to PRINCIPAL_ID."""
    from .identity_graph import load_graph

    graph = load_graph(spec_file)
    who = graph.principal(principal_id)
    paths = graph.escalation_paths(principal_id, max_depth=max_depth)
    click.echo(f"Escalation paths from {who.kind.value} '{who.name}' ({principal_id}):")
    if not paths:
        click.echo("  (none — cannot acquire rights beyond its effective set)")
    for ep in paths:
        trail = principal_id + "".join(f" → {s.via.value} → {s.principal}" for s in ep.path)
        gained = ", ".join(f"{g.action}:{g.resource}" for g in ep.gained)
        click.echo(f"  {trail}")
        click.echo(f"      gains: {gained}")
    AuditLog().record("id-escalate", actor="cli", scope=principal_id, decision="allowed",
                      detail={"paths": len(paths)})


@main.command("id-dormant")
@click.argument("spec_file", type=click.Path(exists=True))
@click.option("--idle-days", type=int, default=90, help="Idle threshold in days (default 90).")
@click.option("--as-of", default=None, help="Reference date YYYY-MM-DD (default: today).")
@click.option("--sensitive-only", is_flag=True, help="Only principals holding sensitive grants.")
def id_dormant_cmd(spec_file: str, idle_days: int, as_of: str | None,
                   sensitive_only: bool) -> None:
    """Identity graph: privileged principals that have gone dormant."""
    from datetime import date

    from .identity_graph import load_graph

    graph = load_graph(spec_file)
    ref = date.fromisoformat(as_of) if as_of else date.today()
    dormant = graph.dormant_privileges(as_of=ref, idle_days=idle_days,
                                       sensitive_only=sensitive_only)
    click.echo(f"Dormant privileged principals (idle ≥ {idle_days}d as of {ref.isoformat()}):")
    if not dormant:
        click.echo("  (none)")
    for d in dormant:
        idle = "never active" if d.idle_days is None else f"idle {d.idle_days}d"
        tag = " [sensitive]" if d.sensitive else ""
        click.echo(f"  {d.principal.id:18s} {idle:16s} {d.permissions} perm(s){tag}")
    AuditLog().record("id-dormant", actor="cli", scope=spec_file, decision="allowed",
                      detail={"dormant": len(dormant)})


@main.command("id-sod")
@click.argument("spec_file", type=click.Path(exists=True))
@click.option("--conflict", "conflicts", multiple=True, metavar="NAME:A:B",
              help="Duty conflict as name:dutyA:dutyB (repeatable). Default: release author/approve.")
def id_sod_cmd(spec_file: str, conflicts: tuple[str, ...]) -> None:
    """Identity graph: separation-of-duties breaks (one principal, two conflicting duties)."""
    from .identity_graph import DutyConflict, load_graph

    graph = load_graph(spec_file)
    if conflicts:
        parsed = []
        for raw in conflicts:
            name, a, b = raw.split(":", 2)
            parsed.append(DutyConflict(name=name, a=a, b=b))
    else:
        parsed = [DutyConflict(name="release author/approver", a="author", b="approve")]
    breaks = graph.separation_of_duties_breaks(parsed)
    click.echo("Separation-of-duties breaks:")
    if not breaks:
        click.echo("  (none)")
    for b in breaks:
        click.echo(f"  {b.principal:18s} {b.conflict.name}: "
                   f"{b.action_a} ({b.conflict.a}) + {b.action_b} ({b.conflict.b})")
    AuditLog().record("id-sod", actor="cli", scope=spec_file, decision="allowed",
                      detail={"breaks": len(breaks)})
    raise SystemExit(1 if breaks else 0)


if __name__ == "__main__":  # pragma: no cover
    main()
