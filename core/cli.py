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


if __name__ == "__main__":  # pragma: no cover
    main()
