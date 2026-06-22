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


if __name__ == "__main__":  # pragma: no cover
    main()
