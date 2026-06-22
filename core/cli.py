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


@main.command("lineage-trace")
@click.argument("spec_file", type=click.Path(exists=True))
@click.argument("field_id")
@click.option("--up", is_flag=True, help="Trace upstream (provenance) instead of downstream.")
def lineage_trace_cmd(spec_file: str, field_id: str, up: bool) -> None:
    """Data lineage: where FIELD_ID's data flows to (or, with --up, where it came from)."""
    from .lineage import load_graph

    graph = load_graph(spec_file)
    f = graph.field(field_id)
    nodes = graph.upstream(field_id) if up else graph.downstream(field_id)
    direction = "Upstream of" if up else "Downstream of"
    click.echo(f"{direction} {f.dataset}.{f.name} ({field_id}):")
    if not nodes:
        click.echo("  (no connected fields — isolated)")
    for n in nodes:
        trail = " → ".join(f"{s.via}:{s.field}" for s in n.path)
        click.echo(f"  [{n.distance}] {n.field.classification.value:12s} {n.field.id}   ({trail})")
    AuditLog().record("lineage-trace", actor="cli", scope=field_id, decision="allowed",
                      detail={"direction": "up" if up else "down", "reached": len(nodes)})


@main.command("lineage-class")
@click.argument("spec_file", type=click.Path(exists=True))
@click.argument("field_id")
def lineage_class_cmd(spec_file: str, field_id: str) -> None:
    """Data lineage: the propagated (effective) classification of FIELD_ID."""
    from .lineage import load_graph

    graph = load_graph(spec_file)
    f = graph.field(field_id)
    classes = graph.propagated_classifications(field_id)
    pk = graph.peak_classification(field_id)
    labels = ", ".join(sorted(c.value for c in classes))
    click.echo(f"Propagated classification of {f.dataset}.{f.name} ({field_id}):")
    click.echo(f"  declared: {f.classification.value}")
    click.echo(f"  effective: {pk.value}  (from {{{labels}}})")
    AuditLog().record("lineage-class", actor="cli", scope=field_id, decision="allowed",
                      detail={"peak": pk.value})


@main.command("lineage-boundary")
@click.argument("spec_file", type=click.Path(exists=True))
def lineage_boundary_cmd(spec_file: str) -> None:
    """Data lineage: fields holding data their boundary is not approved for (gate)."""
    from .lineage import load_graph

    graph = load_graph(spec_file)
    violations = graph.boundary_violations()
    click.echo("Boundary violations (data outside its approved boundary):")
    if not violations:
        click.echo("  (none)")
    for v in violations:
        click.echo(f"  {v.field:26s} {v.offending.value:10s} not approved in {v.boundary} "
                   f"(introduced by {v.introduced_by})")
    AuditLog().record("lineage-boundary", actor="cli", scope=spec_file,
                      decision="denied" if violations else "allowed",
                      detail={"violations": len(violations)})
    raise SystemExit(1 if violations else 0)


@main.command("lineage-retention")
@click.argument("spec_file", type=click.Path(exists=True))
def lineage_retention_cmd(spec_file: str) -> None:
    """Data lineage: fields that would outlive an upstream deletion obligation (gate)."""
    from .lineage import load_graph

    graph = load_graph(spec_file)
    violations = graph.retention_violations()
    click.echo("Retention violations (derived data outliving an upstream obligation):")
    if not violations:
        click.echo("  (none)")
    for v in violations:
        held = "none" if v.declared_days is None else f"{v.declared_days}d"
        click.echo(f"  {v.field:26s} keeps {held:8s} > obligation {v.obligation_days}d "
                   f"(from {v.source})")
    AuditLog().record("lineage-retention", actor="cli", scope=spec_file,
                      decision="denied" if violations else "allowed",
                      detail={"violations": len(violations)})
    raise SystemExit(1 if violations else 0)


@main.command("twin-gate")
@click.argument("spec_file", type=click.Path(exists=True))
@click.option("--files-from", default="-", type=click.File("r"),
              help="File of changed paths, one per line ('-' = stdin).")
@click.option("--fail-on", default="critical", show_default=True,
              help="Severity that fails the gate: low|medium|high|critical.")
def twin_gate_cmd(spec_file, files_from, fail_on: str) -> None:
    """Digital twin: ambient PR gate — map changed files to assets, then assess blast radius.

    Reads changed paths (from a PR diff), resolves them to twin assets via each asset's
    declared path globs, and runs the blast-radius gate. Unmapped changes pass cleanly.
    """
    from .twin import Severity, assess_change, load_twin, resolve_changed_assets

    threshold = Severity.from_label(fail_on)
    twin = load_twin(spec_file)
    changed_files = [ln.strip() for ln in files_from.read().splitlines() if ln.strip()]
    changed_assets = resolve_changed_assets(twin, changed_files)
    if not changed_assets:
        click.echo(f"twin-gate: {len(changed_files)} changed file(s) map to no twin assets → PASS")
        AuditLog().record("twin-gate", actor="cli", decision="allowed",
                          detail={"changed_files": len(changed_files), "mapped_assets": 0})
        raise SystemExit(0)

    click.echo(f"twin-gate: changed files map to assets: {', '.join(changed_assets)}")
    result = assess_change(twin, changed_assets)
    for a in result.assessments:
        if not a.hits:
            continue
        click.echo(f"  {a.origin.id} ({a.origin.kind.value}): {a.severity.label.upper()}")
        for h in a.hits:
            trail = " → ".join(f"{s.via.value}:{s.asset}" for s in h.path)
            click.echo(f"      [{h.severity.label:8s}] {h.reason}  ({trail})")
    breached = result.breaches(threshold)
    click.echo(f"\ntwin-gate: {result.severity.label.upper()} (fail-on={threshold.label}) "
               f"→ {'FAIL' if breached else 'PASS'}")
    AuditLog().record("twin-gate", actor="cli",
                      decision="denied" if breached else "allowed",
                      detail={"severity": result.severity.label, "mapped_assets": len(changed_assets)})
    raise SystemExit(1 if breached else 0)


@main.command("endpoint-packs")
@click.argument("spec_file", type=click.Path(exists=True))
def endpoint_packs_cmd(spec_file: str) -> None:
    """Endpoint fabric: admit signed, reviewed osquery packs and list the approved surface."""
    from .endpoint import load_reviewed_packs, seal_and_admit

    packs = load_reviewed_packs(spec_file)
    fabric = seal_and_admit(packs)  # signs each with a one-off demo reviewer key, then admits
    click.echo(f"Admitted {len(fabric)} signed, reviewed pack(s):")
    for pack in fabric.packs():
        click.echo(f"  {pack.id}  (author {pack.author} → reviewed by {pack.reviewed_by}, "
                   f"signed by {fabric.admitting_key(pack.id)})")
        for q in pack.queries:
            click.echo(f"      {q.name:18s} [{q.platform.value:7s} @ {q.interval}s] {q.query}")
    AuditLog().record("endpoint-packs", actor="cli", scope=spec_file, decision="allowed",
                      detail={"packs": len(fabric), "queries": len(fabric.approved_queries())})


@main.command("endpoint-vet")
@click.argument("spec_file", type=click.Path(exists=True))
@click.argument("sql")
def endpoint_vet_cmd(spec_file: str, sql: str) -> None:
    """Endpoint fabric: is SQL allowed? Only verbatim queries from signed packs pass (gate)."""
    from .endpoint import load_reviewed_packs, seal_and_admit

    fabric = seal_and_admit(load_reviewed_packs(spec_file))
    verdict = fabric.vet_query(sql)
    if verdict.approved:
        click.echo(f"APPROVED — {verdict.pack}:{verdict.query}")
    else:
        click.echo("REFUSED — ad-hoc / model-generated osquery is not allowed")
        click.echo(f"  {verdict.reason}")
    AuditLog().record("endpoint-vet", actor="cli", scope=spec_file,
                      decision="allowed" if verdict.approved else "denied",
                      detail={"query": verdict.query})
    raise SystemExit(0 if verdict.approved else 1)


@main.command("events-tail")
@click.argument("spec_file", type=click.Path(exists=True))
@click.option("--source", default=None, help="Filter to one source (opa, github, falco, …).")
@click.option("--min-severity", default=None, help="Minimum severity (info|low|medium|high|critical).")
def events_tail_cmd(spec_file: str, source: str | None, min_severity: str | None) -> None:
    """Event fabric: print the ordered stream (optionally filtered)."""
    from .event_fabric import EventSeverity, EventSource, load_stream

    fabric = load_stream(spec_file)
    src = EventSource(source) if source else None
    sev = EventSeverity(min_severity) if min_severity else None
    rows = fabric.query(source=src, min_severity=sev)
    click.echo(f"Stream: {len(fabric)} event(s), showing {len(rows)}:")
    for s in rows:
        e = s.event
        who = f" {e.actor or '·'}→{e.target}" if e.target else (f" {e.actor}" if e.actor else "")
        out = f" [{e.outcome.value}]" if e.outcome else ""
        click.echo(f"  #{s.offset:<3d} {e.ts.isoformat()} {e.source.value:9s} "
                   f"{e.severity.value:8s} {e.action}{out}{who}")
    AuditLog().record("events-tail", actor="cli", scope=spec_file, decision="allowed",
                      detail={"shown": len(rows)})


@main.command("events-stats")
@click.argument("spec_file", type=click.Path(exists=True))
@click.option("--by", "field", default="source", help="Group by: source|severity|outcome|actor|target|action.")
def events_stats_cmd(spec_file: str, field: str) -> None:
    """Event fabric: aggregate event counts grouped by a field."""
    from .event_fabric import load_stream

    fabric = load_stream(spec_file)
    counts = fabric.counts_by(field)
    click.echo(f"Counts by {field} ({len(fabric)} events):")
    for key, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        click.echo(f"  {key:24s} {n}")
    AuditLog().record("events-stats", actor="cli", scope=spec_file, decision="allowed",
                      detail={"field": field, "groups": len(counts)})


@main.command("events-spikes")
@click.argument("spec_file", type=click.Path(exists=True))
@click.option("--window", "window_seconds", type=int, default=60, show_default=True,
              help="Sliding window in seconds.")
@click.option("--threshold", type=int, default=3, show_default=True, help="Events to flag a spike.")
@click.option("--outcome", default=None, help="Restrict to one outcome (e.g. deny).")
def events_spikes_cmd(spec_file: str, window_seconds: int, threshold: int, outcome: str | None) -> None:
    """Event fabric: per-actor burst detection (gate — exits non-zero when spikes are found)."""
    from .event_fabric import Outcome, load_stream

    fabric = load_stream(spec_file)
    oc = Outcome(outcome) if outcome else None
    spikes = fabric.spikes(window_seconds=window_seconds, threshold=threshold, outcome=oc)
    click.echo(f"Spikes (≥{threshold} events in {window_seconds}s"
               f"{f', outcome={outcome}' if outcome else ''}):")
    if not spikes:
        click.echo("  (none)")
    for sp in spikes:
        click.echo(f"  {sp.actor:18s} {sp.count} events  "
                   f"{sp.first_ts.isoformat()} → {sp.last_ts.isoformat()}")
    AuditLog().record("events-spikes", actor="cli", scope=spec_file,
                      decision="denied" if spikes else "allowed",
                      detail={"spikes": len(spikes)})
    raise SystemExit(1 if spikes else 0)


@main.command("events-verify")
@click.argument("spec_file", type=click.Path(exists=True))
def events_verify_cmd(spec_file: str) -> None:
    """Event fabric: verify the stream's tamper-evident hash chain."""
    from .event_fabric import load_stream

    fabric = load_stream(spec_file)
    ok = fabric.verify()
    click.echo(f"event stream ({len(fabric)} events): {'OK' if ok else 'TAMPERED'}")
    AuditLog().record("events-verify", actor="cli", scope=spec_file,
                      decision="allowed" if ok else "denied", detail={"ok": ok})
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":  # pragma: no cover
    main()
