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


@main.command("forensics")
@click.option("--log-dir", type=click.Path(), default=None,
              help="Audit-log directory to reconstruct (default: the standard Guardian log).")
@click.option("--rules", type=click.Path(exists=True), default=None,
              help="YAML with 'corroboration' and/or 'expected_sequences' for anomaly detection.")
@click.option("--case", default=None, help="Filter to one case_id / trace_id.")
@click.option("--alerts-jsonl", type=click.Path(), default=None,
              help="Route detected anomalies through the alert router, appending each as a "
                   "JSON line to this file (for an alert pipeline / log shipper).")
def forensics_cmd(log_dir: str | None, rules: str | None, case: str | None,
                  alerts_jsonl: str | None) -> None:
    """Forensic timeline: reconstruct an ordered incident timeline from the audit log and
    flag anomalies (integrity failures, missing events, unsupported successes).

    Read-only analysis: it draws conclusions and authorises nothing. Exits non-zero when any
    anomaly is found, so it can gate a pipeline or wake an operator.
    """
    from pathlib import Path

    import yaml

    from forensics import ForensicTimeline, events_from_audit_log

    audit = AuditLog(log_dir) if log_dir else AuditLog()
    events = events_from_audit_log(audit)
    if case:
        events = [e for e in events if case in (e.case_id, e.trace_id)]

    corroboration: dict = {}
    expected: dict = {}
    if rules:
        data = yaml.safe_load(Path(rules).read_text(encoding="utf-8")) or {}
        corroboration = data.get("corroboration", {}) or {}
        expected = data.get("expected_sequences", {}) or {}

    report = ForensicTimeline(corroboration=corroboration, expected_sequences=expected).build(events)
    click.echo(f"Timeline: {len(report.entries)} event(s), "
               f"{report.duplicates_removed} duplicate(s) removed")
    for c in report.chain_of_custody():
        flag = "" if c["integrity_ok"] else "  [INTEGRITY-FAIL]"
        click.echo(f"  {c['corrected_timestamp']:.0f}  {c['source']:9s} "
                   f"{c['action']:24s} {c['outcome']}{flag}")
    if report.anomalies:
        click.echo("Anomalies:")
        for a in report.anomalies:
            click.echo(f"  ! {a}")
    else:
        click.echo("No anomalies.")

    if alerts_jsonl:
        routed = _route_forensic_alerts(report, alerts_jsonl)
        click.echo(f"Routed {routed} alert(s) to {alerts_jsonl}")

    audit.record("forensics", actor="cli", decision="denied" if report.anomalies else "allowed",
                 detail={"events": len(report.entries), "anomalies": len(report.anomalies)})
    raise SystemExit(1 if report.anomalies else 0)


def _route_forensic_alerts(report, alerts_jsonl: str) -> int:
    """Route a timeline report's anomalies through the alert router to a JSONL file sink.

    Every severity is routed to one local file channel (no network), so nothing is dropped;
    each delivered alert is appended as one JSON line. Returns the number of alerts delivered.
    """
    import json
    from pathlib import Path

    from forensics import raise_forensic_alerts
    from observability.alerts import AlertRouter, Severity

    out = Path(alerts_jsonl)

    def file_sink(alert) -> None:
        with out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert.as_dict(), sort_keys=True) + "\n")

    router = AlertRouter(routes={Severity.INFO: ("file",)}, sinks={"file": file_sink})
    delivered = raise_forensic_alerts(report, router)
    return sum(1 for channels in delivered.values() if channels)


def _federate_from_opts(twin_spec, identity_spec, lineage_spec, bridges_spec):
    """Load + federate a twin / identity / lineage / bridges set of specs (any subset)."""
    from .twin import federate, load_twin

    twin = load_twin(twin_spec) if twin_spec else None
    identity = lineage = None
    if identity_spec:
        from .identity_graph import load_graph as load_identity
        identity = load_identity(identity_spec)
    if lineage_spec:
        from .lineage import load_graph as load_lineage
        lineage = load_lineage(lineage_spec)
    bridges = ()
    if bridges_spec:
        from pathlib import Path

        import yaml
        data = yaml.safe_load(Path(bridges_spec).read_text(encoding="utf-8")) or {}
        bridges = tuple((b["src"], b["relation"], b["dst"]) for b in data.get("bridges", []))
    return federate(twin, identity=identity, lineage=lineage, bridges=bridges)


@main.command("twin-federate-blast")
@click.argument("asset_id")
@click.option("--twin", "twin_spec", type=click.Path(exists=True), help="Digital-twin spec.")
@click.option("--identity", "identity_spec", type=click.Path(exists=True), help="Identity-graph spec.")
@click.option("--lineage", "lineage_spec", type=click.Path(exists=True), help="Lineage-graph spec.")
@click.option("--bridges", "bridges_spec", type=click.Path(exists=True), help="Cross-domain bridges spec.")
def twin_federate_blast_cmd(asset_id, twin_spec, identity_spec, lineage_spec, bridges_spec) -> None:
    """Cross-domain blast radius: fold identity + lineage into the twin, then trace from ASSET_ID."""
    fed = _federate_from_opts(twin_spec, identity_spec, lineage_spec, bridges_spec)
    radius = fed.blast_radius(asset_id)
    origin = fed.asset(asset_id)
    click.echo(f"Cross-domain blast radius of {origin.kind.value} '{origin.name}' ({asset_id}):")
    if not radius.impacted:
        click.echo("  (no downstream assets — isolated)")
    for item in radius.impacted:
        trail = " → ".join(f"{s.via.value}:{s.asset}" for s in item.path)
        click.echo(f"  [{item.distance}] {item.asset.kind.value:16s} {item.asset.id}   ({trail})")
    AuditLog().record("twin-federate-blast", actor="cli", scope=asset_id, decision="allowed",
                      detail={"impacted": len(radius.impacted)})


@main.command("twin-chokepoints")
@click.option("--twin", "twin_spec", type=click.Path(exists=True), help="Digital-twin spec.")
@click.option("--identity", "identity_spec", type=click.Path(exists=True), help="Identity-graph spec.")
@click.option("--lineage", "lineage_spec", type=click.Path(exists=True), help="Lineage-graph spec.")
@click.option("--bridges", "bridges_spec", type=click.Path(exists=True), help="Cross-domain bridges spec.")
@click.option("--top", type=int, default=10, show_default=True, help="Show the top N chokepoints.")
def twin_chokepoints_cmd(twin_spec, identity_spec, lineage_spec, bridges_spec, top) -> None:
    """Forecast: which single node, if controlled/removed, cuts the most attack paths to sinks."""
    from .twin import attack_surface, chokepoint_ranking

    fed = _federate_from_opts(twin_spec, identity_spec, lineage_spec, bridges_spec)
    surface = attack_surface(fed)
    ranking = chokepoint_ranking(fed)
    click.echo(f"Attack surface: {len(surface)} source→sink path(s) to sensitive sinks.")
    if not ranking:
        click.echo("  (no chokepoints — no attacker path reaches a sensitive sink)")
    for c in ranking[:top]:
        click.echo(f"  {c.paths_cut:3d} paths  {c.kind.value:16s} {c.node}  "
                   f"→ protects {', '.join(c.protects_sinks)}")
    AuditLog().record("twin-chokepoints", actor="cli", decision="allowed",
                      detail={"surface": len(surface), "chokepoints": len(ranking)})


@main.command("timeline")
@click.argument("stream_file", type=click.Path(exists=True))
@click.option("--actor", default=None, help="Scope the story to one principal.")
@click.option("--target", default=None, help="Scope the story to one asset.")
def timeline_cmd(stream_file: str, actor: str | None, target: str | None) -> None:
    """Forensic timeline: reconstruct the incident chronology from an event-fabric stream."""
    from .event_fabric import load_stream
    from .timeline import from_fabric

    sketch = from_fabric(load_stream(stream_file))
    if actor:
        beats = sketch.for_actor(actor)
        click.echo(f"Chronology for actor {actor} ({len(beats)} events):")
    elif target:
        beats = sketch.for_target(target)
        click.echo(f"Chronology for target {target} ({len(beats)} events):")
    else:
        beats = sketch.chronology()
        click.echo(f"Incident chronology ({len(beats)} events):")
    for b in beats:
        e = b.event
        mark = "★" if e.key else " "
        who = f" [{e.actor or '·'}→{e.target or '·'}]" if (e.actor or e.target) else ""
        click.echo(f" {mark} +{b.elapsed_seconds:>5.0f}s (Δ{b.delta_seconds:>4.0f}s) "
                   f"{e.phase.value:18s} {e.message}{who}")
    AuditLog().record("timeline", actor="cli", scope=stream_file, decision="allowed",
                      detail={"events": len(beats)})


@main.command("timeline-phases")
@click.argument("stream_file", type=click.Path(exists=True))
def timeline_phases_cmd(stream_file: str) -> None:
    """Forensic timeline: incident phases + dwell metrics reconstructed from a stream."""
    from .event_fabric import load_stream
    from .timeline import from_fabric

    sketch = from_fabric(load_stream(stream_file))
    click.echo("Incident phases (recon → … → containment):")
    for bucket in sketch.phases():
        ids = ", ".join(e.id for e in bucket.events)
        click.echo(f"  {bucket.phase.value:18s} {len(bucket.events)}  ({ids})")
    d = sketch.dwell()
    ttr = "n/a" if d.time_to_respond_seconds is None else f"{d.time_to_respond_seconds:.0f}s"
    click.echo(f"\nspan {d.total_span_seconds:.0f}s over {d.events} events; "
               f"time-to-contain: {ttr}")
    AuditLog().record("timeline-phases", actor="cli", scope=stream_file, decision="allowed",
                      detail={"phases": len(sketch.phases()), "ttr": d.time_to_respond_seconds})


@main.command("reason-causal")
@click.argument("spec_file", type=click.Path(exists=True))
@click.option("--observed", required=True, help="Comma-separated observed-compromised asset ids.")
@click.option("--sink", required=True, help="The sensitive asset that was reached.")
def reason_causal_cmd(spec_file: str, observed: str, sink: str) -> None:
    """Wave 2: causal root-cause of how OBSERVED compromise reached SINK (over a twin spec)."""
    from .reasoning import root_cause
    from .twin import load_twin

    twin = load_twin(spec_file)
    ids = [o.strip() for o in observed.split(",") if o.strip()]
    r = root_cause(twin, observed=ids, sink=sink)
    if r.first_event is None:
        click.echo(f"No path from {ids} to {sink} — sink not reached.")
        raise SystemExit(0)
    click.echo(f"Incident reaching {sink}:")
    click.echo(f"  first event:    {r.first_event}")
    click.echo(f"  root cause:     {r.root_cause}  (earliest necessary link — cut this)")
    click.echo(f"  enabling:       {' → '.join(r.enabling_conditions) or '(none)'}")
    click.echo(f"  amplifiers:     {', '.join(r.amplifiers) or '(none)'}")
    click.echo(f"  symptoms:       {' → '.join(r.symptoms)}")
    AuditLog().record("reason-causal", actor="cli", scope=sink, decision="allowed",
                      detail={"root_cause": r.root_cause, "first_event": r.first_event})


@main.command("threat-hunt")
@click.option("--twin", "twin_spec", type=click.Path(exists=True), help="Digital-twin spec.")
@click.option("--identity", "identity_spec", type=click.Path(exists=True), help="Identity-graph spec.")
@click.option("--lineage", "lineage_spec", type=click.Path(exists=True), help="Lineage-graph spec.")
@click.option("--fail-on-high", is_flag=True, help="Exit non-zero if any HIGH/CRITICAL hunt fires.")
def threat_hunt_cmd(twin_spec, identity_spec, lineage_spec, fail_on_high) -> None:
    """Wave 2: run read-only defensive hunts over the awareness graphs (Sovereign #11)."""
    from .reasoning import run_hunts

    twin = identity = lineage = None
    if twin_spec:
        from .twin import load_twin
        twin = load_twin(twin_spec)
    if identity_spec:
        from .identity_graph import load_graph as li
        identity = li(identity_spec)
    if lineage_spec:
        from .lineage import load_graph as ll
        lineage = ll(lineage_spec)

    results = run_hunts(twin=twin, identity=identity, lineage=lineage)
    if not results:
        click.echo("threat-hunt: no findings.")
    for r in results:
        flag = "+" if r.truncated else " "
        click.echo(f"[{r.severity.upper():8s}] {r.title} ({r.hunt_id})")
        click.echo(f"    hits{flag}: {', '.join(r.hits)}")
        click.echo(f"    → detection: {r.detection}")
    high = [r for r in results if r.severity in ("high", "critical")]
    AuditLog().record("threat-hunt", actor="cli", decision="allowed",
                      detail={"findings": len(results), "high": len(high)})
    raise SystemExit(1 if (fail_on_high and high) else 0)


@main.command("reason-ach")
@click.argument("case_file", type=click.Path(exists=True))
def reason_ach_cmd(case_file: str) -> None:
    """Competing hypotheses (ACH): rank rival explanations by least-contradicted; seek disproof."""
    from .reasoning import analyze, load_case

    case = load_case(case_file)
    view = analyze(case.hypotheses, case.evidence)
    click.echo(f"Analysis of Competing Hypotheses ({len(case.hypotheses)} hypotheses):")
    for v in view.ranked:
        lead = "→" if v.hypothesis_id == view.leading_id else " "
        click.echo(f" {lead} contradiction {v.contradiction_weight:>4.1f}  support {v.support_weight:>4.1f}  "
                   f"[{v.status}] {v.statement}")
    click.echo(f"\ndiagnostic evidence ({len(view.diagnostic_evidence)} discriminating, "
               f"{len(view.non_diagnostic_evidence)} non-diagnostic):")
    for d in view.diagnostic_evidence:
        click.echo(f"  • {d.summary}  (rules against {len(d.inconsistent_with)} hypothesis/es)")
    click.echo(f"\nverdict: {view.verdict}")
    if view.next_tests:
        click.echo("seek disproof — run next:")
        for t in view.next_tests:
            click.echo(f"  ? {t.description}")
    AuditLog().record("reason-ach", actor="cli", scope=case_file,
                      decision="allowed" if view.decisive else "inconclusive",
                      detail={"leading": str(view.leading_id), "decisive": view.decisive,
                              "abstained": view.case.abstained})


@main.command("reason-matrix")
@click.argument("case_file", type=click.Path(exists=True))
def reason_matrix_cmd(case_file: str) -> None:
    """Competing hypotheses (ACH): print the hypothesis × evidence consistency matrix."""
    from .reasoning import ach_matrix, load_case

    case = load_case(case_file)
    glyph = {"consistent": "+", "inconsistent": "−", "neutral": "·"}
    for row in ach_matrix(case.hypotheses, case.evidence):
        click.echo(row.statement)
        for cell in row.cells:
            click.echo(f"  {glyph[cell.consistency.value]} (w{cell.weight:g}) {cell.summary}")
    AuditLog().record("reason-matrix", actor="cli", scope=case_file, decision="allowed",
                      detail={"hypotheses": len(case.hypotheses)})


@main.command("twin-live")
@click.argument("twin_spec", type=click.Path(exists=True))
@click.argument("stream_spec", type=click.Path(exists=True))
@click.option("--min-severity", default="high", show_default=True,
              help="Flag events at/above this severity: info|low|medium|high|critical.")
def twin_live_cmd(twin_spec: str, stream_spec: str, min_severity: str) -> None:
    """Runtime fold: overlay the event fabric on the twin — what is at risk right now."""
    from .event_fabric import EventSeverity, load_stream
    from .twin import live_risk, load_twin

    twin = load_twin(twin_spec)
    fabric = load_stream(stream_spec)
    risk = live_risk(twin, fabric, min_severity=EventSeverity(min_severity.lower()))
    click.echo(f"Live runtime risk ({len(risk.signals)} notable signal(s), "
               f"{len(risk.runtime_edges)} observed edge(s)):")
    for s in risk.signals:
        oc = s.outcome.value if s.outcome else "-"
        click.echo(f"  [{s.severity.value:8s} {oc:9s}] {s.action} → {s.asset_id}")
    click.echo(f"\nAt risk now ({len(risk.at_risk)}): {', '.join(risk.at_risk) or '(none)'}")
    AuditLog().record("twin-live", actor="cli", scope=twin_spec, decision="allowed",
                      detail={"signals": len(risk.signals), "at_risk": len(risk.at_risk)})


if __name__ == "__main__":  # pragma: no cover
    main()
