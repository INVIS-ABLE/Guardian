"""Wave 1 completion: the router emits a canonical CaseEvent for every routed outcome.

This closes the Wave 1 loop — the typed contracts (#73/#78) are now produced at the
chokepoint: every ``route()`` / ``execute_capability()`` outcome becomes a content-
addressable ``CaseEvent``, accumulated on the router, linked into the tamper-evident
audit log, and forwarded to an optional sink. Emission is additive — callers that
ignore it see no behaviour change.
"""

from __future__ import annotations

from core.router import ToolRouter
from core.schemas import CaseEvent


def test_route_completed_emits_case_event(staging_scope):
    router = ToolRouter(staging_scope, dry_run=True)
    result = router.route("static_code", repo="github.com/invisable/app")
    assert result.allowed is True
    assert len(router.events) == 1
    ev = router.events[-1]
    assert isinstance(ev, CaseEvent)
    assert ev.event_type == "guardian.tool.completed"
    assert "tool:semgrep" in ev.asset_refs
    assert ev.payload_intact()
    assert ev.payload["capability"] == "static_code"


def test_route_refused_emits_refused_event(staging_scope):
    router = ToolRouter(staging_scope, dry_run=True)
    result = router.route("login_resilience", target="staging.invisable.co.uk")
    assert result.allowed is False
    ev = router.events[-1]
    assert ev.event_type == "guardian.tool.refused"
    assert ev.payload["refusal_reason"]
    assert ev.payload_intact()


def test_event_sink_receives_every_event(staging_scope):
    seen: list[CaseEvent] = []
    router = ToolRouter(staging_scope, dry_run=True, event_sink=seen.append)
    router.route("static_code", repo="github.com/invisable/app")
    router.route("privacy_simulation")
    assert len(seen) == 2
    assert seen == router.events
    assert all(e.payload_intact() for e in seen)


def test_emitted_event_is_linked_into_audit_log(staging_scope):
    import json

    router = ToolRouter(staging_scope, dry_run=True)
    router.route("static_code", repo="github.com/invisable/app")
    ev = router.events[-1]
    # the tamper-evident audit log (hash-chained JSONL) carries a record referencing the
    # canonical event; filter by the unique event UUID so the shared log file is fine.
    entries = [
        json.loads(line)
        for line in router.audit.path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    linked = [e for e in entries if e.get("detail", {}).get("event_id") == str(ev.event_id)]
    assert linked, "emitted CaseEvent must be linked into the audit log"
    assert linked[0]["detail"]["payload_sha256"] == ev.payload_sha256
