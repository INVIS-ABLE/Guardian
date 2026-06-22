"""Event-fabric adapters — turn real Guardian emitter outputs into TimelineEvents.

So the forensic timeline runs on live signals, not hand-built events. Each adapter maps one
canonical emitter (the tamper-evident audit log, the policy gate, the evidence ledger, the
Shadow Guardian, connector execution) into the §16 ``TimelineEvent`` envelope. Inputs are
duck-typed (read by attribute), so this stays import-light and does not couple ``forensics``
to every producer package.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .timeline import TimelineEvent

if TYPE_CHECKING:  # hints only
    from core.audit import AuditLog
    from core.evidence.store import EvidenceReceipt
    from core.policy_gate import PolicyDecision
    from shadow_guardian.verifier import ShadowReport


def _iso_to_epoch(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return 0.0


def _mint(source: str, action: str, timestamp: float, case_id: str | None) -> str:
    seed = f"{source}:{action}:{timestamp}:{case_id}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def from_audit_entry(entry: Mapping[str, Any], *, integrity_ok: bool = True) -> TimelineEvent:
    """Map one tamper-evident audit-log record (core.audit) to a TimelineEvent."""
    detail = entry.get("detail", {}) or {}
    return TimelineEvent(
        event_id=str(entry.get("hash", ""))[:16] or _mint("audit", str(entry.get("action")),
                                                          _iso_to_epoch(str(entry.get("ts", ""))), None),
        source="audit",
        action=str(entry.get("action", "")),
        timestamp=_iso_to_epoch(str(entry.get("ts", ""))),
        actor=entry.get("actor"),
        asset=entry.get("scope"),
        case_id=detail.get("case_id"),
        trace_id=detail.get("trace_id"),
        outcome=str(entry.get("decision", "")),
        integrity_ok=integrity_ok,
        attributes=dict(detail),
    )


def events_from_audit_log(audit: "AuditLog") -> list[TimelineEvent]:
    """Read a hash-chained audit log into TimelineEvents.

    The whole-chain integrity check gates per-event ``integrity_ok``: if the chain does not
    verify, every derived event is marked integrity-failed (the tamper signal).
    """
    import json

    chain_ok = audit.verify()
    events: list[TimelineEvent] = []
    if not audit.path.exists():
        return events
    for line in audit.path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        events.append(from_audit_entry(json.loads(line), integrity_ok=chain_ok))
    return events


def from_policy_decision(
    decision: "PolicyDecision", *, action: str, actor: str, timestamp: float,
    case_id: str | None = None, trace_id: str | None = None, asset: str | None = None,
) -> TimelineEvent:
    """Map a central-policy decision (core.policy_gate) to a TimelineEvent."""
    allow = bool(getattr(decision, "allow", False))
    return TimelineEvent(
        event_id=_mint("opa", action, timestamp, case_id),
        source="opa", action=action, timestamp=timestamp, actor=actor, asset=asset,
        case_id=case_id, trace_id=trace_id,
        outcome="success" if allow else "denied",
        attributes={"denies": list(getattr(decision, "denies", []))},
    )


def from_evidence_receipt(
    receipt: "EvidenceReceipt", *, action: str = "append", timestamp: float,
    case_id: str | None = None,
) -> TimelineEvent:
    """Map an immutable-ledger append receipt (core.evidence) to a TimelineEvent.
    Integrity tracks the receipt's verifiable flag."""
    return TimelineEvent(
        event_id=getattr(receipt, "event_id", "") or _mint("evidence", action, timestamp, case_id),
        source="evidence", action=action, timestamp=timestamp, case_id=case_id,
        outcome="recorded", integrity_ok=bool(getattr(receipt, "verifiable", False)),
        attributes={"backend": getattr(receipt, "backend", ""),
                    "entry_hash": getattr(receipt, "entry_hash", "")},
    )


def from_shadow_report(
    report: "ShadowReport", *, timestamp: float, case_id: str | None = None,
) -> TimelineEvent:
    """Map a Shadow Guardian verification report to a TimelineEvent."""
    ok = bool(getattr(report, "ok", False))
    findings = getattr(report, "findings", [])
    return TimelineEvent(
        event_id=_mint("shadow", "verify_transition", timestamp, case_id),
        source="shadow", action="verify_transition", timestamp=timestamp, case_id=case_id,
        outcome="success" if ok else "failure", integrity_ok=ok,
        attributes={"frozen": bool(getattr(report, "frozen", False)),
                    "failures": [f.check for f in findings if not getattr(f, "ok", True)]},
    )


def from_execution(
    result: Any, *, action: str, timestamp: float, case_id: str | None = None,
    source: str = "connector",
) -> TimelineEvent:
    """Map a connector execution result to a TimelineEvent. A returncode of 0 is success;
    None (dry-run) is left as an unknown outcome rather than claimed success."""
    rc = getattr(result, "returncode", None)
    outcome = "success" if rc == 0 else ("failure" if rc not in (None, 0) else "")
    return TimelineEvent(
        event_id=getattr(result, "output_hash", "")[:16] or _mint(source, action, timestamp, case_id),
        source=source, action=action, timestamp=timestamp, case_id=case_id, outcome=outcome,
        attributes={"returncode": rc},
    )


__all__ = [
    "from_audit_entry", "events_from_audit_log", "from_policy_decision",
    "from_evidence_receipt", "from_shadow_report", "from_execution",
]
