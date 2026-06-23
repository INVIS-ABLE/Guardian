"""Forensic anomalies → routed alerts (bridges §17 timeline into area-12 alerting).

The forensic timeline (:mod:`forensics.timeline`) is read-only analysis: it *finds* problems
but raises nothing. This module is the one-way bridge that turns its findings into real,
severity-routed alerts via :class:`observability.alerts.AlertRouter`, so an unsupported success
or a tampered audit record actually reaches a responder instead of sitting in a report.

It is deliberately thin and one-directional — forensics concludes, alerting delivers. The
router is duck-typed (anything with ``emit(alert) -> list[str]``), and the severity mapping is
fail-loud: an unrecognised anomaly still alerts (at ``WARNING``) rather than being dropped.

Severity rationale:
  * ``unsupported_success`` — a tool claims success with the required independent evidence
    absent. This is the forensic heart of §17 and the strongest tampering/forgery signal →
    ``CRITICAL``.
  * ``integrity_failed`` — an event arrived without a valid integrity signal (possible
    tampering of the record itself) → ``CRITICAL``.
  * ``missing_event`` — an expected follow-up control never fired → ``HIGH``.
"""

from __future__ import annotations

from observability.alerts import Alert, Severity

from .timeline import TimelineReport

_FORENSIC_SOURCE = "forensics.timeline"

# anomaly kind (the token before the first ':') -> severity. Unknown kinds fall back to
# WARNING so a new anomaly type is never silently swallowed.
_SEVERITY_BY_KIND: dict[str, Severity] = {
    "unsupported_success": Severity.CRITICAL,
    "integrity_failed": Severity.CRITICAL,
    "missing_event": Severity.HIGH,
}
_DEFAULT_SEVERITY = Severity.WARNING


def severity_for(anomaly: str) -> Severity:
    """Map an anomaly string to its alert severity (fail-loud default of WARNING)."""
    return _SEVERITY_BY_KIND.get(anomaly.split(":", 1)[0], _DEFAULT_SEVERITY)


def _parse(kind: str, parts: list[str]) -> dict[str, object]:
    """Pull the structured fields out of a positional anomaly string, best-effort."""
    if kind == "integrity_failed" and len(parts) >= 3:
        return {"event_source": parts[1], "event_id": parts[2]}
    if kind == "missing_event" and len(parts) >= 3:
        return {"case_id": parts[1], "missing_action": parts[2]}
    if kind == "unsupported_success" and len(parts) >= 4:
        return {
            "case_id": parts[1],
            "action": parts[2],
            "missing_source": parts[3].removeprefix("no_"),
        }
    return {}


def anomaly_to_alert(
    anomaly: str,
    *,
    source: str = _FORENSIC_SOURCE,
    correlation_id: str | None = None,
) -> Alert:
    """Build (but do not emit) the alert for a single timeline anomaly string."""
    parts = anomaly.split(":")
    kind = parts[0]
    detail: dict[str, object] = {"anomaly": anomaly, "kind": kind, **_parse(kind, parts)}
    return Alert(
        title=f"forensic anomaly: {kind}",
        severity=severity_for(anomaly),
        source=source,
        detail=detail,
        correlation_id=correlation_id,
        # The full anomaly string is the natural dedup key: the same finding re-derived on a
        # later timeline rebuild throttles instead of re-paging responders.
        dedup_key=f"{source}:{anomaly}",
    )


def alerts_from_report(
    report: TimelineReport,
    *,
    source: str = _FORENSIC_SOURCE,
    correlation_id: str | None = None,
) -> list[Alert]:
    """All anomalies in a report, as constructed (un-emitted) alerts."""
    return [
        anomaly_to_alert(a, source=source, correlation_id=correlation_id)
        for a in report.anomalies
    ]


def raise_forensic_alerts(
    report: TimelineReport,
    router: object,
    *,
    source: str = _FORENSIC_SOURCE,
    correlation_id: str | None = None,
) -> dict[str, list[str]]:
    """Emit an alert for every anomaly in ``report`` through ``router``.

    ``router`` is duck-typed: anything exposing ``emit(alert) -> list[str]`` (e.g.
    :class:`observability.alerts.AlertRouter`). Returns a mapping of each anomaly string to the
    channel names it was delivered to (empty list when throttled or unrouted). A clean report
    raises nothing and returns an empty mapping.
    """
    emit = router.emit  # type: ignore[attr-defined]
    results: dict[str, list[str]] = {}
    for anomaly in report.anomalies:
        alert = anomaly_to_alert(anomaly, source=source, correlation_id=correlation_id)
        results[anomaly] = emit(alert)
    return results


__all__ = [
    "severity_for",
    "anomaly_to_alert",
    "alerts_from_report",
    "raise_forensic_alerts",
]
