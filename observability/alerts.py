"""Routed, deduplicated alerting (area 12 / observability).

Turns security-relevant events — especially denials and fail-closed refusals — into severity-
routed alerts. Routing is deterministic and allowlist-based: each severity maps to a set of
named channels, and an alert is only delivered to channels configured for its severity.

Channels are **injected sinks** (callables). By default there are none, so this module never
makes a network call on its own — a deployment wires Slack/PagerDuty/Alertmanager sinks
explicitly. Alerts are deduplicated within a throttle window so one noisy condition can't flood
responders, and each alert carries the active correlation id so it links back to its trace.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable

from .trace import current_correlation_id


class Severity(IntEnum):
    INFO = 10
    WARNING = 20
    HIGH = 30
    CRITICAL = 40


@dataclass
class Alert:
    title: str
    severity: Severity
    source: str
    detail: dict[str, object] = field(default_factory=dict)
    correlation_id: str | None = None
    dedup_key: str = ""
    ts: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.dedup_key:
            self.dedup_key = f"{self.source}:{self.title}:{int(self.severity)}"

    def as_dict(self) -> dict[str, object]:
        """JSON-serialisable view of the alert (for file/JSONL sinks and audit records)."""
        return {
            "title": self.title,
            "severity": self.severity.name,
            "source": self.source,
            "detail": self.detail,
            "correlation_id": self.correlation_id,
            "dedup_key": self.dedup_key,
            "ts": self.ts,
        }


Sink = Callable[[Alert], None]


@dataclass
class AlertRouter:
    """Deterministic severity → channel routing with dedup/throttle.

    ``routes`` maps a severity to the channel names that should receive it. ``sinks`` maps a
    channel name to its delivery callable. An alert is delivered to every configured sink whose
    channel is listed for the alert's severity (and any higher severity routed to that channel).
    """

    routes: dict[Severity, tuple[str, ...]] = field(default_factory=dict)
    sinks: dict[str, Sink] = field(default_factory=dict)
    throttle_seconds: float = 300.0
    history: list[Alert] = field(default_factory=list)
    _last_sent: dict[str, float] = field(default_factory=dict)

    def channels_for(self, severity: Severity) -> set[str]:
        """Channels that should receive an alert at this severity (or anything noisier)."""
        chans: set[str] = set()
        for routed_sev, names in self.routes.items():
            if severity >= routed_sev:
                chans.update(names)
        return chans

    def _throttled(self, alert: Alert, now: float) -> bool:
        last = self._last_sent.get(alert.dedup_key)
        return last is not None and (now - last) < self.throttle_seconds

    def emit(self, alert: Alert) -> list[str]:
        """Route an alert. Returns the channel names it was delivered to (empty if throttled)."""
        if alert.correlation_id is None:
            alert.correlation_id = current_correlation_id()
        self.history.append(alert)

        now = time.time()
        if self._throttled(alert, now):
            return []

        delivered: list[str] = []
        for channel in sorted(self.channels_for(alert.severity)):
            sink = self.sinks.get(channel)
            if sink is None:
                continue
            try:
                sink(alert)
            except Exception:  # pragma: no cover - one bad sink must not drop the others
                continue
            delivered.append(channel)

        if delivered:
            self._last_sent[alert.dedup_key] = now
        return delivered

    def alert_denial(
        self,
        action: str,
        *,
        source: str,
        reason: str,
        severity: Severity = Severity.HIGH,
        **detail: object,
    ) -> list[str]:
        """Convenience: raise an alert for a denied / fail-closed action."""
        return self.emit(
            Alert(
                title=f"denied: {action}",
                severity=severity,
                source=source,
                detail={"action": action, "reason": reason, **detail},
            )
        )
