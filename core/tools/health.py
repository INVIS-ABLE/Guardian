"""Tool-health service (Wave 2 — router fabric).

The manifest gateway decides whether a tool *may* run; this decides whether a tool is
currently *worth* running. It tracks the outcome of every execution per tool, derives a
health score and a circuit-breaker state, and lets the resolver prefer healthy tools and
fail closed when a tool is repeatedly broken — so one flaky scanner can't stall a case.

Pure and in-memory: no I/O, no clocks beyond an injectable ``now`` for testability.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class HealthState(str, Enum):
    """Circuit-breaker state for a tool."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"          # usable, but recent failures lowered its score
    UNAVAILABLE = "unavailable"    # circuit open — refuse until cooldown elapses


class ToolHealth(BaseModel):
    """Immutable snapshot of one tool's health."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: str
    state: HealthState
    score: float = Field(ge=0.0, le=1.0)
    successes: int = Field(ge=0, default=0)
    failures: int = Field(ge=0, default=0)
    consecutive_failures: int = Field(ge=0, default=0)
    last_latency_ms: float | None = None
    last_error: str | None = None

    @property
    def available(self) -> bool:
        return self.state is not HealthState.UNAVAILABLE


class ToolHealthTracker:
    """Records execution outcomes and exposes health with a circuit breaker.

    A tool starts optimistically HEALTHY (score 1.0). Each success/failure updates an
    EWMA success score. After ``failure_threshold`` consecutive failures the circuit
    opens (UNAVAILABLE) for ``cooldown_seconds``; afterwards it half-opens (DEGRADED) so
    a single trial can close it again. A score below ``degraded_below`` reads DEGRADED.
    """

    def __init__(
        self,
        *,
        alpha: float = 0.3,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
        degraded_below: float = 0.5,
    ) -> None:
        if not 0.0 < alpha <= 1.0:
            raise ValueError("alpha must be in (0, 1]")
        self._alpha = alpha
        self._failure_threshold = failure_threshold
        self._cooldown = timedelta(seconds=cooldown_seconds)
        self._degraded_below = degraded_below
        self._score: dict[str, float] = {}
        self._successes: dict[str, int] = {}
        self._failures: dict[str, int] = {}
        self._consecutive: dict[str, int] = {}
        self._opened_at: dict[str, datetime] = {}
        self._last_latency: dict[str, float | None] = {}
        self._last_error: dict[str, str | None] = {}

    def _ensure(self, tool: str) -> None:
        if tool not in self._score:
            self._score[tool] = 1.0
            self._successes[tool] = 0
            self._failures[tool] = 0
            self._consecutive[tool] = 0
            self._last_latency[tool] = None
            self._last_error[tool] = None

    def record_success(self, tool: str, *, latency_ms: float | None = None) -> None:
        self._ensure(tool)
        self._score[tool] = (1 - self._alpha) * self._score[tool] + self._alpha * 1.0
        self._successes[tool] += 1
        self._consecutive[tool] = 0
        self._opened_at.pop(tool, None)  # a success closes the circuit
        self._last_latency[tool] = latency_ms
        self._last_error[tool] = None

    def record_failure(self, tool: str, *, error: str = "", now: datetime | None = None) -> None:
        self._ensure(tool)
        self._score[tool] = (1 - self._alpha) * self._score[tool] + self._alpha * 0.0
        self._failures[tool] += 1
        self._consecutive[tool] += 1
        self._last_error[tool] = error or None
        if self._consecutive[tool] >= self._failure_threshold:
            self._opened_at[tool] = now or _utcnow()

    def _state(self, tool: str, now: datetime) -> HealthState:
        opened = self._opened_at.get(tool)
        if opened is not None:
            if now - opened < self._cooldown:
                return HealthState.UNAVAILABLE
            return HealthState.DEGRADED  # half-open: allow a trial run
        if self._score.get(tool, 1.0) < self._degraded_below:
            return HealthState.DEGRADED
        return HealthState.HEALTHY

    def health(self, tool: str, *, now: datetime | None = None) -> ToolHealth:
        self._ensure(tool)
        moment = now or _utcnow()
        return ToolHealth(
            tool=tool,
            state=self._state(tool, moment),
            score=round(self._score[tool], 6),
            successes=self._successes[tool],
            failures=self._failures[tool],
            consecutive_failures=self._consecutive[tool],
            last_latency_ms=self._last_latency[tool],
            last_error=self._last_error[tool],
        )

    def is_available(self, tool: str, *, now: datetime | None = None) -> bool:
        return self.health(tool, now=now).available

    def snapshot(self, *, now: datetime | None = None) -> dict[str, ToolHealth]:
        return {tool: self.health(tool, now=now) for tool in sorted(self._score)}


__all__ = ["HealthState", "ToolHealth", "ToolHealthTracker"]
