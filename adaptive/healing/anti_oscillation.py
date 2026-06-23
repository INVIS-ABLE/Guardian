"""Anti-oscillation controls for autonomous repair (directive §35).

Self-healing systems can loop: restart loops, scale up/down oscillation, repeated canary
rollback, feature-flag flapping, failover/failback loops, credential revoke/reissue loops.
This module is the deterministic governor that prevents them. It tracks recent repair
attempts per exact target and refuses a new repair when:

* a per-target repair is already in flight (repair lock);
* the target is still inside its cooldown window;
* the per-window repair budget is exhausted (rate limit);
* the same action (or a small alternating set) repeats too often (loop detection);
* the last N attempts for the target all failed (freeze, with escalation).

It grants nothing — it only allows or refuses, and a refusal is recorded with a reason.
Pairs with the runbook budget's ``cooldown_seconds`` and the autonomy budget's
``recent_repair_success_rate`` (``adaptive.autonomy.budgets``).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .contracts import RepairAction


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


RepairOutcome = Literal["success", "failure"]


class RepairAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target_ref: str
    action: RepairAction
    outcome: RepairOutcome
    at: datetime = Field(default_factory=_utcnow)


class AntiOscillationPolicy(BaseModel):
    """Tunable limits. Conservative defaults; a runbook may tighten them, never loosen."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cooldown_seconds: int = Field(ge=0, default=300)
    window_seconds: int = Field(ge=1, default=3600)
    max_per_window: int = Field(ge=1, default=3)
    max_consecutive_failures: int = Field(ge=1, default=2)
    loop_threshold: int = Field(ge=2, default=3)  # same/alternating action repeats


class OscillationVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    frozen: bool = False
    reason: str = ""


class RepairLedger:
    """In-memory record of repair attempts and in-flight locks per target.

    Deliberately backend-free (like ``core.memory``'s fallback): the durable record lives
    in immudb/evidence; this is the fast operational view the governor reasons over.
    """

    def __init__(self) -> None:
        self._attempts: list[RepairAttempt] = []
        self._locked: set[str] = set()

    def record(self, attempt: RepairAttempt) -> None:
        self._attempts.append(attempt)

    def recent(self, target_ref: str, *, window_seconds: int, now: datetime | None = None
               ) -> list[RepairAttempt]:
        cutoff = (now or _utcnow()) - timedelta(seconds=window_seconds)
        return [a for a in self._attempts if a.target_ref == target_ref and a.at >= cutoff]

    def is_locked(self, target_ref: str) -> bool:
        return target_ref in self._locked

    def acquire_lock(self, target_ref: str) -> bool:
        """Take the per-target in-flight lock. Returns False if already held."""
        if target_ref in self._locked:
            return False
        self._locked.add(target_ref)
        return True

    def release_lock(self, target_ref: str) -> None:
        self._locked.discard(target_ref)


def _consecutive_failures(attempts: list[RepairAttempt]) -> int:
    """Count trailing failures in chronological order."""
    ordered = sorted(attempts, key=lambda a: a.at)
    count = 0
    for a in reversed(ordered):
        if a.outcome == "failure":
            count += 1
        else:
            break
    return count


def _detects_loop(attempts: list[RepairAttempt], action: RepairAction, threshold: int) -> bool:
    """Same action repeats >= threshold, or it alternates with one other action >= threshold."""
    actions = [a.action for a in sorted(attempts, key=lambda a: a.at)] + [action]
    same = sum(1 for x in actions if x is action)
    if same >= threshold:
        return True
    # Flapping: the candidate plus exactly one other action dominate the recent window.
    distinct = set(actions)
    if len(distinct) == 2 and len(actions) >= threshold:
        return True
    return False


def check_repair(
    ledger: RepairLedger,
    target_ref: str,
    action: RepairAction,
    *,
    policy: AntiOscillationPolicy | None = None,
    now: datetime | None = None,
) -> OscillationVerdict:
    """Decide whether a repair may proceed for this exact target. Pure given the ledger."""
    policy = policy or AntiOscillationPolicy()
    now = now or _utcnow()

    if ledger.is_locked(target_ref):
        return OscillationVerdict(allowed=False, reason=f"repair already in flight for {target_ref}")

    recent = ledger.recent(target_ref, window_seconds=policy.window_seconds, now=now)

    # Freeze after repeated failure (§35): escalate, do not keep trying.
    fails = _consecutive_failures(recent)
    if fails >= policy.max_consecutive_failures:
        return OscillationVerdict(
            allowed=False, frozen=True,
            reason=(f"{fails} consecutive failures for {target_ref} — automation frozen, "
                    "escalate to human"),
        )

    # Cooldown: respect the minimum gap since the last attempt.
    if recent:
        last = max(recent, key=lambda a: a.at)
        if now - last.at < timedelta(seconds=policy.cooldown_seconds):
            return OscillationVerdict(
                allowed=False,
                reason=f"within cooldown ({policy.cooldown_seconds}s) for {target_ref}",
            )

    # Rate limit per window.
    if len(recent) >= policy.max_per_window:
        return OscillationVerdict(
            allowed=False,
            reason=(f"{len(recent)} repairs in {policy.window_seconds}s exceeds "
                    f"max_per_window={policy.max_per_window} for {target_ref}"),
        )

    # Loop / flapping detection.
    if _detects_loop(recent, action, policy.loop_threshold):
        return OscillationVerdict(
            allowed=False,
            reason=f"repair loop/flapping detected for {target_ref} (action {action.value})",
        )

    return OscillationVerdict(allowed=True, reason="within anti-oscillation limits")


__all__ = [
    "RepairAttempt",
    "AntiOscillationPolicy",
    "OscillationVerdict",
    "RepairLedger",
    "check_repair",
]
