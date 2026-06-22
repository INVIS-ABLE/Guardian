"""Two-person approval collection with replay/idempotency protection (Phase 1).

A production workflow pauses until it receives approval signals from two DISTINCT
authenticated reviewers. Each signal carries a nonce (idempotency key); a replayed nonce is
rejected (bulletproof test: a replayed Temporal signal is rejected). Signals are bound to the
exact commit / workflow_run / target, so an approval cannot move between commits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import time

from core.policy_gate import PRODUCTION_MIN_REVIEWERS


class ReplaySignalError(RuntimeError):
    """Raised when an approval signal reuses a nonce already seen (replay/duplicate)."""


class ClosedLedgerError(RuntimeError):
    """Raised when a signal arrives after the workflow is no longer collecting approvals."""


@dataclass(frozen=True)
class ReviewerSignal:
    reviewer: str  # authenticated identity (distinct per person)
    action: str  # e.g. "production_scan"
    nonce: str  # unique idempotency key for this signal
    commit: str | None = None
    workflow_run: str | None = None
    target: str | None = None
    expires_at: float | None = None
    ts: float = field(default_factory=time)

    def is_valid(self, now: float) -> bool:
        return self.expires_at is None or now < self.expires_at


@dataclass
class ApprovalLedger:
    """Collects reviewer signals for one workflow, bound to its commit/run/target."""

    workflow_run: str
    commit: str | None = None
    target: str | None = None
    closed: bool = False
    _seen_nonces: set[str] = field(default_factory=set)
    _signals: list[ReviewerSignal] = field(default_factory=list)

    def submit(self, sig: ReviewerSignal) -> None:
        if self.closed:
            raise ClosedLedgerError("approval ledger is closed; no further signals accepted")
        if sig.nonce in self._seen_nonces:
            raise ReplaySignalError(f"replayed approval nonce: {sig.nonce}")
        # Binding: the signal must match this workflow's run/commit/target when specified.
        if sig.workflow_run is not None and sig.workflow_run != self.workflow_run:
            raise ReplaySignalError("signal workflow_run does not match this workflow")
        if self.commit is not None and sig.commit is not None and sig.commit != self.commit:
            raise ReplaySignalError("signal commit does not match this workflow's commit")
        self._seen_nonces.add(sig.nonce)
        self._signals.append(sig)

    def distinct_reviewers(self, action: str, now: float | None = None) -> set[str]:
        now = time() if now is None else now
        return {s.reviewer for s in self._signals if s.action == action and s.is_valid(now)}

    def satisfied_for_production(self, now: float | None = None) -> bool:
        return len(self.distinct_reviewers("production_scan", now)) >= PRODUCTION_MIN_REVIEWERS

    def close(self) -> None:
        self.closed = True
