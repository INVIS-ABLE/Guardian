"""Confidence calibration & abstention — Sovereign system #10.

A model that says "90% confident" is only useful if it is right ~90% of the time. The
:class:`Calibrator` learns the relationship between *claimed* confidence and *actual*
correctness from recorded outcomes, then:

  * **recalibrates** a raw confidence to the value its track record actually justifies, and
  * **abstains** ("insufficient evidence for a safe conclusion") when a claim's confidence is
    not supported by history — which the Sovereign design treats as intelligence, not weakness.

Deterministic, dependency-free, with an optional JSONL store so calibration survives across
runs (mirrors core.memory / core.audit). Outcomes are booleans (was the conclusion correct?),
never private content.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BINS = 10


@dataclass(frozen=True)
class Bin:
    lo: float
    hi: float
    n: int          # samples recorded in this confidence band
    correct: int    # how many were actually correct

    @property
    def accuracy(self) -> float | None:
        return None if self.n == 0 else self.correct / self.n

    @property
    def midpoint(self) -> float:
        return (self.lo + self.hi) / 2


class Calibrator:
    """Tracks predicted-confidence vs actual-correctness in fixed bins."""

    def __init__(self, *, bins: int = DEFAULT_BINS, store: str | Path | None = None) -> None:
        if bins < 1:
            raise ValueError("bins must be >= 1")
        self.bins = bins
        self._n = [0] * bins
        self._correct = [0] * bins
        self.store = Path(store) if store else None
        if self.store and self.store.exists():
            self._load()

    # --- recording -------------------------------------------------------------
    def _bin_index(self, confidence: float) -> int:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError(f"confidence must be in [0,1], got {confidence}")
        idx = int(confidence * self.bins)
        return min(idx, self.bins - 1)  # 1.0 lands in the last bin

    def record(self, confidence: float, correct: bool) -> None:
        """Record one outcome: a claim made at ``confidence`` was/ wasn't ``correct``."""
        i = self._bin_index(confidence)
        self._n[i] += 1
        self._correct[i] += 1 if correct else 0
        if self.store:
            with self.store.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"confidence": confidence, "correct": bool(correct)}) + "\n")

    def _load(self) -> None:
        for line in self.store.read_text(encoding="utf-8").splitlines():  # type: ignore[union-attr]
            if not line.strip():
                continue
            d = json.loads(line)
            i = self._bin_index(float(d["confidence"]))
            self._n[i] += 1
            self._correct[i] += 1 if d["correct"] else 0

    # --- reading ---------------------------------------------------------------
    def bin_for(self, confidence: float) -> Bin:
        i = self._bin_index(confidence)
        return Bin(lo=i / self.bins, hi=(i + 1) / self.bins, n=self._n[i], correct=self._correct[i])

    def accuracy_for(self, confidence: float) -> float | None:
        """Historical accuracy of claims made at ``confidence`` (None if no samples)."""
        return self.bin_for(confidence).accuracy

    def calibrated(self, confidence: float, *, min_samples: int = 5) -> float:
        """Recalibrate a raw confidence to what its bin's track record justifies.

        Falls back to the raw value when there is not enough history (``min_samples``) to
        justify overriding it — we do not invent calibration from one or two samples.
        """
        b = self.bin_for(confidence)
        if b.n >= min_samples and b.accuracy is not None:
            return b.accuracy
        return confidence

    def should_abstain(
        self, confidence: float, *, floor: float = 0.5, min_samples: int = 5, gap: float = 0.2
    ) -> bool:
        """Whether to abstain rather than assert at this confidence.

        Abstain if the (recalibrated) confidence is below ``floor``, or if history has enough
        samples to show the claimed confidence overshoots actual accuracy by more than ``gap``.
        """
        b = self.bin_for(confidence)
        if b.n >= min_samples and b.accuracy is not None and (confidence - b.accuracy) > gap:
            return True
        return self.calibrated(confidence, min_samples=min_samples) < floor

    def expected_calibration_error(self) -> float:
        """ECE: sample-weighted gap between bin confidence (midpoint) and bin accuracy."""
        total = sum(self._n)
        if total == 0:
            return 0.0
        err = 0.0
        for i in range(self.bins):
            if self._n[i] == 0:
                continue
            acc = self._correct[i] / self._n[i]
            mid = (i + 0.5) / self.bins
            err += (self._n[i] / total) * abs(mid - acc)
        return err

    def samples(self) -> int:
        return sum(self._n)
