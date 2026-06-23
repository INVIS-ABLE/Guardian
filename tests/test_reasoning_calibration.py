"""Tests for confidence calibration & abstention (Sovereign #10)."""

from __future__ import annotations

from core.reasoning import Calibrator


def test_calibrated_falls_back_without_history():
    cal = Calibrator()
    assert cal.calibrated(0.9) == 0.9  # no samples ⇒ trust the raw value


def test_calibrated_overrides_overconfidence_with_history():
    cal = Calibrator()
    # 20 claims at ~0.9 confidence, only half actually correct.
    for i in range(20):
        cal.record(0.9, correct=(i % 2 == 0))
    assert cal.accuracy_for(0.9) == 0.5
    assert cal.calibrated(0.9) == 0.5  # recalibrated down to the track record


def test_should_abstain_on_overconfidence():
    cal = Calibrator()
    for i in range(20):
        cal.record(0.9, correct=(i % 5 == 0))  # 20% actual accuracy at 90% claimed
    assert cal.should_abstain(0.9) is True


def test_should_not_abstain_when_well_calibrated():
    cal = Calibrator()
    for i in range(20):
        cal.record(0.9, correct=(i % 10 != 0))  # 90% accuracy at 90% claimed
    assert cal.should_abstain(0.9) is False


def test_low_confidence_abstains_by_floor():
    assert Calibrator().should_abstain(0.3) is True   # below the 0.5 floor


def test_expected_calibration_error_zero_when_perfect():
    cal = Calibrator(bins=2)
    for _ in range(10):
        cal.record(0.25, correct=False)   # bin midpoint 0.25 → 0% accuracy: |0.25-0|=0.25
    # one populated bin, accuracy 0, midpoint 0.25 → ECE 0.25
    assert abs(cal.expected_calibration_error() - 0.25) < 1e-9


def test_persistence_roundtrip(tmp_path):
    store = tmp_path / "calib.jsonl"
    cal = Calibrator(store=store)
    for i in range(10):
        cal.record(0.8, correct=(i % 2 == 0))
    reloaded = Calibrator(store=store)
    assert reloaded.samples() == 10
    assert reloaded.accuracy_for(0.8) == 0.5
