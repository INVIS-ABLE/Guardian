"""Level 6 §35: anti-oscillation controls for autonomous repair."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from adaptive.healing.anti_oscillation import (
    AntiOscillationPolicy,
    RepairAttempt,
    RepairLedger,
    check_repair,
)
from adaptive.healing.contracts import RepairAction

T0 = datetime(2026, 6, 23, 12, 0, 0, tzinfo=timezone.utc)
TARGET = "k8s://staging/message-relay/replica-0"


def _at(seconds: int) -> datetime:
    return T0 + timedelta(seconds=seconds)


def test_first_repair_is_allowed():
    led = RepairLedger()
    v = check_repair(led, TARGET, RepairAction.RESTART_REPLICA, now=T0)
    assert v.allowed is True


def test_in_flight_lock_blocks_concurrent_repair():
    led = RepairLedger()
    assert led.acquire_lock(TARGET) is True
    v = check_repair(led, TARGET, RepairAction.RESTART_REPLICA, now=T0)
    assert v.allowed is False and "in flight" in v.reason
    led.release_lock(TARGET)
    assert check_repair(led, TARGET, RepairAction.RESTART_REPLICA, now=T0).allowed is True


def test_cooldown_blocks_rapid_repeat():
    led = RepairLedger()
    pol = AntiOscillationPolicy(cooldown_seconds=300, max_per_window=10, loop_threshold=10)
    led.record(RepairAttempt(target_ref=TARGET, action=RepairAction.RESTART_REPLICA,
                             outcome="success", at=T0))
    v = check_repair(led, TARGET, RepairAction.RESTART_REPLICA, policy=pol, now=_at(60))
    assert v.allowed is False and "cooldown" in v.reason
    # after the cooldown, allowed again
    v2 = check_repair(led, TARGET, RepairAction.SCALE_SERVICE, policy=pol, now=_at(301))
    assert v2.allowed is True


def test_rate_limit_per_window():
    led = RepairLedger()
    pol = AntiOscillationPolicy(cooldown_seconds=0, max_per_window=2, window_seconds=3600,
                               loop_threshold=10, max_consecutive_failures=10)
    for i in range(2):
        led.record(RepairAttempt(target_ref=TARGET, action=RepairAction.SCALE_SERVICE,
                                 outcome="success", at=_at(i)))
    v = check_repair(led, TARGET, RepairAction.SCALE_SERVICE, policy=pol, now=_at(100))
    assert v.allowed is False and "max_per_window" in v.reason


def test_repeated_failure_freezes_and_escalates():
    led = RepairLedger()
    pol = AntiOscillationPolicy(cooldown_seconds=0, max_per_window=10,
                               max_consecutive_failures=2, loop_threshold=10)
    led.record(RepairAttempt(target_ref=TARGET, action=RepairAction.RESTART_REPLICA,
                             outcome="failure", at=_at(0)))
    led.record(RepairAttempt(target_ref=TARGET, action=RepairAction.RESTART_REPLICA,
                             outcome="failure", at=_at(1)))
    v = check_repair(led, TARGET, RepairAction.RESTART_REPLICA, policy=pol, now=_at(2))
    assert v.allowed is False
    assert v.frozen is True
    assert "frozen" in v.reason


def test_success_resets_consecutive_failure_count():
    led = RepairLedger()
    pol = AntiOscillationPolicy(cooldown_seconds=0, max_per_window=10,
                               max_consecutive_failures=2, loop_threshold=10)
    led.record(RepairAttempt(target_ref=TARGET, action=RepairAction.RESTART_REPLICA,
                             outcome="failure", at=_at(0)))
    led.record(RepairAttempt(target_ref=TARGET, action=RepairAction.RESTART_REPLICA,
                             outcome="success", at=_at(1)))
    v = check_repair(led, TARGET, RepairAction.RESTART_REPLICA, policy=pol, now=_at(2))
    assert v.allowed is True and v.frozen is False


def test_loop_detection_same_action():
    led = RepairLedger()
    pol = AntiOscillationPolicy(cooldown_seconds=0, max_per_window=10,
                               max_consecutive_failures=10, loop_threshold=3)
    # two prior restarts + this one == 3 -> loop
    led.record(RepairAttempt(target_ref=TARGET, action=RepairAction.RESTART_REPLICA,
                             outcome="success", at=_at(0)))
    led.record(RepairAttempt(target_ref=TARGET, action=RepairAction.RESTART_REPLICA,
                             outcome="success", at=_at(1)))
    v = check_repair(led, TARGET, RepairAction.RESTART_REPLICA, policy=pol, now=_at(2))
    assert v.allowed is False and "loop" in v.reason


def test_per_target_isolation():
    led = RepairLedger()
    other = "k8s://staging/message-relay/replica-1"
    led.record(RepairAttempt(target_ref=TARGET, action=RepairAction.RESTART_REPLICA,
                             outcome="failure", at=_at(0)))
    led.record(RepairAttempt(target_ref=TARGET, action=RepairAction.RESTART_REPLICA,
                             outcome="failure", at=_at(1)))
    # other target is unaffected by TARGET's failures
    v = check_repair(led, other, RepairAction.RESTART_REPLICA, now=_at(2))
    assert v.allowed is True
