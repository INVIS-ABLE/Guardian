"""Level 6 §7: self-healing hierarchy — pick the lowest viable repair layer."""

from __future__ import annotations

import pytest

from adaptive.healing.contracts import RepairAction
from adaptive.healing.hierarchy import (
    HierarchyError,
    assert_no_layer_jump,
    select_repair,
)


def test_selects_lowest_viable_layer():
    viable = {
        RepairAction.REGIONAL_RECOVERY,   # layer 10
        RepairAction.RESTART_REPLICA,     # layer 1
        RepairAction.SCALE_SERVICE,       # layer 3
    }
    sel = select_repair(viable)
    assert sel.action is RepairAction.RESTART_REPLICA
    assert sel.layer == 1
    assert sel.layer_name == "process replacement"


def test_empty_viable_set_fails_closed():
    with pytest.raises(HierarchyError):
        select_repair(set())


def test_no_jump_passes_for_lowest():
    viable = {RepairAction.RESTART_REPLICA, RepairAction.EVACUATE_CLUSTER}
    assert_no_layer_jump(RepairAction.RESTART_REPLICA, viable) is None


def test_no_jump_refuses_broader_when_narrower_viable():
    viable = {RepairAction.RESTART_REPLICA, RepairAction.EVACUATE_CLUSTER}
    with pytest.raises(HierarchyError):
        assert_no_layer_jump(RepairAction.EVACUATE_CLUSTER, viable)


def test_no_jump_refuses_action_outside_viable_set():
    with pytest.raises(HierarchyError):
        assert_no_layer_jump(RepairAction.SCALE_SERVICE, {RepairAction.RESTART_REPLICA})
