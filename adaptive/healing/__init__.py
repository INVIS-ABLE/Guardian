"""Self-healing contracts, the restricted runbook IR and its compiler (directive §5–7)."""

from .compiler import (
    CompiledRunbook,
    CompiledStep,
    GateAttestation,
    GateName,
    GateResult,
    GateStatus,
    RunbookCompileError,
    compile_runbook,
    plan_execution_jobs,
)
from .contracts import (
    HealingContract,
    HealingContractViolation,
    RepairAction,
    assert_repair_allowed,
)
from .anti_oscillation import (
    AntiOscillationPolicy,
    OscillationVerdict,
    RepairAttempt,
    RepairLedger,
    check_repair,
)
from .hierarchy import (
    LAYER_NAMES,
    HierarchyError,
    RepairSelection,
    assert_no_layer_jump,
    select_repair,
)
from .runbooks import Runbook, RunbookBudget, RunbookOperation, RunbookTrigger

__all__ = [
    "RepairAttempt",
    "AntiOscillationPolicy",
    "OscillationVerdict",
    "RepairLedger",
    "check_repair",
    "LAYER_NAMES",
    "HierarchyError",
    "RepairSelection",
    "select_repair",
    "assert_no_layer_jump",
    "HealingContract",
    "HealingContractViolation",
    "RepairAction",
    "assert_repair_allowed",
    "Runbook",
    "RunbookBudget",
    "RunbookOperation",
    "RunbookTrigger",
    "GateName",
    "GateStatus",
    "GateResult",
    "GateAttestation",
    "CompiledRunbook",
    "CompiledStep",
    "RunbookCompileError",
    "compile_runbook",
    "plan_execution_jobs",
]
