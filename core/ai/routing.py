"""Model-routing policy — pick a model *class* for a unit of work (§2).

Routing uses a policy, not "Opus for everything". The default work→class map lives in
:data:`core.ai.schemas.DEFAULT_WORK_ROUTING`; this module layers the safety overrides
on top:

* ``POLICY`` work is never routed to a model — authority is deterministic.
* Sensitive content (or any content the caller will not allow off-box) is forced to a
  local/private model class, regardless of the work class.

Every decision carries a human-readable ``reason`` that is recorded in the call's
provenance, so an auditor can see *why* a given model handled a given piece of work.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from ..evidence.models import Classification
from .schemas import DEFAULT_WORK_ROUTING, ModelClass, WorkClass

# Classifications that must not leave the box for an external model without explicit
# permission. (MESSAGE_PLAINTEXT / DECRYPTION_KEY are refused outright by the firewall.)
SENSITIVE_CLASSES: frozenset[Classification] = frozenset(
    {
        Classification.CONFIDENTIAL,
        Classification.RESTRICTED,
        Classification.PII,
        Classification.HEALTH,
    }
)


class RoutingDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    model_class: ModelClass
    reason: str


def route(
    work_class: WorkClass,
    *,
    classification: Classification = Classification.INTERNAL,
    allow_external_processing: bool = False,
) -> RoutingDecision:
    """Choose a model class for this work. Pure and deterministic."""
    if work_class is WorkClass.POLICY:
        return RoutingDecision(
            model_class=ModelClass.NONE,
            reason="policy/authority work is deterministic — no model permitted",
        )

    base = DEFAULT_WORK_ROUTING[work_class]

    # Sensitive content that the caller will not send off-box → force a local model.
    if classification in SENSITIVE_CLASSES and not allow_external_processing:
        if base is not ModelClass.LOCAL:
            return RoutingDecision(
                model_class=ModelClass.LOCAL,
                reason=(
                    f"sensitive content ({classification.value}) without external "
                    f"permission — forced local instead of {base.value}"
                ),
            )

    return RoutingDecision(
        model_class=base,
        reason=f"default routing for work_class={work_class.value}",
    )


__all__ = ["RoutingDecision", "route", "SENSITIVE_CLASSES"]
