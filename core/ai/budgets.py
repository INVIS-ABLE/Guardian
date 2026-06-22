"""Per-call token + cost budgets for the model gateway (§2).

Budgets are bounded, recorded limits — not soft suggestions. The gateway checks the
output-token request against the model's ceiling *before* a call, and the realised
cost against the budget *after*, raising :class:`BudgetExceededError` either way.
Cost is estimated from the model spec's per-million-token prices.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .schemas import BudgetExceededError, ModelSpec


class CallBudget(BaseModel):
    """The ceiling for one model call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_output_tokens: int = Field(ge=1, default=4096)
    max_cost_usd: float = Field(ge=0.0, default=1.0)


def estimate_cost_usd(spec: ModelSpec, *, input_tokens: int, output_tokens: int) -> float:
    """Estimate the USD cost of a call from the spec's per-Mtok prices."""
    return (
        input_tokens / 1_000_000 * spec.input_price_per_mtok
        + output_tokens / 1_000_000 * spec.output_price_per_mtok
    )


def check_pre_call(spec: ModelSpec, budget: CallBudget, requested_output_tokens: int) -> None:
    """Validate a call *before* it runs. Raises BudgetExceededError if it cannot fit."""
    ceiling = min(spec.max_output_tokens, budget.max_output_tokens)
    if requested_output_tokens > ceiling:
        raise BudgetExceededError(
            f"requested {requested_output_tokens} output tokens exceeds ceiling {ceiling} "
            f"(model={spec.model_id}, budget={budget.max_output_tokens})"
        )


def check_post_call(spec: ModelSpec, budget: CallBudget, *, input_tokens: int,
                    output_tokens: int) -> float:
    """Compute realised cost and enforce the cost budget. Returns the cost."""
    cost = estimate_cost_usd(spec, input_tokens=input_tokens, output_tokens=output_tokens)
    if cost > budget.max_cost_usd:
        raise BudgetExceededError(
            f"call cost ${cost:.4f} exceeds budget ${budget.max_cost_usd:.4f} "
            f"(model={spec.model_id})"
        )
    return cost


__all__ = ["CallBudget", "estimate_cost_usd", "check_pre_call", "check_post_call"]
