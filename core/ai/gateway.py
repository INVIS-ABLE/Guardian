"""The model gateway — the one path every model call in Guardian must take (§2).

Responsibilities, in order, for each call:

1. **Context firewall** — refuse forbidden content; compute the data classification.
2. **Routing** — pick a model *class* by work class + classification (never a model for
   policy/authority work).
3. **Registry** — resolve the class to a pinned, allow-listed model spec.
4. **Privacy boundary** — refuse to send sensitive content to an external model without
   permission.
5. **Budget** — enforce the output-token ceiling before, and the cost budget after.
6. **Provider** — call the backend, with bounded retries and **no fallback** to a
   different model on failure (a provider failure must not cause an unsafe substitution).
7. **Output firewall** — screen the result for high-risk content.
8. **Provenance** — emit one immutable :class:`ModelCallRecord` for the call.

The gateway returns model output as ``MODEL_GENERATED`` trust: it can never become
verified evidence or trusted memory without separate validation.
"""

from __future__ import annotations

from typing import Callable

from . import budgets as _budgets
from . import context_firewall as _firewall
from . import output_firewall as _output
from . import routing as _routing
from .budgets import CallBudget
from .provenance import ModelCallRecord, hash_text
from .provider_base import ModelProvider
from .registry import ModelRegistry, default_registry
from .schemas import (
    ModelClass,
    ModelRequest,
    ModelResponse,
    ModelUnavailableError,
    PolicyRoutingError,
    WorkClass,
)

RecordSink = Callable[[ModelCallRecord], None]


class ModelGateway:
    """Routes, guards, budgets, calls and records every model interaction."""

    def __init__(
        self,
        *,
        registry: ModelRegistry,
        providers: dict[str, ModelProvider],
        record_sink: RecordSink | None = None,
    ) -> None:
        self._registry = registry
        self._providers = providers
        self._sink = record_sink

    # --- public API ------------------------------------------------------------
    def complete(self, request: ModelRequest, *, budget: CallBudget | None = None) -> ModelResponse:
        budget = budget or CallBudget(max_output_tokens=request.max_output_tokens)

        # 1. context firewall — forbidden content is refused here.
        assessment = _firewall.assess(request)
        classification = assessment.classification

        # 2. routing — may refuse (policy) or force a local model (sensitive).
        decision = _routing.route(
            request.work_class,
            classification=classification,
            allow_external_processing=request.allow_external_processing,
        )
        if decision.model_class is ModelClass.NONE:
            raise PolicyRoutingError(
                f"work_class={request.work_class.value} must be decided deterministically; "
                f"{decision.reason}"
            )

        # 3. registry — resolve the class to a pinned spec.
        spec = self._registry.resolve(decision.model_class)
        if spec is None:
            raise ModelUnavailableError(
                f"no registered model for class {decision.model_class.value}"
            )

        # 4. privacy boundary — external model + sensitive content needs permission.
        _firewall.enforce_boundary(spec, classification, request.allow_external_processing)

        # 5. budget pre-check.
        _budgets.check_pre_call(spec, budget, request.max_output_tokens)

        # 6. provider — fail closed if missing/unavailable; never substitute.
        provider = self._providers.get(spec.provider)
        if provider is None or not provider.available():
            self._emit_failure(request, spec, decision.reason, classification,
                               error=f"provider '{spec.provider}' unavailable")
            raise ModelUnavailableError(
                f"provider '{spec.provider}' for model {spec.model_id} is unavailable"
            )

        system, user = _firewall.render_prompt(request)
        template_hash = hash_text(system + "\n" + request.instruction + "\n" + request.extra_context)

        # 7. call with bounded retries; no fallback to a different model.
        result = None
        retries = 0
        last_error: Exception | None = None
        for attempt in range(request.max_retries + 1):
            try:
                result = provider.complete(
                    model_id=spec.model_id,
                    system=system,
                    user=user,
                    max_output_tokens=request.max_output_tokens,
                    timeout_s=request.timeout_s,
                )
                retries = attempt
                break
            except Exception as exc:  # noqa: BLE001 - fail closed, record, re-raise
                last_error = exc
                retries = attempt
        if result is None:
            self._emit_failure(request, spec, decision.reason, classification,
                               error=f"provider error: {last_error}", retry_count=retries)
            raise ModelUnavailableError(
                f"model {spec.model_id} failed after {retries + 1} attempts: {last_error}"
            )

        # 8. budget post-check (cost).
        cost = _budgets.check_post_call(
            spec, budget, input_tokens=result.input_tokens, output_tokens=result.output_tokens
        )

        # 9. output firewall.
        high_risk, findings = _output.screen_output(result.text)

        record = ModelCallRecord(
            model_id=spec.model_id,
            provider=spec.provider,
            routing_reason=decision.reason,
            work_class=request.work_class.value,
            prompt_template_version=request.prompt_template_version,
            prompt_template_hash=template_hash,
            tool_schema_version=request.tool_schema_version,
            input_evidence_ids=tuple(e.id for e in request.evidence),
            data_classification=classification,
            external_processing_permitted=request.allow_external_processing,
            tenant_id=request.tenant_id,
            case_id=request.case_id,
            output_hash=hash_text(result.text),
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cost_usd=cost,
            timeout_s=request.timeout_s,
            retry_count=retries,
            eval_version=request.eval_version,
            succeeded=True,
        )
        self._record(record)
        return ModelResponse(
            text=result.text,
            high_risk=high_risk,
            firewall_findings=findings,
            record=record,
        )

    # --- internals -------------------------------------------------------------
    def _emit_failure(self, request: ModelRequest, spec, routing_reason: str,
                      classification, *, error: str, retry_count: int = 0) -> None:
        self._record(
            ModelCallRecord(
                model_id=spec.model_id,
                provider=spec.provider,
                routing_reason=routing_reason,
                work_class=request.work_class.value,
                prompt_template_version=request.prompt_template_version,
                prompt_template_hash=hash_text(request.instruction),
                tool_schema_version=request.tool_schema_version,
                input_evidence_ids=tuple(e.id for e in request.evidence),
                data_classification=classification,
                external_processing_permitted=request.allow_external_processing,
                tenant_id=request.tenant_id,
                case_id=request.case_id,
                timeout_s=request.timeout_s,
                retry_count=retry_count,
                eval_version=request.eval_version,
                succeeded=False,
                error=error,
            )
        )

    def _record(self, record: ModelCallRecord) -> None:
        if self._sink is not None:
            self._sink(record)


def default_gateway(record_sink: RecordSink | None = None) -> ModelGateway:
    """A gateway wired with the default registry + the three provider adapters.

    Only the local provider is guaranteed available offline; the Anthropic/OpenAI
    adapters require their SDK + API key, otherwise the gateway fails closed for the
    work classes that route to them.
    """
    from .provider_anthropic import AnthropicProvider
    from .provider_local import LocalProvider
    from .provider_openai import OpenAIProvider

    return ModelGateway(
        registry=default_registry(),
        providers={
            "anthropic": AnthropicProvider(),
            "openai": OpenAIProvider(),
            "local": LocalProvider(),
        },
        record_sink=record_sink,
    )


__all__ = ["ModelGateway", "default_gateway", "RecordSink", "WorkClass"]
