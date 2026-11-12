"""ITSM-owned paid-call admission; provider adapters only supply usage evidence.

Admission reserves serialized non-binary input plus existing attachment estimates
and the output cap. This is an admission estimate, not a tokenizer or billing bound.
Unknown outcomes retain their reservation for explicit reconciliation.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any, Protocol

from pydantic_ai.messages import (
    BinaryContent,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    UserPromptPart,
)
from pydantic_ai.models import Model, ModelRequestParameters
from pydantic_ai.models.wrapper import WrapperModel
from pydantic_ai.settings import ModelSettings


class CallBudget(Protocol):
    def before_call(self, bound: int) -> str: ...
    def after_call(self, call_id: str, evidence: dict[str, Any]) -> None: ...


def sdk_usage(source: Any) -> dict[str, Any]:
    """Normalize one RequestUsage, never an accumulated run counter."""
    from itsm.agents.usage import measured_usage, unavailable_usage

    if source is None or getattr(source, "unmeasured_requests", 1):
        return unavailable_usage(source="provider").event()
    return measured_usage(
        input_tokens=source.input_tokens,
        output_tokens=source.output_tokens,
        cache_read_tokens=source.cache_read_tokens,
        cache_write_tokens=source.cache_write_tokens,
        reasoning_tokens=source.output_reasoning_tokens,
        input_includes_cache=True,
        output_includes_reasoning=True,
        source="provider",
    ).event()


class BudgetedModel(WrapperModel):
    """One immutable run-local wrapper, never installed on a cached shared agent."""

    def __init__(
        self, wrapped: Model, budget: CallBudget, *, context_tokens: int | None, output_tokens: int
    ) -> None:
        super().__init__(wrapped)
        self._budget = budget
        self._context_tokens = context_tokens
        self._output_tokens = output_tokens
        self.quota_enforcement = "bounded"

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        settings = dict(model_settings or {})
        settings["max_tokens"] = min(
            settings.get("max_tokens") or self._output_tokens, self._output_tokens
        )
        from itsm.agent_integrations.attachments import binary_input_estimate
        from pydantic_core import to_json

        # Only typed binary user content is estimated. Text, history and schemas
        # retain the serialized floor; a dict with binary-looking keys cannot hide it.
        accounted = []
        attachment_tokens = 0
        for message in messages:
            if not isinstance(message, ModelRequest):
                accounted.append(message)
                continue
            parts = []
            for part in message.parts:
                if isinstance(part, UserPromptPart) and not isinstance(part.content, str):
                    content = []
                    for item in part.content:
                        if isinstance(item, BinaryContent) and (
                            item.media_type.startswith("image/")
                            or item.media_type == "application/pdf"
                        ):
                            attachment_tokens += binary_input_estimate(
                                item.data,
                                "image" if item.media_type.startswith("image/") else "file",
                            )
                            item = replace(item, data=b"")
                        content.append(item)
                    part = replace(part, content=content)
                parts.append(part)
            accounted.append(replace(message, parts=parts))
        input_estimate = (
            len(to_json([accounted, model_request_parameters], bytes_mode="base64"))
            + attachment_tokens
        )
        bound = max(self._context_tokens or 0, input_estimate) + settings["max_tokens"]
        call_id = self._budget.before_call(bound)
        try:
            response = await self.wrapped.request(messages, settings, model_request_parameters)
        except BaseException:
            from itsm.agents.usage import unavailable_usage

            self._budget.after_call(call_id, unavailable_usage(source="provider").event())
            raise
        self._budget.after_call(call_id, sdk_usage(response.usage))
        return response


class RunBudget:
    """Bind callbacks to immutable actor/funding/original-period SQL authority."""

    def __init__(self, service: Any, reservation: Any) -> None:
        self.service = service
        self.reservation = reservation
        self.calls = 0
        self.evidence: list[dict[str, Any]] = []
        self._sentinel_released = False

    def before_call(self, bound: int) -> str:
        if not self._sentinel_released:
            self.service.release(
                self.reservation.reservation_id,
                reason="admission sentinel replaced before first provider call",
                trusted_no_upstream=True,
            )
            self._sentinel_released = True
        grant = self.service.reserve(
            None,
            parent_reservation_id=self.reservation.reservation_id,
            reserved_tokens=bound,
        )
        self.calls += 1
        return grant.reservation_id

    def after_call(self, call_id: str, evidence: dict[str, Any]) -> None:
        accepted = {key: value for key, value in evidence.items() if key not in {"type", "cost"}}
        self.service.settle(call_id, accepted)
        self.evidence.append(evidence)

    def finish_without_dispatch(self) -> None:
        if not self.calls and not self._sentinel_released:
            self.service.release(
                self.reservation.reservation_id,
                reason="runtime ended before any provider dispatch",
                trusted_no_upstream=True,
            )
            self._sentinel_released = True


def reserve_run(
    settings: Any,
    session_factory: Any,
    principal: Any,
    *,
    run_id: str,
    engine: str = "pydantic",
    provider: Mapping[str, Any] | None = None,
    attachment_tokens: int = 0,
) -> RunBudget:
    from itsm.ai_usage.service import AiUsageService

    attribution = dict(provider or {})
    if engine == "pydantic" and not attribution.get("provider_id"):
        from itsm.system.providers import effective_selection

        with session_factory() as db:
            selected = effective_selection(db, settings)
        if selected is not None:
            attribution.update(
                provider_id=selected.provider,
                provider_name=selected.provider,
                provider_scope="global",
                model=selected.model,
            )
    scope = attribution.get("provider_scope")
    # Company-funded runs reserve a conservative attachment estimate up front;
    # the measured provider usage still replaces it on settlement. Personal
    # funding stays record-only, so the estimate never blocks that owner.
    reserved = 1 + max(0, int(attachment_tokens or 0))
    service = AiUsageService(settings, session_factory)
    grant = service.reserve(
        principal.actor_id,
        funding="personal" if scope == "personal" else "company",
        reserved_tokens=reserved,
        engine=engine,
        run_id=run_id,
        provider_id=attribution.get("provider_id"),
        provider_scope=scope,
        provider_name=attribution.get("provider_name"),
        model=attribution.get("model"),
    )
    return RunBudget(service, grant)
