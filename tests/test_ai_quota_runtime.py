"""Provider calls must be admitted individually, including tool-loop retries."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from itsm.agents.quota import BudgetedModel
from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, UserPromptPart
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.usage import RequestUsage


class CallBudget:
    def __init__(self, *, deny_after: int | None = None) -> None:
        self.started: list[int] = []
        self.finished: list[tuple[str, dict[str, Any]]] = []
        self.deny_after = deny_after

    def before_call(self, bound: int) -> str:
        if self.deny_after is not None and len(self.started) >= self.deny_after:
            raise PermissionError("quota_exceeded")
        self.started.append(bound)
        return f"call-{len(self.started)}"

    def after_call(self, call_id: str, evidence: dict[str, Any]) -> None:
        self.finished.append((call_id, evidence))


def invoke(model: BudgetedModel) -> ModelResponse:
    return asyncio.run(
        model.request(
            [ModelRequest(parts=[UserPromptPart("hello")])],
            {"max_tokens": 100},
            ModelRequestParameters(),
        )
    )


def test_each_model_request_is_admitted_before_provider_and_cache_is_not_added_twice() -> None:
    budget = CallBudget(deny_after=1)
    upstream_calls: list[object] = []

    def provider(messages: Any, info: Any) -> ModelResponse:
        upstream_calls.append(info)
        return ModelResponse(
            parts=[TextPart("ok")],
            usage=RequestUsage(
                input_tokens=30,
                output_tokens=10,
                cache_read_tokens=20,
                cache_write_tokens=3,
                output_reasoning_tokens=4,
            ),
        )

    model = BudgetedModel(FunctionModel(provider), budget, context_tokens=200, output_tokens=100)
    invoke(model)
    with pytest.raises(PermissionError, match="quota_exceeded"):
        invoke(model)
    assert len(upstream_calls) == 1
    assert budget.started == [300]
    evidence = budget.finished[0][1]
    assert evidence["totalTokens"] == 40
    assert evidence["cacheReadTokens"] == 20
    assert evidence["reasoningTokens"] == 4
    assert evidence["inputIncludesCache"] is True
    assert evidence["outputIncludesReasoning"] is True


def test_failed_upstream_keeps_unresolved_call_and_does_not_report_zero() -> None:
    budget = CallBudget()

    def provider(messages: Any, info: Any) -> ModelResponse:
        raise TimeoutError("upstream outcome unknown")

    model = BudgetedModel(FunctionModel(provider), budget, context_tokens=200, output_tokens=100)
    with pytest.raises(TimeoutError):
        invoke(model)
    assert budget.started == [300]
    evidence = budget.finished[0][1]
    assert evidence["precision"] == "unavailable"
    assert evidence["totalTokens"] is None
    assert evidence["inputTokens"] is None


def test_unmeasured_sdk_usage_does_not_become_measured_zero() -> None:
    budget = CallBudget()
    model = BudgetedModel(
        FunctionModel(
            lambda messages, info: ModelResponse(
                parts=[TextPart("ok")],
                usage=RequestUsage(unmeasured_requests=1),
            )
        ),
        budget,
        context_tokens=200,
        output_tokens=100,
    )
    invoke(model)
    assert budget.finished[0][1]["precision"] == "unavailable"
    assert budget.finished[0][1]["totalTokens"] is None


def test_output_cap_is_enforced_before_provider_even_without_input_counter() -> None:
    budget = CallBudget()
    limits: list[int] = []

    def provider(messages: Any, info: Any) -> ModelResponse:
        limits.append(info.model_settings["max_tokens"])
        return ModelResponse(
            parts=[TextPart("ok")], usage=RequestUsage(input_tokens=2, output_tokens=1)
        )

    model = BudgetedModel(FunctionModel(provider), budget, context_tokens=None, output_tokens=20)
    invoke(model)
    assert limits == [20]
    assert budget.started == [20]
    assert model.quota_enforcement == "admission_only"
