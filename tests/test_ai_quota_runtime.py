"""Provider calls must be admitted individually, including tool-loop retries."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from itsm.agents.quota import BudgetedModel, reserve_run
from itsm.ai_usage.models import AiUsageReservation
from itsm.ai_usage.service import AiUsageService, QuotaExceeded
from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, UserPromptPart
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.usage import RequestUsage
from sqlalchemy import select
from tests.inventory_support import prepare


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


def _runtime_owner(catalog: Any) -> Any:
    return catalog.add_user("runtime.owner", "Runtime Owner", "user")


def test_personal_run_is_record_only_and_attributed_to_its_provider(
    settings_factory: Any,
) -> None:
    catalog = prepare(settings_factory, agent_daily_token_budget=10)
    owner = _runtime_owner(catalog)
    service = AiUsageService(catalog.settings, catalog.factory())
    company = service.reserve(owner.actor_id, funding="company", reserved_tokens=10)
    service.settle(
        company.reservation_id,
        {"totalTokens": 10, "precision": "measured", "source": "provider"},
    )
    with pytest.raises(QuotaExceeded):
        service.reserve(owner.actor_id, funding="company", reserved_tokens=1)

    quota = reserve_run(
        catalog.settings,
        catalog.factory(),
        owner,
        run_id="run-personal",
        engine="pydantic",
        provider={
            "provider_id": "provider-mine",
            "provider_scope": "personal",
            "provider_name": "My key",
            "model": "my-model",
        },
    )
    assert quota.reservation.funding == "personal"
    assert quota.reservation.limit_tokens is None
    assert quota.reservation.remaining_tokens is None

    call_id = quota.before_call(120)
    quota.after_call(
        call_id,
        {
            "totalTokens": 80,
            "precision": "estimated",
            "source": "estimate",
            "estimationMethod": "chars/4-v1",
        },
    )
    quota.finish_without_dispatch()

    funding = service.me(owner.actor_id)["funding"]
    assert funding["company"]["consumedTokens"] == 10
    assert funding["company"]["availableTokens"] == 0
    assert funding["personal"]["consumedTokens"] == 80
    assert funding["personal"]["availableTokens"] is None
    assert funding["personal"]["unlimited"] is True

    report = service.report(
        catalog.admin(), funding="personal", group_by=("provider", "engine", "funding")
    )
    items = [item for item in report["items"] if item["settledTokens"]]
    assert items
    assert items[0]["providerId"] == "provider-mine"
    assert items[0]["providerScope"] == "personal"
    assert items[0]["funding"] == "personal"
    assert items[0]["settledTokens"] == 80
    # The personal child call was attributed to the personal provider, not to
    # the global company balance.
    with catalog.session() as session:
        fundings = {
            row.funding
            for row in session.scalars(
                select(AiUsageReservation).where(AiUsageReservation.actor_id == owner.actor_id)
            )
        }
    assert fundings == {"company", "personal"}


def test_switching_runs_between_global_and_personal_provider_keeps_attribution(
    settings_factory: Any,
) -> None:
    catalog = prepare(settings_factory, agent_daily_token_budget=100)
    owner = _runtime_owner(catalog)
    service = AiUsageService(catalog.settings, catalog.factory())
    runs = [
        ("run-global", "provider-company", "global"),
        ("run-personal", "provider-mine", "personal"),
        ("run-global-again", "provider-company", "global"),
    ]
    for run_id, provider_id, scope in runs:
        quota = reserve_run(
            catalog.settings,
            catalog.factory(),
            owner,
            run_id=run_id,
            engine="pydantic",
            provider={
                "provider_id": provider_id,
                "provider_scope": scope,
                "provider_name": provider_id,
                "model": "shared-model",
            },
        )
        assert quota.reservation.funding == ("personal" if scope == "personal" else "company")
        quota.finish_without_dispatch()

    with catalog.session() as session:
        rows = session.scalars(
            select(AiUsageReservation)
            .where(AiUsageReservation.actor_id == owner.actor_id)
            .order_by(AiUsageReservation.created_at)
        ).all()
    assert [(row.run_id, row.provider_id, row.provider_scope, row.funding) for row in rows] == [
        (run_id, provider_id, scope, "personal" if scope == "personal" else "company")
        for run_id, provider_id, scope in runs
    ]

    funding = service.me(owner.actor_id)["funding"]
    assert funding["company"]["reservedTokens"] == 0
    assert funding["personal"]["reservedTokens"] == 0
