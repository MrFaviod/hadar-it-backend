"""Contract tests for truthful external-engine usage evidence."""

from __future__ import annotations

import pytest
from itsm.agents.usage import (
    UsageEvidence,
    estimated_usage,
    measured_usage,
    unavailable_usage,
)
from pydantic import ValidationError


def test_unavailable_usage_preserves_missing_values_instead_of_zero() -> None:
    event = unavailable_usage().event()

    assert event == {
        "type": "usage",
        "inputTokens": None,
        "outputTokens": None,
        "cacheReadTokens": None,
        "cacheWriteTokens": None,
        "reasoningTokens": None,
        "totalTokens": None,
        "precision": "unavailable",
        "source": "none",
        "estimationMethod": None,
        "inputIncludesCache": False,
        "outputIncludesReasoning": None,
        "totalSource": None,
    }


def test_derived_total_does_not_double_count_cache_or_reasoning() -> None:
    event = measured_usage(
        input_tokens=10,
        output_tokens=5,
        cache_read_tokens=2,
        cache_write_tokens=3,
        reasoning_tokens=1,
        input_includes_cache=False,
        output_includes_reasoning=False,
        cost=0.25,
    ).event()

    assert event["totalTokens"] == 21
    assert event["totalSource"] == "derived"
    assert event["precision"] == "measured"
    assert event["source"] == "engine"
    assert event["inputIncludesCache"] is False
    assert event["outputIncludesReasoning"] is False
    assert event["cost"] == 0.25

    included = measured_usage(
        input_tokens=10,
        output_tokens=5,
        cache_read_tokens=2,
        cache_write_tokens=3,
        reasoning_tokens=1,
        input_includes_cache=True,
        output_includes_reasoning=True,
    ).event()

    assert included["totalTokens"] == 15


def test_provider_total_is_kept_apart_from_derivation() -> None:
    event = measured_usage(
        input_tokens=10,
        output_tokens=5,
        total_tokens=42,
        total_source="provider",
        input_includes_cache=False,
        output_includes_reasoning=True,
    ).event()

    assert event["totalTokens"] == 42
    assert event["totalSource"] == "provider"


def test_unknown_optional_components_leave_total_underivable() -> None:
    event = measured_usage(
        input_tokens=10,
        output_tokens=5,
        input_includes_cache=False,
        output_includes_reasoning=True,
    ).event()

    assert event["totalTokens"] is None
    assert event["totalSource"] is None
    assert event["cacheReadTokens"] is None
    assert event["cacheWriteTokens"] is None


def test_estimate_requires_an_explicit_method() -> None:
    event = estimated_usage(
        "tokenizer/v1 over the exact prompt and visible response",
        input_tokens=12,
        output_tokens=3,
        cache_read_tokens=0,
        cache_write_tokens=0,
        reasoning_tokens=0,
        output_includes_reasoning=False,
    ).event()

    assert event["precision"] == "estimated"
    assert event["source"] == "estimate"
    assert event["estimationMethod"] == "tokenizer/v1 over the exact prompt and visible response"
    assert event["totalTokens"] == 15


@pytest.mark.parametrize(
    "kwargs",
    [
        {"input_tokens": -1},
        {"output_tokens": True},
        {"cache_read_tokens": 1.5},
        {"cache_write_tokens": "3"},
        {"reasoning_tokens": float("nan")},
        {"total_tokens": 5, "total_source": None},
        {"total_source": "derived"},
    ],
)
def test_measured_usage_rejects_malformed_or_untraceable_values(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        measured_usage(
            input_tokens=kwargs.pop("input_tokens", 1),
            output_tokens=kwargs.pop("output_tokens", 1),
            cache_read_tokens=kwargs.pop("cache_read_tokens", 0),
            cache_write_tokens=kwargs.pop("cache_write_tokens", 0),
            reasoning_tokens=kwargs.pop("reasoning_tokens", 0),
            input_includes_cache=False,
            output_includes_reasoning=False,
            **kwargs,
        )


def test_measured_usage_rejects_cost_that_is_not_finite_money() -> None:
    with pytest.raises(ValueError):
        measured_usage(
            input_tokens=1,
            output_tokens=1,
            input_includes_cache=False,
            output_includes_reasoning=False,
            cost=float("inf"),
        )


def test_estimated_usage_rejects_blank_method() -> None:
    with pytest.raises(ValueError):
        estimated_usage(
            "   ",
            input_tokens=1,
            output_tokens=1,
            output_includes_reasoning=False,
        )


def test_unavailable_usage_rejects_fabricated_values() -> None:
    with pytest.raises((TypeError, ValueError)):
        unavailable_usage(input_tokens=1)

    with pytest.raises(ValidationError):
        UsageEvidence(
            precision="unavailable",
            source="none",
            input_tokens=1,
            input_includes_cache=False,
            output_includes_reasoning=None,
        )
