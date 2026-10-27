"""Truthful, provider-independent usage evidence for external engines.

The contract keeps three questions separate:

* **What was counted?** Token components are nullable. ``None`` means the engine
  did not report that component; it is never rewritten as ``0``.
* **How precise is it?** ``precision`` is ``measured`` (exact engine/provider
  counters), ``estimated`` (an explicit method was applied), or ``unavailable``.
* **Who produced it?** ``source`` records provenance: ``provider``, ``engine``,
  ``estimate`` or ``none``. Exact engine counters are measured engine evidence,
  not an independent provider-billed measurement.

Components are disjoint unless an inclusion flag says otherwise. The builders
require both inclusion flags explicitly; ``output_includes_reasoning=None``
means the relationship is unknown. A derived total adds cache only when input
excludes it and adds reasoning only when output is known to exclude it. If
reasoning is present while the relationship is unknown, the total stays
``None``. A provider-supplied total is retained with ``totalSource``.

The returned dict is deliberately dict-compatible with the existing event
transport; consumers must not treat missing keys or ``None`` as a zero-token
turn.
"""

from __future__ import annotations

import math
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

Precision = Literal["measured", "estimated", "unavailable"]
Source = Literal["provider", "engine", "estimate", "none"]
TotalSource = Literal["provider", "derived"]


def genuine_count(value: object) -> int | None:
    """Return a nonnegative integer token count.

    ``None`` is preserved as unknown. Booleans, text, fractional numbers and
    negative numbers are malformed evidence and raise ``ValueError`` instead of
    being silently coerced or clamped.
    """

    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("token counts must be genuine integers")
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        raise ValueError("token counts must be genuine integers")
    count = int(value)
    if count < 0:
        raise ValueError("token counts must not be negative")
    return count


def _count(value: object) -> int | None:
    return genuine_count(value)


def _cost(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("cost must be a finite nonnegative number")
    amount = float(value)
    if not math.isfinite(amount) or amount < 0:
        raise ValueError("cost must be a finite nonnegative number")
    return amount


Count = Annotated[int | None, BeforeValidator(_count)]
Cost = Annotated[float | None, BeforeValidator(_cost)]


class UsageEvidence(BaseModel):
    """Normalized evidence for one completed turn (never a session cumulative)."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    input_tokens: Count = None
    output_tokens: Count = None
    cache_read_tokens: Count = None
    cache_write_tokens: Count = None
    reasoning_tokens: Count = None
    total_tokens: Count = None
    precision: Precision
    source: Source
    estimation_method: str | None = Field(default=None)
    input_includes_cache: bool = False
    output_includes_reasoning: bool | None = None
    total_source: TotalSource | None = None
    cost: Cost = None

    @model_validator(mode="after")
    def _coherent(self) -> UsageEvidence:
        components = (
            self.input_tokens,
            self.output_tokens,
            self.cache_read_tokens,
            self.cache_write_tokens,
            self.reasoning_tokens,
        )
        if self.precision == "measured":
            if self.source not in {"provider", "engine"}:
                raise ValueError("measured evidence must come from a provider or engine")
            if self.total_tokens is None and all(value is None for value in components):
                raise ValueError("measured evidence must contain at least one token count")
        elif self.precision == "estimated":
            if self.source != "estimate":
                raise ValueError("estimated evidence must use the estimate source")
            if self.estimation_method is None:
                raise ValueError("estimated evidence requires an explicit estimation method")
            if self.total_tokens is None and all(value is None for value in components):
                raise ValueError("estimated evidence must contain at least one token count")
        else:
            if self.source == "estimate":
                raise ValueError("unavailable evidence cannot use the estimate source")
            if self.estimation_method is not None:
                raise ValueError("unavailable evidence has no estimation method")
            if self.cost is not None:
                raise ValueError("unavailable evidence has no cost")
            if self.total_tokens is not None or any(value is not None for value in components):
                raise ValueError("unavailable evidence must not carry token values")
        if (self.total_tokens is None) != (self.total_source is None):
            raise ValueError("total tokens and total source must be provided together")
        return self

    def event(self) -> dict[str, object]:
        """Return the transport event consumed by the ITSM gateway."""

        event: dict[str, object] = {
            "type": "usage",
            "inputTokens": self.input_tokens,
            "outputTokens": self.output_tokens,
            "cacheReadTokens": self.cache_read_tokens,
            "cacheWriteTokens": self.cache_write_tokens,
            "reasoningTokens": self.reasoning_tokens,
            "totalTokens": self.total_tokens,
            "precision": self.precision,
            "source": self.source,
            "estimationMethod": self.estimation_method,
            "inputIncludesCache": self.input_includes_cache,
            "outputIncludesReasoning": self.output_includes_reasoning,
            "totalSource": self.total_source,
        }
        if self.cost is not None:
            event["cost"] = self.cost
        return event


def _derived_total(
    *,
    input_tokens: int | None,
    output_tokens: int | None,
    cache_read_tokens: int | None,
    cache_write_tokens: int | None,
    reasoning_tokens: int | None,
    input_includes_cache: bool,
    output_includes_reasoning: bool | None,
) -> int | None:
    if input_tokens is None or output_tokens is None:
        return None
    total = input_tokens + output_tokens
    if not input_includes_cache:
        if cache_read_tokens is None or cache_write_tokens is None:
            return None
        total += cache_read_tokens + cache_write_tokens
    if output_includes_reasoning is False:
        if reasoning_tokens is None:
            return None
        total += reasoning_tokens
    elif output_includes_reasoning is None and reasoning_tokens is not None:
        return None
    return total


def _usage(
    *,
    precision: Precision,
    source: Source,
    estimation_method: str | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    cache_read_tokens: int | None = None,
    cache_write_tokens: int | None = None,
    reasoning_tokens: int | None = None,
    total_tokens: int | None = None,
    total_source: TotalSource | None = None,
    input_includes_cache: bool,
    output_includes_reasoning: bool | None,
    cost: float | int | None = None,
) -> UsageEvidence:
    input_tokens = genuine_count(input_tokens)
    output_tokens = genuine_count(output_tokens)
    cache_read_tokens = genuine_count(cache_read_tokens)
    cache_write_tokens = genuine_count(cache_write_tokens)
    reasoning_tokens = genuine_count(reasoning_tokens)
    total_tokens = genuine_count(total_tokens)
    amount = _cost(cost)
    method = None
    if estimation_method is not None:
        method = estimation_method.strip()
        if not method:
            raise ValueError("estimation method must not be blank")
    if total_tokens is None and total_source is None:
        total_tokens = _derived_total(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read_tokens,
            cache_write_tokens=cache_write_tokens,
            reasoning_tokens=reasoning_tokens,
            input_includes_cache=input_includes_cache,
            output_includes_reasoning=output_includes_reasoning,
        )
        if total_tokens is not None:
            total_source = "derived"
    return UsageEvidence(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read_tokens=cache_read_tokens,
        cache_write_tokens=cache_write_tokens,
        reasoning_tokens=reasoning_tokens,
        total_tokens=total_tokens,
        precision=precision,
        source=source,
        estimation_method=method,
        input_includes_cache=input_includes_cache,
        output_includes_reasoning=output_includes_reasoning,
        total_source=total_source,
        cost=amount,
    )


def measured_usage(
    *,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    cache_read_tokens: int | None = None,
    cache_write_tokens: int | None = None,
    reasoning_tokens: int | None = None,
    total_tokens: int | None = None,
    total_source: TotalSource | None = None,
    input_includes_cache: bool = False,
    output_includes_reasoning: bool | None = None,
    cost: float | int | None = None,
    source: Literal["provider", "engine"] = "engine",
) -> UsageEvidence:
    """Build exact evidence from engine or provider counters."""

    return _usage(
        precision="measured",
        source=source,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read_tokens=cache_read_tokens,
        cache_write_tokens=cache_write_tokens,
        reasoning_tokens=reasoning_tokens,
        total_tokens=total_tokens,
        total_source=total_source,
        input_includes_cache=input_includes_cache,
        output_includes_reasoning=output_includes_reasoning,
        cost=cost,
    )


def estimated_usage(
    method: str,
    *,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    cache_read_tokens: int | None = None,
    cache_write_tokens: int | None = None,
    reasoning_tokens: int | None = None,
    total_tokens: int | None = None,
    total_source: TotalSource | None = None,
    input_includes_cache: bool = False,
    output_includes_reasoning: bool | None = None,
    cost: float | int | None = None,
) -> UsageEvidence:
    """Build evidence only when an explicit estimation method is named."""

    return _usage(
        precision="estimated",
        source="estimate",
        estimation_method=method,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read_tokens=cache_read_tokens,
        cache_write_tokens=cache_write_tokens,
        reasoning_tokens=reasoning_tokens,
        total_tokens=total_tokens,
        total_source=total_source,
        input_includes_cache=input_includes_cache,
        output_includes_reasoning=output_includes_reasoning,
        cost=cost,
    )


def unavailable_usage(
    *,
    source: Literal["provider", "engine", "none"] = "none",
    input_includes_cache: bool = False,
    output_includes_reasoning: bool | None = None,
) -> UsageEvidence:
    """Build an explicit unknown-usage event instead of dropping accounting."""

    return UsageEvidence(
        precision="unavailable",
        source=source,
        input_includes_cache=input_includes_cache,
        output_includes_reasoning=output_includes_reasoning,
    )


__all__ = [
    "UsageEvidence",
    "estimated_usage",
    "genuine_count",
    "measured_usage",
    "unavailable_usage",
]
