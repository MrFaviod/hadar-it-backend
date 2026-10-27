"""Container-side Pydantic AI worker for ordinary ITSM roles.

The process is started only by the host broker with a server-configured image
and command. It receives one bounded ``run.start`` line on stdin, performs
inference with the server-resolved provider, forwards every tool call to the
broker (which relays it to the API) and writes one ``final`` line.

It has no database, filesystem, shell or HTTP tool and no credential in its
environment or argv: the provider secret arrives in the start message. Tool
results are produced exclusively by the API under the requesting principal, so
nothing in this process can grant permissions or change identity.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import sys
from collections.abc import Callable
from typing import Any, TextIO

from itsm.agents.isolation import RunStart, ToolSchema, WorkerFinal
from pydantic_ai import Agent
from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    TextPart,
    UserPromptPart,
)
from pydantic_ai.models import Model
from pydantic_ai.settings import ModelSettings
from pydantic_ai.tools import Tool
from pydantic_ai.toolsets.function import FunctionToolset
from pydantic_ai.usage import RunUsage, UsageLimits

_MAX_LINE = 512 * 1024
_MAX_TOOL_RESULT = 64 * 1024
_MAX_TOOL_CALLS = 80


class WorkerProtocolError(Exception):
    """The broker or API sent a frame outside the bounded protocol."""


class _Bridge:
    """Synchronous request/response channel for canonical tools."""

    def __init__(self, source: TextIO, sink: TextIO) -> None:
        self._source = source
        self._sink = sink
        self._calls = 0

    def tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self._calls += 1
        if self._calls > _MAX_TOOL_CALLS:
            raise WorkerProtocolError("tool call budget exhausted")
        call_id = f"c{self._calls}"
        self._write(
            {
                "type": "tool.call",
                "callId": call_id,
                "name": name,
                "arguments": arguments,
            }
        )
        message = self._read()
        if message.get("type") != "tool.result" or message.get("callId") != call_id:
            raise WorkerProtocolError("unexpected tool result")
        result = message.get("result")
        if not isinstance(result, dict):
            raise WorkerProtocolError("tool result is not an object")
        if len(json.dumps(result, default=str).encode("utf-8")) > _MAX_TOOL_RESULT:
            raise WorkerProtocolError("tool result is too large")
        return result

    def before_call(self, bound: int) -> str:
        self._calls += 1
        call_id = f"q{self._calls}"
        self._quota(call_id, "reserve")
        return call_id

    def after_call(self, call_id: str, evidence: dict[str, Any]) -> None:
        self._quota(call_id, "settle", evidence)

    def _quota(self, call_id: str, phase: str, evidence: dict[str, Any] | None = None) -> None:
        self._write({"type": "quota.call", "callId": call_id, "phase": phase, "evidence": evidence})
        result = self._read()
        if result.get("type") != "quota.result" or result.get("callId") != call_id:
            raise WorkerProtocolError("unexpected quota response")
        if result.get("ok") is not True:
            raise WorkerProtocolError("quota admission denied")

    def _write(self, payload: dict[str, Any]) -> None:
        line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if len(line.encode("utf-8")) > _MAX_LINE:
            raise WorkerProtocolError("outgoing frame is too large")
        self._sink.write(line + "\n")
        self._sink.flush()

    def _read(self) -> dict[str, Any]:
        line = self._source.readline(_MAX_LINE)
        if not line:
            raise WorkerProtocolError("bridge closed")
        if len(line.encode("utf-8")) > _MAX_LINE:
            raise WorkerProtocolError("incoming frame is too large")
        try:
            payload = json.loads(line)
        except ValueError:
            raise WorkerProtocolError("incoming frame is not JSON") from None
        if not isinstance(payload, dict):
            raise WorkerProtocolError("incoming frame is not an object")
        return payload


def _history(start: RunStart) -> list[ModelMessage]:
    messages: list[ModelMessage] = []
    for turn in start.history:
        if turn.role == "user":
            messages.append(ModelRequest(parts=[UserPromptPart(content=turn.content)]))
        else:
            messages.append(ModelResponse(parts=[TextPart(content=turn.content)]))
    return messages


def _tool_callback(
    bridge: _Bridge, tool_name: str, allowed: frozenset[str]
) -> Callable[..., dict[str, Any]]:
    def call(**arguments: Any) -> dict[str, Any]:
        if not set(arguments).issubset(allowed):
            return {"ok": False, "message": "argumentos no permitidos"}
        return bridge.tool(tool_name, arguments)

    return call


def _tools(schemas: list[ToolSchema], bridge: _Bridge) -> list[Tool[Any]]:
    tools: list[Tool[Any]] = []
    for schema in schemas:
        properties = set(schema.parameters.get("properties", {}))
        if not properties and schema.parameters.get("type") not in (None, "object"):
            raise WorkerProtocolError("unsupported tool schema")
        tools.append(
            Tool.from_schema(
                _tool_callback(bridge, schema.name, frozenset(properties)),
                name=schema.name,
                description=schema.description,
                json_schema=schema.parameters,
            )
        )
    return tools


def _model(start: RunStart) -> tuple[Model, Any]:
    """Build the inference model, re-validating the private endpoint at use time."""
    from itsm.agent_integrations.providers import (
        ProviderEndpointError,
        ProviderModelSelection,
        build_provider_model,
        ensure_public_endpoint,
        provider_http_client,
    )

    provider = start.provider
    if provider.kind == "openai-compatible":
        if not provider.base_url:
            raise WorkerProtocolError("provider baseUrl is required")
        if not provider.allow_private:
            try:
                ensure_public_endpoint(provider.base_url)
            except ProviderEndpointError, OSError:
                raise WorkerProtocolError("provider endpoint is not allowed") from None
        client = provider_http_client(allow_private=provider.allow_private)
        selection = ProviderModelSelection(
            base_url=provider.base_url,
            model=provider.model,
            api_key=provider.api_key or "",
            allow_private=provider.allow_private,
        )
        try:
            return build_provider_model(selection, http_client=client), client
        except Exception:
            asyncio.run(client.aclose())
            raise
    if provider.kind == "openai":
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.providers.openai import OpenAIProvider

        client = provider_http_client(allow_private=True)
        return (
            OpenAIChatModel(
                provider.model,
                provider=OpenAIProvider(
                    base_url=provider.base_url,
                    api_key=provider.api_key,
                    http_client=client,
                ),
            ),
            client,
        )
    if provider.kind == "anthropic":
        from pydantic_ai.models.anthropic import AnthropicModel
        from pydantic_ai.providers.anthropic import AnthropicProvider

        return (
            AnthropicModel(
                provider.model,
                provider=AnthropicProvider(
                    base_url=provider.base_url,
                    api_key=provider.api_key,
                ),
            ),
            None,
        )
    raise WorkerProtocolError("unsupported provider kind")


async def _run(start: RunStart, bridge: _Bridge) -> tuple[RunUsage, str]:
    model, client = _model(start)
    if start.quota_enabled:
        from itsm.agents.quota import BudgetedModel

        model = BudgetedModel(
            model,
            bridge,
            context_tokens=start.context_token_bound,
            output_tokens=start.max_output_tokens,
        )
    agent: Agent[None, str] = Agent(
        model,
        output_type=str,
        instructions=start.instructions,
        retries=1,
        model_settings=ModelSettings(max_tokens=start.max_output_tokens),
        toolsets=[FunctionToolset(tools=_tools(start.tools, bridge))],
    )
    run_usage = RunUsage()
    limits = UsageLimits(
        request_limit=start.max_steps,
        tool_calls_limit=start.max_steps * 4,
    )
    if start.token_limit is not None and start.token_limit > 0:
        limits = UsageLimits(
            request_limit=start.max_steps,
            tool_calls_limit=start.max_steps * 4,
            total_tokens_limit=start.token_limit,
        )
    try:
        result = await agent.run(
            start.prompt,
            message_history=_history(start),
            usage_limits=limits,
            usage=run_usage,
        )
        return run_usage, result.output
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                await client.aclose()


def serve(
    source: TextIO,
    sink: TextIO,
    *,
    run: Callable[[RunStart, _Bridge], tuple[RunUsage, str]] | None = None,
) -> int:
    """Execute exactly one start frame; stdout carries only protocol lines."""
    bridge = _Bridge(source, sink)
    sink.write(json.dumps({"type": "ready"}) + "\n")
    sink.flush()
    line = source.readline(_MAX_LINE)
    if not line:
        return 1
    try:
        raw = json.loads(line)
    except ValueError:
        _error(sink, "invalid_start", "start frame is not JSON")
        return 1
    try:
        start = RunStart.model_validate(raw)
    except Exception:
        _error(sink, "invalid_start", "start frame is invalid")
        return 1
    if not _bounded_start(start):
        _error(sink, "invalid_start", "start frame is too large")
        return 1
    runner = run or _run
    try:
        outcome = runner(start, bridge)
        result = asyncio.run(outcome) if inspect.isawaitable(outcome) else outcome
        usage, message = result
    except WorkerProtocolError:
        _error(sink, "protocol_error", "the bridge protocol was violated")
        return 1
    except Exception as exc:
        _error(sink, "worker_failed", type(exc).__name__)
        return 1
    _usage(sink, usage)
    _final(sink, message)
    return 0


def _bounded_start(start: RunStart) -> bool:
    try:
        encoded = json.dumps(
            start.model_dump(by_alias=True, exclude_none=True), default=str
        ).encode("utf-8")
    except TypeError, ValueError:
        return False
    return len(encoded) <= _MAX_LINE


def _error(sink: TextIO, code: str, message: str) -> None:
    sink.write(json.dumps({"type": "error", "code": code, "message": message}) + "\n")
    sink.flush()


def _usage(sink: TextIO, usage: RunUsage) -> None:
    sink.write(
        json.dumps(
            {
                "type": "usage",
                "inputTokens": max(0, int(getattr(usage, "input_tokens", 0) or 0)),
                "outputTokens": max(0, int(getattr(usage, "output_tokens", 0) or 0)),
            }
        )
        + "\n"
    )
    sink.flush()


def _final(sink: TextIO, message: str) -> None:
    final = WorkerFinal(message=(message.strip() or "No pude completar la solicitud.")[:4000])
    sink.write(final.model_dump_json(by_alias=True) + "\n")
    sink.flush()


def main() -> int:
    return serve(sys.stdin, sys.stdout)


if __name__ == "__main__":  # pragma: no cover - container entrypoint
    raise SystemExit(main())
