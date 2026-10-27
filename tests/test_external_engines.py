"""Behavioral boundaries for external engine adapters; no provider is contacted."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest
from itsm.agents.engines import EngineConfig, EngineError
from itsm.agents.hermes import HermesEngine
from itsm.agents.opencode import OpenCodeEngine

BASE = "http://engine.test"


class _SSEStream(httpx.AsyncByteStream):
    """Async byte stream that can fail after a complete frame."""

    def __init__(self, chunks: list[str | Exception]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            if isinstance(chunk, Exception):
                raise chunk
            yield chunk.encode()

    async def aclose(self) -> None:
        return None


class _GeneratedSSE(httpx.AsyncByteStream):
    """Adapt an asynchronous frame generator to httpx's byte stream."""

    def __init__(self, frames: AsyncIterator[bytes]) -> None:
        self._frames = frames

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._frames:
            yield chunk

    async def aclose(self) -> None:
        await self._frames.aclose()


def _sse(*frames: Mapping[str, Any] | str) -> httpx.Response:
    body = "".join(f"data: {json.dumps(frame)}\n\n" for frame in frames)
    return httpx.Response(
        200,
        headers={"content-type": "text/event-stream"},
        stream=_SSEStream([body]),
    )


def _sse_then_failure(*frames: Mapping[str, Any]) -> httpx.Response:
    body = "".join(f"data: {json.dumps(frame)}\n\n" for frame in frames)
    return httpx.Response(
        200,
        headers={"content-type": "text/event-stream"},
        stream=_SSEStream([body, httpx.ReadError("connection lost")]),
    )


def _named_sse(*frames: tuple[str, Mapping[str, Any] | str]) -> httpx.Response:
    body = "".join(f"event: {name}\ndata: {json.dumps(payload)}\n\n" for name, payload in frames)
    return httpx.Response(
        200,
        headers={"content-type": "text/event-stream"},
        stream=_SSEStream([body]),
    )


def _v2_model(
    model_id: str,
    provider: str = "opencode",
    *,
    input_cost: float = 0,
    output_cost: float = 0,
    cache_read: float = 0,
    cache_write: float = 0,
    enabled: bool = True,
) -> dict[str, Any]:
    return {
        "id": model_id,
        "modelID": model_id,
        "providerID": provider,
        "name": model_id.replace("-", " ").title(),
        "cost": [
            {
                "input": input_cost,
                "output": output_cost,
                "cache": {"read": cache_read, "write": cache_write},
            }
        ],
        "status": "active",
        "enabled": enabled,
    }


def test_v2_discovery_uses_live_schema_and_never_treats_spa_as_connected() -> None:
    async def scenario() -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            if request.url.path == "/api/info":
                return httpx.Response(200, json={"version": "2.1.2"})
            if request.url.path == "/api/model":
                return httpx.Response(
                    200,
                    json={
                        "location": {},
                        "data": [
                            _v2_model("big-pickle"),
                            _v2_model("claude", "anthropic", input_cost=3),
                            _v2_model("hidden", enabled=False),
                        ],
                    },
                )
            raise AssertionError(f"unexpected request {request.url}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(
                EngineConfig(BASE, directory="/srv/itsm"),
                client=client,
            )
            info = await engine.discover()

        assert info.version == "2.1.2"
        assert [model.id for model in info.models] == [
            "opencode/big-pickle",
            "anthropic/claude",
        ]
        assert info.models[0].free is True
        assert info.models[1].free is False
        assert info.models[0].as_dict() == {
            "id": "opencode/big-pickle",
            "name": "Big Pickle",
            "provider": "opencode",
            "free": True,
        }
        assert info.capabilities == {
            "streaming": True,
            "sessions": True,
            "model_switch": True,
            "cancel": True,
            "tools": True,
            "usage": True,
            "history": True,
        }
        model_request = next(request for request in seen if request.url.path == "/api/model")
        assert model_request.url.params["location[directory]"] == "/srv/itsm"
        assert "directory" not in model_request.url.params

        def spa_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<!doctype html><html>OpenCode</html>",
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(spa_handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            with pytest.raises(EngineError) as failed:
                await engine.discover()

        assert failed.value.code == "protocol"
        assert failed.value.retryable is False
        assert "<html" not in failed.value.message

    asyncio.run(scenario())


def test_model_free_uses_all_reported_prices_without_provider_allowlist() -> None:
    async def v2_models() -> dict[str, bool | None]:
        unknown = _v2_model("unknown")
        unknown["cost"] = [{"input": 0}]
        missing_cache = _v2_model("missing-cache")
        missing_cache["cost"] = [{"input": 0, "output": 0}]
        paid_reasoning = _v2_model("paid-reasoning", "fourth")
        paid_reasoning["cost"][0]["reasoning"] = 1
        partial_cache = _v2_model("partial-cache", "fifth")
        partial_cache["cost"] = [{"input": 0, "output": 0, "cache": {"read": 0}}]
        data = [
            _v2_model("zero-other", "custom"),
            _v2_model("paid-output", "opencode", output_cost=2),
            _v2_model("paid-cache", "third-party", cache_write=1),
            paid_reasoning,
            partial_cache,
            unknown,
            missing_cache,
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/info":
                return httpx.Response(200, json={"version": "2.1.2"})
            if request.url.path == "/api/model":
                return httpx.Response(200, json={"location": {}, "data": data})
            raise AssertionError(f"unexpected request {request.url}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            info = await engine.discover()
        return {model.id: model.free for model in info.models}

    async def v1_models() -> dict[str, bool | None]:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/info":
                return httpx.Response(404, json={"error": "not found"})
            if path == "/global/health":
                return httpx.Response(200, json={"healthy": True, "version": "1.15.0"})
            if path == "/config/providers":
                return httpx.Response(
                    200,
                    json={
                        "providers": [
                            {
                                "id": "custom",
                                "models": {
                                    "zero": {
                                        "name": "Zero",
                                        "cost": {"input": 0, "output": 0},
                                    },
                                    "paid-output": {
                                        "name": "Paid Output",
                                        "cost": {"input": 0, "output": 3},
                                    },
                                    "paid-cache": {
                                        "name": "Paid Cache",
                                        "cost": {
                                            "input": 0,
                                            "output": 0,
                                            "cache": {"read": 0, "write": 1},
                                        },
                                    },
                                    "paid-reasoning": {
                                        "name": "Paid Reasoning",
                                        "cost": {
                                            "input": 0,
                                            "output": 0,
                                            "reasoning": 1,
                                        },
                                    },
                                    "partial-read": {
                                        "name": "Partial Read",
                                        "cost": {
                                            "input": 0,
                                            "output": 0,
                                            "cache": {"read": 0},
                                        },
                                    },
                                    "partial-write": {
                                        "name": "Partial Write",
                                        "cost": {
                                            "input": 0,
                                            "output": 0,
                                            "cache": {"write": 1},
                                        },
                                    },
                                    "unknown": {
                                        "name": "Unknown",
                                        "cost": {"input": 0},
                                    },
                                },
                            }
                        ]
                    },
                )
            raise AssertionError(f"unexpected request {request.url}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            info = await engine.discover()
        return {model.id: model.free for model in info.models}

    assert asyncio.run(v2_models()) == {
        "custom/zero-other": True,
        "opencode/paid-output": False,
        "third-party/paid-cache": False,
        "fourth/paid-reasoning": False,
        "fifth/partial-cache": None,
        "opencode/unknown": None,
        "opencode/missing-cache": None,
    }
    assert asyncio.run(v1_models()) == {
        "custom/zero": True,
        "custom/paid-output": False,
        "custom/paid-cache": False,
        "custom/paid-reasoning": False,
        "custom/partial-read": True,
        "custom/partial-write": False,
        "custom/unknown": None,
    }


def test_v212_native_execution_success_finishes_without_waiting_for_stream_close() -> None:
    async def scenario() -> list[dict[str, Any]]:
        async def frames() -> AsyncIterator[bytes]:
            for payload in (
                {"type": "session.execution.succeeded", "data": {"sessionID": "other"}},
                {"type": "session.text.delta", "data": {"sessionID": "ses_native", "delta": "OK"}},
                {"type": "session.tool.input.started", "data": {
                    "sessionID": "other", "id": "call_other", "name": "wrong_tool",
                }},
                {"type": "session.tool.input.started", "data": {
                    "sessionID": "ses_native", "id": "call_native", "name": "itsm_search_assets",
                }},
                {"type": "session.tool.called", "data": {
                    "sessionID": "ses_native", "id": "call_native", "input": {"query": "AI"},
                }},
                {"type": "session.tool.success", "data": {
                    "sessionID": "ses_native", "id": "call_native",
                    "content": [{"type": "text", "text": "found"}],
                }},
                {"type": "session.execution.succeeded", "data": {"sessionID": "ses_native"}},
            ):
                yield f"data: {json.dumps(payload)}\n\n".encode()
            await asyncio.sleep(10)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/event":
                return httpx.Response(
                    200, headers={"content-type": "text/event-stream"},
                    stream=_GeneratedSSE(frames()),
                )
            if request.url.path.endswith("/prompt"):
                return httpx.Response(200, json={"data": {"id": "user_native"}})
            if request.url.path.endswith("/message"):
                return httpx.Response(200, json={"data": []})
            raise AssertionError(f"unexpected request {request.url.path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE, agent=None), client=client)
            engine._variant = "v2"

            async def collect() -> list[dict[str, Any]]:
                return [event async for event in engine.stream("hello", session_id="ses_native")]

            return await asyncio.wait_for(collect(), timeout=0.5)

    events = asyncio.run(scenario())
    assert [event["text"] for event in events if event["type"] == "delta"] == ["OK"]
    assert not [event for event in events if event["type"] == "error"]
    assert [event for event in events if event["type"] == "tool"] == [
        {
            "type": "tool", "tool": "itsm_search_assets", "status": "running",
            "input": {"query": "AI"},
        },
        {"type": "tool", "tool": "itsm_search_assets", "status": "completed", "output": "found"},
    ]
    assert events[-1] == {"type": "done", "cancelled": False}


def test_v212_native_execution_failure_finishes_without_waiting_for_stream_close() -> None:
    async def scenario() -> list[dict[str, Any]]:
        async def frames() -> AsyncIterator[bytes]:
            for payload in (
                {"type": "session.execution.failed", "data": {
                    "sessionID": "other", "error": {"message": "foreign failure"},
                }},
                {"type": "session.execution.failed", "data": {
                    "sessionID": "ses_native", "error": {"message": "output bound exceeded"},
                }},
            ):
                yield f"data: {json.dumps(payload)}\n\n".encode()
            await asyncio.sleep(10)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/event":
                return httpx.Response(
                    200, headers={"content-type": "text/event-stream"},
                    stream=_GeneratedSSE(frames()),
                )
            if request.url.path.endswith("/prompt"):
                return httpx.Response(200, json={"data": {"id": "user_native"}})
            if request.url.path.endswith("/message"):
                return httpx.Response(200, json={"data": []})
            if request.url.path.endswith("/interrupt"):
                return httpx.Response(200, json={})
            raise AssertionError(f"unexpected request {request.url.path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE, agent=None), client=client)
            engine._variant = "v2"

            async def collect() -> list[dict[str, Any]]:
                return [event async for event in engine.stream("hello", session_id="ses_native")]

            return await asyncio.wait_for(collect(), timeout=0.5)

    events = asyncio.run(scenario())
    errors = [event for event in events if event["type"] == "error"]
    assert len(errors) == 1
    assert errors[0]["message"] == "output bound exceeded"
    assert not [event for event in events if event["type"] == "delta"]
    assert events[-1] == {"type": "done", "cancelled": False}


def test_v2_stream_is_cumulative_session_isolated_and_reports_engine_usage() -> None:
    async def scenario() -> list[dict[str, Any]]:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            path = request.url.path
            if path == "/api/info":
                return httpx.Response(200, json={"version": "2.1.2"})
            if path == "/api/model":
                return httpx.Response(
                    200,
                    json={"location": {}, "data": [_v2_model("big-pickle")]},
                )
            if path == "/api/session":
                return httpx.Response(200, json={"data": {"id": "ses_1"}})
            if path == "/api/event":
                return _sse(
                    {
                        "id": "1",
                        "type": "session.text.started",
                        "data": {"sessionID": "ses_1"},
                    },
                    {
                        "id": "2",
                        "type": "session.text.delta",
                        "data": {"sessionID": "ses_1", "delta": "Hola"},
                    },
                    {
                        "id": "3",
                        "type": "session.text.delta",
                        "data": {"sessionID": "ses_other", "delta": "NO"},
                    },
                    {
                        "id": "4",
                        "type": "session.tool.called",
                        "data": {
                            "sessionID": "ses_1",
                            "tool": "itsm_inventory_search",
                            "id": "call_1",
                            "input": {"query": "nvr"},
                        },
                    },
                    {
                        "id": "5",
                        "type": "session.tool.success",
                        "data": {
                            "sessionID": "ses_1",
                            "id": "call_1",
                            "content": [{"type": "text", "text": "2 activos"}],
                        },
                    },
                    {
                        "id": "6",
                        "type": "session.text.delta",
                        "data": {"sessionID": "ses_1", "delta": " mundo"},
                    },
                    {
                        "id": "6",
                        "type": "session.text.delta",
                        "data": {"sessionID": "ses_1", "delta": " mundo"},
                    },
                    {
                        "id": "8",
                        "type": "session.status",
                        "data": {"sessionID": "ses_1", "status": {"type": "idle"}},
                    },
                )
            if path == "/api/session/ses_1/agent":
                return httpx.Response(204)
            if path == "/api/session/ses_1/model":
                return httpx.Response(204)
            if path == "/api/session/ses_1/prompt":
                return httpx.Response(200, json={"data": {"id": "msg_user"}})
            if path == "/api/session/ses_1/message":
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            {
                                "id": "msg_assistant",
                                "type": "assistant",
                                "time": {"created": 1, "completed": 2},
                                "tokens": {
                                    "input": 12,
                                    "output": 5,
                                    "reasoning": 0,
                                    "cache": {"read": 0, "write": 0},
                                },
                                "cost": 0,
                                "content": [{"type": "text", "text": "Hola mundo"}],
                            },
                            {"id": "msg_user", "type": "user"},
                        ],
                        "cursor": {},
                    },
                )
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            await engine.discover()
            assert await engine.create_session() == "ses_1"
            events = [
                event
                async for event in engine.stream(
                    "Busca activos",
                    session_id="ses_1",
                    model="opencode/big-pickle",
                )
            ]

        prompt_requests = [
            request for request in requests if request.url.path == "/api/session/ses_1/prompt"
        ]
        assert len(prompt_requests) == 1
        assert json.loads(prompt_requests[0].content)["text"] == "Busca activos"
        create_requests = [request for request in requests if request.url.path == "/api/session"]
        assert json.loads(create_requests[0].content)["agent"] == "itsm"
        agent_requests = [
            request for request in requests if request.url.path == "/api/session/ses_1/agent"
        ]
        assert json.loads(agent_requests[0].content) == {"agent": "itsm"}
        model_requests = [
            request for request in requests if request.url.path == "/api/session/ses_1/model"
        ]
        assert json.loads(model_requests[0].content) == {
            "model": {"id": "big-pickle", "providerID": "opencode"}
        }
        return events

    events = asyncio.run(scenario())

    assert events[0] == {"type": "session", "sessionId": "ses_1"}
    fragments = [str(event["text"]) for event in events if event["type"] == "delta"]
    assert fragments == ["Hola", " mundo"]
    assert "".join(fragments) == "Hola mundo"
    tools = [event for event in events if event["type"] == "tool"]
    assert tools[0] == {
        "type": "tool",
        "tool": "itsm_inventory_search",
        "status": "running",
        "input": {"query": "nvr"},
    }
    assert tools[1] == {
        "type": "tool",
        "tool": "itsm_inventory_search",
        "status": "completed",
        "output": "2 activos",
    }
    usage = [event for event in events if event["type"] == "usage"]
    assert usage == [
        {
            "type": "usage",
            "inputTokens": 12,
            "outputTokens": 5,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0,
            "reasoningTokens": 0,
            "totalTokens": 17,
            "precision": "measured",
            "source": "engine",
            "estimationMethod": None,
            "inputIncludesCache": False,
            "outputIncludesReasoning": False,
            "totalSource": "derived",
            "cost": 0,
        }
    ]
    assert events[-1] == {"type": "done", "cancelled": False}


def test_v2_usage_aggregates_every_distinct_assistant_message_once() -> None:
    async def scenario() -> list[dict[str, Any]]:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/info":
                return httpx.Response(200, json={"version": "2.1.2"})
            if path == "/api/model":
                return httpx.Response(
                    200,
                    json={"location": {}, "data": [_v2_model("big-pickle")]},
                )
            if path == "/api/session":
                return httpx.Response(200, json={"data": {"id": "ses_multi"}})
            if path == "/api/event":
                return _sse(
                    {
                        "id": "1",
                        "type": "session.text.delta",
                        "data": {
                            "sessionID": "ses_multi",
                            "assistantMessageID": "msg_b",
                            "delta": "fin",
                        },
                    },
                    {
                        "id": "2",
                        "type": "session.idle",
                        "data": {"sessionID": "ses_multi"},
                    },
                )
            if path == "/api/session/ses_multi/agent":
                return httpx.Response(204)
            if path == "/api/session/ses_multi/model":
                return httpx.Response(204)
            if path == "/api/session/ses_multi/prompt":
                return httpx.Response(200, json={"data": {"id": "msg_user"}})
            if path == "/api/session/ses_multi/message":
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            {
                                "id": "msg_b",
                                "type": "assistant",
                                "time": {"created": 2, "completed": 3},
                                "tokens": {
                                    "input": 5,
                                    "output": 1,
                                    "reasoning": 0,
                                    "cache": {"read": 0, "write": 2},
                                },
                                "cost": 0.2,
                                "content": [{"type": "text", "text": "fin"}],
                            },
                            {
                                "id": "msg_a",
                                "type": "assistant",
                                "time": {"created": 1, "completed": 2},
                                "tokens": {
                                    "input": 10,
                                    "output": 2,
                                    "reasoning": 1,
                                    "cache": {"read": 3, "write": 0},
                                },
                                "cost": 0.1,
                                "content": [{"type": "text", "text": "inicio"}],
                            },
                            {"id": "msg_user", "type": "user"},
                            {
                                "id": "msg_prior_turn",
                                "type": "assistant",
                                "tokens": {
                                    "input": 999,
                                    "output": 999,
                                    "reasoning": 999,
                                    "cache": {"read": 999, "write": 999},
                                },
                                "cost": 99,
                            },
                        ]
                    },
                )
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            await engine.discover()
            assert await engine.create_session() == "ses_multi"
            return [
                event
                async for event in engine.stream(
                    "Busca activos",
                    session_id="ses_multi",
                    model="opencode/big-pickle",
                )
            ]

    events = asyncio.run(scenario())

    assert [event for event in events if event["type"] == "usage"] == [
        {
            "type": "usage",
            "inputTokens": 15,
            "outputTokens": 3,
            "cacheReadTokens": 3,
            "cacheWriteTokens": 2,
            "reasoningTokens": 1,
            "totalTokens": 24,
            "precision": "measured",
            "source": "engine",
            "estimationMethod": None,
            "inputIncludesCache": False,
            "outputIncludesReasoning": False,
            "totalSource": "derived",
            "cost": 0.3,
        }
    ]
    assert events[-1] == {"type": "done", "cancelled": False}


def test_v2_missing_prompt_anchor_never_sums_prior_turn_assistants() -> None:
    async def scenario() -> list[dict[str, Any]]:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/session/ses_1/agent":
                return httpx.Response(204)
            if path == "/api/session/ses_1/model":
                return httpx.Response(204)
            if path == "/api/session/ses_1/prompt":
                return httpx.Response(200, json={"data": {"id": "msg_user"}})
            if path == "/api/session/ses_1/message":
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            {
                                "id": "msg_prior_turn",
                                "type": "assistant",
                                "tokens": {
                                    "input": 999,
                                    "output": 999,
                                    "reasoning": 999,
                                    "cache": {"read": 999, "write": 999},
                                },
                                "cost": 99,
                            },
                            {"id": "msg_other_user", "type": "user"},
                        ]
                    },
                )
            if path == "/api/event":
                return _sse(
                    {
                        "type": "session.idle",
                        "data": {"sessionID": "ses_1"},
                    }
                )
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE, agent=None), client=client)
            engine._variant = "v2"
            return [
                event
                async for event in engine.stream(
                    "Busca activos",
                    session_id="ses_1",
                    model="opencode/big-pickle",
                )
            ]

    events = asyncio.run(scenario())

    assert [event for event in events if event["type"] == "usage"] == [
        {
            "type": "usage",
            "inputTokens": None,
            "outputTokens": None,
            "cacheReadTokens": None,
            "cacheWriteTokens": None,
            "reasoningTokens": None,
            "totalTokens": None,
            "precision": "unavailable",
            "source": "engine",
            "estimationMethod": None,
            "inputIncludesCache": False,
            "outputIncludesReasoning": None,
            "totalSource": None,
        }
    ]


def test_v1_unreadable_prompt_baseline_never_sums_event_snapshots() -> None:
    async def scenario() -> list[dict[str, Any]]:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/event":
                return _named_sse(
                    (
                        "message.updated",
                        {
                            "info": {
                                "id": "msg_current",
                                "role": "assistant",
                                "tokens": {"input": 8, "output": 3},
                            }
                        },
                    ),
                    ("session.idle", {"sessionID": "ses_v1"}),
                )
            if path == "/session/ses_v1/message":
                if request.method == "GET":
                    return httpx.Response(500, json={"error": "unavailable"})
                return httpx.Response(
                    200,
                    json={
                        "info": {
                            "id": "msg_current",
                            "role": "assistant",
                            "tokens": {"input": 8, "output": 3},
                        },
                        "parts": [{"id": "prt_text", "type": "text", "text": "fin"}],
                    },
                )
            if path == "/session/ses_v1/model":
                return httpx.Response(204)
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE, agent=None), client=client)
            engine._variant = "v1"
            return [
                event
                async for event in engine.stream(
                    "Busca activos",
                    session_id="ses_v1",
                    model="opencode/big-pickle",
                )
            ]

    events = asyncio.run(scenario())

    usage = [event for event in events if event["type"] == "usage"]
    assert len(usage) == 1
    assert usage[0]["precision"] == "unavailable"
    assert usage[0]["inputTokens"] is None
    assert usage[0]["totalTokens"] is None


def test_v2_reconnects_without_resubmitting_prompt_or_duplicating_usage() -> None:
    async def scenario() -> tuple[list[dict[str, Any]], int, int, int]:
        sse_calls = 0
        prompt_calls = 0
        usage_calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal sse_calls, prompt_calls, usage_calls
            path = request.url.path
            if path == "/api/info":
                return httpx.Response(200, json={"version": "2.1.2"})
            if path == "/api/model":
                return httpx.Response(
                    200,
                    json={"location": {}, "data": [_v2_model("big-pickle")]},
                )
            if path == "/api/event":
                sse_calls += 1
                if sse_calls == 1:
                    return _sse_then_failure(
                        {
                            "id": "1",
                            "type": "session.text.delta",
                            "data": {"sessionID": "ses_1", "delta": "Hola"},
                        }
                    )
                return _sse(
                    {
                        "id": "2",
                        "type": "session.text.delta",
                        "data": {"sessionID": "ses_1", "delta": " mundo"},
                    },
                    {
                        "id": "2",
                        "type": "session.text.delta",
                        "data": {"sessionID": "ses_1", "delta": " mundo"},
                    },
                    {
                        "id": "4",
                        "type": "session.status",
                        "data": {"sessionID": "ses_1", "status": {"type": "idle"}},
                    },
                )
            if path == "/api/session/ses_1/agent":
                return httpx.Response(204)
            if path == "/api/session/ses_1/model":
                return httpx.Response(204)
            if path == "/api/session/ses_1/prompt":
                prompt_calls += 1
                return httpx.Response(200, json={"data": {"id": "msg_user"}})
            if path == "/api/session/ses_1/message":
                if sse_calls < 2:
                    return httpx.Response(200, json={"data": []})
                usage_calls += 1
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            {
                                "id": "msg_assistant",
                                "type": "assistant",
                                "time": {"created": 1, "completed": 2},
                                "tokens": {
                                    "input": 3,
                                    "output": 2,
                                    "reasoning": 0,
                                    "cache": {"read": 0, "write": 0},
                                },
                                "cost": 0,
                                "content": [{"type": "text", "text": "Hola mundo"}],
                            },
                            {"id": "msg_user", "type": "user"},
                        ]
                    },
                )
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            await engine.discover()
            events = [
                event
                async for event in engine.stream(
                    "Busca activos",
                    session_id="ses_1",
                    model="opencode/big-pickle",
                )
            ]
        return events, sse_calls, prompt_calls, usage_calls

    events, sse_calls, prompt_calls, usage_calls = asyncio.run(scenario())

    assert sse_calls == 2
    assert prompt_calls == 1
    assert usage_calls == 1
    fragments = [str(event["text"]) for event in events if event["type"] == "delta"]
    assert fragments == ["Hola", " mundo"]
    assert "".join(fragments) == "Hola mundo"
    assert [event for event in events if event["type"] == "error"] == []
    assert len([event for event in events if event["type"] == "usage"]) == 1
    assert events[-1] == {"type": "done", "cancelled": False}


def test_v2_disconnect_recovery_emits_completed_message_once() -> None:
    async def scenario() -> tuple[list[dict[str, Any]], int, int, int]:
        sse_calls = 0
        prompt_calls = 0
        message_calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal sse_calls, prompt_calls, message_calls
            path = request.url.path
            if path == "/api/info":
                return httpx.Response(200, json={"version": "2.1.2"})
            if path == "/api/model":
                return httpx.Response(
                    200,
                    json={"location": {}, "data": [_v2_model("big-pickle")]},
                )
            if path == "/api/event":
                sse_calls += 1
                return _sse_then_failure(
                    {
                        "id": "1",
                        "type": "session.text.delta",
                        "data": {"sessionID": "ses_1", "delta": "Hola"},
                    }
                )
            if path == "/api/session/ses_1/agent":
                return httpx.Response(204)
            if path == "/api/session/ses_1/model":
                return httpx.Response(204)
            if path == "/api/session/ses_1/prompt":
                prompt_calls += 1
                return httpx.Response(200, json={"data": {"id": "msg_user"}})
            if path == "/api/session/ses_1/message":
                message_calls += 1
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            {
                                "id": "msg_assistant",
                                "type": "assistant",
                                "time": {"created": 1, "completed": 2},
                                "tokens": {
                                    "input": 3,
                                    "output": 2,
                                    "reasoning": 0,
                                    "cache": {"read": 0, "write": 0},
                                },
                                "cost": 0,
                                "content": [{"type": "text", "text": "Hola mundo"}],
                            },
                            {"id": "msg_user", "type": "user"},
                        ]
                    },
                )
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            await engine.discover()
            events = [
                event
                async for event in engine.stream(
                    "Busca activos",
                    session_id="ses_1",
                    model="opencode/big-pickle",
                )
            ]
        return events, sse_calls, prompt_calls, message_calls

    events, sse_calls, prompt_calls, message_calls = asyncio.run(scenario())

    assert sse_calls == 1
    assert prompt_calls == 1
    assert message_calls == 1
    fragments = [str(event["text"]) for event in events if event["type"] == "delta"]
    assert fragments == ["Hola", " mundo"]
    assert "".join(fragments) == "Hola mundo"
    assert [event for event in events if event["type"] == "error"] == []
    assert [event for event in events if event["type"] == "usage"] == [
        {
            "type": "usage",
            "inputTokens": 3,
            "outputTokens": 2,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0,
            "reasoningTokens": 0,
            "totalTokens": 5,
            "precision": "measured",
            "source": "engine",
            "estimationMethod": None,
            "inputIncludesCache": False,
            "outputIncludesReasoning": False,
            "totalSource": "derived",
            "cost": 0,
        }
    ]
    assert events[-1] == {"type": "done", "cancelled": False}


def test_v2_failed_tool_stays_failed_with_appended_text_and_reported_usage() -> None:
    async def scenario() -> list[dict[str, Any]]:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/info":
                return httpx.Response(200, json={"version": "2.1.2"})
            if path == "/api/model":
                return httpx.Response(
                    200,
                    json={"location": {}, "data": [_v2_model("big-pickle")]},
                )
            if path == "/api/event":
                return _sse(
                    {
                        "id": "1",
                        "type": "session.text.delta",
                        "data": {"sessionID": "ses_1", "delta": "ha"},
                    },
                    {
                        "id": "2",
                        "type": "session.text.delta",
                        "data": {"sessionID": "ses_1", "delta": "ha"},
                    },
                    {
                        "id": "3",
                        "type": "session.tool.called",
                        "data": {
                            "sessionID": "ses_1",
                            "tool": "itsm_search_assets",
                            "id": "call_1",
                            "input": {},
                        },
                    },
                    {
                        "id": "4",
                        "type": "session.tool.failed",
                        "data": {
                            "sessionID": "ses_1",
                            "id": "call_1",
                            "error": "permission denied",
                        },
                    },
                    {
                        "id": "5",
                        "type": "session.idle",
                        "data": {"sessionID": "ses_1"},
                    },
                )
            if path == "/api/session/ses_1/agent":
                return httpx.Response(204)
            if path == "/api/session/ses_1/model":
                return httpx.Response(204)
            if path == "/api/session/ses_1/prompt":
                return httpx.Response(200, json={"data": {"id": "msg_user"}})
            if path == "/api/session/ses_1/message":
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            {
                                "id": "msg_assistant",
                                "type": "assistant",
                                "time": {"created": 1, "completed": 2},
                                "tokens": {
                                    "input": 3,
                                    "output": 2,
                                    "reasoning": 0,
                                    "cache": {"read": 0, "write": 0},
                                },
                                "cost": 0,
                                "content": [{"type": "text", "text": "haha"}],
                            },
                            {"id": "msg_user", "type": "user"},
                        ],
                        "cursor": {},
                    },
                )
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            await engine.discover()
            return [
                event
                async for event in engine.stream(
                    "Find devices",
                    session_id="ses_1",
                    model="opencode/big-pickle",
                )
            ]

    events = asyncio.run(scenario())

    fragments = [str(event["text"]) for event in events if event["type"] == "delta"]
    assert fragments == ["ha", "ha"]
    assert "".join(fragments) == "haha"
    tools = [event for event in events if event["type"] == "tool"]
    assert tools[-1]["type"] == "tool"
    assert tools[-1]["tool"] == "itsm_search_assets"
    assert tools[-1]["status"] == "failed"
    assert tools[-1]["output"] == "engine reported an error"
    assert [event for event in events if event["type"] == "usage"] == [
        {
            "type": "usage",
            "inputTokens": 3,
            "outputTokens": 2,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0,
            "reasoningTokens": 0,
            "totalTokens": 5,
            "precision": "measured",
            "source": "engine",
            "estimationMethod": None,
            "inputIncludesCache": False,
            "outputIncludesReasoning": False,
            "totalSource": "derived",
            "cost": 0,
        }
    ]
    assert events[-1] == {"type": "done", "cancelled": False}


def test_v2_cancel_actually_interrupts_and_stream_reports_cancelled_done() -> None:
    async def scenario() -> tuple[list[dict[str, Any]], int]:
        interrupted = asyncio.Event()
        interrupt_calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal interrupt_calls
            path = request.url.path
            if path == "/api/info":
                return httpx.Response(200, json={"version": "2.1.2"})
            if path == "/api/model":
                return httpx.Response(
                    200,
                    json={"location": {}, "data": [_v2_model("big-pickle")]},
                )
            if path == "/api/event":

                async def frames() -> AsyncIterator[bytes]:
                    yield (
                        "data: "
                        + json.dumps(
                            {
                                "id": "1",
                                "type": "session.text.delta",
                                "data": {"sessionID": "ses_1", "delta": "Parcial"},
                            }
                        )
                        + "\n\n"
                    ).encode()
                    await interrupted.wait()
                    yield (
                        "data: "
                        + json.dumps(
                            {
                                "id": "2",
                                "type": "session.status",
                                "data": {
                                    "sessionID": "ses_1",
                                    "status": {"type": "idle"},
                                },
                            }
                        )
                        + "\n\n"
                    ).encode()

                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=_GeneratedSSE(frames()),
                )
            if path == "/api/session/ses_1/agent":
                return httpx.Response(204)
            if path == "/api/session/ses_1/model":
                return httpx.Response(204)
            if path == "/api/session/ses_1/prompt":
                return httpx.Response(200, json={"data": {"id": "msg_user"}})
            if path == "/api/session/ses_1/interrupt":
                interrupt_calls += 1
                interrupted.set()
                return httpx.Response(200, json={"interrupted": True})
            if path == "/api/session/ses_1/message":
                return httpx.Response(200, json={"data": []})
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            await engine.discover()
            stream = engine.stream(
                "Busca activos",
                session_id="ses_1",
                model="opencode/big-pickle",
            )
            first = await stream.__anext__()
            assert first == {"type": "session", "sessionId": "ses_1"}
            second = await stream.__anext__()
            assert second == {"type": "delta", "text": "Parcial"}
            await engine.cancel("ses_1")
            events = [event async for event in stream]
        return events, interrupt_calls

    events, interrupt_calls = asyncio.run(scenario())

    assert interrupt_calls == 1
    assert events[-1] == {"type": "done", "cancelled": True}
    assert [event for event in events if event["type"] == "error"] == []


def _frame(name: str, payload: Mapping[str, Any]) -> bytes:
    return f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode()


def _v1_message(text: str = "Hola mundo") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "info": {
                "id": "msg_assistant",
                "role": "assistant",
                "tokens": {
                    "input": 8,
                    "output": 3,
                    "reasoning": 0,
                    "cache": {"read": 0, "write": 0},
                },
                "cost": 0.001,
            },
            "parts": [{"id": "prt_text", "type": "text", "text": text}],
        },
    )


def test_v1_event_stream_diffs_cumulative_parts_and_aborts_official_endpoint() -> None:
    async def scenario() -> tuple[list[dict[str, Any]], list[httpx.Request], int]:
        requests: list[httpx.Request] = []
        aborted = asyncio.Event()
        sse_open = asyncio.Event()
        abort_calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal abort_calls
            requests.append(request)
            path = request.url.path
            if path == "/api/info":
                return httpx.Response(404, json={"error": "not found"})
            if path == "/global/health":
                return httpx.Response(
                    200,
                    json={"healthy": True, "version": "1.15.0"},
                )
            if path == "/config/providers":
                return httpx.Response(
                    200,
                    json={
                        "providers": [
                            {
                                "id": "opencode",
                                "models": {
                                    "big-pickle": {
                                        "name": "Big Pickle",
                                        "cost": {"input": 0},
                                    }
                                },
                            }
                        ]
                    },
                )
            if path == "/session":
                return httpx.Response(200, json={"id": "ses_1"})
            if path == "/event":

                async def frames() -> AsyncIterator[bytes]:
                    yield _frame(
                        "message.part.updated",
                        {
                            "sessionID": "ses_1",
                            "part": {
                                "id": "prt_text",
                                "type": "text",
                                "text": "Hola",
                            },
                        },
                    )
                    yield _frame(
                        "message.part.updated",
                        {
                            "sessionID": "ses_1",
                            "part": {
                                "id": "prt_text",
                                "type": "text",
                                "text": "Hola mundo",
                            },
                        },
                    )
                    pending = {
                        "id": "prt_tool",
                        "type": "tool",
                        "tool": "itsm_inventory_search",
                        "callID": "call_1",
                        "state": {"status": "pending", "input": {"query": "nvr"}},
                    }
                    yield _frame(
                        "message.part.updated",
                        {"sessionID": "ses_1", "part": pending},
                    )
                    for state in (
                        {"status": "running", "input": {"query": "nvr"}},
                        {
                            "status": "completed",
                            "input": {"query": "nvr"},
                            "output": "2 activos",
                        },
                        {
                            "status": "error",
                            "input": {"query": "nvr"},
                            "error": "permission denied",
                        },
                    ):
                        yield _frame(
                            "message.part.updated",
                            {
                                "sessionID": "ses_1",
                                "part": {
                                    **pending,
                                    "state": state,
                                },
                            },
                        )
                    yield _frame(
                        "message.part.updated",
                        {
                            "sessionID": "ses_1",
                            "part": {
                                "type": "step-finish",
                                "tokens": {"input": 8, "output": 3},
                                "cost": 0.001,
                            },
                        },
                    )
                    sse_open.set()
                    await aborted.wait()
                    yield _frame("session.idle", {"sessionID": "ses_1"})

                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=_GeneratedSSE(frames()),
                )
            if path == "/session/ses_1/message":
                if request.method == "GET":
                    return httpx.Response(200, json=[])
                return _v1_message()
            if path == "/session/ses_1/abort":
                abort_calls += 1
                aborted.set()
                return httpx.Response(200, json=True)
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            await engine.discover()
            assert await engine.create_session() == "ses_1"
            stream = engine.stream(
                "Busca activos",
                session_id="ses_1",
                model="opencode/big-pickle",
            )
            assert await stream.__anext__() == {"type": "session", "sessionId": "ses_1"}

            async def collect() -> list[dict[str, Any]]:
                return [event async for event in stream]

            consumer = asyncio.create_task(collect())
            await asyncio.wait_for(sse_open.wait(), 1)
            await engine.cancel("ses_1")
            events = await asyncio.wait_for(consumer, 2)
        return events, requests, abort_calls

    events, requests, abort_calls = asyncio.run(scenario())

    fragments = [str(event["text"]) for event in events if event["type"] == "delta"]
    assert fragments == ["Hola", " mundo"]
    tools = [event for event in events if event["type"] == "tool"]
    assert tools[0] == {
        "type": "tool",
        "tool": "itsm_inventory_search",
        "status": "running",
        "input": {"query": "nvr"},
    }
    assert tools[-2] == {
        "type": "tool",
        "tool": "itsm_inventory_search",
        "status": "completed",
        "output": "2 activos",
    }
    assert tools[-1] == {
        "type": "tool",
        "tool": "itsm_inventory_search",
        "status": "failed",
        "output": "engine reported an error",
    }
    assert [event for event in events if event["type"] == "usage"] == [
        {
            "type": "usage",
            "inputTokens": 8,
            "outputTokens": 3,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0,
            "reasoningTokens": 0,
            "totalTokens": 11,
            "precision": "measured",
            "source": "engine",
            "estimationMethod": None,
            "inputIncludesCache": False,
            "outputIncludesReasoning": False,
            "totalSource": "derived",
            "cost": 0.001,
        }
    ]
    assert events[-1] == {"type": "done", "cancelled": True}
    assert abort_calls == 1
    create_requests = [
        request
        for request in requests
        if request.method == "POST" and request.url.path == "/session"
    ]
    assert json.loads(create_requests[0].content) == {"title": "ITSM chat"}
    message_requests = [
        request
        for request in requests
        if request.method == "POST" and request.url.path == "/session/ses_1/message"
    ]
    assert len(message_requests) == 1
    body = json.loads(message_requests[0].content)
    assert body["parts"] == [{"type": "text", "text": "Busca activos"}]
    assert body["model"] == "opencode/big-pickle"
    assert body["agent"] == "itsm"


def test_v1_usage_aggregates_distinct_messages_without_replaying_cumulative_snapshots() -> None:
    def info(message_id: str, tokens: Mapping[str, Any], cost: float) -> dict[str, Any]:
        return {
            "info": {
                "id": message_id,
                "role": "assistant",
                "tokens": tokens,
                "cost": cost,
            }
        }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/info":
            return httpx.Response(404, json={"error": "not found"})
        if path == "/global/health":
            return httpx.Response(200, json={"healthy": True, "version": "1.15.0"})
        if path == "/config/providers":
            return httpx.Response(
                200,
                json={
                    "providers": [
                        {
                            "id": "opencode",
                            "models": {"big-pickle": {"name": "Big Pickle", "cost": {"input": 0}}},
                        }
                    ]
                },
            )
        if path == "/session":
            return httpx.Response(200, json={"id": "ses_v1"})
        if path == "/event":
            return _named_sse(
                (
                    "message.updated",
                    info(
                        "msg_a",
                        {
                            "input": 4,
                            "output": 1,
                            "reasoning": 0,
                            "cache": {"read": 2, "write": 0},
                        },
                        0.0001,
                    ),
                ),
                (
                    "message.updated",
                    info(
                        "msg_a",
                        {
                            "input": 6,
                            "output": 2,
                            "reasoning": 1,
                            "cache": {"read": 2, "write": 0},
                        },
                        0.0001,
                    ),
                ),
                (
                    "message.updated",
                    {
                        "info": {
                            "id": "msg_user",
                            "role": "user",
                            "tokens": {
                                "input": 999,
                                "output": 999,
                                "reasoning": 999,
                                "cache": {"read": 999, "write": 999},
                            },
                            "cost": 99,
                        }
                    },
                ),
                (
                    "message.updated",
                    info(
                        "msg_prior",
                        {
                            "input": 999,
                            "output": 999,
                            "reasoning": 999,
                            "cache": {"read": 999, "write": 999},
                        },
                        99,
                    ),
                ),
                (
                    "message.updated",
                    info(
                        "msg_b",
                        {
                            "input": 2,
                            "output": 1,
                            "reasoning": 0,
                            "cache": {"read": 0, "write": 0},
                        },
                        0.0002,
                    ),
                ),
                ("session.idle", {"sessionID": "ses_v1"}),
            )
        if path == "/session/ses_v1/message":
            if request.method == "GET":
                return httpx.Response(
                    200,
                    json=[
                        {
                            "info": {
                                "id": "msg_prior",
                                "role": "assistant",
                                "tokens": {"input": 5, "output": 5},
                                "cost": 1,
                            },
                            "parts": [],
                        }
                    ],
                )
            return httpx.Response(
                200,
                json={
                    "info": {
                        "id": "msg_b",
                        "role": "assistant",
                        "tokens": {
                            "input": 2,
                            "output": 1,
                            "reasoning": 0,
                            "cache": {"read": 0, "write": 0},
                        },
                        "cost": 0.0002,
                    },
                    "parts": [{"id": "prt_text", "type": "text", "text": "fin"}],
                },
            )
        raise AssertionError(f"unexpected request {request.method} {path}")

    async def scenario() -> list[dict[str, Any]]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            await engine.discover()
            assert await engine.create_session() == "ses_v1"
            return [
                event
                async for event in engine.stream(
                    "Busca activos",
                    session_id="ses_v1",
                    model="opencode/big-pickle",
                )
            ]

    events = asyncio.run(scenario())

    assert [event for event in events if event["type"] == "usage"] == [
        {
            "type": "usage",
            "inputTokens": 8,
            "outputTokens": 3,
            "cacheReadTokens": 2,
            "cacheWriteTokens": 0,
            "reasoningTokens": 1,
            "totalTokens": 14,
            "precision": "measured",
            "source": "engine",
            "estimationMethod": None,
            "inputIncludesCache": False,
            "outputIncludesReasoning": False,
            "totalSource": "derived",
            "cost": 0.0003,
        }
    ]
    assert events[-1] == {"type": "done", "cancelled": False}


def test_v2_repeated_delta_text_is_not_treated_as_cumulative() -> None:
    async def scenario() -> list[dict[str, Any]]:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/info":
                return httpx.Response(200, json={"version": "2.1.2"})
            if path == "/api/model":
                return httpx.Response(
                    200,
                    json={"location": {}, "data": [_v2_model("big-pickle")]},
                )
            if path == "/api/session/ses_1/agent":
                return httpx.Response(204)
            if path == "/api/session/ses_1/model":
                return httpx.Response(204)
            if path == "/api/event":
                return _sse(
                    {
                        "id": "1",
                        "type": "session.text.delta",
                        "data": {"sessionID": "ses_1", "delta": "ha"},
                    },
                    {
                        "id": "2",
                        "type": "session.text.delta",
                        "data": {"sessionID": "ses_1", "delta": "ha"},
                    },
                    {
                        "id": "3",
                        "type": "session.status",
                        "data": {"sessionID": "ses_1", "status": {"type": "idle"}},
                    },
                )
            if path == "/api/session/ses_1/prompt":
                return httpx.Response(200, json={"data": {"id": "msg_user"}})
            if path == "/api/session/ses_1/message":
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            {
                                "id": "msg_assistant",
                                "type": "assistant",
                                "time": {"created": 1, "completed": 2},
                                "tokens": {
                                    "input": 1,
                                    "output": 1,
                                    "reasoning": 0,
                                    "cache": {"read": 0, "write": 0},
                                },
                                "cost": 0,
                                "content": [{"type": "text", "text": "haha"}],
                            },
                            {"id": "msg_user", "type": "user"},
                        ]
                    },
                )
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            await engine.discover()
            return [
                event
                async for event in engine.stream(
                    "Di ha",
                    session_id="ses_1",
                    model="opencode/big-pickle",
                )
            ]

    events = asyncio.run(scenario())
    fragments = [str(event["text"]) for event in events if event["type"] == "delta"]
    assert fragments == ["ha", "ha"]
    assert "".join(fragments) == "haha"














class _HermesSocket:
    """Deterministic native dashboard socket; no network or provider call."""

    def __init__(self, responder: Any) -> None:
        self.incoming: asyncio.Queue[str] = asyncio.Queue()
        self.sent: list[dict[str, Any]] = []
        self._responder = responder
        self.incoming.put_nowait(
            json.dumps(
                {"jsonrpc": "2.0", "method": "event", "params": {"type": "gateway.ready"}}
            )
        )

    async def recv(self) -> str:
        return await self.incoming.get()

    async def send(self, raw: str) -> None:
        request = json.loads(raw)
        self.sent.append(request)
        for frame in self._responder(request):
            self.incoming.put_nowait(json.dumps(frame))

    def methods(self) -> list[str]:
        return [str(request["method"]) for request in self.sent]


def _native_http(
    *, ticket: int = 200, token_page: bool = False
) -> tuple[Any, list[tuple[str, str]]]:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        path = request.url.path
        if path == "/auth/password-login":
            assert json.loads(request.content)["provider"] == "basic"
            return httpx.Response(200, json={})
        if path == "/api/auth/ws-ticket":
            if ticket == 200:
                return httpx.Response(200, json={"ticket": "native-ticket", "ttl_seconds": 30})
            return httpx.Response(ticket, json={"detail": "Unauthorized"})
        if path == "/":
            marker = "false" if token_page else "true"
            token = (
                '<script>window.__HERMES_SESSION_TOKEN__ = "process-token";</script>'
                if token_page
                else ""
            )
            return httpx.Response(
                200,
                text=f"<html><script>window.__HERMES_AUTH_REQUIRED__ = {marker};</script>"
                f"{token}</html>",
            )
        if path == "/openapi.json":
            return httpx.Response(200, json={"info": {"version": "0.22.5"}})
        raise AssertionError(f"unexpected HTTP request {request.method} {path}")

    return httpx.MockTransport(handler), seen


def _native_result(request: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request.get("id"), "result": dict(result)}


def _native_event(kind: str, payload: Mapping[str, Any], session: str = "rt-1") -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "method": "event",
        "params": {"type": kind, "session_id": session, "payload": dict(payload)},
    }


def _native_engine(
    client: httpx.AsyncClient,
    socket: _HermesSocket,
    *,
    urls: list[str] | None = None,
    directory: str | None = None,
) -> HermesEngine:
    async def factory(uri: str) -> _HermesSocket:
        if urls is not None:
            urls.append(uri)
        return socket

    return HermesEngine(
        EngineConfig(BASE, username="admin", token="dev-password", directory=directory),
        client=client,
        socket_factory=factory,
    )


def test_hermes_native_loopback_login_uses_process_token_and_real_models() -> None:
    async def scenario() -> tuple[Any, list[str], list[tuple[str, str]]]:
        urls: list[str] = []

        def responder(request: Mapping[str, Any]) -> list[dict[str, Any]]:
            assert request["method"] == "model.options"
            return [
                _native_result(
                    request,
                    {
                        "providers": [
                            {"slug": "itsm-omp", "models": ["omni/one", "omni/two"], "free": True},
                            {"slug": "other", "models": ["omni/two"]},
                        ],
                        "model": "omni/one",
                        "provider": "itsm-omp",
                    },
                )
            ]

        socket = _HermesSocket(responder)
        transport, seen = _native_http(ticket=401, token_page=True)
        async with httpx.AsyncClient(transport=transport) as client:
            engine = _native_engine(client, socket, urls=urls)
            info = await engine.discover()
            await engine.close()
        return info, urls, seen

    info, urls, seen = asyncio.run(scenario())

    assert info.version == "0.22.5"
    assert [(model.id, model.provider) for model in info.models] == [
        ("omni/one", "itsm-omp"),
        ("omni/two", "itsm-omp"),
        ("omni/two", "other"),
    ]
    assert info.models[0].free is True
    assert info.capabilities == {
        "streaming": True,
        "sessions": True,
        "model_switch": True,
        "cancel": True,
        "tools": True,
        "usage": True,
        "history": False,
    }
    assert urls and "token=process-token" in urls[0]
    assert "ticket=" not in urls[0]
    assert seen == [
        ("POST", "/auth/password-login"),
        ("POST", "/api/auth/ws-ticket"),
        ("GET", "/"),
        ("GET", "/openapi.json"),
    ]


def test_hermes_native_gated_serve_without_ticket_fails_closed() -> None:
    async def scenario() -> EngineError:
        socket = _HermesSocket(lambda request: [])
        transport, _ = _native_http(ticket=401, token_page=False)
        async with httpx.AsyncClient(transport=transport) as client:
            engine = _native_engine(client, socket)
            with pytest.raises(EngineError) as failed:
                await engine.discover()
            await engine.close()
        return failed.value

    failed = asyncio.run(scenario())

    assert failed.code == "authentication"
    assert "ticket" in failed.message.lower()
    assert "process-token" not in failed.message


def test_hermes_native_inspection_normalizes_active_surface_and_cleans_up(
    tmp_path: Path,
) -> None:
    async def scenario() -> tuple[dict[str, object], _HermesSocket]:
        def responder(request: Mapping[str, Any]) -> list[dict[str, Any]]:
            method = request["method"]
            if method == "session.create":
                assert request["params"] == {
                    "source": "cli",
                    "close_on_disconnect": True,
                    "cwd": str(tmp_path),
                }
                return [
                    _native_result(
                        request,
                        {"session_id": "rt-inspect", "stored_session_id": "stored-inspect"},
                    )
                ]
            if method == "tools.list":
                assert request["params"] == {"session_id": "rt-inspect"}
                return [
                    _native_result(
                        request,
                        {
                            "toolsets": [
                                {
                                    "name": "itsm",
                                    "description": "",
                                    "tool_count": 2,
                                    "enabled": True,
                                    "tools": [
                                        "itsm_search_assets",
                                        "mcp__itsm__search_assets",
                                    ],
                                },
                                {
                                    "name": "skills",
                                    "description": "",
                                    "tool_count": 1,
                                    "enabled": True,
                                    "tools": ["skills_list"],
                                },
                                {
                                    "name": "plugin-search",
                                    "description": "",
                                    "tool_count": 1,
                                    "enabled": True,
                                    "tools": ["mcp__plugin-search__lookup"],
                                },
                                {
                                    "name": "project",
                                    "description": "",
                                    "tool_count": 1,
                                    "enabled": False,
                                    "tools": ["Bash"],
                                },
                            ]
                        },
                    )
                ]
            if method == "mcp.servers.list":
                assert request["params"] == {}
                return [
                    _native_result(
                        request,
                        {
                            "servers": [
                                {
                                    "name": "itsm",
                                    "transport": "http",
                                    "url": "http://127.0.0.1:9000/mcp",
                                    "enabled": True,
                                    "source": "config",
                                },
                                {
                                    "name": "plugin-search",
                                    "transport": "http",
                                    "url": "http://127.0.0.1:9000/plugin",
                                    "enabled": True,
                                    "source": "plugin",
                                },
                                {
                                    "name": "disabled-search",
                                    "transport": "http",
                                    "url": "http://127.0.0.1:9000/disabled",
                                    "enabled": False,
                                    "source": "config",
                                },
                            ]
                        },
                    )
                ]
            if method == "skills.manage":
                assert request["params"] == {"action": "list"}
                return [
                    _native_result(
                        request,
                        {
                            "skills": {
                                "productivity": ["itsm-inventory", "hermes-agent"],
                                "creative": ["other"],
                                "duplicate": ["other"],
                            }
                        },
                    )
                ]
            if method == "session.close":
                assert request["params"] == {"session_id": "rt-inspect"}
                return [_native_result(request, {"closed": True, "messages": []})]
            if method == "session.delete":
                assert request["params"] == {"session_id": "stored-inspect"}
                return [_native_result(request, {"deleted": True})]
            raise AssertionError(f"unexpected method {method}")

        socket = _HermesSocket(responder)
        transport, _ = _native_http()
        async with httpx.AsyncClient(transport=transport) as client:
            engine = _native_engine(client, socket, directory=str(tmp_path))
            runtime = await engine.inspect_profile_runtime()
            await engine.close()
        return runtime, socket

    runtime, socket = asyncio.run(scenario())

    assert runtime == {
        "protocol": "hermes-native-serve-v1",
        "endpoint": BASE,
        "profileHome": str(tmp_path),
        "toolsets": ["itsm", "plugin-search", "skills"],
        "mcpServers": [
            {
                "name": "itsm",
                "url": "http://127.0.0.1:9000/mcp",
                "enabled": True,
            },
            {
                "name": "plugin-search",
                "url": "http://127.0.0.1:9000/plugin",
                "enabled": True,
            },
        ],
        "skills": ["hermes-agent", "itsm-inventory", "other"],
        "tools": [
            "itsm_search_assets",
            "mcp__itsm__search_assets",
            "mcp__plugin-search__lookup",
            "skills_list",
        ],
    }
    methods = socket.methods()
    assert methods[:4] == [
        "session.create",
        "tools.list",
        "mcp.servers.list",
        "skills.manage",
    ]
    assert methods[-2:] == ["session.close", "session.delete"]


def test_hermes_native_inspection_requires_managed_mcp_tools_and_cleans_up(
    tmp_path: Path,
) -> None:
    async def scenario() -> tuple[EngineError, _HermesSocket]:
        def responder(request: Mapping[str, Any]) -> list[dict[str, Any]]:
            method = request["method"]
            if method == "session.create":
                return [
                    _native_result(
                        request,
                        {"session_id": "rt-missing", "stored_session_id": "stored-missing"},
                    )
                ]
            if method == "tools.list":
                return [
                    _native_result(
                        request,
                        {
                            "toolsets": [
                                {
                                    "name": "itsm",
                                    "description": "",
                                    "tool_count": 1,
                                    "enabled": True,
                                    "tools": ["itsm_search_assets"],
                                }
                            ]
                        },
                    )
                ]
            if method == "session.close":
                return [_native_result(request, {"closed": True})]
            if method == "session.delete":
                return [_native_result(request, {"deleted": True})]
            raise AssertionError(f"unexpected method {method}")

        socket = _HermesSocket(responder)
        transport, _ = _native_http()
        async with httpx.AsyncClient(transport=transport) as client:
            engine = _native_engine(client, socket, directory=str(tmp_path))
            with pytest.raises(EngineError) as failed:
                await engine.inspect_profile_runtime()
            await engine.close()
        return failed.value, socket

    failed, socket = asyncio.run(scenario())

    assert failed.code == "protocol"
    assert "MCP" in failed.message
    assert socket.methods()[-2:] == ["session.close", "session.delete"]


def test_hermes_native_stream_maps_deltas_tools_usage_and_completion() -> None:
    async def scenario() -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
        socket: _HermesSocket

        def responder(request: Mapping[str, Any]) -> list[dict[str, Any]]:
            method = request["method"]
            if method == "model.options":
                return [
                    _native_result(
                        request,
                        {"providers": [{"slug": "itsm-omp", "models": ["omni/one"]}]},
                    )
                ]
            if method == "session.create":
                return [
                    _native_result(
                        request, {"session_id": "rt-1", "stored_session_id": "stored-1"}
                    )
                ]
            if method == "config.set":
                return [_native_result(request, {"ok": True})]
            if method == "prompt.submit":
                return [
                    _native_result(request, {}),
                    _native_event("message.delta", {"text": "Hola"}),
                    _native_event(
                        "tool.start", {"tool_id": "t1", "name": "itsm_search", "args": {"q": "nvr"}}
                    ),
                    _native_event(
                        "tool.complete",
                        {"tool_id": "t1", "name": "itsm_search", "result": {"items": 2}},
                    ),
                    _native_event(
                        "session.usage",
                        {
                            "input_tokens": 7,
                            "output_tokens": 4,
                            "cache_read_tokens": 2,
                            "cache_write_tokens": 1,
                            "reasoning_tokens": 1,
                            "total_tokens": 14,
                        },
                    ),
                    _native_event(
                        "message.complete",
                        {
                            "status": "complete",
                            "text": "Hola mundo",
                            "usage": {"input": 7, "output": 4, "cost_usd": 0.0004},
                        },
                    ),
                ]
            if method == "session.interrupt":
                return [_native_result(request, {"status": "interrupted"})]
            raise AssertionError(f"unexpected RPC {method}")

        socket = _HermesSocket(responder)
        transport, _ = _native_http()
        async with httpx.AsyncClient(transport=transport) as client:
            engine = _native_engine(client, socket)
            await engine.discover()
            stored = await engine.create_session()
            events = [
                event
                async for event in engine.stream(
                    "Busca activos",
                    session_id=stored,
                    model="omni/one",
                    history=[
                        {"role": "user", "content": "uno"},
                        {"role": "assistant", "content": "dos"},
                    ],
                )
            ]
            await engine.cancel(stored)
            await engine.close()
        return events, socket.sent, stored

    events, sent, stored = asyncio.run(scenario())

    assert stored == "stored-1"
    create = next(item for item in sent if item["method"] == "session.create")
    assert create["params"]["source"] == "cli"
    assert create["params"]["close_on_disconnect"] is False
    switch = next(item for item in sent if item["method"] == "config.set")
    assert switch["params"] == {
        "key": "model",
        "value": "omni/one --session --provider itsm-omp",
        "session_id": "rt-1",
    }
    prompt = next(item for item in sent if item["method"] == "prompt.submit")
    assert prompt["params"]["session_id"] == "rt-1"
    assert "Busca activos" in prompt["params"]["text"]
    assert "uno" in prompt["params"]["text"] and "dos" in prompt["params"]["text"]
    assert [event["text"] for event in events if event["type"] == "delta"] == ["Hola"]
    assert [event for event in events if event["type"] == "tool"] == [
        {
            "type": "tool",
            "tool": "itsm_search",
            "status": "running",
            "input": {"q": "nvr"},
        },
        {
            "type": "tool",
            "tool": "itsm_search",
            "status": "completed",
            "output": '{"items": 2}',
        },
    ]
    assert [event for event in events if event["type"] == "usage"] == [
        {
            "type": "usage",
            "inputTokens": 7,
            "outputTokens": 4,
            "cacheReadTokens": 2,
            "cacheWriteTokens": 1,
            "reasoningTokens": 1,
            "totalTokens": 14,
            "precision": "measured",
            "source": "engine",
            "estimationMethod": None,
            "inputIncludesCache": False,
            "outputIncludesReasoning": True,
            "totalSource": "provider",
            "cost": 0.0004,
        }
    ]
    assert events[-1] == {"type": "done", "cancelled": False}
    assert "session.resume" not in [item["method"] for item in sent]


def _hermes_counters(
    input_tokens: int,
    output_tokens: int,
    cache_read: int,
    cache_write: int,
    reasoning: int,
    total: int,
    calls: int,
) -> dict[str, int]:
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_read_tokens": cache_read,
        "cache_write_tokens": cache_write,
        "reasoning_tokens": reasoning,
        "total_tokens": total,
        "prompt_tokens": input_tokens + cache_read + cache_write,
        "completion_tokens": output_tokens,
        "api_calls": calls,
    }


def test_hermes_usage_reports_each_turn_delta_from_cumulative_counters() -> None:
    async def scenario() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        prompt_count = 0
        baseline = _hermes_counters(100, 20, 30, 5, 3, 155, 1)
        finals = [
            _hermes_counters(150, 30, 40, 5, 4, 225, 2),
            _hermes_counters(160, 33, 41, 6, 5, 240, 3),
        ]

        def responder(request: Mapping[str, Any]) -> list[dict[str, Any]]:
            nonlocal prompt_count
            method = request["method"]
            if method == "session.resume":
                return [_native_result(request, {"session_id": "rt-9"})]
            if method == "session.stats":
                return [_native_result(request, baseline)]
            if method == "prompt.submit":
                final = finals[prompt_count]
                prompt_count += 1
                return [
                    _native_result(request, {}),
                    _native_event("session.usage", final, "rt-9"),
                    _native_event(
                        "message.complete", {"status": "complete", "text": ""}, "rt-9"
                    ),
                ]
            raise AssertionError(f"unexpected RPC {method}")

        socket = _HermesSocket(responder)
        transport, _ = _native_http()
        async with httpx.AsyncClient(transport=transport) as client:
            engine = _native_engine(client, socket)
            first = [
                event
                async for event in engine.stream("turno uno", session_id="stored-9")
            ]
            second = [
                event
                async for event in engine.stream("turno dos", session_id="stored-9")
            ]
            await engine.close()
        return first + second, socket.sent

    events, sent = asyncio.run(scenario())
    usage = [event for event in events if event["type"] == "usage"]

    assert [item["method"] for item in sent].count("session.stats") == 1
    assert usage == [
        {
            "type": "usage",
            "inputTokens": 50,
            "outputTokens": 10,
            "cacheReadTokens": 10,
            "cacheWriteTokens": 0,
            "reasoningTokens": 1,
            "totalTokens": 70,
            "precision": "measured",
            "source": "engine",
            "estimationMethod": None,
            "inputIncludesCache": False,
            "outputIncludesReasoning": True,
            "totalSource": "provider",
        },
        {
            "type": "usage",
            "inputTokens": 10,
            "outputTokens": 3,
            "cacheReadTokens": 1,
            "cacheWriteTokens": 1,
            "reasoningTokens": 1,
            "totalTokens": 15,
            "precision": "measured",
            "source": "engine",
            "estimationMethod": None,
            "inputIncludesCache": False,
            "outputIncludesReasoning": True,
            "totalSource": "provider",
        },
    ]


def test_hermes_usage_counter_reset_emits_unavailable_instead_of_a_negative_delta() -> None:
    baseline = _hermes_counters(100, 20, 30, 5, 3, 155, 1)
    reset = _hermes_counters(90, 25, 31, 5, 4, 150, 2)

    def responder(request: Mapping[str, Any]) -> list[dict[str, Any]]:
        method = request["method"]
        if method == "session.resume":
            return [_native_result(request, {"session_id": "rt-reset"})]
        if method == "session.stats":
            return [_native_result(request, baseline)]
        if method == "prompt.submit":
            return [
                _native_result(request, {}),
                _native_event("session.usage", reset, "rt-reset"),
                _native_event(
                    "message.complete", {"status": "complete", "text": "hola"}, "rt-reset"
                ),
            ]
        raise AssertionError(f"unexpected RPC {method}")

    async def scenario() -> list[dict[str, Any]]:
        socket = _HermesSocket(responder)
        transport, _ = _native_http()
        async with httpx.AsyncClient(transport=transport) as client:
            engine = _native_engine(client, socket)
            events = [
                event
                async for event in engine.stream("turno", session_id="stored-reset")
            ]
            await engine.close()
        return events

    events = asyncio.run(scenario())

    assert [event for event in events if event["type"] == "usage"] == [
        {
            "type": "usage",
            "inputTokens": None,
            "outputTokens": None,
            "cacheReadTokens": None,
            "cacheWriteTokens": None,
            "reasoningTokens": None,
            "totalTokens": None,
            "precision": "unavailable",
            "source": "engine",
            "estimationMethod": None,
            "inputIncludesCache": False,
            "outputIncludesReasoning": True,
            "totalSource": None,
        }
    ]
    assert events[-1] == {"type": "done", "cancelled": False}


def test_hermes_usage_missing_final_evidence_emits_unavailable() -> None:
    async def scenario() -> list[dict[str, Any]]:
        def responder(request: Mapping[str, Any]) -> list[dict[str, Any]]:
            method = request["method"]
            if method == "session.create":
                return [
                    _native_result(
                        request, {"session_id": "rt-missing", "stored_session_id": "stored-missing"}
                    )
                ]
            if method == "prompt.submit":
                return [
                    _native_result(request, {}),
                    _native_event(
                        "message.complete", {"status": "complete", "text": "hola"}, "rt-missing"
                    ),
                ]
            raise AssertionError(f"unexpected RPC {method}")

        socket = _HermesSocket(responder)
        transport, _ = _native_http()
        async with httpx.AsyncClient(transport=transport) as client:
            engine = _native_engine(client, socket)
            stored = await engine.create_session()
            events = [
                event async for event in engine.stream("turno", session_id=stored)
            ]
            await engine.close()
        return events

    events = asyncio.run(scenario())

    assert [event for event in events if event["type"] == "usage"] == [
        {
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
            "outputIncludesReasoning": True,
            "totalSource": None,
        }
    ]
    assert events[-1] == {"type": "done", "cancelled": False}


def test_hermes_native_resume_and_interrupt_use_stored_session_identity() -> None:
    async def scenario() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        def responder(request: Mapping[str, Any]) -> list[dict[str, Any]]:
            method = request["method"]
            if method == "session.resume":
                return [_native_result(request, {"session_id": "rt-2"})]
            if method == "session.stats":
                return [
                    _native_result(
                        request,
                        {
                            "input_tokens": 0,
                            "output_tokens": 0,
                            "cache_read_tokens": 0,
                            "cache_write_tokens": 0,
                            "reasoning_tokens": 0,
                            "total_tokens": 0,
                        },
                    )
                ]
            if method == "prompt.submit":
                return [
                    _native_result(request, {}),
                    _native_event(
                        "message.complete", {"status": "interrupted", "text": ""}, "rt-2"
                    ),
                ]
            if method == "session.interrupt":
                return [_native_result(request, {"status": "not_interrupted"})]
            raise AssertionError(f"unexpected RPC {method}")

        socket = _HermesSocket(responder)
        transport, _ = _native_http()
        async with httpx.AsyncClient(transport=transport) as client:
            engine = _native_engine(client, socket)
            events = [
                event
                async for event in engine.stream(
                    "continua", session_id="stored-2", history=[{"role": "user", "content": "x"}]
                )
            ]
            with pytest.raises(EngineError):
                await engine.cancel("stored-2")
            await engine.close()
        return events, socket.sent

    events, sent = asyncio.run(scenario())

    assert [event["type"] for event in events] == ["session", "usage", "done"]
    assert events[-1] == {"type": "done", "cancelled": False}
    assert events[1]["precision"] == "unavailable"
    assert events[1]["source"] == "none"
    assert events[1]["inputTokens"] is None
    resume = next(item for item in sent if item["method"] == "session.resume")
    assert resume["params"] == {"session_id": "stored-2"}
    prompt = next(item for item in sent if item["method"] == "prompt.submit")
    assert prompt["params"]["session_id"] == "rt-2"
    assert [item["method"] for item in sent].count("config.set") == 0


def test_hermes_native_failed_turn_emits_truthful_error_and_done() -> None:
    async def scenario() -> list[dict[str, Any]]:
        def responder(request: Mapping[str, Any]) -> list[dict[str, Any]]:
            method = request["method"]
            if method == "session.create":
                return [
                    _native_result(
                        request, {"session_id": "rt-3", "stored_session_id": "stored-3"}
                    )
                ]
            if method == "prompt.submit":
                return [
                    _native_result(request, {}),
                    _native_event(
                        "message.complete",
                        {"status": "error", "failure_reason": "provider rejected the turn"},
                        "rt-3",
                    ),
                ]
            raise AssertionError(f"unexpected RPC {method}")

        socket = _HermesSocket(responder)
        transport, _ = _native_http()
        async with httpx.AsyncClient(transport=transport) as client:
            engine = _native_engine(client, socket)
            stored = await engine.create_session()
            events = [
                event async for event in engine.stream("falla", session_id=stored)
            ]
            await engine.close()
        return events

    events = asyncio.run(scenario())

    assert events[-1] == {"type": "done", "cancelled": False}
    error = next(event for event in events if event["type"] == "error")
    assert error["code"] == "upstream"
    assert "provider rejected the turn" in error["message"]
    assert error["retryable"] is False


def test_v2_unauthorized_discovery_redacts_credentials() -> None:
    async def scenario() -> tuple[EngineError, list[str]]:
        requests: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request.url.path)
            return httpx.Response(
                401,
                headers={"content-type": "text/html"},
                text="<html>secret-token-should-not-leak</html>",
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE, token="super-secret-token"), client=client)
            with pytest.raises(EngineError) as failed:
                await engine.discover()
        return failed.value, requests

    error, requests = asyncio.run(scenario())

    assert error.code == "unauthorized"
    assert error.retryable is False
    assert "super-secret-token" not in error.message
    assert "html" not in error.message.lower()
    assert requests == ["/api/info"]


def test_v2_disappearing_model_fails_before_any_prompt_or_event_stream() -> None:
    async def scenario() -> tuple[EngineError, list[str]]:
        requests: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request.url.path)
            path = request.url.path
            if path == "/api/info":
                return httpx.Response(200, json={"version": "2.1.2", "capabilities": {}})
            if path == "/api/model":
                return httpx.Response(
                    200,
                    json={"location": {}, "data": [_v2_model("big-pickle")]},
                )
            if path == "/api/session":
                return httpx.Response(200, json={"data": {"id": "ses_1"}})
            if path == "/api/session/ses_1/agent":
                return httpx.Response(204)
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            await engine.discover()
            assert await engine.create_session() == "ses_1"
            with pytest.raises(EngineError) as failed:
                await engine.stream(
                    "Nunca debe enviarse",
                    session_id="ses_1",
                    model="opencode/removed-model",
                ).__anext__()
        return failed.value, requests

    error, requests = asyncio.run(scenario())

    assert error.code == "model_unavailable"
    assert "/api/session/ses_1/prompt" not in requests
    assert "/api/session/ses_1/model" not in requests
    assert "/api/event" not in requests


def test_v2_history_prompt_is_bounded_and_omits_tool_call_wire_fields() -> None:
    async def scenario() -> tuple[dict[str, Any], bool]:
        prompt_body: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/info":
                return httpx.Response(200, json={"version": "2.1.2", "capabilities": {}})
            if path == "/api/model":
                return httpx.Response(
                    200,
                    json={"location": {}, "data": [_v2_model("big-pickle")]},
                )
            if path == "/api/session/ses_1/agent":
                return httpx.Response(204)
            if path == "/api/session/ses_1/prompt":
                prompt_body.update(json.loads(request.content))
                return httpx.Response(200, json={"data": {"messageID": "msg_1"}})
            if path == "/api/session/ses_1/message":
                return httpx.Response(200, json={"data": []})
            if path == "/api/event":
                return _sse({"id": "1", "type": "session.idle", "data": {"sessionID": "ses_1"}})
            raise AssertionError(f"unexpected request {request.method} {path}")

        history = [
            {
                "role": "assistant",
                "content": "dato " * 900,
                "tool_calls": [{"id": "call_1", "function": {"name": "shell"}}],
            }
            for _ in range(20)
        ]
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig(BASE), client=client)
            await engine.discover()
            events = [
                event
                async for event in engine.stream(
                    "Mensaje actual", session_id="ses_1", history=history
                )
            ]
            cancelled = events[-1] == {"type": "done", "cancelled": False}
            injected_open = not client.is_closed
        return prompt_body, injected_open and cancelled

    prompt_body, passed = asyncio.run(scenario())

    text = prompt_body["text"]
    assert passed is True
    assert text.endswith("Mensaje actual")
    assert "tool_calls" not in text
    assert len(text) <= 9_000
    assert text.count("Asistente:") <= 12
