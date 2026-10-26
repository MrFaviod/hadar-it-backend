"""Behavioral boundaries for external engine adapters; no provider is contacted."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Mapping
from typing import Any

import httpx
import pytest

from itsm.agents.engines import EngineConfig, EngineError, EngineModel
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
    body = "".join(
        f"event: {name}\ndata: {json.dumps(payload)}\n\n" for name, payload in frames
    )
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
        data = [
            _v2_model("zero-other", "custom"),
            _v2_model("paid-output", "opencode", output_cost=2),
            _v2_model("paid-cache", "third-party", cache_write=1),
            paid_reasoning,
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
        "opencode/unknown": None,
        "opencode/missing-cache": None,
    }
    assert asyncio.run(v1_models()) == {
        "custom/zero": True,
        "custom/paid-output": False,
        "custom/paid-cache": False,
        "custom/paid-reasoning": False,
        "custom/unknown": None,
    }


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
                            }
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
        create_requests = [
            request for request in requests if request.url.path == "/api/session"
        ]
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
            "source": "reported",
            "cost": 0,
        }
    ]
    assert events[-1] == {"type": "done", "cancelled": False}


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
                            }
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
                            }
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
            "source": "reported",
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
    assert tools[-1] == {
        "type": "tool",
        "tool": "itsm_inventory_search",
        "status": "completed",
        "output": "2 activos",
    }
    assert [event for event in events if event["type"] == "usage"] == [
        {
            "type": "usage",
            "inputTokens": 8,
            "outputTokens": 3,
            "source": "reported",
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
                            }
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


def test_hermes_session_stream_uses_capabilities_tools_usage_and_no_profile_field() -> None:
    async def scenario() -> tuple[
        list[dict[str, Any]], list[httpx.Request], Any, list[httpx.Request]
    ]:
        from itsm.agents.engines import EngineInfo

        requests: list[httpx.Request] = []
        create_bodies: list[dict[str, Any]] = []
        stream_bodies: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            path = request.url.path
            if path == "/v1/capabilities":
                return httpx.Response(
                    200,
                    json={
                        "version": "1.0.0",
                        "features": {
                            "session_resources": True,
                            "session_chat_stream": True,
                        },
                    },
                )
            if path == "/v1/models":
                return httpx.Response(
                    200,
                    json={"data": [{"id": "anthropic/claude", "owned_by": "anthropic"}]},
                )
            if path == "/api/sessions" and request.method == "POST":
                create_bodies.append(json.loads(request.content))
                return httpx.Response(201, json={"session": {"id": "sess_hermes"}})
            if path == "/api/sessions/sess_hermes/chat/stream":
                stream_bodies.append(json.loads(request.content))
                return _named_sse(
                    (
                        "assistant.delta",
                        {"session_id": "sess_hermes", "delta": "Hola"},
                    ),
                    (
                        "assistant.commentary",
                        {"session_id": "sess_hermes", "delta": "nota"},
                    ),
                    (
                        "assistant.delta",
                        {"session_id": "sess_hermes", "delta": " mundo"},
                    ),
                    (
                        "tool.started",
                        {
                            "session_id": "sess_hermes",
                            "tool": "itsm_inventory_search",
                            "preview": {"query": "nvr"},
                        },
                    ),
                    (
                        "tool.completed",
                        {
                            "session_id": "sess_hermes",
                            "tool": "itsm_inventory_search",
                            "preview": "2 activos",
                        },
                    ),
                    (
                        "run.completed",
                        {
                            "session_id": "sess_hermes",
                            "content": "Hola mundo",
                            "usage": {
                                "input_tokens": 7,
                                "output_tokens": 4,
                                "cost_usd": 0.0004,
                            },
                        },
                    ),
                )
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = HermesEngine(
                EngineConfig(BASE, profile="itsm-verification"),
                client=client,
            )
            info: EngineInfo = await engine.discover()
            session_id = await engine.create_session()
            assert session_id == "sess_hermes"
            with pytest.raises(EngineError) as failed:
                await engine.cancel(session_id)
            assert failed.value.code == "unsupported"
            events = [
                event
                async for event in engine.stream(
                    "Busca activos",
                    session_id=session_id,
                    model="anthropic/claude",
                )
            ]
        return events, requests, info, []

    events, requests, info, _ = asyncio.run(scenario())

    assert [model.id for model in info.models] == ["anthropic/claude"]
    assert info.models[0].provider == "anthropic"
    assert info.models[0].free is None
    assert info.capabilities == {
        "streaming": True,
        "sessions": True,
        "model_switch": True,
        "cancel": False,
        "tools": True,
        "usage": True,
        "history": True,
    }
    create_requests = [r for r in requests if r.url.path == "/api/sessions"]
    assert "profile" not in json.loads(create_requests[0].content)
    stream_request = next(
        r for r in requests if r.url.path == "/api/sessions/sess_hermes/chat/stream"
    )
    stream_body = json.loads(stream_request.content)
    assert stream_body["input"] == "Busca activos"
    assert stream_body["model"] == "anthropic/claude"
    assert "profile" not in stream_body
    fragments = [str(event["text"]) for event in events if event["type"] == "delta"]
    assert fragments == ["Hola", " mundo"]
    tools = [event for event in events if event["type"] == "tool"]
    assert tools[0] == {
        "type": "tool",
        "tool": "itsm_inventory_search",
        "status": "running",
        "input": {"query": "nvr"},
    }
    assert tools[-1] == {
        "type": "tool",
        "tool": "itsm_inventory_search",
        "status": "completed",
        "output": "2 activos",
    }
    assert [event for event in events if event["type"] == "usage"] == [
        {
            "type": "usage",
            "inputTokens": 7,
            "outputTokens": 4,
            "source": "reported",
            "cost": 0.0004,
        }
    ]
    assert [event for event in events if event["type"] == "error"] == []
    assert events[-1] == {"type": "done", "cancelled": False}


def test_hermes_runs_ignore_interim_events_and_emit_final_answer_usage() -> None:
    async def scenario() -> tuple[list[dict[str, Any]], dict[str, Any]]:
        run_body: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/v1/capabilities":
                return httpx.Response(
                    200,
                    json={
                        "version": "1.1.0",
                        "features": {
                            "run_submission": True,
                            "run_events_sse": True,
                            "run_stop": True,
                        },
                    },
                )
            if path == "/v1/models":
                return httpx.Response(
                    200,
                    json={"data": [{"id": "hermes-4", "owned_by": "nous"}]},
                )
            if path == "/v1/runs" and request.method == "POST":
                run_body.update(json.loads(request.content))
                return httpx.Response(202, json={"run_id": "run_1"})
            if path == "/v1/runs/run_1/events":
                return _named_sse(
                    (
                        "message.delta",
                        {"session_id": "sess_runs", "delta": "partial"},
                    ),
                    (
                        "tool.started",
                        {"tool": "itsm_inventory_search", "input": {"query": "nvr"}},
                    ),
                    (
                        "tool.completed",
                        {"tool": "itsm_inventory_search", "output": "2 activos"},
                    ),
                    (
                        "run.completed",
                        {
                            "content": "Final completo",
                            "usage": {
                                "input_tokens": 2,
                                "output_tokens": 1,
                                "cost_usd": 0.0002,
                            },
                        },
                    ),
                )
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = HermesEngine(EngineConfig(BASE), client=client)
            await engine.discover()
            session_id = await engine.create_session()
            events = [
                event
                async for event in engine.stream(
                    "Busca activos",
                    session_id=session_id,
                    model="hermes-4",
                    history=[
                        {"role": "user", "content": "uno"},
                        {"role": "assistant", "content": "dos"},
                    ],
                )
            ]
        return events, run_body

    events, run_body = asyncio.run(scenario())

    assert run_body["input"] == "Busca activos"
    assert run_body["model"] == "hermes-4"
    assert run_body["conversation_history"] == [
        {"role": "user", "content": "uno"},
        {"role": "assistant", "content": "dos"},
    ]
    assert "tool_calls" not in json.dumps(run_body["conversation_history"])
    fragments = [str(event["text"]) for event in events if event["type"] == "delta"]
    assert fragments == ["Final completo"]
    assert "partial" not in "".join(fragments)
    assert [event for event in events if event["type"] == "usage"] == [
        {
            "type": "usage",
            "inputTokens": 2,
            "outputTokens": 1,
            "source": "reported",
            "cost": 0.0002,
        }
    ]
    assert events[-1] == {"type": "done", "cancelled": False}


def test_hermes_runs_stop_reports_cancelled_without_resubmitting() -> None:
    async def scenario() -> tuple[list[dict[str, Any]], int, int]:
        run_calls = 0
        stop_calls = 0
        events_open = asyncio.Event()
        stopped = asyncio.Event()

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal run_calls, stop_calls
            path = request.url.path
            if path == "/v1/capabilities":
                return httpx.Response(
                    200,
                    json={
                        "version": "1.1.0",
                        "features": {
                            "run_submission": True,
                            "run_events_sse": True,
                            "run_stop": True,
                        },
                    },
                )
            if path == "/v1/models":
                return httpx.Response(200, json={"data": [{"id": "hermes-4"}]})
            if path == "/v1/runs" and request.method == "POST":
                run_calls += 1
                return httpx.Response(202, json={"run_id": "run_1"})
            if path == "/v1/runs/run_1/events":
                async def frames() -> AsyncIterator[bytes]:
                    yield _frame(
                        "message.delta",
                        {"session_id": "sess_runs", "delta": "parcial"},
                    )
                    events_open.set()
                    await stopped.wait()
                    yield _frame("run.cancelled", {"status": "cancelled"})

                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=_GeneratedSSE(frames()),
                )
            if path == "/v1/runs/run_1/stop":
                stop_calls += 1
                stopped.set()
                return httpx.Response(200, json={"status": "stopping"})
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = HermesEngine(EngineConfig(BASE), client=client)
            await engine.discover()
            session_id = await engine.create_session()
            stream = engine.stream("Busca activos", session_id=session_id)
            assert await stream.__anext__() == {"type": "session", "sessionId": session_id}

            async def collect() -> list[dict[str, Any]]:
                return [event async for event in stream]

            consumer = asyncio.create_task(collect())
            await asyncio.wait_for(events_open.wait(), 1)
            await engine.cancel(session_id)
            events = await asyncio.wait_for(consumer, 1)

            idle_session = await engine.create_session()
            with pytest.raises(EngineError) as failed:
                await engine.cancel(idle_session)
            assert failed.value.code == "not_found"
        return events, run_calls, stop_calls

    events, run_calls, stop_calls = asyncio.run(scenario())

    assert run_calls == 1
    assert stop_calls == 1
    assert [event for event in events if event["type"] == "delta"] == []
    assert events[-1] == {"type": "done", "cancelled": True}


def test_hermes_legacy_chat_is_stateless_fragmented_and_truthful_about_capabilities() -> None:
    async def scenario() -> tuple[list[dict[str, Any]], Any, str]:
        from itsm.agents.engines import EngineInfo

        requests: list[httpx.Request] = []
        chat_bodies: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            path = request.url.path
            if path == "/v1/capabilities":
                return httpx.Response(404, json={"error": "not found"})
            if path == "/health":
                return httpx.Response(
                    200,
                    json={"status": "ok", "version": "0.9.0"},
                )
            if path == "/v1/models":
                return httpx.Response(
                    200,
                    json={"data": [{"id": "hermes-3", "owned_by": "nous"}]},
                )
            if path == "/v1/chat/completions":
                chat_bodies.append(json.loads(request.content))
                return _sse(
                    {"choices": [{"delta": {"content": "ha"}}]},
                    {"choices": [{"delta": {"content": "ha"}}]},
                    {
                        "choices": [],
                        "usage": {
                            "prompt_tokens": 2,
                            "completion_tokens": 2,
                            "cost_usd": 0.0001,
                        },
                    },
                    "[DONE]",
                )
            raise AssertionError(f"unexpected request {request.method} {path}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = HermesEngine(EngineConfig(BASE), client=client)
            info: EngineInfo = await engine.discover()
            session_id = await engine.create_session()
            events = [
                event
                async for event in engine.stream(
                    "Di ha",
                    session_id=session_id,
                    model="hermes-3",
                    history=[{"role": "user", "content": "antes"}],
                )
            ]
            with pytest.raises(EngineError) as failed:
                await engine.cancel(session_id)
            assert failed.value.code == "unsupported"
        return events, info, session_id

    events, info, session_id = asyncio.run(scenario())

    assert info.version == "0.9.0"
    assert info.models[0].id == "hermes-3"
    assert info.models[0].provider == "nous"
    assert info.capabilities == {
        "streaming": True,
        "sessions": False,
        "model_switch": True,
        "cancel": False,
        "tools": False,
        "usage": True,
        "history": True,
    }
    assert session_id.startswith("itsm-")
    fragments = [str(event["text"]) for event in events if event["type"] == "delta"]
    assert fragments == ["ha", "ha"]
    assert "".join(fragments) == "haha"
    assert events[-1] == {"type": "done", "cancelled": False}


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
            engine = OpenCodeEngine(
                EngineConfig(BASE, token="super-secret-token"), client=client
            )
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
