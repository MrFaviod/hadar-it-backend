"""Trusted-side protocol limits with a deterministic clock and fake socket."""

import json
from types import SimpleNamespace

import pytest
from itsm.agents import isolation


class Socket:
    def __init__(self, messages, clock, increment=0):
        self.messages = iter(messages)
        self.clock = clock
        self.increment = increment
        self.closed = False
        self.timeouts = []
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def send(self, message):
        self.sent.append(json.loads(message))

    def recv(self, timeout):
        self.timeouts.append(timeout)
        self.clock[0] += self.increment
        return json.dumps(next(self.messages))


def exchange(settings_factory, monkeypatch, messages, increment=0, tool_cost=0):
    clock = [0.0]
    monkeypatch.setattr(isolation, "monotonic", lambda: clock[0], raising=False)
    socket = Socket(messages, clock, increment)
    settings = settings_factory(
        ai_broker_url="ws://127.0.0.1:9/runs",
        ai_broker_token="x" * 48,
        agent_run_timeout_seconds=10,
        agent_max_steps=1,
    )
    runtime = isolation.IsolatedRuntime(settings, lambda: None, connect=lambda *a, **kw: socket)
    calls = []

    def tool(call, prepared):
        calls.append(call.call_id)
        clock[0] += tool_cost
        return isolation.ToolResult(call_id=call.call_id, ok=True)

    monkeypatch.setattr(runtime, "_tool_result", tool)
    start = SimpleNamespace(max_steps=1, model_dump_json=lambda **kw: "{}")
    return runtime, socket, calls, start


@pytest.mark.parametrize("kind", ["ready", "usage"])
def test_repeated_messages_do_not_refresh_absolute_deadline(settings_factory, monkeypatch, kind):
    runtime, socket, calls, start = exchange(
        settings_factory,
        monkeypatch,
        [{"type": kind}] * 6 + [{"type": "final", "message": "late"}],
        increment=4,
    )
    with pytest.raises(isolation.IsolationUnavailable):
        runtime._exchange(start, None, None)
    assert socket.closed
    assert len(socket.timeouts) <= 3
    assert calls == []


def test_trusted_side_limits_excessive_tool_calls(settings_factory, monkeypatch):
    messages = [
        {"type": "tool.call", "name": "search_assets", "callId": f"c{i}"} for i in range(5)
    ] + [{"type": "final", "message": "late"}]
    runtime, socket, calls, start = exchange(settings_factory, monkeypatch, messages)
    with pytest.raises(isolation.IsolationUnavailable):
        runtime._exchange(start, None, None)
    assert calls == ["c0", "c1", "c2", "c3"]
    assert socket.closed


def test_legitimate_turn_finishes_and_closes(settings_factory, monkeypatch):
    runtime, socket, calls, start = exchange(
        settings_factory,
        monkeypatch,
        [
            {"type": "tool.call", "name": "search_assets", "callId": "ok"},
            {"type": "usage", "inputTokens": 2, "outputTokens": 1},
            {"type": "final", "message": "ok"},
        ],
        increment=1,
    )
    assert runtime._exchange(start, None, None) == (2, 1, "ok")
    assert socket.closed and calls == ["ok"]


def test_overdue_blocking_tool_is_not_claimed_interrupted(settings_factory, monkeypatch):
    runtime, socket, calls, start = exchange(
        settings_factory,
        monkeypatch,
        [
            {"type": "tool.call", "name": "search_assets", "callId": "slow"},
            {"type": "final", "message": "late"},
        ],
        tool_cost=11,
    )
    with pytest.raises(isolation.IsolationUnavailable):
        runtime._exchange(start, None, None)
    assert calls == ["slow"]  # completed; no unsafe background mutation/thread kill
    assert len(socket.timeouts) == 1  # no continuation after return
    assert socket.closed


def test_trusted_quota_reserves_known_prompt_and_tool_results(settings_factory, monkeypatch):
    runtime, socket, _calls, start = exchange(
        settings_factory,
        monkeypatch,
        [
            {"type": "quota.call", "callId": "q1", "phase": "reserve"},
            {"type": "tool.call", "name": "search_assets", "callId": "c1"},
            {"type": "quota.call", "callId": "q2", "phase": "reserve"},
            {"type": "final", "message": "ok"},
        ],
    )
    start.max_steps = 2
    start.model_dump = lambda **kw: {"prompt": "é" * 2000, "tools": []}
    bounds = []
    quota = SimpleNamespace(before_call=lambda bound: bounds.append(bound) or str(len(bounds)))
    runtime._exchange(start, None, None, quota=quota)
    assert bounds[0] >= 4000 + runtime._settings.agent_max_output_tokens
    assert bounds[1] > bounds[0]
    assert socket.closed


@pytest.mark.parametrize("kind", ["image", "file"])
def test_m3_trusted_isolation_uses_binary_estimate_not_base64(settings_factory, monkeypatch, kind):
    import base64

    runtime, socket, _calls, start = exchange(
        settings_factory,
        monkeypatch,
        [
            {"type": "quota.call", "callId": "q1", "phase": "reserve"},
            {"type": "final", "message": "ok"},
        ],
    )
    payload = {
        "prompt": "é" * 10000,
        "history": [{"content": "history" * 1000}],
        "tools": [{"parameters": {"description": "schema" * 1000}}],
        "attachments": [
            {
                "kind": kind,
                "mediaType": "image/png" if kind == "image" else "application/pdf",
                "filename": "test",
                "data": base64.b64encode(
                    (b"\x89PNG\r\n\x1a\n" if kind == "image" else b"%PDF-1.7\n")
                    + b"\x00" * (1024 * 1024)
                    + (b"" if kind == "image" else b"\n%%EOF")
                ).decode(),
            }
        ],
    }
    start.model_dump = lambda **kw: payload
    bounds = []
    quota = SimpleNamespace(before_call=lambda bound: bounds.append(bound) or "q1")
    runtime._exchange(start, None, None, quota=quota)
    assert 33000 + runtime._settings.agent_max_output_tokens < bounds[0] < 128000
    assert len(payload["attachments"][0]["data"]) > 1000000
    assert socket.closed


@pytest.mark.parametrize("suffix", [b"", b"\x00", b"\xff"])
def test_m3_isolated_binary_text_retains_floor(settings_factory, monkeypatch, suffix):
    import base64

    runtime, socket, _calls, start = exchange(
        settings_factory,
        monkeypatch,
        [
            {"type": "quota.call", "callId": "q1", "phase": "reserve"},
            {"type": "final", "message": "ok"},
        ],
    )
    payload = {
        "attachments": [{"kind": "file", "data": base64.b64encode(b"A" * 100000 + suffix).decode()}]
    }
    start.model_dump = lambda **kw: payload
    bounds = []
    quota = SimpleNamespace(before_call=lambda bound: bounds.append(bound) or "q1")
    runtime._exchange(start, None, None, quota=quota)
    assert bounds[0] >= 100000 + runtime._settings.agent_max_output_tokens
    assert len(payload["attachments"][0]["data"]) > 100000
    assert socket.closed
