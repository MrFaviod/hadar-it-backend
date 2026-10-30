"""Role ceiling and per-user container isolation for the conversational agent.

The API tests use a real WebSocket broker process-thread that speaks the bounded
worker protocol, so canonical tools execute through the real service with the
requesting principal. The broker test launches the real broker over a real
socket and a fake Docker CLI that execs a real protocol-speaking worker.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from itsm.agents.runtime_broker import Broker, BrokerConfig
from itsm.config import Settings
from itsm.main import create_app
from tests.inventory_support import MACHINE_PASSWORD, READER, prepare, sign_in_as
from websockets.asyncio.server import serve as async_serve
from websockets.exceptions import InvalidStatus
from websockets.sync.client import connect as sync_connect
from websockets.sync.server import serve as sync_serve

API = "/api/v1"
TOKEN = "b" * 48


@pytest.fixture(autouse=True)
def _provider_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The in-process default provider reads its key from the environment."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass
class FakeBroker:
    server: Any
    thread: threading.Thread
    port: int
    starts: list[dict[str, Any]] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.port}/runs"

    def close(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=10)


def fake_broker(script: Callable[[Any, dict[str, Any], FakeBroker], None]) -> FakeBroker:
    state: dict[str, Any] = {}

    def authorized(connection: Any, request: Any) -> Any:
        if request.path != "/runs" or request.headers.get("Authorization") != f"Bearer {TOKEN}":
            return connection.respond(401, "unauthorized\n")
        return None

    def handler(connection: Any) -> None:
        broker: FakeBroker = state["broker"]
        try:
            start = json.loads(connection.recv(timeout=10))
            broker.starts.append(start)
            script(connection, start, broker)
        except Exception as exc:  # test double records failure
            broker.errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            with contextlib.suppress(Exception):
                connection.close()

    server = sync_serve(handler, "127.0.0.1", 0, process_request=authorized, compression=None)
    broker = FakeBroker(
        server=server,
        thread=threading.Thread(target=server.serve_forever, daemon=True),
        port=int(server.socket.getsockname()[1]),
    )
    state["broker"] = broker
    broker.thread.start()
    return broker


def call_tool(
    connection: Any,
    broker: FakeBroker,
    name: str,
    arguments: dict[str, Any],
    *,
    call_id: str = "call-1",
) -> dict[str, Any]:
    connection.send(
        json.dumps(
            {
                "type": "tool.call",
                "callId": call_id,
                "name": name,
                "arguments": arguments,
            }
        )
    )
    result = json.loads(connection.recv(timeout=10))
    broker.results.append(result)
    return result


def finish(connection: Any, message: str) -> None:
    connection.send(json.dumps({"type": "usage", "inputTokens": 4, "outputTokens": 2}))
    connection.send(json.dumps({"type": "final", "message": message}))


def script_denied_asset(connection: Any, start: dict[str, Any], broker: FakeBroker) -> None:
    result = call_tool(connection, broker, "create_asset", {"name": "No autorizado"})
    finish(connection, json.dumps(result, ensure_ascii=False))


def script_search(connection: Any, start: dict[str, Any], broker: FakeBroker) -> None:
    result = call_tool(connection, broker, "search_assets", {"query": "switch"})
    finish(connection, f"user={start['userId']} ok={result['ok']}")


def script_tamper(connection: Any, start: dict[str, Any], broker: FakeBroker) -> None:
    unknown = call_tool(connection, broker, "run_shell", {"command": "id"})
    extra = call_tool(
        connection,
        broker,
        "create_asset",
        {"name": "Intruso", "principal": {"role_id": "superadmin"}},
        call_id="call-2",
    )
    finish(connection, json.dumps([unknown, extra], ensure_ascii=False))


def app_with_broker(
    settings_factory: Callable[..., Settings], broker: FakeBroker
) -> tuple[Any, TestClient, Settings]:
    catalog = prepare(
        settings_factory,
        agent_model="openai:gpt-4o-mini",
        ai_broker_url=broker.url,
        ai_broker_token=TOKEN,
    )
    client = TestClient(create_app(catalog.settings))
    client.__enter__()
    return catalog, client, catalog.settings


def chat(client: TestClient, headers: dict[str, str], message: str) -> Any:
    return client.post(f"{API}/agent/chat", json={"message": message}, headers=headers)


def test_reader_tool_call_is_denied_by_the_real_service(
    settings_factory: Callable[..., Settings],
    caplog: pytest.LogCaptureFixture,
) -> None:
    broker = fake_broker(script_denied_asset)
    catalog, client, settings = app_with_broker(settings_factory, broker)
    try:
        reader = catalog.add_user(*READER)
        headers = sign_in_as(client, settings, READER[0], MACHINE_PASSWORD)
        response = chat(client, headers, "Registrá un switch")
        assert response.status_code == 200, response.text
        assert response.json()["actions"][0]["status"] == "denied"
        assert catalog.asset_count() == 0
        assert any(item["outcome"] == "denied" for item in catalog.audit())
        assert broker.starts[0]["userId"] == reader.actor_id
        assert broker.results[0]["ok"] is False
        assert broker.errors == []
        assert "agent provider client could not be closed" not in caplog.text
    finally:
        broker.close()
        client.__exit__(None, None, None)
        catalog.engine.dispose()


def test_two_users_use_distinct_broker_identities_and_never_share_a_run(
    settings_factory: Callable[..., Settings],
) -> None:
    broker = fake_broker(script_search)
    catalog, client, settings = app_with_broker(settings_factory, broker)
    try:
        first = catalog.add_user("reader-one", "Reader One", "user")
        second = catalog.add_user("reader-two", "Reader Two", "user")
        one = sign_in_as(client, settings, "reader-one", MACHINE_PASSWORD)
        assert chat(client, one, "buscá switch").status_code == 200
        two = sign_in_as(client, settings, "reader-two", MACHINE_PASSWORD)
        assert chat(client, two, "buscá switch").status_code == 200
        assert [start["userId"] for start in broker.starts] == [
            first.actor_id,
            second.actor_id,
        ]
        assert len({start["runId"] for start in broker.starts}) == 2
        assert broker.errors == []
    finally:
        broker.close()
        client.__exit__(None, None, None)
        catalog.engine.dispose()


def test_session_turn_uses_the_isolated_runtime(
    settings_factory: Callable[..., Settings],
) -> None:
    broker = fake_broker(script_search)
    catalog, client, settings = app_with_broker(settings_factory, broker)
    try:
        reader = catalog.add_user(*READER)
        headers = sign_in_as(client, settings, READER[0], MACHINE_PASSWORD)
        created = client.post(
            f"{API}/agent/sessions",
            json={"instanceId": "pydantic", "model": "openai:gpt-4o-mini"},
            headers=headers,
        )
        assert created.status_code == 201, created.text
        with client.stream(
            "POST",
            f"{API}/agent/sessions/{created.json()['id']}/messages",
            json={"message": "¿hay switches?"},
            headers=headers,
        ) as response:
            assert response.status_code == 200, response.text
            events = [
                json.loads(line.removeprefix("data: "))
                for line in response.iter_lines()
                if line.startswith("data: ")
            ]
        assert broker.starts[0]["userId"] == reader.actor_id
        assert broker.results[0]["ok"] is True
        assert events[-1]["type"] == "done"
        assert events[-1]["actions"][0]["tool"] == "search_assets"
        stored = client.get(f"{API}/agent/sessions/{created.json()['id']}", headers=headers)
        assert [item["role"] for item in stored.json()["messages"]] == [
            "user",
            "assistant",
        ]
        assert broker.errors == []
    finally:
        broker.close()
        client.__exit__(None, None, None)
        catalog.engine.dispose()


def test_worker_tampering_cannot_execute_or_widen_arguments(
    settings_factory: Callable[..., Settings],
) -> None:
    broker = fake_broker(script_tamper)
    catalog, client, settings = app_with_broker(settings_factory, broker)
    try:
        catalog.add_user(*READER)
        headers = sign_in_as(client, settings, READER[0], MACHINE_PASSWORD)
        response = chat(client, headers, "hacé algo")
        assert response.status_code == 200, response.text
        assert [item["ok"] for item in broker.results] == [False, False]
        assert catalog.asset_count() == 0
        assert broker.errors == []
    finally:
        broker.close()
        client.__exit__(None, None, None)
        catalog.engine.dispose()


def test_worker_argument_types_are_validated_before_the_canonical_handler() -> None:
    from itsm.agents.isolation import IsolatedRuntime, WorkerToolCall, _PreparedTools
    from pydantic_ai import RunContext
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.toolsets.function import FunctionToolset
    from pydantic_ai.usage import RunUsage

    calls: list[tuple[Any, ...]] = []

    toolset: FunctionToolset[Any] = FunctionToolset()

    @toolset.tool_plain
    def mutate(name: str, limit: int = 1) -> dict[str, Any]:
        calls.append((name, limit))
        return {"ok": True}

    context: RunContext[Any] = RunContext(
        deps=None,
        model=FunctionModel(lambda messages, info: None, model_name="validation-test"),
        usage=RunUsage(),
    )
    tools = asyncio.run(toolset.get_tools(context))
    prepared = _PreparedTools(toolset=toolset, context=context, tools=tools, schemas=[])
    runtime = IsolatedRuntime(None, lambda: None)  # type: ignore[arg-type]

    accepted = runtime._tool_result(
        WorkerToolCall(call_id="call-1", name="mutate", arguments={"name": "ok"}),
        prepared,
    )
    assert accepted.ok is True
    assert calls == [("ok", 1)]

    denied = runtime._tool_result(
        WorkerToolCall(
            call_id="call-2",
            name="mutate",
            arguments={"name": {"not": "text"}},
        ),
        prepared,
    )
    assert denied.ok is False
    assert denied.result == {}
    assert calls == [("ok", 1)]


def test_worker_adapter_forwards_real_create_asset_name(
    settings_factory: Callable[..., Settings],
) -> None:
    from itsm.agents.isolated_worker import _tools
    from itsm.agents.isolation import IsolatedRuntime
    from itsm.agents.runtime import AgentDeps

    settings = settings_factory()
    runtime = IsolatedRuntime(settings, lambda: None)
    deps = AgentDeps(
        settings=settings,
        session_factory=lambda: None,  # type: ignore[arg-type]
        principal=SimpleNamespace(),  # type: ignore[arg-type]
    )
    prepared = runtime._prepare_tools(deps)
    schema = next(item for item in prepared.schemas if item.name == "create_asset")

    calls: list[tuple[str, dict[str, Any]]] = []

    class Bridge:
        def tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            calls.append((name, arguments))
            return {"ok": True}

    tools = _tools([schema], Bridge())  # type: ignore[arg-type]
    assert tools[0].function(name="Router-01") == {"ok": True}
    assert calls == [("create_asset", {"name": "Router-01"})]


def test_broker_stops_owned_worker_when_initial_start_write_fails() -> None:
    from itsm.agents.isolation import RunStart

    start = RunStart(
        run_id="11111111-1111-4111-8111-111111111111",
        user_id="22222222-2222-4222-8222-222222222222",
        provider={"kind": "openai", "model": "m"},
        instructions="i",
        prompt="p",
    )

    class Input:
        def write(self, payload: bytes) -> None:
            pass

        async def drain(self) -> None:
            raise BrokenPipeError("worker exited before first frame")

    class Connection:
        async def recv(self) -> str:
            return start.model_dump_json(by_alias=True)

        async def close(self, **kwargs: Any) -> None:
            pass

    async def probe() -> None:
        broker = Broker(BrokerConfig(token=TOKEN, image="worker:test", command=("worker",)))
        process = SimpleNamespace(stdin=Input(), stdout=object(), stderr=None, returncode=None)
        stopped = AsyncMock()
        with (
            patch(
                "itsm.agents.runtime_broker.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=process),
            ),
            patch.object(broker, "_stop", new=stopped),
        ):
            await broker.handle(Connection())
        assert stopped.await_count == 1
        assert not broker._active

    asyncio.run(probe())


def test_unconfigured_isolation_fails_closed_without_in_process_fallback(
    settings_factory: Callable[..., Settings],
) -> None:
    catalog = prepare(settings_factory, agent_model="openai:gpt-4o-mini")
    client = TestClient(create_app(catalog.settings))
    client.__enter__()
    try:
        catalog.add_user(*READER)
        headers = sign_in_as(client, catalog.settings, READER[0], MACHINE_PASSWORD)
        response = chat(client, headers, "hola")
        assert response.status_code == 503
        assert "isolation" in response.text
        assert catalog.asset_count() == 0
    finally:
        client.__exit__(None, None, None)
        catalog.engine.dispose()


def test_unreachable_broker_fails_closed(
    settings_factory: Callable[..., Settings],
) -> None:
    port = free_port()
    catalog = prepare(
        settings_factory,
        agent_model="openai:gpt-4o-mini",
        ai_broker_url=f"ws://127.0.0.1:{port}/runs",
        ai_broker_token=TOKEN,
    )
    client = TestClient(create_app(catalog.settings))
    client.__enter__()
    try:
        catalog.add_user(*READER)
        headers = sign_in_as(client, catalog.settings, READER[0], MACHINE_PASSWORD)
        response = chat(client, headers, "hola")
        assert response.status_code == 503
        assert "isolation" in response.text
    finally:
        client.__exit__(None, None, None)
        catalog.engine.dispose()


# ---------------------------------------------------------------- real broker
def _write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o755)


def _fake_docker(path: Path, worker: Path, log: Path) -> None:
    script = f"""#!{sys.executable}
import json, os, sys
args = sys.argv[1:]
with open({str(log)!r}, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(args) + "\\n")
if args and args[0] == "rm":
    raise SystemExit(0)
if args and args[0] == "run":
    image = {str(worker)!r}
    index = args.index("worker:test")
    os.execv({sys.executable!r}, [{sys.executable!r}, {str(worker)!r}])
raise SystemExit(2)
"""
    _write_executable(path, script)


def _worker_script(path: Path) -> None:
    script = """#!/usr/bin/env python3
import json, sys

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\\n")
    sys.stdout.flush()

emit({"type": "ready"})
start = json.loads(sys.stdin.readline())
assert start["type"] == "run.start"
emit({"type": "tool.call", "callId": "call-1",
      "name": "search_assets", "arguments": {"query": "switch"}})
result = json.loads(sys.stdin.readline())
emit({"type": "usage", "inputTokens": 3, "outputTokens": 1})
emit({"type": "final", "message": "ok=" + str(result["ok"])})
"""
    _write_executable(path, script)


def run_broker(config: BrokerConfig) -> tuple[threading.Thread, Callable[[], None]]:
    loop_ready = threading.Event()
    holder: dict[str, Any] = {}

    async def main() -> None:
        broker = Broker(config)
        stop = asyncio.Event()
        holder["stop"] = stop
        async with async_serve(
            broker.handle,
            config.host,
            config.port,
            process_request=broker.authorized_request,
            max_size=512 * 1024,
            compression=None,
        ):
            holder["loop"] = asyncio.get_running_loop()
            loop_ready.set()
            await stop.wait()

    thread = threading.Thread(target=lambda: asyncio.run(main()), daemon=True)
    thread.start()
    assert loop_ready.wait(10), "broker did not start"

    def shutdown() -> None:
        loop = holder.get("loop")
        stop = holder.get("stop")
        if loop is not None and stop is not None:
            loop.call_soon_threadsafe(stop.set)
        thread.join(timeout=10)

    return thread, shutdown


def test_broker_rejects_unauthorized_and_wrong_path_before_upgrade(
    tmp_path: Path,
) -> None:
    worker = tmp_path / "worker.py"
    docker = tmp_path / "docker"
    log = tmp_path / "docker.log"
    _worker_script(worker)
    _fake_docker(docker, worker, log)
    port = free_port()
    config = BrokerConfig(
        token=TOKEN,
        image="worker:test",
        command=(sys.executable, str(worker)),
        network="testnet",
        docker=str(docker),
        port=port,
    )
    _thread, shutdown = run_broker(config)
    try:
        with pytest.raises(InvalidStatus) as missing:
            sync_connect(f"ws://127.0.0.1:{port}/runs")
        assert TOKEN not in str(missing.value)
        with pytest.raises(InvalidStatus):
            sync_connect(
                f"ws://127.0.0.1:{port}/runs",
                additional_headers={"Authorization": "Bearer wrong"},
            )
        with pytest.raises(InvalidStatus):
            sync_connect(
                f"ws://127.0.0.1:{port}/wrong",
                additional_headers={"Authorization": f"Bearer {TOKEN}"},
            )
    finally:
        shutdown()


def test_broker_launches_one_hardened_worker_and_relays_tools(tmp_path: Path) -> None:
    worker = tmp_path / "worker.py"
    docker = tmp_path / "docker"
    log = tmp_path / "docker.log"
    _worker_script(worker)
    _fake_docker(docker, worker, log)
    port = free_port()
    config = BrokerConfig(
        token=TOKEN,
        image="worker:test",
        command=(sys.executable, str(worker)),
        network="testnet",
        docker=str(docker),
        port=port,
    )
    _thread, shutdown = run_broker(config)
    user_id = "22222222-2222-4222-8222-222222222222"
    start = {
        "type": "run.start",
        "runId": "11111111-1111-4111-8111-111111111111",
        "userId": user_id,
        "provider": {"kind": "openai", "model": "m"},
        "instructions": "i",
        "prompt": "p",
        "tools": [
            {
                "name": "search_assets",
                "description": "d",
                "parameters": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                },
            }
        ],
    }
    try:
        with sync_connect(
            f"ws://127.0.0.1:{port}/runs",
            additional_headers={"Authorization": f"Bearer {TOKEN}"},
        ) as socket_connection:
            socket_connection.send(json.dumps(start))
            ready = json.loads(socket_connection.recv(timeout=10))
            assert ready["type"] == "ready"
            call = json.loads(socket_connection.recv(timeout=10))
            assert call["type"] == "tool.call"
            assert call["name"] == "search_assets"
            socket_connection.send(
                json.dumps(
                    {
                        "type": "tool.result",
                        "callId": call["callId"],
                        "ok": True,
                        "result": {"ok": True},
                    }
                )
            )
            while True:
                event = json.loads(socket_connection.recv(timeout=10))
                if event["type"] == "final":
                    assert event["message"] == "ok=True"
                    break
    finally:
        shutdown()
    lines = [json.loads(line) for line in log.read_text().splitlines()]
    run = next(item for item in lines if item and item[0] == "run")
    assert "--read-only" in run
    assert "--user" in run and "65534:65534" in run
    assert "--cap-drop" in run and "ALL" in run
    assert "--network" in run and "testnet" in run
    assert "-v" not in run and "--volume" not in run
    assert "-e" not in run and "--env" not in run
    assert not any(part.startswith("itsm.ai.image") for part in run)
    assert f"itsm.ai.user={__import__('hashlib').sha256(user_id.encode()).hexdigest()[:32]}" in run
    assert any(item and item[0] == "rm" and "--force" in item for item in lines)


def test_isolated_calls_settle_then_deny_next_call_without_dispatch(
    settings_factory: Callable[..., Settings],
) -> None:
    from itsm.agents.usage import measured_usage

    admitted: list[str] = []

    def script(connection: Any, start: dict[str, Any], broker: FakeBroker) -> None:
        for call_id in ("q1", "q2"):
            connection.send(
                json.dumps(
                    {"type": "quota.call", "callId": call_id, "phase": "reserve", "evidence": None}
                )
            )
            reply = json.loads(connection.recv(timeout=10))
            if not reply["ok"]:
                return
            admitted.append(call_id)
            connection.send(
                json.dumps(
                    {
                        "type": "quota.call",
                        "callId": call_id,
                        "phase": "settle",
                        "evidence": measured_usage(
                            input_tokens=4,
                            output_tokens=2,
                            total_tokens=6,
                            total_source="provider",
                            source="provider",
                        ).event(),
                    }
                )
            )
            assert json.loads(connection.recv(timeout=10))["ok"] is True
        finish(connection, "unexpected second dispatch")

    broker = fake_broker(script)
    catalog, client, settings = app_with_broker(settings_factory, broker)
    try:
        reader = catalog.add_user(*READER)
        usage = client.app.state.agent_usage
        usage.update_policy(catalog.admin(), company_daily_limit=settings.agent_max_output_tokens)
        headers = sign_in_as(client, settings, READER[0], MACHINE_PASSWORD)
        response = chat(client, headers, "buscá switches")
        assert response.status_code == 429, response.text
        assert response.json()["error"]["code"] == "quota_exceeded"
        assert admitted == ["q1"]
        balance = usage.me(reader.actor_id)["funding"]["company"]
        assert balance["consumedTokens"] == 6
        assert balance["reservedTokens"] == 0
        assert balance["availableTokens"] == settings.agent_max_output_tokens - 6
        assert broker.errors == []
    finally:
        broker.close()
        client.__exit__(None, None, None)
        catalog.engine.dispose()


def test_worker_accepts_only_the_allowlisted_private_provider() -> None:
    from itsm.agents.isolated_worker import WorkerProtocolError, _model

    start = _worker_start("http://127.0.0.1:18081/v1", private_allowlist=["127.0.0.0/8"])
    model, client = _model(start)
    try:
        assert model is not None
        assert client is not None
        assert client.follow_redirects is False
        assert client.trust_env is False
    finally:
        asyncio.run(client.aclose())

    with pytest.raises(WorkerProtocolError):
        _model(_worker_start("http://127.0.0.1:18081/v1"))


def test_worker_refuses_metadata_even_for_an_allowlisted_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itsm.agents import isolated_worker

    monkeypatch.setattr(isolated_worker, "ensure_endpoint_allowed", _raises_blocked_address)
    with pytest.raises(isolated_worker.WorkerProtocolError):
        isolated_worker._model(
            _worker_start(
                "http://metadata.internal:80/v1",
                private_allowlist=["metadata.internal:80"],
            )
        )


def _worker_start(base_url: str, *, private_allowlist: list[str] | None = None) -> Any:
    from itsm.agents.isolation import RunStart

    return RunStart(
        run_id="11111111-1111-4111-8111-111111111111",
        user_id="22222222-2222-4222-8222-222222222222",
        provider={
            "kind": "openai-compatible",
            "model": "model-a",
            "baseUrl": base_url,
            "apiKey": "sk-worker-secret",
            "privateAllowlist": private_allowlist or [],
        },
        instructions="instructions",
        prompt="hola",
    )


def _raises_blocked_address(*args: Any, **kwargs: Any) -> None:
    from itsm.agent_integrations.providers import ProviderEndpointError

    raise ProviderEndpointError("provider endpoint resolves to a non-public address")
