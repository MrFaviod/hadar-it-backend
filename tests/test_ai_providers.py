"""Behavior of global/personal OpenAI-compatible providers and session continuity."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import httpx
import itsm.agent_integrations.providers as providers_module
import itsm.agents.runtime as runtime_module
import pydantic_ai.models
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from itsm.agent_integrations.models import AgentProvider, AgentRun, AgentSession
from itsm.agent_integrations.providers import (
    ProviderEndpointError,
    ProviderModelSelection,
    ProviderNetworkPolicy,
    personal_endpoint_policy,
    provider_http_client,
    validate_provider_endpoint,
)
from itsm.agent_integrations.service import AgentIntegrationService
from itsm.agents.runtime import AgentRuntime, AgentUsage, ChatReply, ChatRequest
from itsm.config import parse_personal_private_endpoints
from itsm.main import create_app
from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models.function import FunctionModel
from sqlalchemy import event, select
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import MACHINE_PASSWORD, prepare

API = "/api/v1"
MASTER_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
PROVIDER_PERMISSION = "agents.providers.personal"


def _login(client: TestClient, settings: Any, username: str, password: str) -> dict[str, str]:
    response = client.post(
        f"{API}/auth/login",
        json={"username": username, "password": password},
        headers={"Origin": settings.auth_origin},
    )
    assert response.status_code == 200, response.text
    return {
        "X-CSRF-Token": str(response.json()["csrfToken"]),
        "Origin": settings.auth_origin,
    }


def _admin_login(client: TestClient, settings: Any) -> dict[str, str]:
    return _login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)


def _role_with_permission(
    catalog: Any, permissions: tuple[str, ...] = ("assets.view", "people.view", PROVIDER_PERMISSION)
) -> str:
    with catalog.session() as session:
        role = catalog.service(session).create_role(
            catalog.admin(),
            name=f"provider-user-{uuid4().hex[:8]}",
            permissions=permissions,
        )
        return role.id


def _create_provider(
    client: TestClient,
    headers: dict[str, str],
    **overrides: Any,
) -> httpx.Response:
    payload: dict[str, Any] = {
        "scope": "global",
        "name": "NOC gateway",
        "baseUrl": "http://127.0.0.1:18081/v1",
        "models": ["model-a", "model-b"],
        "apiKey": "sk-global-secret",
    }
    payload.update(overrides)
    return client.post(f"{API}/agent/providers", json=payload, headers=headers)


@pytest.fixture
def provider_env(settings_factory: Any):
    catalog = prepare(
        settings_factory,
        agent_model="openai:gpt-4o-mini",
        ai_credential_key=MASTER_KEY,
        ai_broker_url="ws://127.0.0.1:9/runs",
        ai_broker_token="t" * 48,
    )
    client = TestClient(create_app(catalog.settings))
    client.__enter__()
    client.app.state.agent_integrations = AgentIntegrationService(
        catalog.settings, catalog.factory()
    )
    try:
        yield catalog, client
    finally:
        client.__exit__(None, None, None)
        catalog.engine.dispose()


def test_global_provider_is_owner_managed_and_secret_is_write_only(provider_env: Any) -> None:
    catalog, client = provider_env
    admin = _admin_login(client, catalog.settings)

    listed = client.get(f"{API}/agent/providers", headers=admin)
    assert listed.status_code == 200, listed.text
    assert listed.json() == {
        "items": [],
        "canManageGlobal": True,
        "canManagePersonal": True,
        "credentialStorageAvailable": True,
    }

    created = _create_provider(client, admin)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["scope"] == "global"
    assert body["name"] == "NOC gateway"
    assert body["baseUrl"] == "http://127.0.0.1:18081/v1"
    assert body["models"] == ["model-a", "model-b"]
    assert body["credentialConfigured"] is True
    assert body["credentialStatus"] == "primary"
    assert body["enabled"] is True
    assert "apiKey" not in body
    assert "apiKeyCiphertext" not in body
    assert "sk-global-secret" not in created.text

    with catalog.session() as session:
        row = session.get(AgentProvider, body["id"])
        assert row is not None
        assert row.api_key_ciphertext is not None
        assert row.api_key_ciphertext != "sk-global-secret"
        assert (
            Fernet(MASTER_KEY.encode()).decrypt(row.api_key_ciphertext.encode())
            == b"sk-global-secret"
        )

    with catalog.session() as session:
        catalog.service(session).create_user(
            catalog.admin(),
            username="plain.user",
            name="Plain User",
            password=MACHINE_PASSWORD,
            role_id="user",
        )
    plain = _login(client, catalog.settings, "plain.user", MACHINE_PASSWORD)
    visible = client.get(f"{API}/agent/providers", headers=plain)
    assert visible.status_code == 200, visible.text
    assert [item["id"] for item in visible.json()["items"]] == [body["id"]]
    assert visible.json()["canManageGlobal"] is False
    assert visible.json()["canManagePersonal"] is True
    owned = _create_provider(
        client,
        plain,
        scope="personal",
        baseUrl="https://api.example.com/v1",
        apiKey="sk-plain-secret",
    )
    assert owned.status_code == 201, owned.text
    assert owned.json()["scope"] == "personal"
    denied = _create_provider(client, plain, scope="global", baseUrl="https://api.example.com/v1")
    assert denied.status_code == 403, denied.text
    assert client.patch(
        f"{API}/agent/providers/{body['id']}", json={"name": "hijacked"}, headers=plain
    ).status_code == 403
    assert client.delete(f"{API}/agent/providers/{body['id']}", headers=plain).status_code == 403

    admin = _admin_login(client, catalog.settings)
    rotated = client.patch(
        f"{API}/agent/providers/{body['id']}",
        json={"apiKey": "sk-rotated", "models": ["model-c"]},
        headers=admin,
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["models"] == ["model-c"]
    assert "sk-rotated" not in rotated.text
    with catalog.session() as session:
        row = session.get(AgentProvider, body["id"])
        assert row is not None
        assert (
            Fernet(MASTER_KEY.encode()).decrypt(row.api_key_ciphertext.encode())
            == b"sk-rotated"
        )


def test_personal_providers_require_explicit_permission_and_stay_owner_isolated(
    provider_env: Any,
) -> None:
    catalog, client = provider_env
    role_id = _role_with_permission(catalog)
    catalog.add_user("alice.provider", "Alice Provider", role_id)
    catalog.add_user("bob.provider", "Bob Provider", role_id)
    admin = _admin_login(client, catalog.settings)
    global_created = _create_provider(client, admin)
    assert global_created.status_code == 201, global_created.text
    global_id = global_created.json()["id"]

    alice = _login(client, catalog.settings, "alice.provider", MACHINE_PASSWORD)
    created = _create_provider(
        client,
        alice,
        scope="personal",
        name="Alice endpoint",
        baseUrl="https://api.alice.example/v1",
        models=["alice-model"],
        apiKey="sk-alice",
    )
    assert created.status_code == 201, created.text
    personal_id = created.json()["id"]
    assert created.json()["scope"] == "personal"

    bob = _login(client, catalog.settings, "bob.provider", MACHINE_PASSWORD)
    bob_items = client.get(f"{API}/agent/providers", headers=bob).json()["items"]
    assert [item["id"] for item in bob_items] == [global_id]
    assert client.patch(
        f"{API}/agent/providers/{personal_id}", json={"name": "stolen"}, headers=bob
    ).status_code == 404
    assert client.delete(f"{API}/agent/providers/{personal_id}", headers=bob).status_code == 404

    alice = _login(client, catalog.settings, "alice.provider", MACHINE_PASSWORD)
    alice_items = client.get(f"{API}/agent/providers", headers=alice).json()["items"]
    assert {item["id"] for item in alice_items} == {global_id, personal_id}
    engines = client.get(f"{API}/agent/engines", headers=alice)
    assert engines.status_code == 200, engines.text
    provider_engine = next(
        item for item in engines.json()["instances"] if item["id"] == personal_id
    )
    assert provider_engine["engine"] == "pydantic"
    assert provider_engine["models"] == [
        {"id": "alice-model", "name": "alice-model", "provider": "openai-compatible", "free": None}
    ]
    bob = _login(client, catalog.settings, "bob.provider", MACHINE_PASSWORD)
    bob_engines = client.get(f"{API}/agent/engines", headers=bob).json()
    assert personal_id not in {item["id"] for item in bob_engines["instances"]}

    admin = _admin_login(client, catalog.settings)
    admin_items = client.get(f"{API}/agent/providers", headers=admin).json()["items"]
    assert [item["id"] for item in admin_items] == [global_id]
    with catalog.session() as session:
        alice_row = session.get(AgentProvider, personal_id)
        assert alice_row is not None
        assert (
            Fernet(MASTER_KEY.encode()).decrypt(alice_row.api_key_ciphertext.encode())
            == b"sk-alice"
        )


def test_builtin_admin_and_user_manage_only_their_own_personal_provider(
    provider_env: Any,
) -> None:
    catalog, client = provider_env
    catalog.add_user("builtin.user", "Builtin User", "user")
    admin = _admin_login(client, catalog.settings)
    admin_created = _create_provider(
        client,
        admin,
        scope="personal",
        name="Admin endpoint",
        baseUrl="https://api.admin.example/v1",
        apiKey="sk-admin",
    )
    assert admin_created.status_code == 201, admin_created.text
    admin_id = admin_created.json()["id"]

    user = _login(client, catalog.settings, "builtin.user", MACHINE_PASSWORD)
    listed = client.get(f"{API}/agent/providers", headers=user)
    assert listed.status_code == 200, listed.text
    assert listed.json()["canManagePersonal"] is True
    assert listed.json()["canManageGlobal"] is False
    user_created = _create_provider(
        client,
        user,
        scope="personal",
        name="User endpoint",
        baseUrl="https://api.user.example/v1",
        apiKey="sk-user",
    )
    assert user_created.status_code == 201, user_created.text
    user_id = user_created.json()["id"]
    assert client.get(f"{API}/agent/providers", headers=user).json()["items"] == [
        user_created.json()
    ]
    assert client.patch(
        f"{API}/agent/providers/{admin_id}", json={"name": "stolen"}, headers=user
    ).status_code == 404
    assert client.delete(f"{API}/agent/providers/{admin_id}", headers=user).status_code == 404

    admin = _admin_login(client, catalog.settings)
    assert client.get(f"{API}/agent/providers", headers=admin).json()["items"] == [
        admin_created.json()
    ]
    assert client.patch(
        f"{API}/agent/providers/{user_id}", json={"name": "stolen"}, headers=admin
    ).status_code == 404
    assert client.delete(f"{API}/agent/providers/{user_id}", headers=admin).status_code == 404
    assert _create_provider(client, user, scope="global").status_code == 403


@pytest.mark.parametrize(
    "base_url",
    [
        "http://api.example.com/v1",
        "https://127.0.0.1/v1",
        "https://[::1]/v1",
        "https://user:pass@api.example.com/v1",
        "https://api.example.com/v1?token=1",
        "https://api.example.com/v1#fragment",
        "ftp://api.example.com/v1",
    ],
)
def test_personal_endpoints_reject_unsafe_destinations(provider_env: Any, base_url: str) -> None:
    catalog, client = provider_env
    role_id = _role_with_permission(catalog)
    catalog.add_user("endpoint.user", "Endpoint User", role_id)
    headers = _login(client, catalog.settings, "endpoint.user", MACHINE_PASSWORD)
    response = _create_provider(
        client,
        headers,
        scope="personal",
        baseUrl=base_url,
        models=["model-a"],
        apiKey="sk-endpoint",
    )
    assert response.status_code == 422, response.text


def test_personal_endpoint_update_revalidates_boundary(provider_env: Any) -> None:
    catalog, client = provider_env
    role_id = _role_with_permission(catalog)
    catalog.add_user("update.user", "Update User", role_id)
    headers = _login(client, catalog.settings, "update.user", MACHINE_PASSWORD)
    created = _create_provider(
        client,
        headers,
        scope="personal",
        baseUrl="https://api.example.com/v1",
        models=["model-a"],
        apiKey="sk-update",
    )
    assert created.status_code == 201, created.text
    response = client.patch(
        f"{API}/agent/providers/{created.json()['id']}",
        json={"baseUrl": "https://localhost/v1"},
        headers=headers,
    )
    assert response.status_code == 422, response.text


def test_missing_master_key_reports_unavailable_credential_writes(settings_factory: Any) -> None:
    catalog = prepare(settings_factory, agent_model="openai:gpt-4o-mini")
    client = TestClient(create_app(catalog.settings))
    client.__enter__()
    client.app.state.agent_integrations = AgentIntegrationService(
        catalog.settings, catalog.factory()
    )
    try:
        headers = _admin_login(client, catalog.settings)
        listed = client.get(f"{API}/agent/providers", headers=headers)
        assert listed.status_code == 200, listed.text
        assert listed.json()["credentialStorageAvailable"] is False
        denied = _create_provider(client, headers)
        assert denied.status_code == 503, denied.text
        assert denied.json()["error"]["message"] == "credential storage is not configured"
        keyless = _create_provider(client, headers, apiKey=None)
        assert keyless.status_code == 201, keyless.text
        assert keyless.json()["credentialConfigured"] is False
        assert keyless.json()["credentialStatus"] == "missing"
    finally:
        client.__exit__(None, None, None)
        catalog.engine.dispose()


def test_session_switches_engine_and_model_without_losing_transcript(provider_env: Any) -> None:
    catalog, client = provider_env
    admin = _admin_login(client, catalog.settings)
    created = _create_provider(client, admin)
    assert created.status_code == 201, created.text
    provider_id = created.json()["id"]

    session = client.post(
        f"{API}/agent/sessions",
        json={
            "instanceId": provider_id,
            "model": "model-a",
            "context": [{"role": "user", "content": "hola"}],
        },
        headers=admin,
    )
    assert session.status_code == 201, session.text
    session_id = session.json()["id"]
    assert session.json()["engine"] == "pydantic"
    assert session.json()["model"] == "model-a"

    switched = client.patch(
        f"{API}/agent/sessions/{session_id}",
        json={"model": "model-b"},
        headers=admin,
    )
    assert switched.status_code == 200, switched.text
    assert switched.json()["id"] == session_id
    assert switched.json()["engine"] == "pydantic"
    assert switched.json()["model"] == "model-b"
    assert switched.json()["messages"] == [{"role": "user", "content": "hola"}]

    to_builtin = client.patch(
        f"{API}/agent/sessions/{session_id}",
        json={"instanceId": "pydantic", "model": "openai:gpt-4o-mini"},
        headers=admin,
    )
    assert to_builtin.status_code == 200, to_builtin.text
    assert to_builtin.json()["id"] == session_id
    assert to_builtin.json()["instanceId"] == "pydantic"
    assert to_builtin.json()["model"] == "openai:gpt-4o-mini"
    assert to_builtin.json()["messages"] == [{"role": "user", "content": "hola"}]

    unknown_model = client.patch(
        f"{API}/agent/sessions/{session_id}",
        json={"model": "not-configured"},
        headers=admin,
    )
    assert unknown_model.status_code == 422, unknown_model.text
    assert client.patch(
        f"{API}/agent/sessions/{session_id}", json={}, headers=admin
    ).status_code == 422
    assert client.patch(
        f"{API}/agent/sessions/{session_id}",
        json={"model": "model-a", "instanceId": "missing"},
        headers=admin,
    ).status_code == 404

    with catalog.session() as db:
        from itsm.agent_integrations.models import AgentSession

        row = db.get(AgentSession, session_id)
        assert row is not None
        row.status = "running"
        db.commit()
    running = client.patch(
        f"{API}/agent/sessions/{session_id}",
        json={"model": "model-a"},
        headers=admin,
    )
    assert running.status_code == 409, running.text


def test_revoked_personal_grant_stops_switching_and_new_turns(provider_env: Any) -> None:
    catalog, client = provider_env
    role_id = _role_with_permission(catalog)
    catalog.add_user("revoked.user", "Revoked User", role_id)
    headers = _login(client, catalog.settings, "revoked.user", MACHINE_PASSWORD)
    created = _create_provider(
        client,
        headers,
        scope="personal",
        baseUrl="https://api.example.com/v1",
        models=["model-a"],
        apiKey="sk-revoked",
    )
    assert created.status_code == 201, created.text
    provider_id = created.json()["id"]
    session = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": provider_id, "model": "model-a"},
        headers=headers,
    )
    assert session.status_code == 201, session.text
    session_id = session.json()["id"]

    with catalog.session() as db:
        catalog.service(db).update_role(
            catalog.admin(),
            role_id,
            permissions=("assets.view", "people.view"),
        )

    switched = client.patch(
        f"{API}/agent/sessions/{session_id}",
        json={"model": "model-a"},
        headers=headers,
    )
    assert switched.status_code == 403, switched.text
    message = client.post(
        f"{API}/agent/sessions/{session_id}/messages",
        json={"message": "hola"},
        headers=headers,
    )
    assert message.status_code == 403, message.text
    still_readable = client.get(f"{API}/agent/sessions/{session_id}", headers=headers)
    assert still_readable.status_code == 200, still_readable.text
    assert still_readable.json()["status"] == "idle"
    assert still_readable.json()["messages"] == []
    assert client.patch(
        f"{API}/agent/providers/{provider_id}", json={"name": "nope"}, headers=headers
    ).status_code == 403


def test_provider_runtime_sends_selected_model_and_server_secret(
    settings_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", True)
    settings = settings_factory()
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-1",
                "object": "chat.completion",
                "created": 0,
                "model": body["model"],
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "hola"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            },
        )

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    runtime = AgentRuntime(settings, None, provider_http_client=http_client)
    selection = ProviderModelSelection(
        base_url="https://api.example.com/v1",
        model="model-a",
        api_key="sk-server-side",
        allow_private=True,
    )
    reply, usage = runtime.chat_with_usage(
        SimpleNamespace(actor_id="user-1", kind="human"),
        ChatRequest(message="hola"),
        provider_selection=selection,
    )
    assert reply.message == "hola"
    assert (usage.input_tokens, usage.output_tokens) == (3, 2)
    assert seen[0].url.path == "/v1/chat/completions"
    assert seen[0].headers["authorization"] == "Bearer sk-server-side"
    assert json.loads(seen[0].content)["model"] == "model-a"

    second = ProviderModelSelection(
        base_url="https://api.example.com/v1",
        model="model-b",
        api_key="sk-server-side",
        allow_private=True,
    )
    runtime.chat_with_usage(
        SimpleNamespace(actor_id="user-1", kind="human"),
        ChatRequest(message="again"),
        provider_selection=second,
    )
    assert json.loads(seen[1].content)["model"] == "model-b"
    asyncio.run(http_client.aclose())


def test_personal_http_client_rechecks_dns_on_every_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []

    def fake_resolve(host: str, port: int) -> list[str]:
        calls.append((host, port))
        return ["10.0.0.5"]
    monkeypatch.setattr(providers_module, "resolve_addresses", fake_resolve)
    client = provider_http_client(allow_private=False)
    assert client.follow_redirects is False
    assert client.trust_env is False
    try:
        for _ in range(2):
            with pytest.raises(httpx.HTTPError):
                asyncio.run(client.get("https://public.example.com/v1/models"))
    finally:
        asyncio.run(client.aclose())
    assert calls == [("public.example.com", 443), ("public.example.com", 443)]


def test_runtime_closes_only_the_provider_client_it_created(
    settings_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    closed: list[bool] = []

    class FakeClient:
        async def aclose(self) -> None:
            closed.append(True)

    fake = FakeClient()
    monkeypatch.setattr(
        "itsm.agents.runtime.build_provider_http_client", lambda allow_private: fake
    )
    monkeypatch.setattr(
        "itsm.agents.runtime.resolve_model",
        lambda *args, **kwargs: FunctionModel(lambda messages, info: "ok"),
    )
    selection = ProviderModelSelection(
        base_url="https://api.example.com/v1",
        model="model-a",
        api_key="sk-owned",
        allow_private=False,
    )
    runtime = AgentRuntime(settings_factory(), None)
    runtime._ensure(provider_selection=selection)
    assert closed == []
    asyncio.run(runtime.aclose())
    assert closed == [True]
    asyncio.run(runtime.aclose())
    assert closed == [True]

    shared = AgentRuntime(settings_factory(), None, provider_http_client=FakeClient())
    shared._ensure(provider_selection=selection)
    asyncio.run(shared.aclose())
    assert closed == [True]


def test_runtime_uses_a_fresh_guarded_transport_for_each_provider_turn(
    settings_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    policies: list[bool] = []
    clients: list[Any] = []
    real_factory = runtime_module.build_provider_http_client

    def guarded_factory(*, allow_private: bool) -> Any:
        policies.append(allow_private)
        client = real_factory(allow_private=allow_private)
        clients.append(client)
        return client

    monkeypatch.setattr(runtime_module, "build_provider_http_client", guarded_factory)
    monkeypatch.setattr(
        "itsm.agents.runtime.resolve_model",
        lambda *args, **kwargs: FunctionModel(
            lambda messages, info: ModelResponse(parts=[TextPart("ok")])
        ),
    )
    runtime = AgentRuntime(settings_factory(), None)
    principal = SimpleNamespace(actor_id="user-1", kind="human")
    for allow_private in (True, False):
        runtime.chat_with_usage(
            principal,
            ChatRequest(message="hola"),
            provider_selection=ProviderModelSelection(
                base_url="https://api.example.com/v1",
                model="model-a",
                api_key="sk-server-side",
                allow_private=allow_private,
            ),
        )
    assert policies == [True, False]
    assert clients[0] is not clients[1]
    assert all(client.is_closed for client in clients)


def test_runtime_closes_a_real_keepalive_socket_on_the_inference_loop(
    settings_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", True)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        active = 0

        def setup(self) -> None:
            super().setup()
            type(self).active += 1

        def finish(self) -> None:
            type(self).active -= 1
            super().finish()

        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            self.rfile.read(length)
            payload = json.dumps(
                {
                    "id": "chatcmpl-live",
                    "object": "chat.completion",
                    "created": 0,
                    "model": "model-a",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "hola"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            self.wfile.flush()

        def log_message(self, format: str, *args: Any) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    clients: list[Any] = []
    real_factory = runtime_module.build_provider_http_client

    def factory(*, allow_private: bool) -> Any:
        client = real_factory(allow_private=allow_private)
        clients.append(client)
        return client

    monkeypatch.setattr(runtime_module, "build_provider_http_client", factory)
    try:
        runtime = AgentRuntime(settings_factory(), None)
        reply, _ = runtime.chat_with_usage(
            SimpleNamespace(actor_id="user-1", kind="human"),
            ChatRequest(message="hola"),
            provider_selection=ProviderModelSelection(
                base_url=f"http://127.0.0.1:{server.server_port}/v1",
                model="model-a",
                api_key="sk-live",
                allow_private=True,
            ),
        )
        assert reply.message == "hola"
        assert len(clients) == 1
        assert clients[0].is_closed
        deadline = time.monotonic() + 2
        while Handler.active and time.monotonic() < deadline:
            time.sleep(0.01)
        assert Handler.active == 0
    finally:
        server.shutdown()
        server.server_close()


def test_turn_closes_runtime_owned_provider_transport(
    provider_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog, client = provider_env
    closed: list[bool] = []

    class FakeRuntime:
        def __init__(self, settings: Any, session_factory: Any) -> None:
            pass

        def chat_with_usage(
            self,
            principal: Any,
            request: ChatRequest,
            *,
            credential_digest: str | None = None,
            usage: AgentUsage | None = None,
            token_limit: int | None = None,
            provider_selection: ProviderModelSelection | None = None,
        ) -> tuple[ChatReply, AgentUsage]:
            assert provider_selection is not None
            assert provider_selection.api_key == "sk-global-secret"
            return ChatReply(message="hola"), AgentUsage(input_tokens=1, output_tokens=1)

        async def aclose(self) -> None:
            closed.append(True)

    monkeypatch.setattr("itsm.agents.runtime.AgentRuntime", FakeRuntime)
    admin = _admin_login(client, catalog.settings)
    created = _create_provider(client, admin)
    assert created.status_code == 201, created.text
    provider_id = created.json()["id"]
    session = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": provider_id, "model": "model-a"},
        headers=admin,
    )
    assert session.status_code == 201, session.text
    session_id = session.json()["id"]
    with client.stream(
        "POST",
        f"{API}/agent/sessions/{session_id}/messages",
        json={"message": "hola"},
        headers=admin,
    ) as response:
        assert response.status_code == 200, response.text
        body = "".join(response.iter_text())
    assert '"type": "done"' in body
    assert closed == [True]


# ------------------------------------------------------- public destination boundary


@pytest.mark.parametrize(
    "address",
    [
        "100.64.0.1",
        "100.127.255.254",
        "::ffff:100.64.0.1",
        "::ffff:127.0.0.1",
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "0.0.0.0",
        "192.0.2.1",
        "224.0.0.1",
        "198.18.0.1",
        "::1",
        "fe80::1",
        "2001:db8::1",
    ],
)
def test_non_public_addresses_are_never_accepted(address: str) -> None:
    assert providers_module.is_public_address(address) is False


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_global_addresses_remain_accepted(address: str) -> None:
    assert providers_module.is_public_address(address) is True


@pytest.mark.parametrize(
    "endpoint", ["https://100.64.0.1/v1", "https://[::ffff:100.64.0.1]/v1"]
)
def test_personal_endpoint_rejects_cgnat_and_mapped_ipv6(endpoint: str) -> None:
    with pytest.raises(ProviderEndpointError):
        validate_provider_endpoint(endpoint, scope="personal")


# ------------------------------------------------------------ provider scope authority


def test_provider_scope_cannot_change_on_patch(provider_env: Any) -> None:
    catalog, client = provider_env
    role = _role_with_permission(catalog)
    catalog.add_user("scope.owner", "Scope Owner", role)
    headers = _login(client, catalog.settings, "scope.owner", MACHINE_PASSWORD)
    created = _create_provider(
        client,
        headers,
        scope="personal",
        baseUrl="https://provider.example/v1",
    )
    assert created.status_code == 201, created.text
    provider_id = created.json()["id"]

    changed = client.patch(
        f"{API}/agent/providers/{provider_id}",
        json={"scope": "global"},
        headers=headers,
    )
    assert changed.status_code == 422, changed.text
    assert changed.json()["error"]["message"] == "provider scope cannot be changed"

    renamed = client.patch(
        f"{API}/agent/providers/{provider_id}",
        json={"scope": "personal", "name": "Renamed"},
        headers=headers,
    )
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["scope"] == "personal"
    assert renamed.json()["name"] == "Renamed"

    admin = _admin_login(client, catalog.settings)
    global_created = _create_provider(client, admin)
    assert global_created.status_code == 201, global_created.text
    rejected = client.patch(
        f"{API}/agent/providers/{global_created.json()['id']}",
        json={"scope": "personal", "name": "Moved"},
        headers=admin,
    )
    assert rejected.status_code == 422, rejected.text
    with catalog.session() as db:
        row = db.get(AgentProvider, global_created.json()["id"])
        assert row is not None
        assert row.scope == "global"
        assert row.name == "NOC gateway"


# ------------------------------------------------- instance-only session patch defaults


def test_instance_only_patch_uses_provider_configured_default(provider_env: Any) -> None:
    catalog, client = provider_env
    admin = _admin_login(client, catalog.settings)
    created = _create_provider(client, admin)
    assert created.status_code == 201, created.text
    provider_id = created.json()["id"]
    session = client.post(
        f"{API}/agent/sessions",
        json={
            "instanceId": "pydantic",
            "model": catalog.settings.agent_model,
            "context": [{"role": "user", "content": "hola"}],
        },
        headers=admin,
    )
    assert session.status_code == 201, session.text
    session_id = session.json()["id"]

    switched = client.patch(
        f"{API}/agent/sessions/{session_id}",
        json={"instanceId": provider_id},
        headers=admin,
    )
    assert switched.status_code == 200, switched.text
    assert switched.json()["instanceId"] == provider_id
    assert switched.json()["engine"] == "pydantic"
    assert switched.json()["model"] == "model-a"
    assert switched.json()["messages"] == [{"role": "user", "content": "hola"}]

    back = client.patch(
        f"{API}/agent/sessions/{session_id}",
        json={"instanceId": "pydantic"},
        headers=admin,
    )
    assert back.status_code == 200, back.text
    assert back.json()["instanceId"] == "pydantic"
    assert back.json()["model"] == catalog.settings.agent_model


def test_instance_only_patch_keeps_current_model_configured_on_target(
    provider_env: Any,
) -> None:
    catalog, client = provider_env
    admin = _admin_login(client, catalog.settings)
    first = _create_provider(client, admin)
    second = _create_provider(client, admin, name="Second", models=["model-b", "model-c"])
    assert first.status_code == 201 and second.status_code == 201
    session = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": first.json()["id"], "model": "model-b"},
        headers=admin,
    )
    assert session.status_code == 201, session.text
    switched = client.patch(
        f"{API}/agent/sessions/{session.json()['id']}",
        json={"instanceId": second.json()["id"]},
        headers=admin,
    )
    assert switched.status_code == 200, switched.text
    assert switched.json()["instanceId"] == second.json()["id"]
    assert switched.json()["model"] == "model-b"


def test_instance_only_patch_rejects_provider_without_models(provider_env: Any) -> None:
    catalog, client = provider_env
    admin = _admin_login(client, catalog.settings)
    empty = _create_provider(client, admin, name="Empty", models=[])
    assert empty.status_code == 201, empty.text
    session = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": "pydantic", "model": catalog.settings.agent_model},
        headers=admin,
    )
    assert session.status_code == 201, session.text
    rejected = client.patch(
        f"{API}/agent/sessions/{session.json()['id']}",
        json={"instanceId": empty.json()["id"]},
        headers=admin,
    )
    assert rejected.status_code == 422, rejected.text
    assert rejected.json()["error"]["message"] == "the selected provider has no configured models"
    with catalog.session() as db:
        row = db.get(AgentSession, session.json()["id"])
        assert row is not None
        assert row.instance_id == "pydantic"
        assert row.model == catalog.settings.agent_model


def test_instance_only_patch_uses_external_instance_default_model(
    provider_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_agent_integrations import (
        FakeEngine,
        FakeInstaller,
        build_service,
        configure_instance,
        install_verified,
    )

    catalog, client = provider_env
    machine, machine_token = catalog.add_machine("opencode-client", "OpenCode Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", machine_token)
    engine = FakeEngine(models=("fake/model-a", "fake/model-b"))
    build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: engine,
        installer=FakeInstaller([{"status": "verified", "verified": True}]),
    )
    admin = _admin_login(client, catalog.settings)
    instance = configure_instance(
        client,
        headers=admin,
        integrationIdentityId=machine.actor_id,
        defaultModel="fake/model-b",
    )
    installed = install_verified(client, admin, instance, machine.actor_id)
    assert installed["status"] == "verified", installed

    session = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": instance["id"], "model": "fake/model-a"},
        headers=admin,
    )
    assert session.status_code == 201, session.text
    session_id = session.json()["id"]
    builtin = client.patch(
        f"{API}/agent/sessions/{session_id}",
        json={"instanceId": "pydantic"},
        headers=admin,
    )
    assert builtin.status_code == 200, builtin.text
    assert builtin.json()["model"] == catalog.settings.agent_model
    switched = client.patch(
        f"{API}/agent/sessions/{session_id}",
        json={"instanceId": instance["id"]},
        headers=admin,
    )
    assert switched.status_code == 200, switched.text
    assert switched.json()["instanceId"] == instance["id"]
    assert switched.json()["model"] == "fake/model-b"


# -------------------------------------------------- atomic session switch / turn claim


def _interleave_update_once(engine: Any, callback: Any) -> Any:
    interleaved: list[Any] = []

    def listener(
        conn: Any,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        if interleaved or not statement.lstrip().upper().startswith("UPDATE AGENT_SESSIONS"):
            return
        interleaved.append(None)
        interleaved[0] = callback()

    event.listen(engine, "before_cursor_execute", listener)
    return interleaved, lambda: event.remove(engine, "before_cursor_execute", listener)


def test_instance_switch_conflicts_with_concurrent_turn_reservation(provider_env: Any) -> None:
    catalog, client = provider_env
    admin = _admin_login(client, catalog.settings)
    first = _create_provider(client, admin)
    second = _create_provider(client, admin, name="Target")
    assert first.status_code == 201 and second.status_code == 201
    session = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": first.json()["id"], "model": "model-a"},
        headers=admin,
    )
    assert session.status_code == 201, session.text
    session_id = session.json()["id"]
    service = client.app.state.agent_integrations
    turns, stop = _interleave_update_once(
        catalog.engine,
        lambda: service.prepare_turn(catalog.admin(), session_id, "race message", None),
    )
    try:
        response = client.patch(
            f"{API}/agent/sessions/{session_id}",
            json={"instanceId": second.json()["id"], "model": "model-b"},
            headers=admin,
        )
    finally:
        stop()
    assert response.status_code == 409, response.text
    assert turns and turns[0].session.instance_id == first.json()["id"]
    with catalog.session() as db:
        row = db.get(AgentSession, session_id)
        assert row is not None
        assert row.status == "running"
        assert row.instance_id == first.json()["id"]
        assert row.model == "model-a"
        assert row.messages == [{"role": "user", "content": "race message"}]


def test_turn_reservation_conflicts_with_concurrent_instance_switch(
    provider_env: Any,
) -> None:
    from itsm.identity.service import Conflict

    catalog, client = provider_env
    admin = _admin_login(client, catalog.settings)
    first = _create_provider(client, admin)
    second = _create_provider(client, admin, name="Target")
    assert first.status_code == 201 and second.status_code == 201
    session = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": first.json()["id"], "model": "model-a"},
        headers=admin,
    )
    assert session.status_code == 201, session.text
    session_id = session.json()["id"]
    service = client.app.state.agent_integrations
    switched, stop = _interleave_update_once(
        catalog.engine,
        lambda: asyncio.run(
            service.update_session(
                catalog.admin(),
                session_id,
                {"instanceId": second.json()["id"], "model": "model-b"},
            )
        ),
    )
    try:
        with pytest.raises(Conflict):
            service.prepare_turn(catalog.admin(), session_id, "race message", None)
    finally:
        stop()
    assert switched and switched[0]["instanceId"] == second.json()["id"]
    with catalog.session() as db:
        row = db.get(AgentSession, session_id)
        assert row is not None
        assert row.status == "idle"
        assert row.instance_id == second.json()["id"]
        assert row.model == "model-b"
        assert row.messages == []
        assert db.execute(select(AgentRun)).scalars().all() == []


# ------------------------------------------------------ strict profile permission shape


def test_strict_profile_boundary_requires_explicit_wildcard_resource() -> None:
    from itsm.agent_integrations.service import (
        _restrictive_permissions,
        _strict_permission_suffix,
    )

    skills = ["itsm-inventory"]
    approved = [
        {"action": "*", "resource": "*", "effect": "deny"},
        {"action": "itsm_*", "resource": "*", "effect": "allow"},
        {"action": "skill", "resource": "itsm-inventory", "effect": "allow"},
    ]
    assert _restrictive_permissions(approved, skills) is True
    assert _strict_permission_suffix(approved, skills) is True

    missing_deny_resource = [
        {"action": "*", "effect": "deny"},
        {"action": "itsm_*", "resource": "*", "effect": "allow"},
        {"action": "skill", "resource": "itsm-inventory", "effect": "allow"},
    ]
    assert _restrictive_permissions(missing_deny_resource, skills) is False

    missing_tool_resource = [
        {"action": "*", "resource": "*", "effect": "deny"},
        {"action": "itsm_search_assets", "effect": "allow"},
        {"action": "skill", "resource": "itsm-inventory", "effect": "allow"},
    ]
    assert _restrictive_permissions(missing_tool_resource, skills) is False

    missing_skill_resource = [
        {"action": "*", "resource": "*", "effect": "deny"},
        {"action": "itsm_*", "resource": "*", "effect": "allow"},
        {"action": "skill", "effect": "allow"},
    ]
    assert _restrictive_permissions(missing_skill_resource, skills) is False
    assert _strict_permission_suffix(missing_skill_resource, skills) is False


# ------------------------------------------- deployment allowlist for private endpoints


@pytest.fixture
def private_provider_env(settings_factory: Any):
    """Providers environment whose deployment authorizes loopback personal targets."""
    catalog = prepare(
        settings_factory,
        agent_model="openai:gpt-4o-mini",
        ai_credential_key=MASTER_KEY,
        ai_personal_private_endpoints="127.0.0.0/8,::1/128",
        ai_broker_url="ws://127.0.0.1:9/runs",
        ai_broker_token="t" * 48,
    )
    client = TestClient(create_app(catalog.settings))
    client.__enter__()
    client.app.state.agent_integrations = AgentIntegrationService(
        catalog.settings, catalog.factory()
    )
    try:
        yield catalog, client
    finally:
        client.__exit__(None, None, None)
        catalog.engine.dispose()


def test_personal_private_endpoint_stays_rejected_without_an_allowlist(provider_env: Any) -> None:
    catalog, client = provider_env
    role_id = _role_with_permission(catalog)
    catalog.add_user("private.user", "Private User", role_id)
    headers = _login(client, catalog.settings, "private.user", MACHINE_PASSWORD)

    response = _create_provider(
        client,
        headers,
        scope="personal",
        baseUrl="http://127.0.0.1:18081/v1",
        models=["model-a"],
        apiKey="sk-private",
    )

    assert response.status_code == 422, response.text
    assert "sk-private" not in response.text


def test_allowlisted_personal_private_endpoint_is_accepted(private_provider_env: Any) -> None:
    catalog, client = private_provider_env
    role_id = _role_with_permission(catalog)
    catalog.add_user("allowed.user", "Allowed User", role_id)
    headers = _login(client, catalog.settings, "allowed.user", MACHINE_PASSWORD)

    response = _create_provider(
        client,
        headers,
        scope="personal",
        baseUrl="http://127.0.0.1:18081/v1",
        models=["model-a"],
        apiKey="sk-allowed",
    )

    assert response.status_code == 201, response.text
    assert response.json()["baseUrl"] == "http://127.0.0.1:18081/v1"


def test_public_https_personal_endpoint_needs_no_allowlist(provider_env: Any) -> None:
    catalog, client = provider_env
    role_id = _role_with_permission(catalog)
    catalog.add_user("public.user", "Public User", role_id)
    headers = _login(client, catalog.settings, "public.user", MACHINE_PASSWORD)

    response = _create_provider(
        client,
        headers,
        scope="personal",
        baseUrl="https://api.example.com/v1",
        models=["model-a"],
        apiKey="sk-public",
    )

    assert response.status_code == 201, response.text


def test_exact_hostname_entry_allows_http_but_keeps_other_private_hosts_out(
    settings_factory: Any,
) -> None:
    settings = settings_factory(ai_personal_private_endpoints="models.internal:8080")
    policy = personal_endpoint_policy(settings)

    accepted = validate_provider_endpoint(
        "http://models.internal:8080/v1", scope="personal", policy=policy
    )
    assert accepted == "http://models.internal:8080/v1"
    with pytest.raises(ProviderEndpointError):
        validate_provider_endpoint(
            "http://models.internal:9090/v1", scope="personal", policy=policy
        )
    with pytest.raises(ProviderEndpointError):
        validate_provider_endpoint(
            "http://other.internal:8080/v1", scope="personal", policy=policy
        )


def test_private_policy_decides_on_the_resolved_address_not_the_hostname() -> None:
    policy = ProviderNetworkPolicy(
        allowlist=parse_personal_private_endpoints("10.0.0.0/8,models.internal:8443")
    )

    assert policy.permits("models.internal", ("10.4.5.6",), port=8443) is True
    assert policy.permits("models.internal", ("192.168.1.5",), port=8443) is True
    assert policy.permits("models.internal", ("192.168.1.5",), port=9100) is False
    assert policy.permits("other.internal", ("192.168.1.5",), port=8443) is False
    assert policy.permits("public.example.com", ("93.184.216.34",), port=443) is True
    assert policy.permits("public.example.com", ("172.16.0.9",), port=443) is False
    assert policy.permits("models.internal", ("127.0.0.1",), port=8443) is False
    assert policy.permits("models.internal", ("::1",), port=8443) is False


def test_metadata_addresses_need_an_explicit_cidr_even_for_an_allowlisted_host() -> None:
    host_only = ProviderNetworkPolicy(
        allowlist=parse_personal_private_endpoints("metadata.internal:80")
    )

    assert host_only.permits("metadata.internal", ("169.254.169.254",), port=80) is False
    assert host_only.permits("metadata.internal", ("fd00:ec2::254",), port=80) is False

    explicit = ProviderNetworkPolicy(
        allowlist=parse_personal_private_endpoints("169.254.169.254/32")
    )
    assert explicit.permits("metadata.internal", ("169.254.169.254",), port=80) is True


def test_guarded_client_refuses_a_private_resolution_without_an_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[str, int]] = []

    def fake_resolve(host: str, port: int) -> list[str]:
        seen.append((host, port))
        return ["192.0.2.10"]

    monkeypatch.setattr(providers_module, "resolve_addresses", fake_resolve)
    client = provider_http_client(policy=ProviderNetworkPolicy())
    try:
        with pytest.raises(httpx.HTTPError):
            asyncio.run(client.get("https://models.internal/v1/models"))
    finally:
        asyncio.run(client.aclose())

    assert seen == [("models.internal", 443)]


def test_global_provider_selection_keeps_owner_trusted_private_access(
    private_provider_env: Any,
) -> None:
    catalog, client = private_provider_env
    admin = _admin_login(client, catalog.settings)
    created = _create_provider(client, admin)
    assert created.status_code == 201, created.text

    service = client.app.state.agent_integrations
    with catalog.session() as session:
        row = session.get(AgentProvider, created.json()["id"])
        principal = catalog.admin()
        selection = service._provider_selection(session, principal, row, "model-a")

    assert selection.allow_private is True
