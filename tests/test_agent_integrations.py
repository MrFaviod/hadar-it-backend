"""Behavioral checks for the agent integration control plane (contracts 3, 4, 7, 11).

Everything is exercised through the public HTTP surface except the two run
concurrency checks that need two overlapping coroutines in one event loop; those
use the service boundary the HTTP route itself calls.
"""

from __future__ import annotations

import asyncio
import base64
import json
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from itsm.agent_integrations import installer as installer_module
from itsm.agent_integrations.installer import receipt_digest
from itsm.agent_integrations.service import AgentIntegrationService
from itsm.agents.runtime import ChatAction, ChatReply
from itsm.config import Settings
from itsm.identity.service import Conflict
from itsm.main import create_app
from itsm.mcp.server import TOOL_NAMES
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import MACHINE_PASSWORD, prepare

API = "/api/v1"


# --------------------------------------------------------------------- doubles
class FakeEngineError(Exception):
    def __init__(self, code: str, message: str, retryable: bool) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


class FakeModel:
    def __init__(self, identifier: str, provider: str = "fake", free: bool | None = None) -> None:
        self.id = identifier
        self.name = identifier
        self.provider = provider
        self.free = free

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "provider": self.provider, "free": self.free}


class FakeEngine:
    """Deterministic stand-in for the frozen engine adapter boundary."""

    def __init__(
        self,
        *,
        models: tuple[str, ...] = ("fake/model-a",),
        capabilities: dict[str, bool] | None = None,
        events: list[dict[str, Any]] | None = None,
        discover_error: Exception | None = None,
        block: bool = False,
    ) -> None:
        self.models = [FakeModel(name) for name in models]
        self.capabilities = capabilities or {
            "streaming": True,
            "sessions": True,
            "model_switch": True,
            "cancel": True,
            "tools": True,
            "usage": True,
            "history": True,
        }
        self.events = events or [
            {"type": "delta", "text": "hola"},
            {
                "type": "usage",
                "inputTokens": 3,
                "outputTokens": 2,
                "totalTokens": 5,
                "totalSource": "provider",
                "precision": "measured",
                "source": "engine",
            },
            {"type": "done", "cancelled": False},
        ]
        self.discover_error = discover_error
        self.block = block
        self.started = threading.Event()
        self.release = threading.Event()
        self.created = 0
        self.cancelled = 0
        self.closed = 0
        self.session_id = "external-session-1"
        self.histories: list[list[dict[str, str]] | None] = []
        self.messages: list[str] = []
        self.received_ids: list[str] = []

    async def discover(self) -> Any:
        if self.discover_error is not None:
            raise self.discover_error
        return SimpleNamespace(version="9.9.9", models=self.models, capabilities=self.capabilities)

    async def create_session(self) -> str:
        self.created += 1
        return self.session_id

    async def stream(
        self,
        message: str,
        *,
        session_id: str,
        model: str,
        history: list[dict[str, str]] | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        self.messages.append(message)
        self.histories.append(history)
        self.received_ids.append(session_id)
        yield {"type": "session", "sessionId": session_id}
        if self.block:
            self.started.set()
            while not self.release.is_set():
                await asyncio.sleep(0.01)
            yield {"type": "delta", "text": "parcial"}
            yield {"type": "done", "cancelled": True}
            return
        for event in self.events:
            if event["type"] == "error":
                yield event
                continue
            yield event

    async def cancel(self, session_id: str) -> None:
        self.cancelled += 1
        self.release.set()

    async def close(self) -> None:
        self.closed += 1


class FakeRuntime:
    """Stand-in for the existing Pydantic AI runtime (same public chat envelope)."""

    configured = True

    def __init__(self, reply: ChatReply) -> None:
        self.reply = reply
        self.requests: list[Any] = []

    def chat_with_usage(
        self,
        principal: Any,
        request: Any,
        *,
        credential_digest: str | None = None,
        usage: Any = None,
        quota: Any = None,
        **options: Any,
    ) -> tuple[ChatReply, Any]:
        self.requests.append(request)
        identifier = quota.before_call(8)
        quota.after_call(
            identifier,
            {"type": "usage", "totalTokens": 5, "precision": "measured", "source": "provider"},
        )
        return self.reply, usage


def _normalize_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    if receipt.get("status") == "verified" and receipt.get("verified") is True:
        receipt.setdefault("profileSafetyVerified", True)
        checks = list(receipt.get("checks") or [])
        if not any(
            isinstance(check, dict) and check.get("name") == "profile.safety" for check in checks
        ):
            checks.append({"name": "profile.safety", "status": "pass"})
        receipt["checks"] = checks
    return receipt


class FakeInstaller:
    def __init__(self, receipts: list[dict[str, Any]]) -> None:
        self.receipts = [_normalize_receipt(receipt) for receipt in receipts]
        self.calls: list[dict[str, Any]] = []
        self.requests: list[dict[str, Any]] = []

    async def detect_target(self, target: Any) -> dict[str, Any]:
        return {
            "engine": target.engine,
            "path": target.path,
            "profile": target.profile,
            "version": "2.1.2",
            "detected": True,
            "directory": target.path,
            "evidence": ["config directory found"],
        }

    async def apply(
        self, target: Any, *, mcp: dict[str, Any], skills: list[str], operation: str, **kwargs: Any
    ) -> dict[str, Any]:
        self.calls.append(
            {"target": target, "mcp": mcp, "skills": skills, "operation": operation, **kwargs}
        )
        receipt = dict(self.receipts.pop(0))
        receipt.setdefault("status", "verified")
        receipt.setdefault("verified", True)
        receipt.setdefault("version", "2.1.2")
        receipt.setdefault("managedFiles", [])
        receipt.setdefault("conflicts", [])
        receipt.setdefault("checks", [{"id": "mcp", "status": "ok"}])
        receipt.setdefault("engine", target.engine)
        receipt.setdefault("profile", target.profile)
        receipt.setdefault("identityId", mcp["identityId"])
        return _normalize_receipt(receipt)

    def build_request(
        self,
        target: Any,
        *,
        mcp: dict[str, Any],
        skills: list[str],
        operation: str,
        expected_manifest_digest: str | None = None,
        catalog: Any = None,
    ) -> dict[str, Any]:
        request = {
            "kind": "itsm-install-request",
            "operation": operation,
            "engine": target.engine,
            "profile": target.profile,
            "path": target.path,
            "version": target.version or "2.1.2",
            "identityId": mcp["identityId"],
            "skills": list(skills),
            "digestAlgorithm": "sha256",
            "requestDigest": "sha256:remote-request",
        }
        self.requests.append(request)
        return request

    def validate_receipt(
        self, receipt: dict[str, Any], *, request: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        digest = (request or {}).get("requestDigest")
        if request is not None and receipt.get("requestDigest") != digest:
            return {"valid": False, "errors": ["request digest mismatch"]}
        return {"valid": True, "errors": []}

    async def verify_connection(self, mcp: dict[str, Any]) -> dict[str, Any]:
        return {"verified": True, "checks": [{"name": "mcp", "status": "pass"}], "toolCount": 3}


class VerifyingInstaller(FakeInstaller):
    """Mirror the real installer's rule that verify input must match the manifest.

    The real installer compares the requested skill names with the managed
    manifest and returns a conflict when they differ, so the double refuses a
    dropped selection instead of accepting whatever list the service forwards.
    """

    def __init__(self, receipts: list[dict[str, Any]]) -> None:
        super().__init__(receipts)
        self.managed: dict[tuple[str, str, str | None], list[str]] = {}

    async def apply(
        self, target: Any, *, mcp: dict[str, Any], skills: list[str], operation: str, **kwargs: Any
    ) -> dict[str, Any]:
        key = (target.engine, target.path, target.profile)
        if operation == "install":
            self.managed[key] = list(skills)
        elif key in self.managed and list(skills) != self.managed[key]:
            self.calls.append(
                {"target": target, "mcp": mcp, "skills": skills, "operation": operation, **kwargs}
            )
            return {
                "status": "conflict",
                "verified": False,
                "version": "2.1.2",
                "engine": target.engine,
                "profile": target.profile,
                "identityId": mcp["identityId"],
                "managedFiles": [],
                "conflicts": [
                    {"path": "skills", "detail": "verification input does not match the manifest"}
                ],
                "checks": [],
            }
        return await super().apply(
            target=target, mcp=mcp, skills=skills, operation=operation, **kwargs
        )


def _receipt_skills(*names: str) -> list[dict[str, str]]:
    return [{"name": name, "version": "1.0.0", "digest": "a" * 64} for name in names]


_MODULE_SKILL = """---
name: demo-skill
description: "Trigger: module demonstration. Exercise one module-provided ITSM skill."
license: UNLICENSED
metadata:
  author: "Example module"
  version: "1.2.0"
tools:
  - get_asset
permissions:
  - assets.view
capabilities:
  - inventory.read
---
# Module demonstration
"""


def _write_module(tmp_path: Any) -> tuple[dict[str, Any], Any]:
    root = tmp_path / "vendor.demo"
    package = root / "skills" / "demo-skill"
    package.mkdir(parents=True)
    (package / "SKILL.md").write_text(_MODULE_SKILL, encoding="utf-8")
    references = package / "references"
    references.mkdir()
    (references / "notes.md").write_text("Local note.\n", encoding="utf-8")
    manifest = {
        "id": "vendor.demo",
        "name": "Demo module",
        "version": "1.2.0",
        "capabilities": ["inventory.read"],
        "permissions": ["assets.view"],
        "skills": ["demo-skill"],
    }
    return manifest, root


def _canonical_receipt(
    exported: dict[str, Any], identity_id: str, version: str = "2.1.2"
) -> dict[str, Any]:
    request = exported["request"]
    receipt: dict[str, Any] = {
        "kind": "itsm-agent-installer-receipt",
        "schemaVersion": request["schemaVersion"],
        "digestAlgorithm": "sha256",
        "status": "verified",
        "verified": True,
        "mcpVerified": True,
        "profileSafetyVerified": True,
        "requestDigest": request["requestDigest"],
        "engine": request["target"]["engine"],
        "profile": request["target"]["profile"],
        "version": version,
        "identityId": identity_id,
        "targetPath": request["target"]["path"],
        "operation": request["operation"],
        "configDigest": "sha256:" + "a" * 64,
        "manifestDigest": "sha256:" + "b" * 64,
        "skillDigests": dict(request["skillDigests"]),
        "managedFiles": [],
        "conflicts": [],
        "checks": [{"name": "profile.safety", "status": "pass"}],
    }
    receipt["receiptDigest"] = receipt_digest(receipt)
    return receipt


class FakeCatalog:
    def __init__(self, *, modules: list[dict[str, Any]] | None = None) -> None:
        self.skills = {
            "itsm-inventory": {
                "name": "itsm-inventory",
                "description": "Inventory procedures",
                "version": "1.0.0",
                "module": "itsm",
                "permissions": ["assets.view"],
                "capabilities": ["skills"],
                "digest": "a" * 64,
            }
        }
        self.modules = modules or [
            {
                "id": "itsm",
                "name": "ITSM official",
                "version": "1.0.0",
                "official": True,
                "enabled": True,
                "permissions": [],
                "capabilities": ["skills"],
                "skills": ["itsm-inventory"],
            }
        ]
        self.enabled_calls: list[tuple[str, bool]] = []

    def list_skills(self) -> list[dict[str, Any]]:
        return [dict(skill) for skill in self.skills.values()]

    def get_skill(self, name: str) -> dict[str, Any]:
        return dict(self.skills[name])

    def list_modules(self) -> list[dict[str, Any]]:
        return [dict(module) for module in self.modules]

    def get_module(self, module_id: str) -> dict[str, Any]:
        return next(dict(module) for module in self.modules if module["id"] == module_id)

    def set_module_enabled(self, module_id: str, enabled: bool) -> None:
        self.enabled_calls.append((module_id, enabled))
        for module in self.modules:
            if module["id"] == module_id:
                module["enabled"] = enabled


# --------------------------------------------------------------------- helpers
def read_sse(response: Any) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in response.iter_lines():
        if not line:
            continue
        assert line.startswith("data: "), line
        events.append(json.loads(line[len("data: ") :]))
    return events


def login(
    client: TestClient,
    settings: Settings,
    username: str,
    password: str = MACHINE_PASSWORD,
) -> dict[str, str]:
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


def logout(client: TestClient, headers: dict[str, str]) -> None:
    response = client.post(f"{API}/auth/logout", headers=headers)
    assert response.status_code == 200, response.text


def build_service(
    client: TestClient,
    catalog: Any,
    *,
    runtime: Any = None,
    engine_factory: Callable[[Any, str | None], Any] | None = None,
    installer: Any = None,
    catalog_api: Any = None,
    extension_sync: Callable[[], None] | None = None,
) -> AgentIntegrationService:
    service = AgentIntegrationService(
        catalog.settings,
        catalog.factory(),
        runtime=runtime,
        engine_factory=engine_factory,
        installer=installer,
        catalog=catalog_api,
        extension_sync=extension_sync,
    )
    client.app.state.agent_integrations = service
    if runtime is not None:
        client.app.state.agent_runtime = runtime
        client.app.state.isolated_runtime = runtime
    return service


@pytest.fixture
def app_client(
    settings_factory: Callable[..., Settings],
) -> Iterator[tuple[Any, TestClient, Settings]]:
    catalog = prepare(
        settings_factory,
        agent_model="openai:gpt-4o-mini",
        ai_broker_url="ws://127.0.0.1:9/runs",
        ai_broker_token="t" * 48,
    )
    client = TestClient(create_app(catalog.settings))
    client.__enter__()
    try:
        yield catalog, client, catalog.settings
    finally:
        client.__exit__(None, None, None)
        catalog.engine.dispose()


def configure_instance(
    client: TestClient, headers: dict[str, str], **overrides: Any
) -> dict[str, Any]:
    payload = {
        "name": "OpenCode NOC",
        "engine": "opencode",
        "baseUrl": "http://127.0.0.1:9",
        "profile": "itsm",
        "directCompanyException": True,
        **overrides,
    }
    response = client.post(f"{API}/agent/integrations/instances", json=payload, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def install_verified(
    client: TestClient,
    headers: dict[str, str],
    instance: dict[str, Any],
    identity_id: str,
    *,
    skills: list[str] | None = None,
    receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    installer = client.app.state.agent_integrations._installer
    assert installer is not None
    if receipt is not None:
        installer.receipts.append(receipt)
    response = client.post(
        f"{API}/agent/integrations/install",
        json={
            "instanceId": instance["id"],
            "target": {
                "engine": "opencode",
                "path": "/srv/opencode/itsm",
                "profile": instance.get("profile") or "itsm",
            },
            "mcp": {
                "url": "http://127.0.0.1:18080/api/v1/mcp",
                "secretRef": "ITSM_TEST_MCP_TOKEN",
                "identityId": identity_id,
            },
            "skills": skills if skills is not None else ["itsm-inventory"],
            "operation": "install",
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


# ------------------------------------------------------------------- admin gate
def test_admin_surface_requires_full_human_administrator(app_client) -> None:
    catalog, client, settings = app_client
    catalog.add_user("reader-one", "Reader One", "user")
    headers = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)

    response = client.get(f"{API}/agent/integrations", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    builtin = next(item for item in body["instances"] if item["id"] == "pydantic")
    assert builtin["engine"] == "pydantic"
    assert builtin["secretRef"] is None
    assert body["defaults"] == {"instanceId": None, "model": None}

    logout(client, headers)
    reader = login(client, settings, "reader-one")
    assert client.get(f"{API}/agent/integrations", headers=reader).status_code == 403
    denied = client.post(
        f"{API}/agent/integrations/instances",
        json={"name": "X", "engine": "opencode", "baseUrl": "http://127.0.0.1:9"},
        headers=reader,
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "forbidden"


def test_instance_validation_never_echoes_the_secret(app_client, monkeypatch) -> None:
    _, client, settings = app_client
    headers = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)

    credentials = client.post(
        f"{API}/agent/integrations/instances",
        json={
            "name": "Bad",
            "engine": "opencode",
            "baseUrl": "http://user:pass@127.0.0.1:9",
        },
        headers=headers,
    )
    assert credentials.status_code == 422, credentials.text
    assert "user:pass" not in credentials.text

    missing = client.post(
        f"{API}/agent/integrations/instances",
        json={
            "name": "Missing secret",
            "engine": "hermes",
            "baseUrl": "http://127.0.0.1:9",
            "secretRef": "ITSM_TEST_MISSING_SECRET_XYZ",
        },
        headers=headers,
    )
    assert missing.status_code == 422
    assert "ITSM_TEST_MISSING_SECRET_XYZ" in missing.text

    monkeypatch.setenv("ITSM_TEST_OPENCODE_TOKEN", "top-secret-value-123")
    created = client.post(
        f"{API}/agent/integrations/instances",
        json={
            "name": "Bound",
            "engine": "opencode",
            "baseUrl": "http://127.0.0.1:9",
            "secretRef": "ITSM_TEST_OPENCODE_TOKEN",
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    assert "top-secret-value-123" not in created.text
    assert created.json()["secretConfigured"] is True
    assert created.json()["secretRef"] == "ITSM_TEST_OPENCODE_TOKEN"

    relative_target = client.post(
        f"{API}/agent/integrations/targets",
        json={"engine": "opencode", "path": "relative/config"},
        headers=headers,
    )
    assert relative_target.status_code == 422


def test_preferences_and_installation_defaults(app_client) -> None:
    catalog, client, settings = app_client
    catalog.add_user("reader-one", "Reader One", "user")
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)

    defaults = client.put(
        f"{API}/agent/integrations/defaults",
        json={"instanceId": "pydantic", "model": "openai:gpt-4o-mini"},
        headers=admin,
    )
    assert defaults.status_code == 200, defaults.text
    assert defaults.json() == {"instanceId": "pydantic", "model": "openai:gpt-4o-mini"}

    snapshot = client.get(f"{API}/agent/integrations", headers=admin).json()
    assert snapshot["defaults"] == {"instanceId": "pydantic", "model": "openai:gpt-4o-mini"}

    logout(client, admin)
    reader = login(client, settings, "reader-one")
    denied = client.put(
        f"{API}/agent/integrations/defaults",
        json={"instanceId": "pydantic", "model": "openai:gpt-4o-mini"},
        headers=reader,
    )
    assert denied.status_code == 403

    chosen = client.put(
        f"{API}/agent/preferences",
        json={"instanceId": "pydantic", "model": "openai:gpt-4o-mini"},
        headers=reader,
    )
    assert chosen.status_code == 200, chosen.text

    engines = client.get(f"{API}/agent/engines", headers=reader)
    assert engines.status_code == 200, engines.text
    body = engines.json()
    assert body["preference"] == {"instanceId": "pydantic", "model": "openai:gpt-4o-mini"}
    company = body["budget"]["funding"]["company"]
    assert company["availableTokens"] == 200_000
    assert company["consumedTokens"] == 0
    assert body["budget"]["funding"]["personal"]["unlimited"] is True
    pydantic = next(item for item in body["instances"] if item["id"] == "pydantic")
    assert pydantic["models"] == [
        {
            "id": "openai:gpt-4o-mini",
            "name": "openai:gpt-4o-mini",
            "provider": "openai",
            "free": None,
            "inputs": {"image": None, "file": None},
        }
    ]
    assert pydantic["capabilities"]["streaming"] is False

    unknown = client.put(
        f"{API}/agent/preferences",
        json={"instanceId": "missing", "model": None},
        headers=reader,
    )
    assert unknown.status_code == 422


def test_reader_discovery_hides_external_engines_and_denies_mutation(
    app_client, monkeypatch
) -> None:
    catalog, client, settings = app_client
    catalog.add_user("reader-one", "Reader One", "user")
    machine, machine_token = catalog.add_machine("hermes-client", "Hermes Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", machine_token)
    build_service(client, catalog)
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    external = configure_instance(
        client,
        headers=admin,
        engine="hermes",
        integrationIdentityId=machine.actor_id,
    )
    logout(client, admin)

    reader = login(client, settings, "reader-one")
    body = client.get(f"{API}/agent/engines", headers=reader)
    assert body.status_code == 200, body.text
    assert [item["id"] for item in body.json()["instances"]] == ["pydantic"]

    created = client.post(
        f"{API}/agent/integrations/instances",
        json={
            "name": "Reader Hermes",
            "engine": "hermes",
            "baseUrl": "http://127.0.0.1:9",
            "profile": "itsm",
        },
        headers=reader,
    )
    assert created.status_code == 403, created.text

    switched = client.put(
        f"{API}/agent/preferences",
        json={"instanceId": external["id"], "model": "hermes/default"},
        headers=reader,
    )
    assert switched.status_code == 403, switched.text

    session = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": external["id"], "model": "hermes/default"},
        headers=reader,
    )
    assert session.status_code == 403, session.text

    admin_only = client.get(f"{API}/agent/integrations", headers=reader)
    assert admin_only.status_code == 403, admin_only.text


def test_pydantic_common_session_streams_cards_and_keeps_agent_chat(app_client) -> None:
    catalog, client, settings = app_client
    reply = ChatReply(
        message="Hay dos activos.",
        actions=[ChatAction(tool="search_assets", status="completed", assetIds=["a-1"])],
        results=[{"kind": "assets", "items": [{"id": "a-1"}]}],
        approvalPending=False,
    )
    runtime = FakeRuntime(reply)
    build_service(client, catalog, runtime=runtime)
    headers = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)

    created = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": "pydantic", "model": "openai:gpt-4o-mini"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    session = created.json()
    assert session["instanceId"] == "pydantic"
    assert session["messages"] == []

    asset_id = "11111111-1111-4111-8111-111111111111"
    with client.stream(
        "POST",
        f"{API}/agent/sessions/{session['id']}/messages",
        json={"message": "¿cuántos activos hay?", "assetId": asset_id},
        headers=headers,
    ) as response:
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("text/event-stream")
        events = read_sse(response)

    assert events[0] == {"type": "session", "sessionId": session["id"]}
    assert {"type": "delta", "text": "Hay dos activos."} in events
    assert {"type": "tool", "tool": "search_assets", "status": "completed"} in events
    done = events[-1]
    assert done["type"] == "done"
    assert done["cancelled"] is False
    assert done["actions"] == [
        {"tool": "search_assets", "status": "completed", "assetIds": ["a-1"]}
    ]
    assert done["results"] == [{"kind": "assets", "items": [{"id": "a-1"}]}]
    assert done["approvalPending"] is False
    assert runtime.requests[-1].assetId == asset_id

    stored = client.get(f"{API}/agent/sessions/{session['id']}", headers=headers)
    assert stored.status_code == 200, stored.text
    body = stored.json()
    assert [message["role"] for message in body["messages"]] == ["user", "assistant"]
    assert body["messages"][1]["content"] == "Hay dos activos."
    assert body["actions"] == done["actions"]
    assert body["results"] == done["results"]
    assert body["assetId"] == asset_id

    legacy = client.post(
        f"{API}/agent/chat",
        json={"message": "hola"},
        headers=headers,
    )
    assert legacy.status_code == 200, legacy.text
    assert legacy.json()["message"] == "Hay dos activos."


def test_sessions_are_owned_by_their_human(app_client) -> None:
    catalog, client, settings = app_client
    catalog.add_user("reader-one", "Reader One", "user")
    catalog.add_user("reader-two", "Reader Two", "user")
    runtime = FakeRuntime(ChatReply(message="ok"))
    build_service(client, catalog, runtime=runtime)

    first = login(client, settings, "reader-one")
    session = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": "pydantic", "model": "openai:gpt-4o-mini"},
        headers=first,
    ).json()
    logout(client, first)

    second = login(client, settings, "reader-two")
    assert client.get(f"{API}/agent/sessions/{session['id']}", headers=second).status_code == 404
    assert client.get(f"{API}/agent/sessions", headers=second).json()["sessions"] == []
    assert (
        client.post(
            f"{API}/agent/sessions/{session['id']}/messages",
            json={"message": "intruso"},
            headers=second,
        ).status_code
        == 404
    )
    assert (
        client.patch(
            f"{API}/agent/sessions/{session['id']}",
            json={"model": "openai:gpt-4o-mini"},
            headers=second,
        ).status_code
        == 404
    )
    assert (
        client.post(f"{API}/agent/sessions/{session['id']}/cancel", headers=second).status_code
        == 404
    )
    assert runtime.requests == []


def test_external_discovery_error_is_per_instance(app_client) -> None:
    catalog, client, settings = app_client
    machine, _ = catalog.add_machine("hermes-client", "Hermes Client")
    broken = FakeEngine(
        discover_error=FakeEngineError("unreachable", "engine is unreachable", True)
    )
    build_service(client, catalog, engine_factory=lambda instance, secret: broken)
    headers = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(
        client,
        headers,
        name="Broken OpenCode",
        engine="hermes",
        baseUrl="http://127.0.0.1:9",
        integrationIdentityId=machine.actor_id,
    )

    body = client.get(f"{API}/agent/engines", headers=headers)
    assert body.status_code == 200, body.text
    payload = body.json()
    failed = next(item for item in payload["instances"] if item["id"] == instance["id"])
    assert failed["error"] == "engine is unreachable"
    assert failed["models"] == []
    assert failed["enabled"] is True
    builtin = next(item for item in payload["instances"] if item["id"] == "pydantic")
    assert builtin["models"][0]["id"] == "openai:gpt-4o-mini"


def test_integration_identity_ceiling_denies_stronger_machine(app_client, monkeypatch) -> None:
    catalog, client, settings = app_client
    catalog.add_user("reader-one", "Reader One", "user")
    operator_machine, operator_token = catalog.add_machine("ops-client", "Ops Client", "operator")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", operator_token)
    engine = FakeEngine()
    build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: engine,
        installer=FakeInstaller([{"status": "verified", "verified": True}]),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(
        client, headers=admin, integrationIdentityId=operator_machine.actor_id
    )
    install_verified(client, admin, instance, operator_machine.actor_id)
    logout(client, admin)

    reader = login(client, settings, "reader-one")
    denied = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": instance["id"], "model": "fake/model-a"},
        headers=reader,
    )
    assert denied.status_code == 403, denied.text
    assert "permissions" in denied.json()["error"]["message"]
    assert engine.created == 0


def test_integration_requires_the_bound_mcp_credential_each_run(app_client, monkeypatch) -> None:
    catalog, client, settings = app_client
    bound_machine, bound_token = catalog.add_machine("bound-client", "Bound Client", "operator")
    other_machine, other_token = catalog.add_machine("swapped-client", "Swapped Client", "operator")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", bound_token)
    engine = FakeEngine()
    build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: engine,
        installer=FakeInstaller([{"status": "verified", "verified": True}]),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(
        client, headers=admin, integrationIdentityId=bound_machine.actor_id
    )
    install_verified(client, admin, instance, bound_machine.actor_id)
    session = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": instance["id"], "model": "fake/model-a"},
        headers=admin,
    )
    assert session.status_code == 201, session.text

    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", other_token)
    denied = client.post(
        f"{API}/agent/sessions/{session.json()['id']}/messages",
        json={"message": "hola"},
        headers=admin,
    )
    assert denied.status_code == 403, denied.text
    assert "bound identity" in denied.json()["error"]["message"]
    assert other_token not in denied.text
    assert bound_token not in denied.text
    assert other_machine.actor_id != bound_machine.actor_id
    assert engine.created == 1  # the session was opened before the credential rotated
    assert engine.messages == []


def test_external_session_stream_redacts_usage_and_enforces_local_budget(
    app_client, monkeypatch
) -> None:
    catalog, client, settings = app_client
    settings.agent_daily_token_budget = 5
    catalog.add_user("reader-one", "Reader One", "user")
    machine, machine_token = catalog.add_machine("hermes-client", "Hermes Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", machine_token)
    events = [
        {"type": "session", "sessionId": "external-session-1"},
        {
            "type": "tool",
            "tool": "search_assets",
            "status": "completed",
            "input": {"query": "switch", "token": "leak-me"},
            "output": {"items": [], "authorization": "Bearer leak-me"},
        },
        {"type": "tool", "tool": "legacy_error", "status": "error"},
        {"type": "tool", "tool": "engine_failed", "status": "failed"},
        {"type": "delta", "text": "Dos activos."},
        {
            "type": "usage",
            "inputTokens": 4,
            "outputTokens": 2,
            "totalTokens": 6,
            "totalSource": "provider",
            "precision": "measured",
            "source": "engine",
        },
        {"type": "done", "cancelled": False},
    ]
    engine = FakeEngine(events=events)
    installer = FakeInstaller([{"status": "verified", "verified": True}])
    build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: engine,
        installer=installer,
        catalog_api=FakeCatalog(),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)
    install_verified(client, admin, instance, machine.actor_id)

    reader = admin
    session = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": instance["id"], "model": "fake/model-a"},
        headers=reader,
    )
    assert session.status_code == 201, session.text
    session_id = session.json()["id"]
    assert engine.created == 1
    assert engine.received_ids == []  # only a real turn creates a session on the engine

    with client.stream(
        "POST",
        f"{API}/agent/sessions/{session_id}/messages",
        json={"message": "hola"},
        headers=reader,
    ) as response:
        streamed = read_sse(response)
    assert streamed[0] == {"type": "session", "sessionId": session_id}
    tool = next(event for event in streamed if event["type"] == "tool")
    assert tool["input"]["token"] == "[redacted]"
    terminal = {
        event["tool"]: event["status"]
        for event in streamed
        if event["type"] == "tool" and event["tool"] != "search_assets"
    }
    assert terminal == {"legacy_error": "failed", "engine_failed": "failed"}
    assert "leak-me" not in json.dumps(streamed)
    assert streamed[-1] == {"type": "done", "cancelled": False}

    engines = client.get(f"{API}/agent/engines", headers=reader).json()
    company = engines["budget"]["funding"]["company"]
    assert company["consumedTokens"] == 6
    assert company["availableTokens"] == 0
    blocked = client.post(
        f"{API}/agent/sessions/{session_id}/messages",
        json={"message": "otra vez"},
        headers=reader,
    )
    assert blocked.status_code == 429, blocked.text
    assert engine.messages == ["hola"]

    stored = client.get(f"{API}/agent/sessions/{session_id}", headers=reader).json()
    assert [message["role"] for message in stored["messages"]] == ["user", "assistant"]
    assert (
        stored["messages"][0]["content"] == "Dos activos."
        or stored["messages"][1]["content"] == "Dos activos."
    )


def test_reconnect_does_not_duplicate_usage(app_client, monkeypatch) -> None:
    catalog, client, settings = app_client
    catalog.add_user("reader-one", "Reader One", "user")
    machine, machine_token = catalog.add_machine("hermes-client", "Hermes Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", machine_token)
    engine = FakeEngine(
        events=[
            {
                "type": "usage",
                "inputTokens": 2,
                "outputTokens": 1,
                "totalTokens": 3,
                "totalSource": "provider",
                "precision": "measured",
                "source": "engine",
            },
            {"type": "done", "cancelled": False},
        ]
    )
    build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: engine,
        installer=FakeInstaller([{"status": "verified", "verified": True}]),
        catalog_api=FakeCatalog(),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)
    install_verified(client, admin, instance, machine.actor_id)
    reader = admin
    session_id = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": instance["id"], "model": "fake/model-a"},
        headers=reader,
    ).json()["id"]
    for _ in range(2):
        with client.stream(
            "POST",
            f"{API}/agent/sessions/{session_id}/messages",
            json={"message": "hola"},
            headers=reader,
        ) as response:
            read_sse(response)
        client.get(f"{API}/agent/sessions/{session_id}", headers=reader)
    budget = client.get(f"{API}/agent/engines", headers=reader).json()["budget"]
    assert budget["funding"]["company"]["consumedTokens"] == 6
    assert budget["funding"]["company"]["reservedTokens"] == 0
    assert engine.created == 1  # the external session id was reused


def test_error_events_are_sanitized_and_usage_kept_once(app_client, monkeypatch) -> None:
    catalog, client, settings = app_client
    catalog.add_user("reader-one", "Reader One", "user")
    machine, machine_token = catalog.add_machine("hermes-client", "Hermes Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", machine_token)
    engine = FakeEngine(
        events=[
            {
                "type": "usage",
                "inputTokens": 1,
                "outputTokens": 1,
                "totalTokens": 2,
                "totalSource": "provider",
                "precision": "measured",
                "source": "engine",
            },
            {
                "type": "error",
                "code": "provider",
                "message": "token mcp-token-value failed at http://127.0.0.1:9/private",
                "retryable": True,
            },
            {"type": "done", "cancelled": False},
        ]
    )
    build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: engine,
        installer=FakeInstaller([{"status": "verified", "verified": True}]),
        catalog_api=FakeCatalog(),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)
    install_verified(client, admin, instance, machine.actor_id)
    reader = admin
    session_id = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": instance["id"], "model": "fake/model-a"},
        headers=reader,
    ).json()["id"]
    with client.stream(
        "POST",
        f"{API}/agent/sessions/{session_id}/messages",
        json={"message": "hola"},
        headers=reader,
    ) as response:
        streamed = read_sse(response)
    error = next(event for event in streamed if event["type"] == "error")
    assert error["code"] == "provider"
    assert error["retryable"] is True
    assert "mcp-token-value" not in json.dumps(error)
    assert "127.0.0.1" not in error["message"]
    assert streamed[-1]["type"] == "done"
    budget = client.get(f"{API}/agent/engines", headers=reader).json()["budget"]
    assert budget["funding"]["company"]["consumedTokens"] == 2


def test_installer_failure_detail_survives_public_receipt_without_secrets(
    app_client, monkeypatch
) -> None:
    catalog, client, settings = app_client
    machine, token = catalog.add_machine("failed-installer", "Failed Installer")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", token)
    build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: FakeEngine(),
        installer=FakeInstaller(
            [
                {
                    "status": "failed",
                    "verified": False,
                    "error": {
                        "code": "config_invalid",
                        "message": f"invalid configuration {token}",
                    },
                    "limitations": ["Profile inspection did not complete"],
                }
            ]
        ),
        catalog_api=FakeCatalog(),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)
    receipt = install_verified(client, admin, instance, machine.actor_id)
    assert receipt["error"]["code"] == "config_invalid"
    assert "invalid configuration" in receipt["error"]["message"]
    assert token not in json.dumps(receipt)
    assert receipt["limitations"] == ["Profile inspection did not complete"]
    stored = client.get(f"{API}/agent/integrations", headers=admin).json()["installations"]
    assert next(row for row in stored if row["id"] == receipt["id"])["error"] == receipt["error"]


def test_install_receipts_are_truthful_and_gate_external_chat(app_client, monkeypatch) -> None:
    catalog, client, settings = app_client
    catalog.add_user("reader-one", "Reader One", "user")
    machine, machine_token = catalog.add_machine("hermes-client", "Hermes Client")
    other_machine, _ = catalog.add_machine("other-client", "Other Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", machine_token)
    engine = FakeEngine()
    installer = FakeInstaller(
        [
            {
                "status": "configured",
                "verified": False,
                "checks": [{"id": "mcp", "status": "unverified"}],
            },
            {"status": "verified", "verified": True},
        ]
    )
    build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: engine,
        installer=installer,
        catalog_api=FakeCatalog(),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)

    configured = install_verified(client, admin, instance, machine.actor_id)
    assert configured["status"] == "configured"
    assert configured["verified"] is False
    snapshot = client.get(f"{API}/agent/integrations", headers=admin).json()
    stored = next(row for row in snapshot["installations"] if row["instanceId"] == instance["id"])
    assert stored["verified"] is False
    assert stored["status"] == "configured"
    assert stored["binding"]["identityId"] == machine.actor_id

    logout(client, admin)
    reader = login(client, settings, "reader-one")
    forbidden = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": instance["id"], "model": "fake/model-a"},
        headers=reader,
    )
    assert forbidden.status_code == 403, forbidden.text
    logout(client, reader)

    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    denied = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": instance["id"], "model": "fake/model-a"},
        headers=admin,
    )
    assert denied.status_code == 409, denied.text
    assert "verified" in denied.json()["error"]["message"]

    installed = install_verified(
        client, admin, instance, machine.actor_id, receipt={"status": "verified", "verified": True}
    )
    assert installed["verified"] is True
    snapshot = client.get(f"{API}/agent/integrations", headers=admin).json()
    rows = [row for row in snapshot["installations"] if row["instanceId"] == instance["id"]]
    assert len(rows) == 1
    assert rows[0]["verified"] is True
    assert rows[0]["status"] == "verified"

    mismatch = client.post(
        f"{API}/agent/integrations/install",
        json={
            "instanceId": instance["id"],
            "target": {"engine": "opencode", "path": "/srv/opencode/itsm", "profile": "itsm"},
            "mcp": {
                "url": "http://127.0.0.1:18080/api/v1/mcp",
                "secretRef": "ITSM_TEST_MCP_TOKEN",
                "identityId": other_machine.actor_id,
            },
            "skills": [],
            "operation": "install",
        },
        headers=admin,
    )
    assert mismatch.status_code == 422
    unknown_skill = client.post(
        f"{API}/agent/integrations/install",
        json={
            "instanceId": instance["id"],
            "target": {"engine": "opencode", "path": "/srv/opencode/itsm", "profile": "itsm"},
            "mcp": {
                "url": "http://127.0.0.1:18080/api/v1/mcp",
                "secretRef": "ITSM_TEST_MCP_TOKEN",
                "identityId": machine.actor_id,
            },
            "skills": ["does-not-exist"],
            "operation": "install",
        },
        headers=admin,
    )
    assert unknown_skill.status_code == 422

    logout(client, admin)
    reader = login(client, settings, "reader-one")
    forbidden = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": instance["id"], "model": "fake/model-a"},
        headers=reader,
    )
    assert forbidden.status_code == 403, forbidden.text
    logout(client, reader)

    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    allowed = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": instance["id"], "model": "fake/model-a"},
        headers=admin,
    )
    assert allowed.status_code == 201, allowed.text


def test_verified_runtime_binding_invalidates_on_instance_reconfiguration(
    app_client, monkeypatch
) -> None:
    catalog, client, settings = app_client
    machine, machine_token = catalog.add_machine("binding-machine", "Binding Machine")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", machine_token)
    contacted: list[tuple[str | None, str | None]] = []

    def factory(instance: Any, secret: str | None) -> Any:
        contacted.append((instance.base_url, instance.directory))
        return FakeEngine(events=[{"type": "done", "cancelled": False}])

    build_service(
        client,
        catalog,
        engine_factory=factory,
        installer=FakeInstaller([{"status": "verified", "verified": True}]),
        catalog_api=FakeCatalog(),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(
        client,
        headers=admin,
        integrationIdentityId=machine.actor_id,
        directory="/srv/opencode/itsm",
    )
    install_verified(client, admin, instance, machine.actor_id)
    first = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": instance["id"], "model": "fake/model-a"},
        headers=admin,
    )
    assert first.status_code == 201, first.text
    session_id = first.json()["id"]

    changed = client.put(
        f"{API}/agent/integrations/instances/{instance['id']}",
        json={
            "baseUrl": "http://127.0.0.1:19",
            "directory": "/srv/unrestricted-workspace",
        },
        headers=admin,
    )
    assert changed.status_code == 200, changed.text
    contacted.clear()

    created = client.post(
        f"{API}/agent/sessions",
        json={"instanceId": instance["id"], "model": "fake/model-a"},
        headers=admin,
    )
    assert created.status_code == 409, created.text
    old = client.post(
        f"{API}/agent/sessions/{session_id}/messages",
        json={"message": "Use the changed runtime"},
        headers=admin,
    )
    assert old.status_code == 409, old.text
    assert contacted == []
    stored = client.get(f"{API}/agent/sessions/{session_id}", headers=admin).json()
    assert stored["messages"] == []


def test_module_state_is_persisted_and_applied(app_client) -> None:
    catalog, client, settings = app_client
    catalog_api = FakeCatalog(
        modules=[
            {
                "id": "third-party",
                "name": "Third party",
                "version": "2.0.0",
                "official": False,
                "enabled": True,
                "permissions": ["assets.view"],
                "capabilities": ["tools"],
                "skills": [],
            }
        ]
    )
    synced: list[int] = []
    build_service(client, catalog, catalog_api=catalog_api, extension_sync=lambda: synced.append(1))
    headers = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)

    modules = client.get(f"{API}/agent/integrations/modules", headers=headers)
    assert modules.status_code == 200, modules.text
    assert modules.json()["modules"][0]["enabled"] is True

    disabled = client.put(
        f"{API}/agent/integrations/modules/third-party",
        json={"enabled": False},
        headers=headers,
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json() == {"id": "third-party", "enabled": False, "registered": True}
    assert catalog_api.enabled_calls == [("third-party", False)]
    assert synced == [1]

    unknown = client.put(
        f"{API}/agent/integrations/modules/missing",
        json={"enabled": False},
        headers=headers,
    )
    assert unknown.status_code == 404

    # A fresh service applies the persisted state at startup.
    build_service(client, catalog, catalog_api=catalog_api)
    catalog_api.modules[0]["enabled"] = True
    service = client.app.state.agent_integrations
    service.apply_module_states()
    assert catalog_api.enabled_calls[-1] == ("third-party", False)


def test_run_concurrency_cancel_and_model_switch_are_owner_scoped(app_client, monkeypatch) -> None:
    catalog, client, settings = app_client
    catalog.add_user("reader-one", "Reader One", "user")
    machine, machine_token = catalog.add_machine("hermes-client", "Hermes Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", machine_token)
    engine = FakeEngine(block=True)
    build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: engine,
        installer=FakeInstaller([{"status": "verified", "verified": True}]),
        catalog_api=FakeCatalog(),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)
    install_verified(client, admin, instance, machine.actor_id)
    logout(client, admin)

    principal = catalog.admin()
    service = client.app.state.agent_integrations

    async def scenario() -> None:
        session = await service.create_session(
            principal, {"instanceId": instance["id"], "model": "fake/model-a"}
        )
        session_id = session["id"]
        turn = service.prepare_turn(principal, session_id, "uno", None)
        stream = turn.stream()
        first = await anext(stream)
        assert first == {"type": "session", "sessionId": session_id}
        with pytest.raises(Conflict):
            service.prepare_turn(principal, session_id, "dos", None)
        with pytest.raises(Conflict):
            await service.update_session(principal, session_id, {"model": "fake/model-a"})
        cancelled = await service.cancel_session(principal, session_id)
        assert cancelled["cancelled"] is True
        rest = [event async for event in stream]
        assert rest[-1]["type"] == "done"
        assert rest[-1]["cancelled"] is True
        assert engine.cancelled == 1
        idle = await service.cancel_session(principal, session_id)
        assert idle == {"cancelled": False, "reason": "no active run"}

        changed = await service.update_session(principal, session_id, {"model": "fake/model-a"})
        assert changed["model"] == "fake/model-a"

    asyncio.run(scenario())


def test_stale_run_is_recovered_and_budget_precheck_skips_engine(app_client, monkeypatch) -> None:
    catalog, client, settings = app_client
    catalog.add_user("reader-one", "Reader One", "user")
    machine, machine_token = catalog.add_machine("hermes-client", "Hermes Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", machine_token)
    engine = FakeEngine()
    service = build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: engine,
        installer=FakeInstaller([{"status": "verified", "verified": True}]),
        catalog_api=FakeCatalog(),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)
    install_verified(client, admin, instance, machine.actor_id)
    logout(client, admin)

    principal = catalog.admin()

    async def scenario() -> None:
        session = await service.create_session(
            principal, {"instanceId": instance["id"], "model": "fake/model-a"}
        )
        service.prepare_turn(principal, session["id"], "primero", None)
        # Simulate a killed worker: the row stayed running past the stale window.
        with service._session() as db:
            from itsm.agent_integrations.models import AgentSession

            row = db.get(AgentSession, session["id"])
            assert row is not None
            row.updated_at = row.updated_at.replace(year=2020)
            db.commit()
        turn = service.prepare_turn(principal, session["id"], "segundo", None)
        stream = turn.stream()
        async for _ in stream:
            pass
        assert engine.messages == ["segundo"]

    asyncio.run(scenario())


def test_budget_precheck_blocks_before_engine_call(app_client, monkeypatch) -> None:
    catalog, client, settings = app_client
    catalog.add_user("reader-one", "Reader One", "user")
    machine, machine_token = catalog.add_machine("hermes-client", "Hermes Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", machine_token)
    engine = FakeEngine()
    service = build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: engine,
        installer=FakeInstaller([{"status": "verified", "verified": True}]),
        catalog_api=FakeCatalog(),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)
    install_verified(client, admin, instance, machine.actor_id)

    principal = catalog.admin()
    service._usage.update_policy(principal, company_daily_limit=0)

    async def scenario() -> None:
        session = await service.create_session(
            principal, {"instanceId": instance["id"], "model": "fake/model-a"}
        )
        with pytest.raises(Exception) as excinfo:
            service.prepare_turn(principal, session["id"], "hola", None)
        assert getattr(excinfo.value, "code", None) == "quota_exceeded"
        assert engine.messages == []

    asyncio.run(scenario())


def test_agent_chat_requires_human_actor_and_sessions_reject_extra_fields(app_client) -> None:
    _, client, settings = app_client
    headers = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    extra = client.post(
        f"{API}/agent/sessions",
        json={
            "instanceId": "pydantic",
            "model": "openai:gpt-4o-mini",
            "endpoint": "http://evil",
        },
        headers=headers,
    )
    assert extra.status_code == 422
    assert "endpoint" in extra.text


def test_real_installer_http_composition(app_client, tmp_path, monkeypatch) -> None:
    catalog, client, settings = app_client
    machine, token = catalog.add_machine("seam-machine", "Seam Machine")
    monkeypatch.setenv("ITSM_SEAM_TOKEN", token)
    headers = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=headers, integrationIdentityId=machine.actor_id)
    root = tmp_path / "selected"
    root.mkdir()
    target = {
        "engine": "opencode",
        "path": str(root),
        "profile": "itsm",
        "version": "2.1.2",
    }

    detect = client.post(f"{API}/agent/integrations/targets", json=target, headers=headers)
    assert detect.status_code == 200, detect.text
    assert detect.json()["target"]["path"] == str(root)

    body = {
        "instanceId": instance["id"],
        "target": target,
        "mcp": {
            "url": "http://127.0.0.1:9/api/v1/mcp",
            "secretRef": "ITSM_SEAM_TOKEN",
            "identityId": machine.actor_id,
        },
        "skills": ["itsm-inventory"],
        "operation": "install",
    }
    local = client.post(f"{API}/agent/integrations/install", json=body, headers=headers)
    assert local.status_code == 200, local.text
    assert local.json()["status"] == "configured", local.text
    assert local.json()["target"]["remote"] is False

    remote_body = {
        **body,
        "mode": "remote",
        "target": {**target, "remote": True},
    }
    remote = client.post(f"{API}/agent/integrations/install", json=remote_body, headers=headers)
    assert remote.status_code == 200, remote.text
    exported = remote.json()
    assert exported["status"] == "exported"
    assert exported["target"]["remote"] is True
    assert exported["request"]["kind"] == "itsm-agent-installer-request"
    assert exported["request"]["target"]["path"] == str(root)
    assert exported["requestDigest"] == exported["request"]["requestDigest"]


def test_mcp_reader_lists_core_operations_and_forged_mutation_is_denied(
    app_client, free_tcp_port: int
) -> None:
    catalog, _, settings = app_client
    _, reader = catalog.add_machine("list-reader", "List Reader", "user")
    app = create_app(settings)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=free_tcp_port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started

    url = f"http://127.0.0.1:{free_tcp_port}/api/v1/mcp"

    def names(token: str) -> set[str]:
        async def run() -> set[str]:
            async with Client(
                StreamableHttpTransport(url, headers={"Authorization": f"Bearer {token}"})
            ) as mcp:
                return {tool.name for tool in await mcp.list_tools()}

        return asyncio.run(run())

    try:
        reader_tools = names(reader)
        assert reader_tools == set(TOOL_NAMES)
        assert {
            "search_assets",
            "get_asset",
            "search_people",
            "get_operational_summary",
            "search_everything",
            "list_saved_views",
        } <= reader_tools
        # The baseline exposes no deployment/admin-only operation; readers see the
        # same inventory surface as everyone and canonical service auth decides calls.
        assert not {name for name in reader_tools if "deploy" in name or "admin" in name}

        async def forged() -> None:
            async with Client(
                StreamableHttpTransport(url, headers={"Authorization": f"Bearer {reader}"})
            ) as mcp:
                await mcp.call_tool("create_asset", {"name": "Forged switch"})

        with pytest.raises(ToolError):
            asyncio.run(forged())
        assert catalog.asset_count() == 0
        assert any(
            row["action"] == "assets.edit" and row["outcome"] == "denied" for row in catalog.audit()
        )
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_install_uses_shared_catalog_for_module_skills(app_client, tmp_path, monkeypatch) -> None:
    catalog, client, settings = app_client
    service = client.app.state.agent_integrations
    manifest, module_root = _write_module(tmp_path)
    service._catalog.register_module(manifest, root=module_root)
    machine, machine_token = catalog.add_machine("module-installer", "Module Installer")
    monkeypatch.setenv("ITSM_MODULE_TOKEN", machine_token)
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)
    available = client.get(f"{API}/agent/integrations/catalog", headers=admin).json()
    assert "demo-skill" in [skill["name"] for skill in available["skills"]]
    selected = tmp_path / "selected"
    selected.mkdir()

    response = client.post(
        f"{API}/agent/integrations/install",
        json={
            "instanceId": instance["id"],
            "target": {
                "engine": "opencode",
                "path": str(selected),
                "profile": "itsm",
                "version": "2.1.2",
            },
            "mcp": {
                "url": "http://127.0.0.1:9/api/v1/mcp",
                "secretRef": "ITSM_MODULE_TOKEN",
                "identityId": machine.actor_id,
            },
            "skills": ["demo-skill"],
            "operation": "install",
        },
        headers=admin,
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "configured", response.text
    assert (selected / ".opencode/skills/demo-skill/SKILL.md").is_file()

    remote = client.post(
        f"{API}/agent/integrations/install",
        json={
            "instanceId": instance["id"],
            "target": {
                "engine": "opencode",
                "path": "/srv/opencode/module",
                "profile": "itsm",
                "version": "2.1.2",
            },
            "mcp": {
                "url": "http://127.0.0.1:9/api/v1/mcp",
                "secretRef": "ITSM_MODULE_TOKEN",
                "identityId": machine.actor_id,
            },
            "skills": ["demo-skill"],
            "operation": "install",
            "mode": "remote",
        },
        headers=admin,
    )
    assert remote.status_code == 200, remote.text
    exported = remote.json()
    assert exported["status"] == "exported"
    assert "demo-skill" in exported["request"]["skillDigests"]


def test_remote_request_export_and_receipt_import_are_bound(app_client, monkeypatch) -> None:
    catalog, client, settings = app_client
    machine, machine_token = catalog.add_machine("hermes-client", "Hermes Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", machine_token)
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)

    remote = client.post(
        f"{API}/agent/integrations/install",
        json={
            "instanceId": instance["id"],
            "target": {
                "engine": "opencode",
                "path": "/srv/opencode/itsm",
                "profile": "itsm",
                "version": "2.1.2",
            },
            "mcp": {
                "url": "http://127.0.0.1:18080/api/v1/mcp",
                "secretRef": "ITSM_TEST_MCP_TOKEN",
                "identityId": machine.actor_id,
            },
            "skills": ["itsm-inventory"],
            "operation": "install",
            "mode": "remote",
        },
        headers=admin,
    )
    assert remote.status_code == 200, remote.text
    exported = remote.json()
    assert exported["status"] == "exported"
    assert exported["verified"] is False
    assert exported["target"] == {
        "engine": "opencode",
        "path": "/srv/opencode/itsm",
        "profile": "itsm",
        "version": "2.1.2",
        "remote": True,
    }
    request = exported["request"]
    assert request["kind"] == "itsm-agent-installer-request"
    assert "itsm-inventory" in request["skillDigests"]
    assert exported["requestDigest"] == request["requestDigest"]
    assert exported["binding"]["requestDigest"] == exported["requestDigest"]
    assert exported["mcp"] == {
        "url": "http://127.0.0.1:18080/api/v1/mcp",
        "secretRef": "ITSM_TEST_MCP_TOKEN",
        "identityId": machine.actor_id,
    }
    assert exported["skills"] == ["itsm-inventory"]

    fetched = client.get(
        f"{API}/agent/integrations/installations/{exported['id']}/request",
        headers=admin,
    )
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["request"] == request
    assert fetched.json()["installation"]["target"]["remote"] is True

    receipt = _canonical_receipt(exported, machine.actor_id)
    mismatch = client.post(
        f"{API}/agent/integrations/receipts",
        json={
            "instanceId": instance["id"],
            "requestDigest": "sha256:another-request",
            "receipt": receipt,
        },
        headers=admin,
    )
    assert mismatch.status_code == 422, mismatch.text

    imported = client.post(
        f"{API}/agent/integrations/receipts",
        json={
            "instanceId": instance["id"],
            "requestDigest": exported["requestDigest"],
            "receipt": receipt,
        },
        headers=admin,
    )
    assert imported.status_code == 200, imported.text
    body = imported.json()
    assert body["status"] == "configured"
    assert body["verified"] is False
    assert body["mcpVerified"] is False
    assert body["profileSafetyVerified"] is False
    assert body["binding"]["requestDigest"] == exported["requestDigest"]
    assert any(
        check["name"] == "control.profile" and check["status"] == "fail" for check in body["checks"]
    )

    snapshot = client.get(f"{API}/agent/integrations", headers=admin).json()
    stored = next(item for item in snapshot["installations"] if item["id"] == exported["id"])
    assert stored["target"]["remote"] is True
    assert stored["binding"]["requestDigest"] == exported["requestDigest"]
    assert "request" not in stored


def test_local_install_uses_trusted_inspector_and_never_caller_evidence(
    app_client, tmp_path, monkeypatch
) -> None:
    catalog, client, settings = app_client
    machine, token = catalog.add_machine("inspector-machine", "Inspector Machine")
    monkeypatch.setenv("ITSM_INSPECTOR_TOKEN", token)
    headers = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    root = tmp_path / "workspace"
    root.mkdir()
    instance = configure_instance(
        client,
        headers=headers,
        baseUrl="http://127.0.0.1:14963",
        directory=str(root),
        integrationIdentityId=machine.actor_id,
    )
    service = build_service(client, catalog)
    inspected: list[dict[str, Any]] = []

    async def verify_connection(_mcp: dict[str, Any]) -> dict[str, Any]:
        return {"verified": True, "checks": [{"name": "mcp.handshake", "status": "pass"}]}

    async def profile_safety(
        instance_snapshot: Any,
        target: Any,
        mcp: dict[str, Any],
        skills: list[str],
        receipt: dict[str, Any],
    ) -> dict[str, Any]:
        digest = receipt["configDigest"]
        inspected.append(
            {
                "instance": instance_snapshot,
                "target": target,
                "mcp": mcp,
                "skills": skills,
                "digest": digest,
            }
        )
        permissions = [
            {"action": "*", "resource": "*", "effect": "deny"},
            {"action": "itsm_*", "resource": "*", "effect": "allow"},
            {"action": "skill", "resource": "*", "effect": "deny"},
        ]
        permissions.extend(
            {"action": "skill", "resource": skill, "effect": "allow"} for skill in skills
        )
        return {
            "verified": True,
            "source": "opencode:http://127.0.0.1:14963",
            "configDigest": digest,
            "targetPath": target.path,
            "location": {"directory": target.path},
            "agent": {
                "id": "itsm",
                "mode": "primary",
                "hidden": False,
                "permissions": permissions,
            },
            "config": [
                {"type": "directory", "path": f"{target.path}/.opencode"},
                {
                    "type": "document",
                    "path": f"{target.path}/opencode.json",
                    "info": {"default_agent": "itsm"},
                },
            ],
            "skills": {
                "location": {"directory": target.path},
                "data": [
                    {
                        "id": skill,
                        "name": skill,
                        "path": f"{target.path}/.opencode/skills/{skill}/SKILL.md",
                    }
                    for skill in skills
                ]
                + [
                    {
                        "id": "opencode.skill",
                        "name": "opencode",
                        "path": "/builtin/opencode.md",
                    }
                ],
            },
            "savedPermissions": [],
            "checks": [{"name": "inspection.config", "status": "pass"}],
        }

    monkeypatch.setattr(installer_module, "verify_connection", verify_connection)
    monkeypatch.setattr(service, "_opencode_profile_safety", profile_safety)
    response = client.post(
        f"{API}/agent/integrations/install",
        json={
            "instanceId": instance["id"],
            "target": {
                "engine": "opencode",
                "path": str(root),
                "profile": "itsm",
                "version": "2.1.2",
            },
            "mcp": {
                "url": "http://127.0.0.1:18080/api/v1/mcp",
                "secretRef": "ITSM_INSPECTOR_TOKEN",
                "identityId": machine.actor_id,
            },
            "skills": ["itsm-inventory"],
            "operation": "install",
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "verified", body.get("error") or body.get("checks")
    assert body["verified"] is True
    assert body["profileSafetyVerified"] is True
    assert any(
        check["name"] == "profile.safety" and check["status"] == "pass" for check in body["checks"]
    )
    assert len(inspected) == 1
    call = inspected[0]
    assert call["target"].path == str(root)
    assert call["skills"] == ["itsm-inventory"]
    assert call["digest"].startswith("sha256:")
    assert call["mcp"]["url"] == "http://127.0.0.1:18080/api/v1/mcp"


def test_opencode_inspection_uses_engine_basic_auth_and_v2_actions(app_client, monkeypatch) -> None:
    catalog, client, _ = app_client
    monkeypatch.setenv("OPENCODE_ENGINE_PASSWORD", "engine-password")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", "unrelated-mcp-token")
    service = build_service(client, catalog)
    expected = "Basic " + base64.b64encode(b"opencode:engine-password").decode()
    seen: list[tuple[str, str | None]] = []
    state: dict[str, Any] = {"agent_ready": True, "session": None}
    agent_permissions = [
        {"action": "*", "resource": "*", "effect": "allow"},
        {"action": "read", "resource": "*.env", "effect": "ask"},
        {"action": "*", "resource": "*", "effect": "deny"},
        {"action": "itsm_*", "resource": "*", "effect": "allow"},
        {"action": "skill", "resource": "*", "effect": "deny"},
        {"action": "skill", "resource": "itsm-inventory", "effect": "allow"},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        authorization = request.headers.get("authorization")
        seen.append((request.url.path, authorization))
        if authorization != expected:
            return httpx.Response(401)
        if request.url.path in {"/api/config", "/api/agent/itsm"}:
            assert request.url.params["location[directory]"] == "/srv/opencode/itsm"
        if request.url.path == "/api/config":
            return httpx.Response(
                200,
                json=[
                    {"type": "directory", "path": "/srv/opencode/itsm/.opencode"},
                    {
                        "type": "document",
                        "path": "/srv/opencode/itsm/opencode.json",
                        "info": {
                            "mcp": {
                                "servers": {
                                    "itsm": {
                                        "type": "remote",
                                        "url": "http://127.0.0.1:18080/api/v1/mcp",
                                        "disabled": False,
                                        "headers": {
                                            "Authorization": "Bearer {env:ITSM_TEST_MCP_TOKEN}"
                                        },
                                    }
                                }
                            },
                            "default_agent": "itsm",
                            "provider": {"apiKey": "provider-secret"},
                        },
                    },
                ],
            )
        if request.url.path == "/api/skill":
            assert request.url.params["location[directory]"] == "/srv/opencode/itsm"
            return httpx.Response(
                200,
                json={
                    "location": {"directory": "/srv/opencode/itsm"},
                    "data": [
                        {
                            "id": "itsm-inventory",
                            "name": "itsm-inventory",
                            "path": ("/srv/opencode/itsm/.opencode/skills/itsm-inventory/SKILL.md"),
                        },
                        {
                            "id": "opencode.skill",
                            "name": "opencode",
                            "path": "/builtin/opencode.md",
                        },
                    ],
                },
            )
        if request.url.path == "/api/agent/itsm":
            if not state["agent_ready"]:
                return httpx.Response(404)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": "itsm",
                        "mode": "primary",
                        "hidden": False,
                        "system": "provider-secret instructions",
                        "request": {"headers": {"Authorization": "Bearer provider-secret"}},
                        "permissions": agent_permissions,
                    }
                },
            )
        if request.url.path == "/api/session" and request.method == "POST":
            body = json.loads(request.content)
            assert body["location"] == {"directory": "/srv/opencode/itsm"}
            state["agent_ready"] = True
            state["session"] = "ses_itsm_inspection"
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": "ses_itsm_inspection",
                        "location": {"directory": "/srv/opencode/itsm"},
                    }
                },
            )
        if request.url.path == "/api/session/ses_itsm_inspection":
            assert request.method == "DELETE"
            state["session"] = None
            return httpx.Response(200, json=True)
        if request.url.path == "/api/permission/saved":
            return httpx.Response(200, json={"data": []})
        return httpx.Response(404)

    real_client = httpx.AsyncClient

    def client_factory(**kwargs: Any) -> httpx.AsyncClient:
        return real_client(**kwargs, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)

    async def discovered(_instance: Any) -> dict[str, Any]:
        return {"version": "2.1.2"}

    monkeypatch.setattr(service, "_discover", discovered)
    instance = SimpleNamespace(
        base_url="http://127.0.0.1:14963",
        secret_ref="OPENCODE_ENGINE_PASSWORD",
        username="opencode",
        directory="/srv/opencode/itsm",
    )
    target = SimpleNamespace(path="/srv/opencode/itsm", version="2.1.2", profile="itsm")
    mcp = {
        "url": "http://127.0.0.1:18080/api/v1/mcp",
        "secretRef": "ITSM_TEST_MCP_TOKEN",
        "identityId": "machine-identity",
    }
    receipt = {"configDigest": "sha256:" + "a" * 64}

    evidence = asyncio.run(
        service._opencode_profile_safety(instance, target, mcp, ["itsm-inventory"], receipt)
    )
    assert evidence is not None, seen
    assert evidence["verified"] is True
    assert evidence["configDigest"] == receipt["configDigest"]
    assert "provider-secret" not in json.dumps(evidence)
    assert evidence["agent"] == {
        "id": "itsm",
        "mode": "primary",
        "hidden": False,
        "permissions": agent_permissions,
    }
    assert evidence["config"] == [
        {"type": "directory", "path": "/srv/opencode/itsm/.opencode"},
        {
            "type": "document",
            "path": "/srv/opencode/itsm/opencode.json",
            "info": {"default_agent": "itsm"},
        },
    ]
    assert evidence["skills"] == {
        "location": {"directory": "/srv/opencode/itsm"},
        "data": [
            {
                "id": "itsm-inventory",
                "name": "itsm-inventory",
                "path": "/srv/opencode/itsm/.opencode/skills/itsm-inventory/SKILL.md",
            },
            {
                "id": "opencode.skill",
                "name": "opencode",
                "path": "/builtin/opencode.md",
            },
        ],
    }
    assert seen == [
        ("/api/config", expected),
        ("/api/agent/itsm", expected),
        ("/api/permission/saved", expected),
        ("/api/skill", expected),
    ]

    state["agent_ready"] = False
    seen.clear()
    lazy = asyncio.run(
        service._opencode_profile_safety(instance, target, mcp, ["itsm-inventory"], receipt)
    )
    assert lazy == evidence
    assert state["session"] is None
    assert seen == [
        ("/api/config", expected),
        ("/api/agent/itsm", expected),
        ("/api/session", expected),
        ("/api/agent/itsm", expected),
        ("/api/session/ses_itsm_inspection", expected),
        ("/api/permission/saved", expected),
        ("/api/skill", expected),
    ]

    # An uppercase server/action grant is not the installer's managed contract.
    agent_permissions[3] = {"action": "ITSM_*", "resource": "*", "effect": "allow"}
    assert (
        asyncio.run(
            service._opencode_profile_safety(instance, target, mcp, ["itsm-inventory"], receipt)
        )
        is None
    )

    # Grants or asks added after the final deny-all are effective and rejected.
    agent_permissions[3] = {"action": "itsm_*", "resource": "*", "effect": "allow"}
    for later in (
        {"action": "read", "resource": "*", "effect": "allow"},
        {"action": "read", "resource": "*.env", "effect": "ask"},
        {"action": "skill", "resource": "other-skill", "effect": "allow"},
    ):
        agent_permissions.append(later)
        assert (
            asyncio.run(
                service._opencode_profile_safety(instance, target, mcp, ["itsm-inventory"], receipt)
            )
            is None
        ), later
        agent_permissions.pop()


def test_opencode_engine_composition_uses_server_basic_auth(app_client, monkeypatch) -> None:
    catalog, client, _ = app_client
    monkeypatch.setenv("OPENCODE_ENGINE_PASSWORD", "engine-password")
    monkeypatch.setenv("HERMES_SERVER_TOKEN", "hermes-token")
    service = build_service(client, catalog)
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("authorization"))
        return httpx.Response(200, json={"version": "2.1.2"})

    real_client = httpx.AsyncClient

    def client_factory(**kwargs: Any) -> httpx.AsyncClient:
        return real_client(**kwargs, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)
    opencode = service._build_engine(
        SimpleNamespace(
            engine="opencode",
            base_url="http://127.0.0.1:14963",
            secret_ref="OPENCODE_ENGINE_PASSWORD",
            username="opencode",
            directory="/srv/opencode/itsm",
            profile="itsm",
        )
    )
    assert opencode.config.token is None
    assert opencode.config.username == "opencode"
    assert opencode.config.password == "engine-password"
    asyncio.run(opencode._request("GET", "/api/info"))
    assert seen == ["Basic " + base64.b64encode(b"opencode:engine-password").decode()]

    hermes = service._build_engine(
        SimpleNamespace(
            engine="hermes",
            base_url="http://127.0.0.1:14964",
            secret_ref="HERMES_SERVER_TOKEN",
            username=None,
            directory=None,
            profile=None,
        )
    )
    assert hermes.config.token == "hermes-token"
    assert hermes.config.username is None
    assert hermes.config.password is None
    asyncio.run(hermes._request("GET", "/api/info"))
    assert seen[-1] == "Bearer hermes-token"


def test_self_certified_receipt_cannot_verify_without_engine_inspection(
    app_client, monkeypatch
) -> None:
    catalog, client, settings = app_client
    machine, machine_token = catalog.add_machine("forgery-client", "Forgery Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", machine_token)
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)
    exported = client.post(
        f"{API}/agent/integrations/install",
        json={
            "instanceId": instance["id"],
            "target": {
                "engine": "opencode",
                "path": "/srv/opencode/itsm",
                "profile": "itsm",
                "version": "2.1.2",
            },
            "mcp": {
                "url": "http://127.0.0.1:18080/api/v1/mcp",
                "secretRef": "ITSM_TEST_MCP_TOKEN",
                "identityId": machine.actor_id,
            },
            "skills": ["itsm-inventory"],
            "operation": "install",
            "mode": "remote",
        },
        headers=admin,
    ).json()

    service = client.app.state.agent_integrations

    async def reachable_mcp(mcp: dict[str, str]) -> dict[str, Any]:
        return {"verified": True, "checks": [{"name": "mcp", "status": "pass"}]}

    async def unavailable_engine(*args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(service, "_verify_connection", reachable_mcp)
    monkeypatch.setattr(service, "_opencode_profile_safety", unavailable_engine)
    forged = _canonical_receipt(exported, machine.actor_id)
    forged["checks"] = [
        {"name": "profile.safety", "status": "pass"},
        {"name": "mcp.handshake", "status": "pass"},
    ]
    forged["receiptDigest"] = receipt_digest(forged)

    imported = client.post(
        f"{API}/agent/integrations/receipts",
        json={
            "instanceId": instance["id"],
            "requestDigest": exported["requestDigest"],
            "receipt": forged,
        },
        headers=admin,
    )
    assert imported.status_code == 200, imported.text
    body = imported.json()
    assert body["verified"] is False
    assert body["status"] == "configured"
    assert body["mcpVerified"] is True
    assert body["profileSafetyVerified"] is False
    assert any(
        check["name"] == "control.profile" and check["status"] == "fail" for check in body["checks"]
    )
    assert not any(check["name"] == "profile.safety" for check in body["checks"])


def test_verify_reuses_installed_skill_names_from_the_stored_binding(
    app_client, monkeypatch
) -> None:
    catalog, client, settings = app_client
    machine, token = catalog.add_machine("binding-skills", "Binding Skills")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", token)
    receipt_skills = [{"name": "itsm-inventory", "version": "1.0.0", "digest": "a" * 64}]
    installer = VerifyingInstaller(
        [{"skills": list(receipt_skills)}, {"skills": list(receipt_skills)}]
    )
    build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: FakeEngine(),
        installer=installer,
        catalog_api=FakeCatalog(),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)

    installed = install_verified(client, admin, instance, machine.actor_id)
    assert installed["skills"] == ["itsm-inventory"]
    stored = client.get(f"{API}/agent/integrations", headers=admin).json()["installations"]
    assert next(row for row in stored if row["id"] == installed["id"])["skills"] == [
        "itsm-inventory"
    ]

    verified = client.post(
        f"{API}/agent/integrations/install",
        json={
            "instanceId": instance["id"],
            "target": {"engine": "opencode", "path": "/srv/opencode/itsm", "profile": "itsm"},
            "operation": "verify",
        },
        headers=admin,
    )
    assert verified.status_code == 200, verified.text
    body = verified.json()
    assert body["status"] == "verified", body
    assert body["verified"] is True
    assert body["skills"] == ["itsm-inventory"]
    assert body["binding"]["skills"] == ["itsm-inventory"]
    assert installer.calls[-1]["operation"] == "verify"
    assert installer.calls[-1]["skills"] == ["itsm-inventory"]


def test_failed_verify_preserves_the_binding_for_the_next_retry(app_client, monkeypatch) -> None:
    catalog, client, settings = app_client
    machine, token = catalog.add_machine("retry-skills", "Retry Skills")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", token)
    receipt_skills = [{"name": "itsm-inventory", "version": "1.0.0", "digest": "a" * 64}]
    installer = VerifyingInstaller(
        [
            {"skills": list(receipt_skills)},
            {
                "status": "failed",
                "verified": False,
                "error": {"code": "mcp_unreachable", "message": "MCP handshake failed"},
            },
            {"skills": list(receipt_skills)},
        ]
    )
    build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: FakeEngine(),
        installer=installer,
        catalog_api=FakeCatalog(),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)
    installed = install_verified(client, admin, instance, machine.actor_id)
    assert installed["skills"] == ["itsm-inventory"]

    payload = {
        "instanceId": instance["id"],
        "target": {"engine": "opencode", "path": "/srv/opencode/itsm", "profile": "itsm"},
        "operation": "verify",
    }
    failed = client.post(f"{API}/agent/integrations/install", json=payload, headers=admin)
    assert failed.status_code == 200, failed.text
    failure = failed.json()
    assert failure["status"] == "failed", failure
    assert failure["verified"] is False
    assert failure["skills"] == ["itsm-inventory"]
    stored = client.get(f"{API}/agent/integrations", headers=admin).json()["installations"]
    row = next(item for item in stored if item["id"] == installed["id"])
    assert row["status"] == "failed"
    assert row["verified"] is False
    assert row["skills"] == ["itsm-inventory"]
    assert row["binding"]["skills"] == ["itsm-inventory"]

    retried = client.post(f"{API}/agent/integrations/install", json=payload, headers=admin)
    assert retried.status_code == 200, retried.text
    recovered = retried.json()
    assert recovered["status"] == "verified", recovered
    assert recovered["verified"] is True
    assert recovered["skills"] == ["itsm-inventory"]
    assert installer.calls[-1]["skills"] == ["itsm-inventory"]


def test_first_install_still_requires_a_skill_selection(app_client, monkeypatch) -> None:
    catalog, client, settings = app_client
    machine, token = catalog.add_machine("first-install", "First Install")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", token)
    installer = FakeInstaller([])
    build_service(
        client,
        catalog,
        engine_factory=lambda instance, secret: FakeEngine(),
        installer=installer,
        catalog_api=FakeCatalog(),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = configure_instance(client, headers=admin, integrationIdentityId=machine.actor_id)

    response = client.post(
        f"{API}/agent/integrations/install",
        json={
            "instanceId": instance["id"],
            "target": {"engine": "opencode", "path": "/srv/opencode/itsm", "profile": "itsm"},
            "mcp": {
                "url": "http://127.0.0.1:18080/api/v1/mcp",
                "secretRef": "ITSM_TEST_MCP_TOKEN",
                "identityId": machine.actor_id,
            },
            "operation": "install",
        },
        headers=admin,
    )
    assert response.status_code == 422, response.text
    assert response.json()["error"]["message"] == "skills are required for the first installation"
    assert installer.calls == []
    assert client.get(f"{API}/agent/integrations", headers=admin).json()["installations"] == []


@pytest.mark.parametrize("constructor_fails", [False, True])
def test_managed_dispatch_binds_real_gateway_and_revokes_lease(
    app_client, monkeypatch, constructor_fails
) -> None:
    from itsm.agents import managed as managed_module
    from itsm.ai_gateway import AiGatewayService
    from itsm.ai_gateway import service as gateway_module
    from itsm.ai_gateway.models import AiGatewayLease
    from pydantic import SecretStr
    from sqlalchemy import select

    catalog, client, settings = app_client
    settings.ai_credential_key = SecretStr("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    settings.ai_managed_gateway_url = "http://127.0.0.1:18080/api/v1/agent/gateway/v1"
    settings.agent_max_output_tokens = 10
    machine, token = catalog.add_machine("managed-client", "Managed Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", token)
    skills = FakeCatalog()
    skills.skills["itsm-inventory"]["files"] = {"SKILL.md": b"# Inventory\n"}
    service = build_service(
        client,
        catalog,
        installer=FakeInstaller([{"skills": ["itsm-inventory"]}]),
        catalog_api=skills,
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    provider = client.post(
        f"{API}/agent/providers",
        headers=admin,
        json={
            "scope": "global",
            "name": "Managed provider",
            "baseUrl": "http://127.0.0.1:18081/v1",
            "models": ["model-a"],
            "apiKey": "test-only-upstream-key",
        },
    )
    assert provider.status_code == 201, provider.text
    instance = configure_instance(
        client,
        admin,
        integrationIdentityId=machine.actor_id,
        quotaMode="managed",
        managedProviderId=provider.json()["id"],
        managedContextTokens=20,
        directCompanyException=False,
        defaultModel="model-a",
    )
    assert install_verified(client, admin, instance, machine.actor_id)["verified"]
    upstream_requests = []
    lease_tokens = []
    closed = []

    def upstream(request):
        upstream_requests.append(request)
        assert request.headers["Authorization"] == "Bearer test-only-upstream-key"
        assert json.loads(request.content)["model"] == "model-a"
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"role": "assistant", "content": "managed reply"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            },
        )

    monkeypatch.setattr(
        gateway_module,
        "provider_http_client",
        lambda **kwargs: httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
    )

    class NativeBoundary:
        native_model = "itsm/model-a"

        def __init__(self, config, instance, lease, gateway_url, *, profile):
            self.lease = lease
            lease_tokens.append(lease.bearer_token)
            if constructor_fails:
                raise ValueError("invalid native profile")

        async def start(self):
            pass

        async def create_session(self):
            return "managed-session"

        async def stream(self, message, **kwargs):
            gateway = AiGatewayService(settings, catalog.factory(), service._usage)
            context = gateway.authenticate(self.lease.bearer_token)
            result = await gateway.chat(
                context,
                {
                    "model": "model-a",
                    "messages": [{"role": "user", "content": message}],
                    "max_tokens": 10,
                },
            )
            assert result.status_code == 200
            yield {"type": "delta", "text": "managed reply"}
            yield {"type": "done", "cancelled": False}

        async def aclose(self):
            closed.append(True)

    monkeypatch.setattr(managed_module, "ManagedEngineRunner", NativeBoundary)
    created = client.post(
        f"{API}/agent/sessions",
        headers=admin,
        json={"instanceId": instance["id"], "model": "model-a"},
    )
    assert created.status_code == 201, created.text
    response = client.post(
        f"{API}/agent/sessions/{created.json()['id']}/messages",
        headers=admin,
        json={"message": "hola"},
    )
    assert response.status_code == 200, response.text
    events = read_sse(response)
    assert lease_tokens, events
    if constructor_fails:
        assert any(event["type"] == "error" for event in events)
        assert not upstream_requests
        assert not closed
    else:
        assert any(event.get("text") == "managed reply" for event in events), events
        assert len(upstream_requests) == 1
        assert closed == [True]
    with catalog.factory()() as db:
        leases = db.scalars(select(AiGatewayLease)).all()
        assert len(leases) == 1
        assert leases[0].revoked_at is not None
    own = client.get(f"{API}/agent/usage/me", headers=admin).json()["funding"]
    assert own["company"]["consumedTokens"] == (0 if constructor_fails else 5)
    assert own["personal"]["consumedTokens"] == 0
    assert own["company"]["reservedTokens"] == 0
    assert all(secret not in response.text for secret in lease_tokens)


# ------------------------------------------------ managed personal provider binding
PERSONAL_KEY = "sk-personal-owner-only"
GLOBAL_KEY = "sk-global-upstream"


def _personal_provider(
    client: TestClient,
    headers: dict[str, str],
    *,
    name: str = "Personal provider",
    models: tuple[str, ...] = ("personal-a",),
    api_key: str = PERSONAL_KEY,
) -> dict[str, Any]:
    response = client.post(
        f"{API}/agent/providers",
        headers=headers,
        json={
            "scope": "personal",
            "name": name,
            "baseUrl": "https://api.example.com/v1",
            "models": list(models),
            "apiKey": api_key,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _second_owner(
    catalog: Any, client: TestClient, settings: Settings, username: str
) -> dict[str, str]:
    """Another signed-in person; owner role keeps the personal-provider grant."""

    with catalog.session() as session:
        catalog.service(session).create_user(
            catalog.admin(),
            username=username,
            name="Second Owner",
            password=MACHINE_PASSWORD,
            role_id="superadmin",
        )
    return login(client, settings, username)


def _managed_setup(
    catalog: Any,
    client: TestClient,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    upstream: Callable[[httpx.Request], httpx.Response],
    *,
    machine_name: str = "managed-personal",
) -> tuple[dict[str, str], dict[str, Any], AgentIntegrationService, list[dict[str, Any]]]:
    """A verified managed instance plus a native boundary that spends through the gateway."""
    from itsm.agents import managed as managed_module
    from itsm.ai_gateway import AiGatewayService
    from itsm.ai_gateway import service as gateway_module
    from pydantic import SecretStr

    settings.ai_credential_key = SecretStr("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    settings.ai_managed_gateway_url = "http://127.0.0.1:18080/api/v1/agent/gateway/v1"
    settings.agent_max_output_tokens = 10
    machine, token = catalog.add_machine(machine_name, "Managed Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", token)
    skills = FakeCatalog()
    skills.skills["itsm-inventory"]["files"] = {"SKILL.md": b"# Inventory\n"}
    service = build_service(
        client,
        catalog,
        installer=FakeInstaller([{"skills": ["itsm-inventory"]}]),
        catalog_api=skills,
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    provider = client.post(
        f"{API}/agent/providers",
        headers=admin,
        json={
            "scope": "global",
            "name": "Managed provider",
            "baseUrl": "http://127.0.0.1:18081/v1",
            "models": ["model-a"],
            "apiKey": GLOBAL_KEY,
        },
    )
    assert provider.status_code == 201, provider.text
    instance = configure_instance(
        client,
        admin,
        integrationIdentityId=machine.actor_id,
        quotaMode="managed",
        managedProviderId=provider.json()["id"],
        managedContextTokens=20,
        directCompanyException=False,
        defaultModel="model-a",
    )
    assert install_verified(client, admin, instance, machine.actor_id)["verified"]
    monkeypatch.setattr(
        gateway_module,
        "provider_http_client",
        lambda **kwargs: httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
    )
    leases: list[dict[str, Any]] = []

    class NativeBoundary:
        native_model = None

        def __init__(
            self, config: Any, instance: Any, lease: Any, gateway_url: str, *, profile: Any
        ):
            self.lease = lease
            leases.append({"lease": lease, "profile": profile, "gateway_url": gateway_url})

        async def start(self) -> None:
            pass

        async def create_session(self) -> str:
            return "managed-session"

        async def stream(self, message: str, **kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            gateway = AiGatewayService(settings, catalog.factory(), service._usage)
            context = gateway.authenticate(self.lease.bearer_token)
            result = await gateway.chat(
                context,
                {
                    "model": context.model,
                    "messages": [{"role": "user", "content": message}],
                    "max_tokens": 10,
                },
            )
            assert result.status_code == 200, result.body
            yield {"type": "delta", "text": "managed reply"}
            yield {"type": "done", "cancelled": False}

        async def aclose(self) -> None:
            pass

    monkeypatch.setattr(managed_module, "ManagedEngineRunner", NativeBoundary)
    return admin, instance, service, leases


def _usage_funding(client: TestClient, headers: dict[str, str]) -> dict[str, Any]:
    response = client.get(f"{API}/agent/usage/me", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["funding"]


def _send(client: TestClient, headers: dict[str, str], session_id: str) -> list[dict[str, Any]]:
    response = client.post(
        f"{API}/agent/sessions/{session_id}/messages",
        headers=headers,
        json={"message": "hola"},
    )
    assert response.status_code == 200, response.text
    return read_sse(response)


def _lease_rows(catalog: Any) -> list[Any]:
    from itsm.ai_gateway.models import AiGatewayLease
    from sqlalchemy import select

    with catalog.factory()() as db:
        return list(db.scalars(select(AiGatewayLease).order_by(AiGatewayLease.created_at)).all())


def test_managed_personal_run_leases_the_owners_provider_without_exposing_its_key(
    app_client, monkeypatch
) -> None:
    from itsm.agent_integrations.providers import unseal_credential

    catalog, client, settings = app_client
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        assert request.headers["Authorization"] == f"Bearer {PERSONAL_KEY}"
        assert json.loads(request.content)["model"] == "personal-a"
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"role": "assistant", "content": "personal reply"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            },
        )

    admin, instance, _, leases = _managed_setup(catalog, client, settings, monkeypatch, upstream)
    personal = _personal_provider(client, admin)
    created = client.post(
        f"{API}/agent/sessions",
        headers=admin,
        json={"instanceId": instance["id"], "model": "personal-a", "providerId": personal["id"]},
    )
    assert created.status_code == 201, created.text
    assert created.json()["providerId"] == personal["id"]

    events = _send(client, admin, created.json()["id"])
    assert any(event.get("text") == "managed reply" for event in events), events
    assert len(upstream_requests) == 1

    rows = _lease_rows(catalog)
    assert len(rows) == 1
    lease = rows[0]
    assert lease.provider_id == personal["id"]
    assert lease.provider_scope == "personal"
    assert lease.funding == "personal"
    assert lease.model == "personal-a"
    assert lease.revoked_at is not None
    assert PERSONAL_KEY not in lease.selection_ciphertext
    selection = json.loads(unseal_credential(settings, lease.selection_ciphertext))
    assert selection == {
        "base_url": "https://api.example.com/v1",
        "model": "personal-a",
        "api_key": PERSONAL_KEY,
        "allow_private": False,
    }

    boundary = leases[0]
    assert boundary["lease"].bearer_token != PERSONAL_KEY
    assert boundary["profile"].mcp_token != PERSONAL_KEY
    assert PERSONAL_KEY not in repr(boundary["profile"])
    assert PERSONAL_KEY not in repr(boundary["lease"])
    funding = _usage_funding(client, admin)
    assert funding["personal"]["consumedTokens"] == 5
    assert funding["company"]["consumedTokens"] == 0


def test_managed_provider_selection_treats_another_persons_provider_as_missing(
    app_client, monkeypatch
) -> None:
    catalog, client, settings = app_client

    def upstream(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"role": "assistant", "content": "reply"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            },
        )

    admin, instance, _, _ = _managed_setup(catalog, client, settings, monkeypatch, upstream)
    alice_provider = _personal_provider(client, admin, name="Alice personal")
    bea = _second_owner(catalog, client, settings, "bea.admin")
    missing_id = "00000000-0000-0000-0000-000000000000"

    created = client.post(
        f"{API}/agent/sessions",
        headers=bea,
        json={"instanceId": instance["id"], "model": "model-a"},
    )
    assert created.status_code == 201, created.text
    session_id = created.json()["id"]

    foreign = client.patch(
        f"{API}/agent/sessions/{session_id}",
        headers=bea,
        json={"providerId": alice_provider["id"]},
    )
    absent = client.patch(
        f"{API}/agent/sessions/{session_id}",
        headers=bea,
        json={"providerId": missing_id},
    )
    assert foreign.status_code == 404, foreign.text
    assert foreign.json() == absent.json()

    foreign_create = client.post(
        f"{API}/agent/sessions",
        headers=bea,
        json={
            "instanceId": instance["id"],
            "model": "personal-a",
            "providerId": alice_provider["id"],
        },
    )
    absent_create = client.post(
        f"{API}/agent/sessions",
        headers=bea,
        json={"instanceId": instance["id"], "model": "personal-a", "providerId": missing_id},
    )
    assert foreign_create.status_code == 404, foreign_create.text
    assert foreign_create.json() == absent_create.json()
    assert (
        client.get(f"{API}/agent/sessions/{session_id}", headers=bea).json()["providerId"] is None
    )

    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    disabled = client.patch(
        f"{API}/agent/providers/{alice_provider['id']}",
        headers=admin,
        json={"enabled": False},
    )
    assert disabled.status_code == 200, disabled.text
    rejected_disabled = client.post(
        f"{API}/agent/sessions",
        headers=admin,
        json={
            "instanceId": instance["id"],
            "model": "personal-a",
            "providerId": alice_provider["id"],
        },
    )
    assert rejected_disabled.status_code == 422, rejected_disabled.text
    assert rejected_disabled.json()["error"]["code"] == "validation_error"

    deleted = client.delete(f"{API}/agent/providers/{alice_provider['id']}", headers=admin)
    assert deleted.status_code in {200, 404}, deleted.text
    deleted_create = client.post(
        f"{API}/agent/sessions",
        headers=admin,
        json={
            "instanceId": instance["id"],
            "model": "personal-a",
            "providerId": alice_provider["id"],
        },
    )
    assert deleted_create.status_code == 404, deleted_create.text
    assert deleted_create.json() == absent_create.json()


def test_direct_engine_rejects_a_provider_selection(app_client, monkeypatch) -> None:
    from pydantic import SecretStr

    catalog, client, settings = app_client
    settings.ai_credential_key = SecretStr("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    machine, token = catalog.add_machine("direct-client", "Direct Client")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", token)
    build_service(
        client,
        catalog,
        installer=FakeInstaller([{"skills": ["itsm-inventory"]}]),
        catalog_api=FakeCatalog(),
    )
    admin = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    personal = _personal_provider(client, admin)
    instance = configure_instance(client, admin, integrationIdentityId=machine.actor_id)
    assert install_verified(client, admin, instance, machine.actor_id)["verified"]

    rejected = client.post(
        f"{API}/agent/sessions",
        headers=admin,
        json={
            "instanceId": instance["id"],
            "model": "personal-a",
            "providerId": personal["id"],
        },
    )
    assert rejected.status_code == 422, rejected.text
    assert rejected.json()["error"]["message"] == "direct engines cannot select a provider"

    with catalog.factory()() as db:
        from itsm.agent_integrations.models import AgentSession
        from sqlalchemy import select

        assert db.scalars(select(AgentSession)).all() == []


def test_managed_session_switching_attributes_each_turn_to_the_used_scope(
    app_client, monkeypatch
) -> None:
    catalog, client, settings = app_client
    seen_keys: list[str] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        authorization = request.headers["Authorization"]
        seen_keys.append(authorization)
        body = json.loads(request.content)
        expected = PERSONAL_KEY if body["model"] == "personal-a" else GLOBAL_KEY
        assert authorization == f"Bearer {expected}"
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"role": "assistant", "content": "reply"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            },
        )

    admin, instance, _, _ = _managed_setup(catalog, client, settings, monkeypatch, upstream)
    personal = _personal_provider(client, admin)
    created = client.post(
        f"{API}/agent/sessions",
        headers=admin,
        json={"instanceId": instance["id"], "model": "model-a"},
    )
    assert created.status_code == 201, created.text
    session_id = created.json()["id"]
    assert created.json()["providerId"] is None

    _send(client, admin, session_id)
    company = _usage_funding(client, admin)
    assert company["company"]["consumedTokens"] == 5
    assert company["personal"]["consumedTokens"] == 0

    switched = client.patch(
        f"{API}/agent/sessions/{session_id}",
        headers=admin,
        json={"providerId": personal["id"]},
    )
    assert switched.status_code == 200, switched.text
    assert switched.json()["providerId"] == personal["id"]
    assert switched.json()["model"] == "personal-a"

    _send(client, admin, session_id)
    personal_usage = _usage_funding(client, admin)
    assert personal_usage["company"]["consumedTokens"] == 5
    assert personal_usage["personal"]["consumedTokens"] == 5

    restored = client.patch(
        f"{API}/agent/sessions/{session_id}",
        headers=admin,
        json={"providerId": None},
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["providerId"] is None
    assert restored.json()["model"] == "model-a"

    _send(client, admin, session_id)
    final = _usage_funding(client, admin)
    assert final["company"]["consumedTokens"] == 10
    assert final["personal"]["consumedTokens"] == 5

    rows = _lease_rows(catalog)
    assert [(row.funding, row.provider_scope, row.model) for row in rows] == [
        ("company", "global", "model-a"),
        ("personal", "personal", "personal-a"),
        ("company", "global", "model-a"),
    ]
    assert all(row.revoked_at is not None for row in rows)
    assert seen_keys == [
        f"Bearer {GLOBAL_KEY}",
        f"Bearer {PERSONAL_KEY}",
        f"Bearer {GLOBAL_KEY}",
    ]
