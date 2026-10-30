"""Owner-only provider check and its bounded destination policy.

The check operation lists models for a stored provider, so it must re-use the
same guarded transport as a turn: no redirects, no environment proxies and no
private destination unless the deployment allowlists it. These tests use a real
FastAPI app, a real SQLite identity database and loopback HTTP servers that
count every request they receive. No provider inference is consumed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from itsm.agent_integrations.providers import probe_provider_models
from itsm.agent_integrations.service import AgentIntegrationService
from itsm.main import create_app
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import MACHINE_PASSWORD, prepare

API = "/api/v1"
MASTER_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
PROVIDER_PERMISSION = "agents.providers.personal"
MODELS_BODY = json.dumps({"object": "list", "data": [{"id": "model-a"}, {"id": "model-b"}]}).encode(
    "utf-8"
)


class _ModelsHandler(BaseHTTPRequestHandler):
    """Tiny OpenAI-compatible models endpoint with controllable answers."""

    def do_GET(self) -> None:
        server = self.server
        server.hits.append(self.path)  # type: ignore[attr-defined]
        server.authorization.append(self.headers.get("Authorization"))  # type: ignore[attr-defined]
        if server.delay:  # type: ignore[attr-defined]
            time.sleep(server.delay)  # type: ignore[attr-defined]
        body = server.body  # type: ignore[attr-defined]
        self.send_response(server.status)  # type: ignore[attr-defined]
        self.send_header("Content-Type", "application/json")
        if server.location:  # type: ignore[attr-defined]
            self.send_header("Location", server.location)  # type: ignore[attr-defined]
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        """Keep the test output clean; every hit is recorded on the server."""


@contextmanager
def _serve_models() -> Iterator[SimpleNamespace]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ModelsHandler)
    server.hits = []  # type: ignore[attr-defined]
    server.authorization = []  # type: ignore[attr-defined]
    server.status = 200  # type: ignore[attr-defined]
    server.body = MODELS_BODY  # type: ignore[attr-defined]
    server.location = None  # type: ignore[attr-defined]
    server.delay = 0.0  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(
            server=server,
            base_url=f"http://127.0.0.1:{server.server_address[1]}/v1",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


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


def _role_with_permission(catalog: Any) -> str:
    with catalog.session() as session:
        role = catalog.service(session).create_role(
            catalog.admin(),
            name=f"check-user-{uuid4().hex[:8]}",
            permissions=("assets.view", "people.view", PROVIDER_PERMISSION),
        )
        return role.id


@contextmanager
def _provider_app(settings_factory: Any, **overrides: Any) -> Iterator[SimpleNamespace]:
    catalog = prepare(
        settings_factory,
        ai_credential_key=MASTER_KEY,
        ai_broker_url="ws://127.0.0.1:9/runs",
        ai_broker_token="t" * 48,
        **overrides,
    )
    client = TestClient(create_app(catalog.settings))
    client.__enter__()
    client.app.state.agent_integrations = AgentIntegrationService(
        catalog.settings, catalog.factory()
    )
    try:
        yield SimpleNamespace(
            catalog=catalog,
            client=client,
            settings=catalog.settings,
            upstream=None,
        )
    finally:
        client.__exit__(None, None, None)
        catalog.engine.dispose()


def _personal_provider(
    environment: SimpleNamespace,
    upstream: SimpleNamespace,
    *,
    username: str = "check.user",
    api_key: str = "sk-check-secret",
    base_url: str | None = None,
) -> tuple[dict[str, str], dict[str, Any]]:
    catalog = environment.catalog
    client = environment.client
    role_id = _role_with_permission(catalog)
    catalog.add_user(username, username.replace(".", " ").title(), role_id)
    headers = _login(client, catalog.settings, username, MACHINE_PASSWORD)
    created = client.post(
        f"{API}/agent/providers",
        json={
            "scope": "personal",
            "name": "Personal endpoint",
            "baseUrl": base_url or upstream.base_url,
            "models": ["model-a"],
            "modelSelection": "manual",
            "apiKey": api_key,
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    # Creating a provider already discovers its models; these tests describe the
    # explicit check operation, so its own requests are counted from zero.
    upstream.server.hits.clear()
    upstream.server.authorization.clear()
    return headers, created.json()


def _check(client: TestClient, headers: dict[str, str], provider_id: str) -> Any:
    return client.post(f"{API}/agent/providers/{provider_id}/check", headers=headers)


def test_check_reports_models_for_an_allowlisted_personal_provider(
    settings_factory: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with (
        _serve_models() as upstream,
        _provider_app(settings_factory, ai_personal_private_endpoints="127.0.0.0/8") as environment,
    ):
        headers, provider = _personal_provider(environment, upstream)

        response = _check(environment.client, headers, provider["id"])

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["ok"] is True
        assert body["code"] == "ok"
        assert body["modelCount"] == 2
        assert set(body) == {"ok", "code", "modelCount", "checkedAt", "provider"}
        assert [entry["id"] for entry in body["provider"]["discoveredModels"]] == [
            "model-a",
            "model-b",
        ]
        assert body["provider"]["discovery"]["code"] == "ok"
        assert "sk-check-secret" not in response.text
        # The public provider fields are returned, but discovery never reports a
        # resolved address, the upstream body or the credential.
        discovery_text = json.dumps(body["provider"]["discovery"]) + json.dumps(
            body["provider"]["modelCapabilities"]
        )
        assert "127.0.0.1" not in discovery_text
        assert "sk-check-secret" not in caplog.text
        assert upstream.server.hits == ["/v1/models"]
        assert upstream.server.authorization == ["Bearer sk-check-secret"]


def test_check_never_follows_a_redirect(settings_factory: Any) -> None:
    with (
        _serve_models() as target,
        _serve_models() as upstream,
        _provider_app(settings_factory, ai_personal_private_endpoints="127.0.0.0/8") as environment,
    ):
        upstream.server.status = 302
        upstream.server.location = target.base_url + "/models"
        headers, provider = _personal_provider(environment, upstream)

        response = _check(environment.client, headers, provider["id"])

        assert response.status_code == 200, response.text
        assert response.json()["ok"] is False
        assert response.json()["code"] == "redirect"
        assert upstream.server.hits == ["/v1/models"]
        assert target.server.hits == []
        assert "modelCount" not in response.json()


@pytest.mark.parametrize("status", [401, 403])
def test_check_reports_unauthorized_credentials(settings_factory: Any, status: int) -> None:
    with (
        _serve_models() as upstream,
        _provider_app(settings_factory, ai_personal_private_endpoints="127.0.0.0/8") as environment,
    ):
        upstream.server.status = status
        headers, provider = _personal_provider(environment, upstream)

        response = _check(environment.client, headers, provider["id"])

        assert response.status_code == 200, response.text
        assert response.json()["ok"] is False
        assert response.json()["code"] == "unauthorized"


def test_check_reports_invalid_or_oversized_responses(settings_factory: Any) -> None:
    with (
        _serve_models() as upstream,
        _provider_app(settings_factory, ai_personal_private_endpoints="127.0.0.0/8") as environment,
    ):
        headers, provider = _personal_provider(environment, upstream)

        upstream.server.body = b"not json"
        assert _check(environment.client, headers, provider["id"]).json()["code"] == (
            "invalid_response"
        )

        upstream.server.body = b"{" + b" " * 200_000 + b"}"
        assert _check(environment.client, headers, provider["id"]).json()["code"] == (
            "invalid_response"
        )


def test_check_blocks_a_private_resolution_that_the_deployment_did_not_allow(
    settings_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    with (
        _serve_models() as upstream,
        _provider_app(
            settings_factory, ai_personal_private_endpoints="blocked.internal:18081"
        ) as environment,
    ):
        headers, provider = _personal_provider(
            environment, upstream, base_url="http://blocked.internal:18081/v1"
        )
        for address in ("127.0.0.1", "169.254.169.254", "fd00:ec2::254"):
            monkeypatch.setattr(
                "itsm.agent_integrations.providers.resolve_addresses",
                lambda host, port, answer=address: (answer,),
            )

            response = _check(environment.client, headers, provider["id"])

            assert response.status_code == 200, response.text
            assert response.json()["ok"] is False
            assert response.json()["code"] == "blocked_address"
            assert "127.0.0.1" not in response.text
            assert "169.254" not in response.text
        assert upstream.server.hits == []


def test_check_hides_another_persons_provider_as_not_found(settings_factory: Any) -> None:
    with (
        _serve_models() as upstream,
        _provider_app(settings_factory, ai_personal_private_endpoints="127.0.0.0/8") as environment,
    ):
        _, provider = _personal_provider(environment, upstream, username="owner.user")
        other = _personal_provider(
            environment, upstream, username="other.user", base_url="http://127.0.0.1:1/v1"
        )[0]

        response = _check(environment.client, other, provider["id"])

        assert response.status_code == 404, response.text
        assert upstream.server.hits == []


def test_check_requires_a_signed_in_person_and_csrf(settings_factory: Any) -> None:
    with (
        _serve_models() as upstream,
        _provider_app(settings_factory, ai_personal_private_endpoints="127.0.0.0/8") as environment,
    ):
        headers, provider = _personal_provider(environment, upstream)
        url = f"{API}/agent/providers/{provider['id']}/check"

        no_csrf = dict(headers)
        no_csrf.pop("X-CSRF-Token")
        assert environment.client.post(url, headers=no_csrf).status_code == 403
        assert (
            environment.client.post(
                url, headers={"Origin": environment.settings.auth_origin}
            ).status_code
            == 403
        )

        environment.client.cookies.clear()
        assert environment.client.post(url).status_code == 401
        assert upstream.server.hits == []


def test_check_reports_an_unreadable_credential_without_a_key_ring(
    settings_factory: Any,
) -> None:
    with (
        _serve_models() as upstream,
        _provider_app(settings_factory, ai_personal_private_endpoints="127.0.0.0/8") as environment,
    ):
        headers, provider = _personal_provider(environment, upstream)
        # Same database and key ring removed: the stored ciphertext is unreadable
        # in this process, so the check reports it instead of failing the route.
        ringless = settings_factory(ai_personal_private_endpoints="127.0.0.0/8")
        environment.client.app.state.agent_integrations = AgentIntegrationService(
            ringless, environment.catalog.factory()
        )

        response = _check(environment.client, headers, provider["id"])

        assert response.status_code == 200, response.text
        assert response.json()["ok"] is False
        assert response.json()["code"] == "credential_unavailable"
        assert upstream.server.hits == []


def test_global_provider_check_keeps_owner_trusted_private_access(
    settings_factory: Any,
) -> None:
    with _serve_models() as upstream, _provider_app(settings_factory) as environment:
        headers = _login(environment.client, environment.settings, ADMIN_USERNAME, ADMIN_PASSWORD)
        created = environment.client.post(
            f"{API}/agent/providers",
            json={
                "scope": "global",
                "name": "Global endpoint",
                "baseUrl": upstream.base_url,
                "models": ["model-a"],
                "modelSelection": "auto",
                "apiKey": "sk-global-secret",
            },
            headers=headers,
        )
        assert created.status_code == 201, created.text
        # No selection is sent, so the default auto mode offers what the endpoint
        # reports instead of the configured list.
        assert created.json()["modelSelection"] == "auto"
        assert created.json()["models"] == ["model-a", "model-b"]
        assert created.json()["discovery"]["code"] == "ok"
        upstream.server.hits.clear()

        response = _check(environment.client, headers, created.json()["id"])

        assert response.status_code == 200, response.text
        assert response.json()["ok"] is True
        assert response.json()["code"] == "ok"
        assert upstream.server.hits == ["/v1/models"]


def test_probe_reports_timeout_without_waiting_for_the_deadline() -> None:
    with _serve_models() as upstream:
        upstream.server.delay = 1.0

        code, count = asyncio.run(
            probe_provider_models(
                upstream.base_url,
                "sk-check-secret",
                allow_private=True,
                timeout=0.1,
            )
        )

        assert (code, count) == ("timeout", None)
