"""Automatic model discovery for OpenAI-compatible provider records.

Every provider (global or personal) discovers its models through the same
bounded, guarded transport as a chat turn: on create, when the endpoint or the
credential changes and on an explicit owner check. A failed discovery never
blocks saving and only a closed status code is reported; the credential, the
upstream body and the resolved address never reach a response or a log record.

The offered ``models`` list follows discovery in ``auto`` mode and the owner's
list in ``manual`` mode, while every other consumer (session model validation,
engine listing, managed gateway model) keeps using that same offered list.

These tests drive the real FastAPI app, a real migrated SQLite identity database
and loopback HTTP servers that count every request they receive. No provider
inference is consumed.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from itsm.agent_integrations.models import AgentProvider
from itsm.agent_integrations.service import AgentIntegrationService
from itsm.main import create_app
from sqlalchemy import create_engine, inspect, text
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, run_cli, run_migrations
from tests.inventory_support import MACHINE_PASSWORD, prepare

API = "/api/v1"
MASTER_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
PROVIDER_PERMISSION = "agents.providers.personal"
LEGACY_REVISION = "0032_managed_personal_provider"
DISCOVERY_REVISION = "0033_provider_model_discovery"

# A protocol-shaped listing: OpenRouter reports modalities under
# ``architecture.input_modalities``, others use a flat list and some report none.
MODELS_BODY = json.dumps(
    {
        "object": "list",
        "data": [
            {"id": "model-a", "architecture": {"input_modalities": ["text", "image"]}},
            {"id": "model-b", "input_modalities": ["text", "file"]},
            {"id": "model-c"},
        ],
    }
).encode("utf-8")


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
            name=f"discovery-user-{uuid4().hex[:8]}",
            permissions=("assets.view", "people.view", PROVIDER_PERMISSION),
        )
        return role.id


@contextmanager
def _provider_app(settings_factory: Any, **overrides: Any) -> Iterator[SimpleNamespace]:
    catalog = prepare(
        settings_factory,
        agent_model="openai:gpt-4o-mini",
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
        yield SimpleNamespace(catalog=catalog, client=client, settings=catalog.settings)
    finally:
        client.__exit__(None, None, None)
        catalog.engine.dispose()


def _admin(environment: SimpleNamespace) -> dict[str, str]:
    return _login(environment.client, environment.settings, ADMIN_USERNAME, ADMIN_PASSWORD)


def _personal_user(
    environment: SimpleNamespace, username: str = "discovery.user"
) -> dict[str, str]:
    catalog = environment.catalog
    role_id = _role_with_permission(catalog)
    catalog.add_user(username, username.replace(".", " ").title(), role_id)
    return _login(environment.client, catalog.settings, username, MACHINE_PASSWORD)


def _create(client: TestClient, headers: dict[str, str], **payload: Any) -> Any:
    body: dict[str, Any] = {
        "scope": "global",
        "name": "Discovery gateway",
        "apiKey": "sk-discovery-secret",
    }
    body.update(payload)
    return client.post(f"{API}/agent/providers", json=body, headers=headers)


def test_create_discovers_models_and_provider_reported_modalities(
    settings_factory: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with _serve_models() as upstream, _provider_app(settings_factory) as environment:
        created = _create(
            environment.client,
            _admin(environment),
            baseUrl=upstream.base_url,
            modelSelection="auto",
        )

        assert created.status_code == 201, created.text
        body = created.json()
        assert body["modelSelection"] == "auto"
        assert body["models"] == ["model-a", "model-b", "model-c"]
        assert body["discoveredModels"] == [
            {"id": "model-a", "inputModalities": ["text", "image"]},
            {"id": "model-b", "inputModalities": ["text", "file"]},
            {"id": "model-c", "inputModalities": None},
        ]
        assert body["modelCapabilities"] == {
            "model-a": {"image": True, "file": False, "source": "provider"},
            "model-b": {"image": False, "file": True, "source": "provider"},
            "model-c": {"image": None, "file": None, "source": "unknown"},
        }
        assert body["discovery"]["code"] == "ok"
        assert body["discovery"]["count"] == 3
        assert datetime.fromisoformat(body["discovery"]["checkedAt"]) is not None
        assert upstream.server.hits == ["/v1/models"]
        assert upstream.server.authorization == ["Bearer sk-discovery-secret"]
        assert "sk-discovery-secret" not in created.text
        assert "sk-discovery-secret" not in caplog.text

        with environment.catalog.session() as session:
            row = session.get(AgentProvider, body["id"])
            assert row is not None
            assert row.model_selection == "auto"
            assert row.discovery_status == "ok"
            assert row.discovery_checked_at is not None
            assert [entry["id"] for entry in row.discovered_models] == [
                "model-a",
                "model-b",
                "model-c",
            ]


def test_auto_selection_offers_fifty_models_and_stores_a_bounded_inventory(
    settings_factory: Any,
) -> None:
    with _serve_models() as upstream, _provider_app(settings_factory) as environment:
        upstream.server.body = json.dumps(
            {"data": [{"id": f"model-{index:04d}"} for index in range(600)]}
        ).encode()

        created = _create(
            environment.client,
            _admin(environment),
            baseUrl=upstream.base_url,
            modelSelection="auto",
        )

        assert created.status_code == 201, created.text
        body = created.json()
        assert len(body["models"]) == 50
        assert body["models"][0] == "model-0000"
        assert body["models"][-1] == "model-0049"
        assert len(body["discoveredModels"]) == 500
        assert body["discovery"]["count"] == 500


def test_manual_selection_keeps_the_owner_list_after_a_successful_discovery(
    settings_factory: Any,
) -> None:
    with _serve_models() as upstream, _provider_app(settings_factory) as environment:
        created = _create(
            environment.client,
            _admin(environment),
            baseUrl=upstream.base_url,
            modelSelection="manual",
            models=["model-b"],
        )

        assert created.status_code == 201, created.text
        body = created.json()
        assert body["modelSelection"] == "manual"
        assert body["models"] == ["model-b"]
        assert [entry["id"] for entry in body["discoveredModels"]] == [
            "model-a",
            "model-b",
            "model-c",
        ]
        assert body["discovery"]["code"] == "ok"


def test_manual_selection_rejects_a_model_the_provider_does_not_report(
    settings_factory: Any,
) -> None:
    with _serve_models() as upstream, _provider_app(settings_factory) as environment:
        headers = _admin(environment)

        rejected = _create(
            environment.client,
            headers,
            baseUrl=upstream.base_url,
            modelSelection="manual",
            models=["ghost-model"],
        )

        assert rejected.status_code == 422, rejected.text
        assert rejected.json()["error"]["code"] == "validation_error"
        assert (
            environment.client.get(f"{API}/agent/providers", headers=headers).json()["items"] == []
        )


def test_owner_capability_marks_override_the_provider_report(
    settings_factory: Any,
) -> None:
    with _serve_models() as upstream, _provider_app(settings_factory) as environment:
        created = _create(
            environment.client,
            _admin(environment),
            baseUrl=upstream.base_url,
            modelSelection="auto",
            modelCapabilities={"model-a": {"image": False, "file": True}},
        )

        assert created.status_code == 201, created.text
        capabilities = created.json()["modelCapabilities"]
        assert capabilities["model-a"] == {"image": False, "file": True, "source": "owner"}
        assert capabilities["model-b"] == {"image": False, "file": True, "source": "provider"}


def test_failed_discovery_saves_the_provider_with_a_closed_code(
    settings_factory: Any,
) -> None:
    with _serve_models() as upstream, _provider_app(settings_factory) as environment:
        upstream.server.status = 401

        created = _create(
            environment.client,
            _admin(environment),
            baseUrl=upstream.base_url,
            modelSelection="auto",
        )

        assert created.status_code == 201, created.text
        body = created.json()
        assert body["models"] == []
        assert body["discoveredModels"] == []
        assert body["modelCapabilities"] == {}
        assert body["discovery"]["code"] == "unauthorized"
        assert body["discovery"]["count"] == 0
        assert body["discovery"]["checkedAt"] is not None
        assert "sk-discovery-secret" not in created.text
        assert upstream.server.hits == ["/v1/models"]


def test_failed_discovery_keeps_free_manual_models(settings_factory: Any) -> None:
    with _serve_models() as upstream, _provider_app(settings_factory) as environment:
        upstream.server.status = 500

        created = _create(
            environment.client,
            _admin(environment),
            baseUrl=upstream.base_url,
            modelSelection="manual",
            models=["private-tuning-v3"],
        )

        assert created.status_code == 201, created.text
        body = created.json()
        assert body["models"] == ["private-tuning-v3"]
        assert body["discovery"]["code"] == "invalid_response"


def test_check_refreshes_discovery_and_the_offered_list(settings_factory: Any) -> None:
    with _serve_models() as upstream, _provider_app(settings_factory) as environment:
        headers = _admin(environment)
        created = _create(
            environment.client,
            headers,
            baseUrl=upstream.base_url,
            modelSelection="auto",
        )
        assert created.status_code == 201, created.text
        provider_id = created.json()["id"]
        upstream.server.body = json.dumps({"data": [{"id": "model-z"}]}).encode()

        response = environment.client.post(
            f"{API}/agent/providers/{provider_id}/check", headers=headers
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["ok"] is True
        assert body["code"] == "ok"
        assert body["modelCount"] == 1
        assert body["checkedAt"] is not None
        assert body["provider"]["models"] == ["model-z"]
        assert body["provider"]["discovery"]["count"] == 1
        assert upstream.server.hits == ["/v1/models", "/v1/models"]

        listed = environment.client.get(f"{API}/agent/providers", headers=headers).json()
        assert listed["items"][0]["models"] == ["model-z"]
        with environment.catalog.session() as session:
            row = session.get(AgentProvider, provider_id)
            assert row is not None
            assert [entry["id"] for entry in row.discovered_models] == ["model-z"]


def test_update_refreshes_discovery_only_when_the_endpoint_or_key_changes(
    settings_factory: Any,
) -> None:
    with (
        _serve_models() as upstream,
        _serve_models() as other,
        _provider_app(settings_factory) as environment,
    ):
        headers = _admin(environment)
        created = _create(
            environment.client,
            headers,
            baseUrl=upstream.base_url,
            modelSelection="auto",
        )
        assert created.status_code == 201, created.text
        provider_id = created.json()["id"]
        assert upstream.server.hits == ["/v1/models"]

        renamed = environment.client.patch(
            f"{API}/agent/providers/{provider_id}",
            json={"name": "Renamed gateway"},
            headers=headers,
        )
        assert renamed.status_code == 200, renamed.text
        assert upstream.server.hits == ["/v1/models"]
        assert other.server.hits == []

        other.server.body = json.dumps({"data": [{"id": "model-new"}]}).encode()
        moved = environment.client.patch(
            f"{API}/agent/providers/{provider_id}",
            json={"baseUrl": other.base_url, "apiKey": "sk-explicit-destination-key"},
            headers=headers,
        )
        assert moved.status_code == 200, moved.text
        assert moved.json()["models"] == ["model-new"]
        assert other.server.hits == ["/v1/models"]
        assert moved.json()["discovery"]["count"] == 1

        other.server.body = json.dumps({"data": [{"id": "model-keyed"}]}).encode()
        rekeyed = environment.client.patch(
            f"{API}/agent/providers/{provider_id}",
            json={"apiKey": "sk-rotated-secret"},
            headers=headers,
        )
        assert rekeyed.status_code == 200, rekeyed.text
        assert rekeyed.json()["models"] == ["model-keyed"]
        assert other.server.authorization[-1] == "Bearer sk-rotated-secret"
        assert other.server.hits == ["/v1/models", "/v1/models"]
        assert upstream.server.hits == ["/v1/models"]


def test_manual_update_is_checked_against_the_last_successful_discovery(
    settings_factory: Any,
) -> None:
    with _serve_models() as upstream, _provider_app(settings_factory) as environment:
        headers = _admin(environment)
        created = _create(
            environment.client,
            headers,
            baseUrl=upstream.base_url,
            modelSelection="auto",
        )
        provider_id = created.json()["id"]

        accepted = environment.client.patch(
            f"{API}/agent/providers/{provider_id}",
            json={"modelSelection": "manual", "models": ["model-c"]},
            headers=headers,
        )
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["models"] == ["model-c"]

        rejected = environment.client.patch(
            f"{API}/agent/providers/{provider_id}",
            json={"models": ["ghost-model"]},
            headers=headers,
        )
        assert rejected.status_code == 422, rejected.text
        listed = environment.client.get(f"{API}/agent/providers", headers=headers).json()
        assert listed["items"][0]["models"] == ["model-c"]


def test_another_person_cannot_refresh_a_personal_providers_discovery(
    settings_factory: Any,
) -> None:
    with (
        _serve_models() as upstream,
        _provider_app(settings_factory, ai_personal_private_endpoints="127.0.0.0/8") as environment,
    ):
        owner = _personal_user(environment, "owner.user")
        created = _create(
            environment.client,
            owner,
            scope="personal",
            baseUrl=upstream.base_url,
            modelSelection="auto",
        )
        assert created.status_code == 201, created.text
        other = _personal_user(environment, "other.user")
        hits = list(upstream.server.hits)

        response = environment.client.post(
            f"{API}/agent/providers/{created.json()['id']}/check", headers=other
        )

        assert response.status_code == 404, response.text
        assert upstream.server.hits == hits
        assert environment.client.get(f"{API}/agent/providers", headers=other).json()["items"] == []


def test_personal_discovery_keeps_the_private_address_policy(
    settings_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    with (
        _serve_models() as upstream,
        _provider_app(
            settings_factory, ai_personal_private_endpoints="blocked.internal:18081"
        ) as environment,
    ):
        monkeypatch.setattr(
            "itsm.agent_integrations.providers.resolve_addresses",
            lambda host, port: ("127.0.0.1",),
        )

        created = _create(
            environment.client,
            _personal_user(environment),
            scope="personal",
            baseUrl="http://blocked.internal:18081/v1",
            modelSelection="auto",
        )

        assert created.status_code == 201, created.text
        assert created.json()["discovery"]["code"] == "blocked_address"
        assert created.json()["models"] == []
        assert "127.0.0.1" not in created.text
        assert upstream.server.hits == []


def test_legacy_providers_keep_their_manual_models_after_the_migration(
    settings_factory: Any, tmp_path: Any
) -> None:
    settings = settings_factory(database_url=f"sqlite:///{tmp_path / 'legacy.db'}")
    legacy = run_cli(
        ["-m", "alembic", "-c", str(settings.alembic_config_path), "upgrade", LEGACY_REVISION],
        settings,
    )
    assert legacy.returncode == 0, legacy.stderr
    engine = create_engine(settings.database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO agent_providers (id, name, scope, owner_id, base_url, models,"
                    " api_key_ciphertext, enabled, created_at, updated_at)"
                    " VALUES (:id, 'Legacy gateway', 'global', NULL, 'https://legacy.example/v1',"
                    " :models, NULL, 1, :now, :now)"
                ),
                {
                    "id": "legacy-provider",
                    "models": json.dumps(["legacy-model"]),
                    "now": datetime(2026, 1, 1),
                },
            )
        upgraded = run_cli(
            ["-m", "alembic", "-c", str(settings.alembic_config_path), "upgrade", "head"],
            settings,
        )
        assert upgraded.returncode == 0, upgraded.stderr
        columns = {column["name"] for column in inspect(engine).get_columns("agent_providers")}
        assert {
            "model_selection",
            "discovered_models",
            "model_capabilities",
            "discovery_status",
            "discovery_checked_at",
        } <= columns
        with engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT model_selection, discovered_models, discovery_status,"
                    " model_capabilities, discovery_checked_at FROM agent_providers"
                    " WHERE id = 'legacy-provider'"
                )
            ).one()
        assert row.model_selection == "manual"
        assert row.discovered_models is None
        assert row.discovery_status is None
        assert row.model_capabilities is None
        assert row.discovery_checked_at is None
    finally:
        engine.dispose()


def test_discovery_migration_round_trips_on_sqlite(settings_factory: Any, tmp_path: Any) -> None:
    settings = settings_factory(database_url=f"sqlite:///{tmp_path / 'roundtrip.db'}")
    upgraded = run_migrations(settings)
    assert upgraded.returncode == 0, upgraded.stderr
    engine = create_engine(settings.database_url)
    try:
        assert "model_selection" in {
            column["name"] for column in inspect(engine).get_columns("agent_providers")
        }
        downgraded = run_cli(
            [
                "-m",
                "alembic",
                "-c",
                str(settings.alembic_config_path),
                "downgrade",
                LEGACY_REVISION,
            ],
            settings,
        )
        assert downgraded.returncode == 0, downgraded.stderr
        remaining = {column["name"] for column in inspect(engine).get_columns("agent_providers")}
        assert "model_selection" not in remaining
        assert "discovered_models" not in remaining
        reupgraded = run_migrations(settings)
        assert reupgraded.returncode == 0, reupgraded.stderr
        restored = {column["name"] for column in inspect(engine).get_columns("agent_providers")}
        assert "model_selection" in restored
        assert "discovered_models" in restored
    finally:
        engine.dispose()
