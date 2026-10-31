"""HTTP contract for the SDK v2 isolation lifecycle.

The routes under test are the public surface an operator uses: status, uninstall
and the 409 upgrade gate for modules installed by SDK v1. Every request is
authenticated and every mutation carries the CSRF header.
"""

# ruff: noqa: F811 - the `env` fixture is imported and also named in signatures.

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from itsm.extensions.api import create_extension_router, install_extension_error_handlers
from itsm.identity.api import create_identity_router, install_error_handlers
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.test_extension_runtime_support import (
    MODULE_ID,
    build_package,
    probe_manifest,
)
from tests.test_extension_storage_lifecycle import seed_installed_v1_module
from tests.test_native_extensions import env  # noqa: F401  (shared host fixture)


def _client(environment) -> TestClient:
    app = FastAPI()
    app.state.settings = environment.settings
    app.state.session_factory = environment.factory
    app.state.extensions = environment.host
    app.include_router(create_identity_router(), prefix=environment.settings.api_prefix)
    app.include_router(create_extension_router(), prefix=environment.settings.api_prefix)
    install_error_handlers(app)
    install_extension_error_handlers(app)
    return TestClient(app)


def _headers(environment, client: TestClient) -> dict[str, str]:
    login = client.post(
        environment.settings.api_prefix + "/auth/login",
        json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        headers={"Origin": environment.settings.auth_origin},
    )
    assert login.status_code == 200, login.text
    return {
        "Origin": environment.settings.auth_origin,
        "X-CSRF-Token": login.json()["csrfToken"],
    }


def test_status_uninstall_and_upgrade_gate_over_http(env, tmp_path) -> None:
    prefix = env.settings.api_prefix + "/extensions"
    with _client(env) as client:
        assert client.get(prefix + "/" + MODULE_ID + "/status").status_code == 401
        headers = _headers(env, client)

        env.install(build_package(probe_manifest()))

        status = client.get(prefix + "/" + MODULE_ID + "/status")
        assert status.status_code == 200, status.text
        body = status.json()
        assert body["status"] == "ready"
        assert body["sandbox"]["available"] is True
        assert body["storagePath"].endswith("/" + MODULE_ID)
        assert body["eventCursor"] == 0 and body["stalled"] is False
        assert body["events"] == {
            "consumer": "extension:" + MODULE_ID,
            "cursor": 0,
            "stalled": False,
            "lastError": None,
            "attempts": 0,
            "retryAfter": None,
            "state": "active",
        }

        # Uninstall is a CSRF-guarded mutation with an optimistic version check.
        denied = client.post(prefix + "/" + MODULE_ID + "/uninstall", json={"expectedVersion": 1})
        assert denied.status_code == 403
        stale = client.post(
            prefix + "/" + MODULE_ID + "/uninstall",
            json={"expectedVersion": 99},
            headers=headers,
        )
        assert stale.status_code == 409 and stale.json()["error"]["code"] == "stale"
        removed = client.post(
            prefix + "/" + MODULE_ID + "/uninstall",
            json={"expectedVersion": 1},
            headers=headers,
        )
        assert removed.status_code == 200, removed.text
        assert removed.json()["dataRetained"] is True
        assert client.get(prefix).json()["items"] == []
        assert client.get(prefix + "/" + MODULE_ID + "/status").status_code == 404


def test_v1_module_is_never_executed_over_http(env, tmp_path) -> None:
    marker = tmp_path / "v1-executed.txt"
    seed_installed_v1_module(env, marker)
    prefix = env.settings.api_prefix + "/extensions"
    with _client(env) as client:
        headers = _headers(env, client)
        items = client.get(prefix).json()["items"]
        assert [item["status"] for item in items] == ["requires_upgrade"]
        invoke = client.post(prefix + "/legacy-book/invoke/read_records", json={}, headers=headers)
        assert invoke.status_code == 409
        assert invoke.json()["error"]["code"] == "extension_requires_upgrade"
        assert "relocate-legacy" in invoke.json()["error"]["message"]
        status = client.get(prefix + "/legacy-book/status").json()
        assert status["status"] == "requires_upgrade"
        assert not marker.exists()
