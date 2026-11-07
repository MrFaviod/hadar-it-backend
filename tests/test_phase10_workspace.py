"""Phase 10 workspace contract: durable per-user state, links, views and integrations.

Every check goes through the real router with real cookie authentication and a
migrated SQLite database. Workspace tables are created from the models because
the coordinator owns the pending migration.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from itsm.dashboard.api import create_dashboard_router
from itsm.identity.api import install_error_handlers
from itsm.identity.service import IdentityService
from itsm.inventory.models import InventoryBase
from itsm.main import create_app
from itsm.workspace.models import (
    WorkspaceIntegration,
    WorkspaceShortcut,
    WorkspaceUserState,
    WorkspaceView,
)
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import (
    MACHINE_PASSWORD,
    OPERATOR,
    READER,
    Catalog,
    prepare,
    sign_in_as,
)

DEFAULT_WIDGETS = [
    "availability",
    "alerts",
    "distribution",
    "infrastructure",
    "activity",
    "maintenance",
    "warranties",
    "inventory",
]


def _create_workspace_tables(catalog: Catalog) -> None:
    tables = [
        WorkspaceUserState.__table__,
        WorkspaceShortcut.__table__,
        WorkspaceView.__table__,
        WorkspaceIntegration.__table__,
    ]
    InventoryBase.metadata.create_all(catalog.engine, tables=tables)


@contextmanager
def _workspace_client(catalog: Catalog) -> Iterator[TestClient]:
    app = FastAPI()
    install_error_handlers(app)
    app.state.settings = catalog.settings
    app.state.session_factory = catalog.factory()
    app.include_router(create_dashboard_router(), prefix=catalog.settings.api_prefix)
    with TestClient(app) as client:
        yield client


def _cookie_and_headers(catalog: Catalog, username: str) -> tuple[str, dict[str, str]]:
    password = ADMIN_PASSWORD if username == ADMIN_USERNAME else MACHINE_PASSWORD
    with TestClient(create_app(catalog.settings)) as main:
        headers = sign_in_as(main, catalog.settings, username, password)
        cookie = main.cookies.get(catalog.settings.auth_cookie_name)
    assert cookie
    return str(cookie), headers


def _signed_in(
    catalog: Catalog, username: str = ADMIN_USERNAME
) -> tuple[TestClient, dict[str, str]]:
    cookie, headers = _cookie_and_headers(catalog, username)
    client = _workspace_client(catalog)
    test_client = client.__enter__()
    test_client.cookies.set(catalog.settings.auth_cookie_name, cookie)
    return test_client, headers


def _close(test_client: TestClient) -> None:
    # TestClient closes the underlying context when garbage-collected; explicit
    # exit keeps deterministic connection teardown for the next case.
    test_client.__exit__(None, None, None)


@pytest.fixture
def catalog(settings_factory: Any) -> Catalog:
    prepared = prepare(settings_factory)
    _create_workspace_tables(prepared)
    prepared.add_user(*READER)
    prepared.add_user(*OPERATOR)
    return prepared


def test_state_defaults_partial_merge_and_account_isolation(catalog: Catalog) -> None:
    admin, headers = _signed_in(catalog)
    try:
        initial = admin.get("/api/v1/workspace/state")
        assert initial.status_code == 200, initial.text
        state = initial.json()
        assert state["widgets"] == DEFAULT_WIDGETS
        assert state["favorites"] == []
        assert state["usage"] == {}
        assert state["lastViews"] == {}
        assert state["themeMode"] == "auto"
        assert state["shortcuts"] == []
        assert state["views"] == []

        patched = admin.put(
            "/api/v1/workspace/state",
            json={"themeMode": "dark"},
            headers=headers,
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["themeMode"] == "dark"
        assert patched.json()["widgets"] == DEFAULT_WIDGETS

        full = admin.put(
            "/api/v1/workspace/state",
            json={
                "widgets": ["alerts", "availability"],
                "favorites": [
                    {
                        "key": "asset:one",
                        "type": "asset",
                        "id": "asset-one",
                        "label": "Gateway",
                        "subtitle": "Red",
                        "icon": "server",
                        "target": {"kind": "asset", "id": "asset-one"},
                    }
                ],
                "usage": {"asset:one": 4},
                "lastViews": {"monitorDevice": {"assetId": "asset-one"}},
            },
            headers=headers,
        )
        assert full.status_code == 200, full.text
        payload = full.json()
        assert payload["widgets"] == ["alerts", "availability"]
        assert payload["themeMode"] == "dark"
        assert payload["usage"] == {"asset:one": 4}
        assert payload["lastViews"] == {"monitorDevice": {"assetId": "asset-one"}}

        reset = admin.put("/api/v1/workspace/state", json={"widgets": None}, headers=headers)
        assert reset.status_code == 200, reset.text
        assert reset.json()["widgets"] == DEFAULT_WIDGETS

        empty = admin.put("/api/v1/workspace/state", json={"widgets": []}, headers=headers)
        assert empty.status_code == 200, empty.text
        assert empty.json()["widgets"] == []

        reader, reader_headers = _signed_in(catalog, READER[0])
        try:
            reader_state = reader.get("/api/v1/workspace/state")
            assert reader_state.status_code == 200, reader_state.text
            assert reader_state.json()["widgets"] == DEFAULT_WIDGETS
            assert reader_state.json()["themeMode"] == "auto"
            assert reader_state.json()["usage"] == {}
            assert (
                reader.put(
                    "/api/v1/workspace/state",
                    json={"widgets": ["latency"]},
                    headers=reader_headers,
                ).json()["widgets"]
                == ["latency"]
            )
            assert admin.get("/api/v1/workspace/state").json()["widgets"] == []
        finally:
            _close(reader)
    finally:
        _close(admin)


def test_state_validation_is_bounded_and_rejects_unknown_widgets(catalog: Catalog) -> None:
    admin, headers = _signed_in(catalog)
    try:
        invalid_cases = [
            {"widgets": ["nope"]},
            {"widgets": ["alerts", "alerts"]},
            {"widgets": "alerts"},
            {"themeMode": "system"},
            {"usage": {"asset:one": -1}},
            {"lastViews": {"bad route!": {}}},
            {"favorites": [{"key": "", "type": "asset", "id": "x"}]},
            {"unknown": True},
        ]
        for case in invalid_cases:
            response = admin.put("/api/v1/workspace/state", json=case, headers=headers)
            assert response.status_code == 422, (case, response.text)
        assert admin.get("/api/v1/workspace/state").json()["widgets"] == DEFAULT_WIDGETS
    finally:
        _close(admin)


def test_shortcuts_are_owned_scoped_and_url_validated(catalog: Catalog) -> None:
    admin, headers = _signed_in(catalog)
    reader, reader_headers = _signed_in(catalog, READER[0])
    try:
        personal = admin.post(
            "/api/v1/workspace/shortcuts",
            json={
                "name": "Panel AnyDesk",
                "url": "https://anydesk.com/remote-support",
                "icon": "link",
                "category": "Soporte",
                "scope": "personal",
            },
            headers=headers,
        )
        assert personal.status_code == 201, personal.text
        shortcut = personal.json()
        assert shortcut["ownerId"] == catalog.admin().actor_id
        assert shortcut["scope"] == "personal"
        assert shortcut["category"] == "Soporte"

        admin_state = admin.get("/api/v1/workspace/state").json()
        assert [item["id"] for item in admin_state["shortcuts"]] == [shortcut["id"]]
        reader_state = reader.get("/api/v1/workspace/state").json()
        assert reader_state["shortcuts"] == []
        assert (
            reader.patch(
                f"/api/v1/workspace/shortcuts/{shortcut['id']}",
                json={"name": "Intento"},
                headers=reader_headers,
            ).status_code
            == 404
        )

        shared = admin.post(
            "/api/v1/workspace/shortcuts",
            json={"name": "RMM", "url": "https://rmm.example.test/", "scope": "shared"},
            headers=headers,
        )
        assert shared.status_code == 201, shared.text
        assert reader.get("/api/v1/workspace/state").json()["shortcuts"] == [shared.json()]
        denied = reader.patch(
            f"/api/v1/workspace/shortcuts/{shared.json()['id']}",
            json={"name": "No permitido"},
            headers=reader_headers,
        )
        assert denied.status_code == 403, denied.text
        assert (
            reader.patch(
                f"/api/v1/workspace/shortcuts/{shared.json()['id']}",
                json={"scope": "personal"},
                headers=reader_headers,
            ).status_code
            == 403
        )
        assert (
            reader.post(
                "/api/v1/workspace/shortcuts",
                json={"name": "Global", "url": "https://example.test/", "scope": "shared"},
                headers=reader_headers,
            ).status_code
            == 403
        )
        with catalog.session() as session:
            events = IdentityService(session, catalog.settings).list_audit(
                catalog.admin(), limit=50
            )
        assert any(
            event.action == "config.general"
            and event.resource == "workspace:shared"
            and event.outcome == "denied"
            and event.actor_username == READER[0]
            for event in events
        )

        updated = admin.patch(
            f"/api/v1/workspace/shortcuts/{shared.json()['id']}",
            json={"name": "RMM actualizado", "icon": "monitor"},
            headers=headers,
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["name"] == "RMM actualizado"

        deleted = admin.delete(
            f"/api/v1/workspace/shortcuts/{personal.json()['id']}", headers=headers
        )
        assert deleted.status_code == 200, deleted.text
        assert deleted.json() == {"id": shortcut["id"], "deleted": True}
        remainder = admin.get("/api/v1/workspace/state").json()["shortcuts"]
        assert [item["id"] for item in remainder] == [shared.json()["id"]]

        invalid_urls = [
            "javascript:alert(1)",
            "ftp://example.test/file",
            "https://user:secret@example.test/",
            "https://",
            "https://example.test/\nnext",
            "https://" + "a" * 1000,
        ]
        for url in invalid_urls:
            response = admin.post(
                "/api/v1/workspace/shortcuts",
                json={"name": "Malo", "url": url},
                headers=headers,
            )
            assert response.status_code == 422, (url, response.text)
    finally:
        _close(reader)
        _close(admin)


def test_views_owner_only_shared_publication_and_hydration(catalog: Catalog) -> None:
    admin, headers = _signed_in(catalog)
    reader, reader_headers = _signed_in(catalog, READER[0])
    try:
        personal = admin.post(
            "/api/v1/workspace/views",
            json={
                "name": "Alertas críticas",
                "route": "monitorAlerts",
                "snapshot": {"state": "firing", "columns": ["asset", "severity"]},
                "scope": "personal",
            },
            headers=headers,
        )
        assert personal.status_code == 201, personal.text
        view = personal.json()
        assert view["ownerId"] == catalog.admin().actor_id
        assert view["route"] == "monitorAlerts"
        assert view["snapshot"]["state"] == "firing"
        assert reader.get("/api/v1/workspace/state").json()["views"] == []

        denied = reader.post(
            "/api/v1/workspace/views",
            json={
                "name": "Compartida",
                "route": "inventory",
                "snapshot": {},
                "scope": "shared",
            },
            headers=reader_headers,
        )
        assert denied.status_code == 403, denied.text

        shared = admin.post(
            "/api/v1/workspace/views",
            json={
                "name": "Inventario crítico",
                "route": "inventory",
                "snapshot": {"category": "Red"},
                "scope": "shared",
            },
            headers=headers,
        )
        assert shared.status_code == 201, shared.text
        assert reader.get("/api/v1/workspace/state").json()["views"] == [shared.json()]
        assert (
            reader.patch(
                f"/api/v1/workspace/views/{shared.json()['id']}",
                json={"name": "No permitido"},
                headers=reader_headers,
            ).status_code
            == 403
        )
        assert (
            reader.delete(
                f"/api/v1/workspace/views/{shared.json()['id']}",
                headers=reader_headers,
            ).status_code
            == 403
        )
        updated = admin.patch(
            f"/api/v1/workspace/views/{shared.json()['id']}",
            json={"name": "Inventario Red"},
            headers=headers,
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["name"] == "Inventario Red"

        invalid = admin.post(
            "/api/v1/workspace/views",
            json={
                "name": "Rota",
                "route": "bad route!",
                "snapshot": [],
                "scope": "personal",
            },
            headers=headers,
        )
        assert invalid.status_code == 422, invalid.text

        removed = admin.delete(
            f"/api/v1/workspace/views/{personal.json()['id']}", headers=headers
        )
        assert removed.status_code == 200, removed.text
        assert removed.json() == {"id": view["id"], "deleted": True}
    finally:
        _close(reader)
        _close(admin)


def test_integrations_defaults_partial_merge_and_permissions(catalog: Catalog) -> None:
    admin, admin_headers = _signed_in(catalog)
    operator, operator_headers = _signed_in(catalog, OPERATOR[0])
    reader, _reader_headers = _signed_in(catalog, READER[0])
    try:
        assert reader.get("/api/v1/workspace/integrations").status_code == 403
        defaults = operator.get("/api/v1/workspace/integrations")
        assert defaults.status_code == 200, defaults.text
        assert defaults.json() == {
            "anydeskUrl": "https://anydesk.com/",
            "rmmUrl": "",
            "anydeskEnabled": True,
            "rmmEnabled": True,
        }
        denied = operator.put(
            "/api/v1/workspace/integrations",
            json={"anydeskUrl": "https://example.test/"},
            headers=operator_headers,
        )
        assert denied.status_code == 403, denied.text

        saved = admin.put(
            "/api/v1/workspace/integrations",
            json={
                "rmmUrl": "https://rmm.example.test/agents/",
                "rmmEnabled": True,
            },
            headers=admin_headers,
        )
        assert saved.status_code == 200, saved.text
        assert saved.json() == {
            "anydeskUrl": "https://anydesk.com/",
            "rmmUrl": "https://rmm.example.test/agents/",
            "anydeskEnabled": True,
            "rmmEnabled": True,
        }
        assert operator.get("/api/v1/workspace/integrations").json()["rmmUrl"] == (
            "https://rmm.example.test/agents/"
        )

        disabled = admin.put(
            "/api/v1/workspace/integrations",
            json={"rmmUrl": "", "rmmEnabled": False},
            headers=admin_headers,
        )
        assert disabled.status_code == 200, disabled.text
        assert disabled.json()["rmmUrl"] == ""
        assert disabled.json()["rmmEnabled"] is False

        invalid = [
            {"anydeskUrl": "javascript:alert(1)"},
            {"anydeskUrl": "https://user:secret@example.test/"},
            {"rmmUrl": "ftp://example.test/"},
            {"rmmUrl": "https://example.test/" + "a" * 600},
            {"anydeskEnabled": "yes"},
        ]
        for payload in invalid:
            response = admin.put(
                "/api/v1/workspace/integrations", json=payload, headers=admin_headers
            )
            assert response.status_code == 422, (payload, response.text)
        assert reader.get("/api/v1/workspace/integrations").status_code == 403
    finally:
        _close(reader)
        _close(operator)
        _close(admin)


def test_workspace_requires_authentication(catalog: Catalog) -> None:
    client = _workspace_client(catalog)
    test_client = client.__enter__()
    try:
        assert test_client.get("/api/v1/workspace/state").status_code == 401
        assert test_client.get("/api/v1/workspace/shortcuts").status_code == 401
        assert test_client.get("/api/v1/workspace/views").status_code == 401
        assert test_client.get("/api/v1/workspace/integrations").status_code == 401
        assert test_client.get("/api/v1/dashboard").status_code == 401
    finally:
        _close(test_client)
