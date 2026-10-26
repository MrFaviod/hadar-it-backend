"""Inventory REST: authenticated CRUD, bounded search, atomic batch and audit."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from tests.inventory_support import (
    MACHINE,
    MACHINE_PASSWORD,
    Catalog,
    asset_values,
    prepare,
    sign_in_as,
)

SettingsFactory = Callable[..., Settings]


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


def api_values(**overrides: Any) -> dict[str, Any]:
    """The public DTO is camelCase; test fixtures keep snake_case service names."""
    return {
        {"quick_code": "quickCode"}.get(key, key): value
        for key, value in asset_values(**overrides).items()
    }


def create_asset(test_client: TestClient, auth: dict[str, str], **overrides: Any) -> dict[str, Any]:
    response = test_client.post("/api/v1/assets", json=api_values(**overrides), headers=auth)
    assert response.status_code == 201, response.text
    return response.json()


def test_create_read_and_search_return_the_same_asset(
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    settings_factory: SettingsFactory,
) -> None:
    test_client, auth = signed_in_client()

    created = create_asset(test_client, auth)

    assert created["quickCode"] == "SITE-DEMO-001"
    assert created["status"] == "in_use"
    assert created["site"] == "Example Site"
    assert set(created) == {
        "id",
        "quickCode",
        "name",
        "category",
        "type",
        "brand",
        "model",
        "serial",
        "ip",
        "site",
        "location",
        "responsible",
        "status",
        "description",
        "cost",
        "technical",
        "archived",
        "archivedAt",
        "archivedBy",
        "images",
        "createdAt",
        "locationId",
        "responsiblePersonId",
        "responsibleLabel",
        "positionX",
        "positionY",
        "siteId",
        "updatedAt",
    }

    fetched = test_client.get(f"/api/v1/assets/{created['id']}", headers=auth)
    assert fetched.status_code == 200
    assert fetched.json()["id"] == created["id"]

    listed = test_client.get("/api/v1/assets", headers=auth)
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["id"] == created["id"]

    searched = test_client.get("/api/v1/assets/search", params={"query": "Aruba"}, headers=auth)
    assert searched.status_code == 200, searched.text
    assert searched.json()["items"][0]["id"] == created["id"]


def test_assets_require_authentication(
    client: Callable[[Settings], TestClient],
    catalog: Catalog,
) -> None:
    anonymous = client(catalog.settings)

    response = anonymous.get("/api/v1/assets")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_cookie_mutations_require_origin_and_csrf(
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    catalog: Catalog,
) -> None:
    test_client, _auth = signed_in_client(catalog.settings)

    forbidden = test_client.post("/api/v1/assets", json=api_values())
    assert forbidden.status_code == 403

    wrong_csrf = test_client.post(
        "/api/v1/assets",
        json=api_values(),
        headers={"Origin": catalog.settings.auth_origin, "X-CSRF-Token": "wrong"},
    )
    assert wrong_csrf.status_code == 403

    assert catalog.asset_count() == 0


def test_duplicate_numeric_quick_code_advances_without_overwriting(
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    catalog: Catalog,
) -> None:
    test_client, auth = signed_in_client(catalog.settings)
    original = create_asset(test_client, auth, quick_code="SITE-DEMO-001")

    duplicate = test_client.post(
        "/api/v1/assets",
        json=api_values(quick_code="SITE-DEMO-001", name="Otro switch"),
        headers=auth,
    )

    assert duplicate.status_code == 201, duplicate.text
    assert duplicate.json()["quickCode"] == "SITE-DEMO-002"
    assert duplicate.json()["id"] != original["id"]
    assert catalog.asset_count() == 2
    stored = test_client.get(f"/api/v1/assets/{original['id']}", headers=auth)
    assert stored.json()["quickCode"] == "SITE-DEMO-001"


def test_validation_rejects_extra_fields_and_unknown_status(
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    catalog: Catalog,
) -> None:
    test_client, auth = signed_in_client(catalog.settings)

    extra = test_client.post("/api/v1/assets", json=api_values(custom_field="x"), headers=auth)
    status = test_client.post("/api/v1/assets", json=api_values(status="deleted"), headers=auth)
    blank = test_client.post("/api/v1/assets", json=api_values(name="  "), headers=auth)

    assert extra.status_code == 422
    assert status.status_code == 422
    assert blank.status_code == 422
    assert catalog.asset_count() == 0


def test_patch_updates_quick_code_and_rejects_id_changes(
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    catalog: Catalog,
) -> None:
    test_client, auth = signed_in_client(catalog.settings)
    created = create_asset(test_client, auth)

    updated = test_client.patch(
        f"/api/v1/assets/{created['id']}",
        json={"quickCode": "SITE-DEMO-777", "responsible": "Soporte Example Site"},
        headers=auth,
    )
    repeated = test_client.patch(
        f"/api/v1/assets/{created['id']}",
        json={"quickCode": "SITE-DEMO-777"},
        headers=auth,
    )
    forged = test_client.patch(
        f"/api/v1/assets/{created['id']}",
        json={"id": "11111111-1111-1111-1111-111111111111"},
        headers=auth,
    )

    assert updated.status_code == 200, updated.text
    assert updated.json()["id"] == created["id"]
    assert updated.json()["quickCode"] == "SITE-DEMO-777"
    assert repeated.status_code == 200
    assert forged.status_code == 422
    stored = test_client.get(f"/api/v1/assets/{created['id']}", headers=auth)
    assert stored.json()["id"] == created["id"]
    assert stored.json()["quickCode"] == "SITE-DEMO-777"


def test_batch_is_atomic_and_reports_both_halves(
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    catalog: Catalog,
) -> None:
    test_client, auth = signed_in_client(catalog.settings)
    first = create_asset(test_client, auth, quick_code="B-1")

    rejected = test_client.post(
        "/api/v1/assets/batch",
        json={
            "create": [
                api_values(quick_code="B-MANUAL"),
                api_values(quick_code="b-manual"),
            ],
            "update": [],
        },
        headers=auth,
    )
    assert rejected.status_code == 409
    assert catalog.asset_count() == 1

    accepted = test_client.post(
        "/api/v1/assets/batch",
        json={
            "create": [api_values(quick_code="B-2")],
            "update": [{"id": first["id"], "name": "Switch renombrado"}],
        },
        headers=auth,
    )

    assert accepted.status_code == 200, accepted.text
    payload = accepted.json()
    assert [item["quickCode"] for item in payload["created"]] == ["B-2"]
    assert [item["id"] for item in payload["updated"]] == [first["id"]]
    assert catalog.asset_count() == 2


def test_search_filters_and_pagination_are_bounded(
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    catalog: Catalog,
) -> None:
    test_client, auth = signed_in_client(catalog.settings)
    create_asset(test_client, auth, quick_code="NET-1", site="Example Site")
    create_asset(test_client, auth, quick_code="NET-2", site="Asuncion", category="Computo")
    create_asset(test_client, auth, quick_code="NET-3", site="Example Site", status="maintenance")

    page = test_client.get(
        "/api/v1/assets",
        params={"site": "Example Site", "limit": 1, "offset": 1},
        headers=auth,
    )
    exact = test_client.get("/api/v1/assets", params={"quickCode": "net-2"}, headers=auth)
    invalid = test_client.get("/api/v1/assets", params={"limit": 500}, headers=auth)

    assert page.status_code == 200
    assert page.json()["total"] == 2
    assert len(page.json()["items"]) == 1
    assert exact.json()["total"] == 1
    assert exact.json()["items"][0]["quickCode"] == "NET-2"
    assert invalid.status_code == 422


def test_machine_bearer_identity_is_authorized_and_audited(
    client: Callable[[Settings], TestClient],
    catalog: Catalog,
) -> None:
    _, operator_token = catalog.add_machine(
        "hermes-operator", "Hermes Operator", role_id="operator"
    )
    _, reader_token = catalog.add_machine(*MACHINE, role_id="user")
    machine = client(catalog.settings)

    denied = machine.post(
        "/api/v1/assets",
        json=api_values(),
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    created = machine.post(
        "/api/v1/assets",
        json=api_values(quick_code="M-1"),
        headers={"Authorization": f"Bearer {operator_token}"},
    )

    assert denied.status_code == 403
    assert created.status_code == 201, created.text
    actions = {event["action"] for event in catalog.audit()}
    assert "inventory.asset_created" in actions
    assert "assets.edit" in actions
    assert catalog.asset_count() == 1


def test_unknown_and_removed_assets_are_not_found(
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    catalog: Catalog,
) -> None:
    test_client, auth = signed_in_client(catalog.settings)

    missing = test_client.get("/api/v1/assets/00000000-0000-0000-0000-000000000000", headers=auth)
    malformed = test_client.get("/api/v1/assets/not-an-id", headers=auth)
    patch_missing = test_client.patch(
        "/api/v1/assets/00000000-0000-0000-0000-000000000000",
        json={"name": "Fantasma"},
        headers=auth,
    )

    assert missing.status_code == 404
    assert malformed.status_code == 404
    assert patch_missing.status_code == 404
    assert test_client.delete(f"/api/v1/assets/{missing.json().get('id', 'x')}").status_code in {
        404,
        405,
    }


def test_batch_create_assign_is_authorized_per_operation(
    client: Callable[[Settings], TestClient],
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    catalog: Catalog,
) -> None:
    with catalog.session() as session:
        role = catalog.service(session).create_role(
            catalog.admin(),
            name="inventario-batch-http",
            permissions=["assets.view", "assets.edit"],
        )
    catalog.add_user("batch-http-editor", "Batch HTTP Editor", role.id)
    test_client = client(catalog.settings)
    auth = sign_in_as(test_client, catalog.settings, "batch-http-editor", MACHINE_PASSWORD)

    denied = test_client.post(
        "/api/v1/assets/batch",
        json={"create": [api_values(quick_code="HTTP-NO-ASSIGN", responsible="Matriz NOC")]},
        headers=auth,
    )
    assert denied.status_code == 403
    assert catalog.asset_count() == 0

    allowed = test_client.post(
        "/api/v1/assets/batch",
        json={"create": [api_values(quick_code="HTTP-NO-ASSIGN-2", responsible=None)]},
        headers=auth,
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["created"][0]["responsible"] is None
    assert catalog.asset_count() == 1

    admin_client, admin_auth = signed_in_client(catalog.settings)
    assigned = admin_client.post(
        "/api/v1/assets/batch",
        json={"create": [api_values(quick_code="HTTP-ASSIGN", responsible="Matriz NOC")]},
        headers=admin_auth,
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["created"][0]["responsible"] == "Matriz NOC"
    assert catalog.asset_count() == 2
