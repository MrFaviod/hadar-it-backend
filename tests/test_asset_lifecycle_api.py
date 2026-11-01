"""Asset core REST: DTO, clone, lifecycle, history, purges and media guards."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from tests.conftest import ADMIN_PASSWORD
from tests.inventory_support import MACHINE, Catalog, asset_values, prepare, sign_in_as

SettingsFactory = Callable[..., Settings]
ClientFactory = Callable[..., tuple[TestClient, dict[str, str]]]

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
JPEG = b"\xff\xd8\xff" + b"\x00" * 16
ASSET_KEYS = {
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
    "statusLabel",
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


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


@pytest.fixture
def production_catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory, environment="production", auth_cookie_secure=False)


def api_values(**overrides: Any) -> dict[str, Any]:
    """The public DTO is camelCase; test fixtures keep snake_case service names."""
    return {
        {"quick_code": "quickCode", "typed_id": "typedId"}.get(key, key): value
        for key, value in asset_values(**overrides).items()
    }


def create_asset(test_client: TestClient, auth: dict[str, str], **overrides: Any) -> dict[str, Any]:
    response = test_client.post("/api/v1/assets", json=api_values(**overrides), headers=auth)
    assert response.status_code == 201, response.text
    return response.json()


def test_asset_dto_adds_the_core_fields_without_losing_the_f3_contract(
    signed_in_client: ClientFactory,
    catalog: Catalog,
) -> None:
    test_client, auth = signed_in_client(catalog.settings)

    created = create_asset(
        test_client,
        auth,
        cost="1250.5",
        technical={"ramGb": 16, "hasWifi": True},
    )

    assert set(created) == ASSET_KEYS
    assert created["cost"] == "1250.50"
    assert created["technical"] == {"ramGb": 16, "hasWifi": True}
    assert created["archived"] is False
    assert created["archivedAt"] is None
    assert created["archivedBy"] is None
    assert created["images"] == {}

    read = test_client.get(f"/api/v1/assets/{created['id']}", headers=auth)
    assert read.status_code == 200, read.text
    assert set(read.json()) == ASSET_KEYS
    assert read.json()["cost"] == "1250.50"


def test_sparse_asset_is_accepted_and_optional_fields_stay_null(
    signed_in_client: ClientFactory,
    catalog: Catalog,
) -> None:
    test_client, auth = signed_in_client(catalog.settings)

    response = test_client.post("/api/v1/assets", json={"name": "Sólo nombre"}, headers=auth)

    assert response.status_code == 201, response.text
    created = response.json()
    assert created["cost"] is None
    assert created["technical"] is None
    assert created["status"] == "in_use"
    assert created["quickCode"].startswith("A-")


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "Costo negativo", "cost": -1},
        {"name": "Costo con tres decimales", "cost": "12.345"},
        {"name": "IP inválida", "ip": "999.1.1.1"},
        {"name": "Técnico anidado", "technical": {"nested": {"a": 1}}},
        {"name": "Campo desconocido", "unknownField": True},
    ],
)
def test_invalid_common_fields_are_rejected_without_writing(
    signed_in_client: ClientFactory,
    catalog: Catalog,
    payload: dict[str, Any],
) -> None:
    test_client, auth = signed_in_client(catalog.settings)

    response = test_client.post("/api/v1/assets", json=payload, headers=auth)

    assert response.status_code == 422, response.text
    listing = test_client.get("/api/v1/assets", headers=auth)
    assert listing.status_code == 200
    assert listing.json()["total"] == 0
    assert catalog.asset_count() == 0


def test_clone_endpoint_returns_a_new_id_and_keeps_the_source(
    signed_in_client: ClientFactory,
    catalog: Catalog,
) -> None:
    test_client, auth = signed_in_client(catalog.settings)
    source = create_asset(test_client, auth, cost="99.99", technical={"ramGb": 8})

    response = test_client.post(
        f"/api/v1/assets/{source['id']}/clone",
        json={"quickCode": "CLONE-REST"},
        headers=auth,
    )

    assert response.status_code == 201, response.text
    clone = response.json()
    assert clone["id"] != source["id"]
    assert clone["quickCode"] == "CLONE-REST"
    assert clone["name"] == source["name"]
    assert clone["cost"] == "99.99"
    assert clone["technical"] == {"ramGb": 8}
    assert clone["archived"] is False
    stored = test_client.get(f"/api/v1/assets/{source['id']}", headers=auth)
    assert stored.status_code == 200
    assert stored.json()["quickCode"] == source["quickCode"]
    assert catalog.asset_count() == 2

    missing = test_client.post(
        "/api/v1/assets/00000000-0000-0000-0000-000000000000/clone", headers=auth
    )
    assert missing.status_code == 404


def test_archive_and_restore_keep_status_assignment_and_location(
    signed_in_client: ClientFactory,
    catalog: Catalog,
) -> None:
    test_client, auth = signed_in_client(catalog.settings)
    created = create_asset(
        test_client,
        auth,
        status="maintenance",
        responsible="Matriz NOC",
        location="Rack 2",
    )

    archived = test_client.post(
        f"/api/v1/assets/{created['id']}/archive",
        json={"reason": "fin de vida"},
        headers=auth,
    )
    assert archived.status_code == 200, archived.text
    body = archived.json()
    assert body["archived"] is True
    assert body["archivedAt"] is not None
    assert body["archivedBy"] == "ana.admin"
    assert body["status"] == "maintenance"
    assert body["responsible"] == "Matriz NOC"
    assert body["location"] == "Rack 2"

    archived_only = test_client.get("/api/v1/assets?archived=true", headers=auth)
    assert archived_only.json()["total"] == 1
    active_only = test_client.get("/api/v1/assets?archived=false", headers=auth)
    assert active_only.json()["total"] == 0

    restored = test_client.post(f"/api/v1/assets/{created['id']}/restore", headers=auth)
    assert restored.status_code == 200, restored.text
    assert restored.json()["archived"] is False
    assert restored.json()["status"] == "maintenance"
    assert restored.json()["responsible"] == "Matriz NOC"
    assert restored.json()["location"] == "Rack 2"

    twice = test_client.post(f"/api/v1/assets/{created['id']}/restore", headers=auth)
    assert twice.status_code == 409


def test_retire_endpoint_requires_a_reason_and_clears_only_the_responsible(
    signed_in_client: ClientFactory,
    catalog: Catalog,
) -> None:
    test_client, auth = signed_in_client(catalog.settings)
    created = create_asset(test_client, auth, responsible="Matriz NOC")

    missing_reason = test_client.post(
        f"/api/v1/assets/{created['id']}/retire", json={}, headers=auth
    )
    assert missing_reason.status_code == 422

    short_reason = test_client.post(
        f"/api/v1/assets/{created['id']}/retire", json={"reason": "abc"}, headers=auth
    )
    assert short_reason.status_code == 422

    retired = test_client.post(
        f"/api/v1/assets/{created['id']}/retire",
        json={"reason": "Baja por fin de vida"},
        headers=auth,
    )
    assert retired.status_code == 200, retired.text
    assert retired.json()["status"] == "retired"
    assert retired.json()["responsible"] is None
    assert retired.json()["location"] == created["location"]
    assert retired.json()["archived"] is False


def test_history_endpoint_is_read_only_and_ordered(
    signed_in_client: ClientFactory,
    catalog: Catalog,
) -> None:
    test_client, auth = signed_in_client(catalog.settings)
    created = create_asset(test_client, auth, quick_code="HIS-API-1")
    patched = test_client.patch(
        f"/api/v1/assets/{created['id']}",
        json={"quickCode": "HIS-API-2", "status": "maintenance"},
        headers=auth,
    )
    assert patched.status_code == 200, patched.text
    test_client.post(
        f"/api/v1/assets/{created['id']}/archive", json={"reason": "guardado"}, headers=auth
    )

    response = test_client.get(f"/api/v1/assets/{created['id']}/history", headers=auth)

    assert response.status_code == 200, response.text
    page = response.json()
    assert page["total"] == 3
    assert [item["action"] for item in page["items"]] == ["created", "updated", "archived"]
    updated = page["items"][1]
    assert updated["quickCodeOld"] == "HIS-API-1"
    assert updated["quickCodeNew"] == "HIS-API-2"
    assert updated["statusNew"] == "maintenance"
    assert updated["actorUsername"] == "ana.admin"
    assert updated["createdAt"]
    assert page["items"][2]["reason"] == "guardado"

    assert test_client.delete(
        f"/api/v1/assets/{created['id']}/history", headers=auth
    ).status_code in (404, 405)
    assert test_client.get("/api/v1/assets/not-an-id/history", headers=auth).status_code == 404


def test_reader_cannot_archive_retire_or_clone(
    signed_in_client: ClientFactory,
    catalog: Catalog,
) -> None:
    catalog.add_user("reader-user", "Reader User", "user")
    test_client, auth = signed_in_client(catalog.settings)
    created = create_asset(test_client, auth, responsible="Matriz NOC")
    reader = sign_in_as(test_client, catalog.settings, "reader-user")

    assert (
        test_client.post(f"/api/v1/assets/{created['id']}/archive", headers=reader).status_code
        == 403
    )
    assert (
        test_client.post(
            f"/api/v1/assets/{created['id']}/retire",
            json={"reason": "Baja sin permiso"},
            headers=reader,
        ).status_code
        == 403
    )
    assert (
        test_client.post(f"/api/v1/assets/{created['id']}/clone", headers=reader).status_code == 403
    )

    unchanged = test_client.get(f"/api/v1/assets/{created['id']}", headers=reader)
    assert unchanged.status_code == 200
    assert unchanged.json()["archived"] is False
    assert unchanged.json()["status"] == "in_use"
    assert unchanged.json()["responsible"] == "Matriz NOC"
    assert catalog.asset_count() == 1


def test_edit_only_identity_cannot_assign_on_clone_or_retire(
    signed_in_client: ClientFactory,
    catalog: Catalog,
) -> None:
    with catalog.session() as session:
        role = catalog.service(session).create_role(
            catalog.admin(),
            name="inventario-solo-edicion",
            permissions=["assets.view", "assets.edit"],
        )
    catalog.add_user("edit-only", "Edit Only", role.id)
    test_client, auth = signed_in_client(catalog.settings)
    created = create_asset(test_client, auth, responsible="Matriz NOC")
    editor = sign_in_as(test_client, catalog.settings, "edit-only")

    denied_clone = test_client.post(f"/api/v1/assets/{created['id']}/clone", headers=editor)
    assert denied_clone.status_code == 403

    denied_retire = test_client.post(
        f"/api/v1/assets/{created['id']}/retire",
        json={"reason": "Baja sin asignación"},
        headers=editor,
    )
    assert denied_retire.status_code == 403

    allowed_archive = test_client.post(f"/api/v1/assets/{created['id']}/archive", headers=editor)
    assert allowed_archive.status_code == 200, allowed_archive.text

    unchanged = test_client.get(f"/api/v1/assets/{created['id']}", headers=auth)
    assert unchanged.json()["status"] == "in_use"
    assert unchanged.json()["responsible"] == "Matriz NOC"
    assert catalog.asset_count() == 1


def test_purge_in_the_test_environment_needs_confirmation_and_leaves_a_tombstone(
    signed_in_client: ClientFactory,
    catalog: Catalog,
) -> None:
    test_client, auth = signed_in_client(catalog.settings)
    created = create_asset(test_client, auth, quick_code="PURGE-API-1")

    unconfirmed = test_client.post(f"/api/v1/assets/{created['id']}/purge", json={}, headers=auth)
    assert unconfirmed.status_code == 422
    assert test_client.get(f"/api/v1/assets/{created['id']}", headers=auth).status_code == 200

    purged = test_client.post(
        f"/api/v1/assets/{created['id']}/purge",
        json={"confirm": True, "reason": "baja definitiva de prueba"},
        headers=auth,
    )
    assert purged.status_code == 200, purged.text
    assert purged.json()["id"] == created["id"]
    assert purged.json()["quickCode"] == "PURGE-API-1"
    assert catalog.asset_count() == 0
    assert test_client.get(f"/api/v1/assets/{created['id']}", headers=auth).status_code == 404
    assert (
        test_client.get(f"/api/v1/assets/{created['id']}/history", headers=auth).status_code == 200
    )


def test_production_purge_denials_are_visible_over_http(
    signed_in_client: ClientFactory,
    production_catalog: Catalog,
) -> None:
    production_catalog.add_user("operator-user", "Operator User", "operator")
    test_client, auth = signed_in_client(production_catalog.settings)
    created = create_asset(test_client, auth)

    not_archived = test_client.post(
        f"/api/v1/assets/{created['id']}/purge",
        json={"confirm": True, "typedId": created["id"], "reason": "baja definitiva"},
        headers=auth,
    )
    assert not_archived.status_code == 409

    test_client.post(f"/api/v1/assets/{created['id']}/archive", headers=auth)

    no_typed_id = test_client.post(
        f"/api/v1/assets/{created['id']}/purge",
        json={"confirm": True, "reason": "baja definitiva"},
        headers=auth,
    )
    assert no_typed_id.status_code == 422

    operator = sign_in_as(test_client, production_catalog.settings, "operator-user")
    operator_denied = test_client.post(
        f"/api/v1/assets/{created['id']}/purge",
        json={"confirm": True, "typedId": created["id"], "reason": "baja definitiva"},
        headers=operator,
    )
    assert operator_denied.status_code == 403
    assert production_catalog.asset_count() == 1

    auth = sign_in_as(
        test_client, production_catalog.settings, "ana.admin", password=ADMIN_PASSWORD
    )
    purged = test_client.post(
        f"/api/v1/assets/{created['id']}/purge",
        json={"confirm": True, "typedId": created["id"], "reason": "baja definitiva"},
        headers=auth,
    )
    assert purged.status_code == 200, purged.text
    assert production_catalog.asset_count() == 0


def test_machine_bearer_identity_cannot_purge(
    signed_in_client: ClientFactory,
    catalog: Catalog,
) -> None:
    with catalog.session() as session:
        role = catalog.service(session).create_role(
            catalog.admin(),
            name="inventario-automatizado",
            permissions=["assets.view", "assets.edit", "assets.purge"],
        )
    _principal, token = catalog.add_machine("purge-machine", "Purge Machine", role.id)
    test_client, auth = signed_in_client(catalog.settings)
    created = create_asset(test_client, auth)

    denied = test_client.post(
        f"/api/v1/assets/{created['id']}/purge",
        json={"confirm": True, "reason": "borrado automático"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert denied.status_code == 403
    assert test_client.get(f"/api/v1/assets/{created['id']}", headers=auth).status_code == 200


def test_machine_and_reader_are_read_only_for_media(
    signed_in_client: ClientFactory,
    catalog: Catalog,
) -> None:
    catalog.add_user("reader-user", "Reader User", "user")
    _machine, machine_token = catalog.add_machine(*MACHINE, role_id="user")
    test_client, auth = signed_in_client(catalog.settings)
    created = create_asset(test_client, auth)

    seeded = test_client.put(
        f"/api/v1/assets/{created['id']}/images/photo",
        content=PNG,
        headers={**auth, "Content-Type": "image/png"},
    )
    assert seeded.status_code == 200, seeded.text

    reader = sign_in_as(test_client, catalog.settings, "reader-user")

    assert (
        test_client.put(
            f"/api/v1/assets/{created['id']}/images/photo",
            content=JPEG,
            headers={**reader, "Content-Type": "image/jpeg"},
        ).status_code
        == 403
    )
    removed = test_client.delete(f"/api/v1/assets/{created['id']}/images/photo", headers=reader)
    assert removed.status_code == 403
    assert (
        test_client.put(
            f"/api/v1/assets/{created['id']}/images/photo",
            content=PNG,
            headers={"Authorization": f"Bearer {machine_token}"},
        ).status_code
        == 403
    )

    read = test_client.get(f"/api/v1/assets/{created['id']}/images/photo", headers=reader)
    assert read.status_code == 200
    assert read.content == PNG
    assert read.headers["content-type"] == "image/png"
    assert read.headers["cache-control"] == "private, no-store"
    assert read.headers["x-content-type-options"] == "nosniff"

    machine_read = test_client.get(
        f"/api/v1/assets/{created['id']}/images/photo",
        headers={"Authorization": f"Bearer {machine_token}"},
    )
    assert machine_read.status_code == 200
    assert machine_read.content == PNG
