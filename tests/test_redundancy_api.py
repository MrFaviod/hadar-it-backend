"""Redundancy REST adapter: DTO contract, guards, error mapping and machine identities."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.inventory.service import InventoryService
from itsm.main import create_app
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import (
    MACHINE_PASSWORD,
    OPERATOR,
    READER,
    Catalog,
    asset_values,
    prepare,
    sign_in_as,
)

SettingsFactory = Callable[..., Settings]

GROUP_KEYS = {
    "id",
    "name",
    "description",
    "mode",
    "active",
    "createdAt",
    "updatedAt",
    "memberCount",
    "members",
}
MEMBER_KEYS = {"assetId", "name", "quickCode", "archived", "role", "share", "host"}


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


@pytest.fixture
def api(catalog: Catalog) -> Iterator[tuple[TestClient, dict[str, str]]]:
    app = create_app(catalog.settings)
    with TestClient(app) as client:
        auth = sign_in_as(client, catalog.settings, ADMIN_USERNAME, ADMIN_PASSWORD)
        yield client, auth


def create_asset(catalog: Catalog, quick_code: str) -> str:
    with catalog.session() as session:
        created = InventoryService(session, catalog.settings).create(
            catalog.admin(),
            asset_values(quick_code=quick_code, name=f"Equipo {quick_code}"),
        )
        return created.id


def group_body(*pairs: tuple[str, str], **overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "name": "Portal web",
        "mode": "active_active",
        "members": [{"assetId": asset_id, "share": share} for asset_id, share in pairs],
    }
    body.update(overrides)
    return body


def group_count(catalog: Catalog) -> tuple[int, int]:
    with catalog.engine.connect() as connection:
        groups = connection.exec_driver_sql("SELECT COUNT(*) FROM redundancy_groups").scalar_one()
        members = connection.exec_driver_sql(
            "SELECT COUNT(*) FROM redundancy_group_members"
        ).scalar_one()
    return int(groups), int(members)


def test_redundancy_lifecycle_over_rest(
    api: tuple[TestClient, dict[str, str]], catalog: Catalog
) -> None:
    client, auth = api
    assert f"{catalog.settings.api_prefix}/redundancy-groups" in client.app.openapi()["paths"]
    first = create_asset(catalog, "RA-1")
    second = create_asset(catalog, "RA-2")
    third = create_asset(catalog, "RA-3")

    created = client.post(
        "/api/v1/redundancy-groups",
        json=group_body((first, "40"), (second, "60"), description="AB 40/60"),
        headers=auth,
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert set(body) == GROUP_KEYS
    assert body["memberCount"] == 2
    assert all(set(member) == MEMBER_KEYS for member in body["members"])
    assert {member["assetId"]: member["share"] for member in body["members"]} == {
        first: "40",
        second: "60",
    }

    listed = client.get("/api/v1/redundancy-groups", headers=auth)
    assert listed.status_code == 200
    page = listed.json()
    assert page["total"] == 1
    assert page["items"][0]["id"] == body["id"]

    fetched = client.get(f"/api/v1/redundancy-groups/{body['id']}", headers=auth)
    assert fetched.status_code == 200
    assert fetched.json() == body

    patched = client.patch(
        f"/api/v1/redundancy-groups/{body['id']}",
        json={
            "members": [
                {"assetId": second, "share": "30"},
                {"assetId": third, "share": "70"},
            ],
            "reason": "rebalanceo de tráfico",
        },
        headers=auth,
    )
    assert patched.status_code == 200, patched.text
    updated = patched.json()
    assert updated["id"] == body["id"]
    assert updated["createdAt"] == body["createdAt"]
    assert {member["assetId"] for member in updated["members"]} == {second, third}

    deactivated = client.post(
        f"/api/v1/redundancy-groups/{body['id']}/deactivate",
        json={"reason": "fin del servicio"},
        headers=auth,
    )
    assert deactivated.status_code == 200, deactivated.text
    assert deactivated.json()["active"] is False
    assert (
        client.post(
            f"/api/v1/redundancy-groups/{body['id']}/deactivate",
            json={"reason": "repetido"},
            headers=auth,
        ).status_code
        == 409
    )


def test_redundancy_routes_require_the_cookie_mutation_guard(
    api: tuple[TestClient, dict[str, str]], catalog: Catalog
) -> None:
    client, _auth = api
    first = create_asset(catalog, "RG-1")
    second = create_asset(catalog, "RG-2")

    assert (
        client.post(
            "/api/v1/redundancy-groups", json=group_body((first, "40"), (second, "60"))
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/redundancy-groups",
            json=group_body((first, "40"), (second, "60")),
            headers={"Origin": "http://testserver", "X-CSRF-Token": "forged"},
        ).status_code
        == 403
    )
    assert group_count(catalog) == (0, 0)


def test_redundancy_body_rejects_forged_actor_source_and_authority(
    api: tuple[TestClient, dict[str, str]], catalog: Catalog
) -> None:
    client, auth = api
    first = create_asset(catalog, "RF-1")
    second = create_asset(catalog, "RF-2")

    forged = group_body((first, "40"), (second, "60"), source="mcp")
    assert client.post("/api/v1/redundancy-groups", json=forged, headers=auth).status_code == 422
    forged = group_body((first, "40"), (second, "60"), actorId="admin")
    assert client.post("/api/v1/redundancy-groups", json=forged, headers=auth).status_code == 422
    forged = group_body((first, "40"), (second, "60"), permission="assets.purge")
    assert client.post("/api/v1/redundancy-groups", json=forged, headers=auth).status_code == 422
    member_forgery = {
        "name": "Falso",
        "mode": "active_active",
        "members": [
            {"assetId": first, "share": "40", "source": "rest"},
            {"assetId": second, "share": "60"},
        ],
    }
    assert (
        client.post("/api/v1/redundancy-groups", json=member_forgery, headers=auth).status_code
        == 422
    )
    assert group_count(catalog) == (0, 0)


def test_redundancy_reads_and_writes_enforce_real_roles(
    api: tuple[TestClient, dict[str, str]], catalog: Catalog
) -> None:
    client, auth = api
    first = create_asset(catalog, "RR-1")
    second = create_asset(catalog, "RR-2")
    created = client.post(
        "/api/v1/redundancy-groups", json=group_body((first, "40"), (second, "60")), headers=auth
    )
    assert created.status_code == 201
    group_id = created.json()["id"]

    catalog.add_user(*READER)
    reader = sign_in_as(client, catalog.settings, READER[0], MACHINE_PASSWORD)
    assert client.get("/api/v1/redundancy-groups", headers=reader).status_code == 200
    assert client.get(f"/api/v1/redundancy-groups/{group_id}", headers=reader).status_code == 200
    assert (
        client.patch(
            f"/api/v1/redundancy-groups/{group_id}", json={"name": "Robado"}, headers=reader
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/redundancy-groups",
            json=group_body((first, "50"), (second, "50")),
            headers=reader,
        ).status_code
        == 403
    )
    assert group_count(catalog) == (1, 2)

    catalog.add_user(*OPERATOR)
    operator = sign_in_as(client, catalog.settings, OPERATOR[0], MACHINE_PASSWORD)
    assert (
        client.patch(
            f"/api/v1/redundancy-groups/{group_id}", json={"name": "Operador"}, headers=operator
        ).status_code
        == 200
    )


def test_redundancy_machine_bearer_uses_the_same_service_rules(
    api: tuple[TestClient, dict[str, str]], catalog: Catalog
) -> None:
    client, auth = api
    first = create_asset(catalog, "RM-1")
    second = create_asset(catalog, "RM-2")
    created = client.post(
        "/api/v1/redundancy-groups", json=group_body((first, "40"), (second, "60")), headers=auth
    )
    group_id = created.json()["id"]
    _, token = catalog.add_machine("redundancy-client", "Redundancy Client", "operator")

    denied = client.post(
        "/api/v1/redundancy-groups",
        json=group_body((first, "50"), (second, "50")),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert denied.status_code == 201, denied.text
    fetched = client.get(
        f"/api/v1/redundancy-groups/{group_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert fetched.status_code == 200
    forbidden = client.patch(
        f"/api/v1/redundancy-groups/{group_id}",
        json={"name": "Máquina admin"},
        headers={
            "Authorization": f"Bearer {catalog.add_machine('redundancy-reader', 'R', 'reader')[1]}"
        },
    )
    assert forbidden.status_code == 403


def test_redundancy_error_mapping_is_stable(
    api: tuple[TestClient, dict[str, str]], catalog: Catalog
) -> None:
    client, auth = api
    first = create_asset(catalog, "RE-1")
    second = create_asset(catalog, "RE-2")

    unknown = client.post(
        "/api/v1/redundancy-groups",
        json=group_body(("00000000-0000-4000-8000-000000000000", "40"), (second, "60")),
        headers=auth,
    )
    assert unknown.status_code == 404
    assert unknown.json()["error"]["code"] == "not_found"

    malformed = client.post(
        "/api/v1/redundancy-groups",
        json=group_body(("not-a-uuid", "40"), (second, "60")),
        headers=auth,
    )
    assert malformed.status_code == 404

    bad_sum = client.post(
        "/api/v1/redundancy-groups",
        json=group_body((first, "40"), (second, "61")),
        headers=auth,
    )
    assert bad_sum.status_code == 422
    assert bad_sum.json()["error"]["code"] == "validation_error"

    bad_mode = client.post(
        "/api/v1/redundancy-groups",
        json=group_body((first, "40"), (second, "60"), mode="active_standby"),
        headers=auth,
    )
    assert bad_mode.status_code == 422

    with catalog.session() as session:
        InventoryService(session, catalog.settings).archive(
            catalog.admin(), first, reason="baja definitiva"
        )
    archived = client.post(
        "/api/v1/redundancy-groups",
        json=group_body((first, "40"), (second, "60")),
        headers=auth,
    )
    assert archived.status_code == 409
    assert archived.json()["error"]["code"] == "conflict"

    assert (
        client.get(
            "/api/v1/redundancy-groups/00000000-0000-4000-8000-000000000000", headers=auth
        ).status_code
        == 404
    )
    assert (
        client.get("/api/v1/redundancy-groups", params={"limit": 0}, headers=auth).status_code
        == 422
    )
    assert group_count(catalog) == (0, 0)


def test_archiving_an_active_group_member_is_a_conflict_and_changes_nothing(
    api: tuple[TestClient, dict[str, str]], catalog: Catalog
) -> None:
    client, auth = api
    first = create_asset(catalog, "RB-1")
    second = create_asset(catalog, "RB-2")
    created = client.post(
        "/api/v1/redundancy-groups",
        json=group_body((first, "40"), (second, "60")),
        headers=auth,
    )
    assert created.status_code == 201
    group_id = created.json()["id"]

    def snapshot() -> tuple[
        dict[str, object], dict[str, object], list[object], int, tuple[int, int]
    ]:
        group = client.get(f"/api/v1/redundancy-groups/{group_id}", headers=auth)
        assert group.status_code == 200
        asset = client.get(f"/api/v1/assets/{first}", headers=auth)
        assert asset.status_code == 200
        asset_history = client.get(f"/api/v1/assets/{first}/history", headers=auth)
        assert asset_history.status_code == 200
        return (
            group.json(),
            asset.json(),
            asset_history.json()["items"],
            len(catalog.audit()),
            group_count(catalog),
        )

    before = snapshot()
    refused = client.post(
        f"/api/v1/assets/{first}/archive",
        json={"reason": "baja de la réplica"},
        headers=auth,
    )
    assert refused.status_code == 409
    assert refused.json() == {
        "error": {
            "code": "conflict",
            "message": "an active redundancy group cannot include archived assets",
        }
    }
    assert snapshot() == before
    assert client.get(f"/api/v1/assets/{first}", headers=auth).json()["archived"] is False


def test_deactivating_first_keeps_the_http_archive_path_working(
    api: tuple[TestClient, dict[str, str]], catalog: Catalog
) -> None:
    client, auth = api
    first = create_asset(catalog, "RC-1")
    second = create_asset(catalog, "RC-2")
    created = client.post(
        "/api/v1/redundancy-groups",
        json=group_body((first, "40"), (second, "60")),
        headers=auth,
    )
    group_id = created.json()["id"]

    deactivated = client.post(
        f"/api/v1/redundancy-groups/{group_id}/deactivate",
        json={"reason": "ventana de mantenimiento"},
        headers=auth,
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["active"] is False

    archived = client.post(
        f"/api/v1/assets/{first}/archive",
        json={"reason": "réplica retirada"},
        headers=auth,
    )
    assert archived.status_code == 200
    assert archived.json()["archived"] is True

    kept = client.get(f"/api/v1/redundancy-groups/{group_id}", headers=auth).json()
    assert kept["active"] is False
    assert {member["assetId"]: member["archived"] for member in kept["members"]} == {
        first: True,
        second: False,
    }

    reactivated = client.patch(
        f"/api/v1/redundancy-groups/{group_id}",
        json={"active": True},
        headers=auth,
    )
    assert reactivated.status_code == 409
    assert reactivated.json()["error"]["code"] == "conflict"
