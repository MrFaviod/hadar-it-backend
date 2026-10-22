"""Directory REST: bounded DTOs, real permissions and the existing mutation guard."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from sqlalchemy import text
from tests.inventory_support import OPERATOR, READER, Catalog, prepare, sign_in_as

SettingsFactory = Callable[..., Settings]
ClientFactory = Callable[..., TestClient]
SignedInFactory = Callable[..., tuple[TestClient, dict[str, str]]]


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


def rows(catalog: Catalog, table: str) -> int:
    with catalog.engine.connect() as connection:
        return int(connection.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one())


def create_person(
    test_client: TestClient, auth: dict[str, str], **overrides: Any
) -> dict[str, Any]:
    payload: dict[str, Any] = {"name": "Ana Benítez", "jobTitle": "Jefa de Redes"}
    payload.update(overrides)
    response = test_client.post("/api/v1/people", json=payload, headers=auth)
    assert response.status_code == 201, response.text
    return response.json()


def create_location(test_client: TestClient, auth: dict[str, str], **values: Any) -> dict[str, Any]:
    response = test_client.post("/api/v1/locations", json=values, headers=auth)
    assert response.status_code == 201, response.text
    return response.json()


def test_person_endpoints_round_trip_with_origin_and_csrf(
    signed_in_client: SignedInFactory, catalog: Catalog
) -> None:
    test_client, auth = signed_in_client(catalog.settings)

    created = create_person(test_client, auth)
    assert set(created) == {
        "id",
        "name",
        "jobTitle",
        "departmentId",
        "siteId",
        "contactEmail",
        "contactPhone",
        "status",
        "label",
        "createdAt",
        "updatedAt",
    }
    assert created["label"] == "Ana Benítez (Jefa de Redes)"
    assert (created["departmentId"], created["siteId"], created["contactEmail"]) == (
        None,
        None,
        None,
    )

    read = test_client.get(f"/api/v1/people/{created['id']}", headers=auth)
    assert read.status_code == 200
    assert read.json()["id"] == created["id"]

    patched = test_client.patch(
        f"/api/v1/people/{created['id']}",
        json={"status": "inactive", "reason": "Baja temporal"},
        headers=auth,
    )
    assert patched.status_code == 200
    assert patched.json()["status"] == "inactive"

    listed = test_client.get("/api/v1/people", headers=auth)
    assert listed.status_code == 200
    assert (listed.json()["total"], listed.json()["limit"], listed.json()["offset"]) == (1, 50, 0)

    no_csrf = test_client.post(
        "/api/v1/people",
        json={"name": "Sneaky"},
        headers={
            "Origin": catalog.settings.auth_origin,
        },
    )
    assert no_csrf.status_code == 403
    wrong_origin = test_client.post(
        "/api/v1/people",
        json={"name": "Sneaky"},
        headers={"X-CSRF-Token": auth["X-CSRF-Token"], "Origin": "http://evil.test"},
    )
    assert wrong_origin.status_code == 403
    assert rows(catalog, "directory_people") == 1


def test_directory_endpoints_require_authentication(
    client: ClientFactory, catalog: Catalog
) -> None:
    anonymous = client(catalog.settings)

    for path in ("/api/v1/people", "/api/v1/departments", "/api/v1/locations"):
        assert anonymous.get(path).status_code == 401


def test_reader_can_read_people_but_cannot_create_or_configure(
    client: ClientFactory, catalog: Catalog
) -> None:
    catalog.add_user(*READER)
    reader = client(catalog.settings)
    auth = sign_in_as(reader, catalog.settings, READER[0])

    assert reader.get("/api/v1/people", headers=auth).status_code == 200
    assert reader.post("/api/v1/people", json={"name": "Nadie"}, headers=auth).status_code == 403
    assert (
        reader.post("/api/v1/departments", json={"name": "Nadie"}, headers=auth).status_code == 403
    )
    assert (
        reader.post(
            "/api/v1/locations", json={"level": "site", "name": "Nadie"}, headers=auth
        ).status_code
        == 403
    )

    assert (rows(catalog, "directory_people"), rows(catalog, "directory_locations")) == (0, 0)


def test_operator_can_manage_people_but_not_departments_or_sites(
    client: ClientFactory, catalog: Catalog
) -> None:
    catalog.add_user(*OPERATOR)
    operator = client(catalog.settings)
    auth = sign_in_as(operator, catalog.settings, OPERATOR[0])

    created = create_person(operator, auth, name="Bruno Cáceres", jobTitle=None)
    assert created["label"] == "Bruno Cáceres"
    assert (
        operator.patch(
            f"/api/v1/people/{created['id']}", json={"jobTitle": "Técnico"}, headers=auth
        ).status_code
        == 200
    )
    assert (
        operator.post("/api/v1/departments", json={"name": "Redes"}, headers=auth).status_code
        == 403
    )
    assert (
        operator.post(
            "/api/v1/locations", json={"level": "site", "name": "Example Site"}, headers=auth
        ).status_code
        == 403
    )


def test_location_hierarchy_and_tree_endpoint_are_bounded(
    signed_in_client: SignedInFactory, catalog: Catalog
) -> None:
    test_client, auth = signed_in_client(catalog.settings)

    site = create_location(test_client, auth, level="site", name="Example Site")
    assert set(site) == {
        "id",
        "level",
        "parentId",
        "name",
        "description",
        "latitude",
        "longitude",
        "planRef",
        "planPage",
        "active",
        "createdAt",
        "updatedAt",
    }
    building = create_location(
        test_client, auth, level="building", name="Edificio A", parentId=site["id"]
    )
    create_location(test_client, auth, level="floor", name="Piso 1", parentId=building["id"])

    tree = test_client.get(
        f"/api/v1/locations/tree?rootId={site['id']}&depth=3&maxNodes=10", headers=auth
    )
    assert tree.status_code == 200
    body = tree.json()
    assert (body["nodeCount"], body["depth"], body["truncated"]) == (3, 3, False)
    assert body["roots"][0]["children"][0]["children"][0]["name"] == "Piso 1"

    sites = test_client.get("/api/v1/locations?level=site", headers=auth)
    assert sites.json()["total"] == 1
    assert test_client.get("/api/v1/locations/tree?depth=9", headers=auth).status_code == 422
    assert test_client.get("/api/v1/locations/tree?maxNodes=0", headers=auth).status_code == 422


def test_history_endpoint_is_paginated_and_newest_first(
    signed_in_client: SignedInFactory, catalog: Catalog
) -> None:
    test_client, auth = signed_in_client(catalog.settings)
    person = create_person(test_client, auth)
    for title in ("Analista", "Supervisora"):
        patched = test_client.patch(
            f"/api/v1/people/{person['id']}", json={"jobTitle": title}, headers=auth
        )
        assert patched.status_code == 200

    page = test_client.get(f"/api/v1/people/{person['id']}/history?limit=2", headers=auth)
    assert page.status_code == 200
    body = page.json()
    assert (body["entity"], body["entityId"], body["total"], body["limit"]) == (
        "person",
        person["id"],
        3,
        2,
    )
    assert [item["action"] for item in body["items"]] == ["updated", "updated"]
    assert body["items"][0]["after"] == {"jobTitle": "Supervisora"}
    assert body["items"][0]["source"] == "rest"

    older = test_client.get(f"/api/v1/people/{person['id']}/history?limit=1&offset=2", headers=auth)
    assert [item["action"] for item in older.json()["items"]] == ["created"]


def test_invalid_payloads_and_unknown_ids_are_reported(
    signed_in_client: SignedInFactory, catalog: Catalog
) -> None:
    test_client, auth = signed_in_client(catalog.settings)

    extra = test_client.post(
        "/api/v1/people", json={"name": "Ana", "nickname": "Anita"}, headers=auth
    )
    assert extra.status_code == 422
    unknown_level = test_client.post(
        "/api/v1/locations", json={"level": "attic", "name": "Techo"}, headers=auth
    )
    assert unknown_level.status_code == 422
    missing = test_client.get("/api/v1/people/0f8c5f1e-0000-4000-8000-000000000000", headers=auth)
    assert missing.status_code == 404
    unknown_envelope = missing.json()
    assert set(unknown_envelope) == {"error"}
    assert set(unknown_envelope["error"]) == {"code", "message"}
    assert rows(catalog, "directory_people") == 0
    assert rows(catalog, "directory_locations") == 0


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("location", "parentId must reference an active location"),
        ("person_site", "siteId must reference an active site"),
        ("person_department", "departmentId must reference an active department"),
    ],
)
def test_reactivation_against_an_inactive_reference_is_rejected(
    signed_in_client: SignedInFactory, catalog: Catalog, case: str, message: str
) -> None:
    test_client, auth = signed_in_client(catalog.settings)
    site = create_location(test_client, auth, level="site", name="Example Site")
    department = test_client.post("/api/v1/departments", json={"name": "Redes"}, headers=auth)
    assert department.status_code == 201
    department_id = department.json()["id"]

    if case == "location":
        target = create_location(
            test_client, auth, level="building", name="Edificio A", parentId=site["id"]
        )
        target_path = f"/api/v1/locations/{target['id']}"
        deactivated = test_client.patch(target_path, json={"active": False}, headers=auth)
        closed_path = f"/api/v1/locations/{site['id']}"
        closed = test_client.patch(closed_path, json={"active": False}, headers=auth)
        reactivation: dict[str, Any] = {"active": True}
    else:
        target = create_person(test_client, auth, siteId=site["id"], departmentId=department_id)
        target_path = f"/api/v1/people/{target['id']}"
        deactivated = test_client.patch(target_path, json={"status": "inactive"}, headers=auth)
        if case == "person_site":
            closed_path = f"/api/v1/locations/{site['id']}"
        else:
            closed_path = f"/api/v1/departments/{department_id}"
        closed = test_client.patch(closed_path, json={"active": False}, headers=auth)
        reactivation = {"status": "active"}
    assert (deactivated.status_code, closed.status_code) == (200, 200)

    history_path = f"{target_path}/history"
    before = test_client.get(history_path, headers=auth)
    assert before.status_code == 200
    assert before.json()["total"] == 2

    rejected = test_client.patch(target_path, json=reactivation, headers=auth)
    assert rejected.status_code == 422
    assert rejected.json() == {"error": {"code": "validation_error", "message": message}}

    unchanged = test_client.get(target_path, headers=auth).json()
    if case == "location":
        assert (unchanged["active"], unchanged["parentId"]) == (False, site["id"])
    else:
        assert (
            unchanged["status"],
            unchanged["siteId"],
            unchanged["departmentId"],
        ) == ("inactive", site["id"], department_id)
    after = test_client.get(history_path, headers=auth)
    assert (after.json()["total"], after.json()["items"]) == (
        before.json()["total"],
        before.json()["items"],
    )

    restored = test_client.patch(closed_path, json={"active": True}, headers=auth)
    assert restored.status_code == 200
    reactivated = test_client.patch(target_path, json=reactivation, headers=auth)
    assert reactivated.status_code == 200
    if case == "location":
        assert reactivated.json()["active"] is True
    else:
        assert reactivated.json()["status"] == "active"


def test_department_and_location_writes_need_delete_free_configuration_permissions(
    signed_in_client: SignedInFactory, catalog: Catalog
) -> None:
    test_client, auth = signed_in_client(catalog.settings)

    department = test_client.post("/api/v1/departments", json={"name": "Redes"}, headers=auth)
    assert department.status_code == 201
    assert set(department.json()) == {"id", "name", "active", "createdAt", "updatedAt"}
    renamed = test_client.patch(
        f"/api/v1/departments/{department.json()['id']}", json={"name": "Redes IP"}, headers=auth
    )
    assert renamed.json()["name"] == "Redes IP"
    unchanged = test_client.patch(
        f"/api/v1/departments/{department.json()['id']}", json={"name": " redes ip "}, headers=auth
    )
    assert unchanged.json()["name"] == "redes ip"
    active = test_client.get("/api/v1/departments", headers=auth)
    assert active.json()["total"] == 1

    site = create_location(test_client, auth, level="site", name="Example Site")
    located = test_client.patch(
        f"/api/v1/locations/{site['id']}",
        json={"latitude": -25.2867, "longitude": -57.3333, "planRef": "SITE-DEMO"},
        headers=auth,
    )
    assert located.status_code == 200
    assert (located.json()["latitude"], located.json()["longitude"]) == (-25.2867, -57.3333)
    invalid = test_client.patch(
        f"/api/v1/locations/{site['id']}", json={"planRef": "/srv/planos/a.pdf"}, headers=auth
    )
    assert invalid.status_code == 422
