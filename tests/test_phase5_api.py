"""Phase 5 REST slice: references, assignments, transfers, relations, map and history."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.inventory.service import InventoryService
from tests.inventory_support import READER, Catalog, prepare, sign_in_as

SettingsFactory = Callable[..., Settings]
EFFECTIVE = "2026-07-01T10:30:00+00:00"

LEGACY_HISTORY_KEYS = {
    "id",
    "sequence",
    "assetId",
    "action",
    "quickCodeOld",
    "quickCodeNew",
    "statusOld",
    "statusNew",
    "archivedOld",
    "archivedNew",
    "changes",
    "reason",
    "actorId",
    "actorUsername",
    "createdAt",
}
STRUCTURED_HISTORY_KEYS = {"source", "entityType", "entityId", "effectiveAt", "notes"}


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


def site_tree(client: TestClient, auth: dict[str, str]) -> tuple[str, str, str]:
    """Sede -> Edificio -> Piso -> Sala through the real directory REST endpoints."""

    def create(payload: dict[str, Any]) -> str:
        response = client.post("/api/v1/locations", json=payload, headers=auth)
        assert response.status_code == 201, response.text
        return str(response.json()["id"])

    site = create(
        {"level": "site", "name": "Sede Central", "latitude": -25.286, "longitude": -57.647}
    )
    building = create({"level": "building", "name": "Edificio A", "parentId": site})
    floor = create({"level": "floor", "name": "Piso 1", "parentId": building})
    room = create({"level": "room_zone", "name": "Sala de servidores", "parentId": floor})
    return site, building, room


def make_person(client: TestClient, auth: dict[str, str], name: str = "Ana Pérez") -> str:
    response = client.post(
        "/api/v1/people", json={"name": name, "jobTitle": "Jefa de infraestructura"}, headers=auth
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def create_asset(client: TestClient, auth: dict[str, str], **values: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"name": "Switch de borde", "category": "Red"}
    payload.update(values)
    response = client.post("/api/v1/assets", json=payload, headers=auth)
    assert response.status_code == 201, response.text
    return response.json()


def relations(catalog: Catalog, source: str, target: str, type_key: str) -> str:
    from itsm.relationships.service import RelationshipService

    session = catalog.factory()()
    try:
        service = RelationshipService(session, catalog.settings, source="internal")
        edge = service.create(
            catalog.admin(),
            source_id=source,
            target_id=target,
            type_key=type_key,
            reason="cableado",
        )
        session.commit()
        return edge.id
    finally:
        session.close()


def history(client: TestClient, auth: dict[str, str], asset_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/assets/{asset_id}/history", headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def test_rest_assignment_return_and_transfer_through_the_public_api(
    signed_in_client: Callable[..., Any], catalog: Catalog
) -> None:
    client, auth = signed_in_client(catalog.settings)
    site, _, room = site_tree(client, auth)
    person = make_person(client, auth)
    created = create_asset(
        client, auth, siteId=site, locationId=room, positionX="0.25", positionY="0.75"
    )
    assert created["siteId"] == site
    assert created["locationId"] == room
    assert created["site"] == "Sede Central"
    assert created["location"] == "Sala de servidores"
    assert created["positionX"] == "0.25"

    assigned = client.post(
        f"/api/v1/assets/{created['id']}/assign",
        json={
            "personId": person,
            "reason": "entrega de equipamiento",
            "notes": "firmado",
            "effectiveAt": EFFECTIVE,
        },
        headers=auth,
    )
    assert assigned.status_code == 200, assigned.text
    body = assigned.json()
    assert body["responsiblePersonId"] == person
    assert body["responsibleLabel"] == "Ana Pérez (Jefa de infraestructura)"
    assert body["responsible"] == "Ana Pérez (Jefa de infraestructura)"

    entries = history(client, auth, created["id"])["items"]
    assert entries[-1]["action"] == "assigned"
    assert entries[-1]["effectiveAt"] == EFFECTIVE
    assert entries[-1]["notes"] == "firmado"

    returned = client.post(
        f"/api/v1/assets/{created['id']}/return", json={"reason": "devolución"}, headers=auth
    )
    assert returned.status_code == 200, returned.text
    assert returned.json()["responsiblePersonId"] is None
    assert returned.json()["responsible"] is None

    moved = client.post(
        f"/api/v1/assets/{created['id']}/transfer",
        json={"locationId": room, "siteId": site, "reason": "reasignación de sala"},
        headers=auth,
    )
    # The same location is not a move.
    assert moved.status_code == 409

    transferred = client.post(
        f"/api/v1/assets/{created['id']}/transfer",
        json={"siteId": site, "locationId": None, "reason": "retiro de la sala"},
        headers=auth,
    )
    assert transferred.status_code == 200, transferred.text
    assert transferred.json()["locationId"] is None
    assert transferred.json()["id"] == created["id"]
    assert transferred.json()["quickCode"] == created["quickCode"]


def test_history_surfaces_structured_fields_with_every_legacy_key(
    signed_in_client: Callable[..., Any], catalog: Catalog
) -> None:
    client, auth = signed_in_client(catalog.settings)
    person = make_person(client, auth)
    created = create_asset(client, auth, responsible=None)
    response = client.post(
        f"/api/v1/assets/{created['id']}/assign",
        json={"personId": person, "effectiveAt": EFFECTIVE, "notes": "acta 12"},
        headers=auth,
    )
    assert response.status_code == 200, response.text

    page = history(client, auth, created["id"])
    assert page["assetId"] == created["id"]
    assert [item["action"] for item in page["items"]] == ["created", "assigned"]
    for item in page["items"]:
        assert set(item) >= LEGACY_HISTORY_KEYS
        assert set(item) >= STRUCTURED_HISTORY_KEYS
    assert page["items"][0]["source"] == "rest"
    assert page["items"][1]["source"] == "rest"
    assert page["items"][1]["entityType"] == "asset"
    assert page["items"][1]["entityId"] == created["id"]
    assert page["items"][1]["effectiveAt"] == EFFECTIVE
    assert page["items"][1]["notes"] == "acta 12"
    assert page["items"][1]["actorUsername"] == "ana.admin"


def test_forged_history_metadata_is_rejected_and_denied_writes_change_nothing(
    signed_in_client: Callable[..., Any], catalog: Catalog
) -> None:
    client, auth = signed_in_client(catalog.settings)
    person = make_person(client, auth)
    created = create_asset(client, auth, responsible=None)
    before = history(client, auth, created["id"])

    forged = client.post(
        f"/api/v1/assets/{created['id']}/assign",
        json={"personId": person, "source": "mcp", "actorId": "forged"},
        headers=auth,
    )
    assert forged.status_code == 422

    catalog.add_user(*READER)
    reader_auth = sign_in_as(client, catalog.settings, READER[0])
    denied = client.post(
        f"/api/v1/assets/{created['id']}/assign",
        json={"personId": person},
        headers=reader_auth,
    )
    assert denied.status_code == 403

    assert history(client, auth, created["id"]) == before
    assert catalog.asset_count() == 1


def test_relations_and_person_assets_are_bounded_rest_queries(
    signed_in_client: Callable[..., Any], catalog: Catalog
) -> None:
    client, auth = signed_in_client(catalog.settings)
    person = make_person(client, auth)
    first = create_asset(client, auth, name="Servidor A", quickCode="REL-1")
    second = create_asset(client, auth, name="Switch B", quickCode="REL-2")
    third = create_asset(client, auth, name="VM C", quickCode="REL-3", category=None)
    edge = relations(catalog, first["id"], second["id"], "connected_to")
    relations(catalog, third["id"], first["id"], "hosted_in")
    client.post(f"/api/v1/assets/{first['id']}/assign", json={"personId": person}, headers=auth)
    client.post(f"/api/v1/assets/{second['id']}/assign", json={"personId": person}, headers=auth)

    single = client.get(f"/api/v1/assets/{first['id']}/relations", headers=auth)
    assert single.status_code == 200, single.text
    payload = single.json()
    assert payload["assetId"] == first["id"]
    assert payload["truncated"] is False
    assert [item["id"] for item in payload["outgoing"]] == [edge]
    assert payload["outgoing"][0]["label"] == "Conectado a"
    assert [item["sourceId"] for item in payload["incoming"]] == [third["id"]]
    assert payload["incoming"][0]["label"] == "Aloja"

    bulk = client.post(
        "/api/v1/assets/relations",
        json={"assetIds": [first["id"], third["id"]]},
        headers=auth,
    )
    assert bulk.status_code == 200, bulk.text
    grouped = {item["assetId"]: item for item in bulk.json()["items"]}
    assert set(grouped) == {first["id"], third["id"]}
    assert [item["id"] for item in grouped[third["id"]]["outgoing"]] == [
        item["id"] for item in payload["incoming"]
    ]
    assert grouped[first["id"]]["outgoing"][0]["targetId"] == second["id"]

    people = client.get(f"/api/v1/people/{person}/assets", headers=auth)
    assert people.status_code == 200, people.text
    page = people.json()
    assert {item["id"] for item in page["items"]} == {first["id"], second["id"]}
    assert page["total"] == 2

    assert (
        client.post(
            "/api/v1/assets/relations", json={"assetIds": [first["id"]] * 51}, headers=auth
        ).status_code
        == 422
    )
    assert (
        client.get(
            "/api/v1/people/00000000-0000-4000-8000-000000000000/assets", headers=auth
        ).status_code
        == 404
    )


def test_map_and_hierarchy_filters_are_bounded(
    signed_in_client: Callable[..., Any], catalog: Catalog
) -> None:
    client, auth = signed_in_client(catalog.settings)
    site, building, room = site_tree(client, auth)
    other_site = client.post(
        "/api/v1/locations", json={"level": "site", "name": "Sede Este"}, headers=auth
    ).json()["id"]
    placed = create_asset(
        client,
        auth,
        quickCode="MAP-REST-1",
        siteId=site,
        locationId=room,
        positionX="0.125",
        positionY="0.5",
    )
    create_asset(client, auth, quickCode="MAP-REST-2", siteId=other_site)

    mapped = client.get("/api/v1/map", headers=auth)
    assert mapped.status_code == 200, mapped.text
    payload = mapped.json()
    assert [item["id"] for item in payload["sites"]] == [site, other_site]
    assert payload["sites"][0]["latitude"] == -25.286
    assert payload["positions"] == [
        {
            "assetId": placed["id"],
            "quickCode": "MAP-REST-1",
            "name": "Switch de borde",
            "siteId": site,
            "locationId": room,
            "x": 0.125,
            "y": 0.5,
        }
    ]
    assert payload["truncated"] is False

    by_site = client.get("/api/v1/assets", params={"siteId": site}, headers=auth)
    assert by_site.status_code == 200, by_site.text
    assert [item["id"] for item in by_site.json()["items"]] == [placed["id"]]

    by_location = client.get("/api/v1/assets", params={"locationId": building}, headers=auth)
    assert [item["id"] for item in by_location.json()["items"]] == [placed["id"]]

    assert (
        client.get("/api/v1/assets", params={"locationId": site}, headers=auth).status_code == 200
    )


def test_relationship_and_directory_routes_are_not_shadowed_by_the_mcp_mount(
    signed_in_client: Callable[..., Any], catalog: Catalog
) -> None:
    client, auth = signed_in_client(catalog.settings)

    types = client.get("/api/v1/relationship-types", headers=auth)
    assert types.status_code == 200, types.text
    assert {item["key"] for item in types.json()} >= {
        "connected_to",
        "installed_in",
        "hosted_in",
        "protected_by",
        "depends_on",
        "associated_with",
    }

    graph = client.get("/api/v1/infrastructure/graph", headers=auth)
    assert graph.status_code == 200, graph.text

    people = client.get("/api/v1/people", headers=auth)
    assert people.status_code == 200, people.text

    # The MCP mount still answers on its own path.
    mcp = client.post("/api/v1/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert mcp.status_code in (401, 406, 415, 400)


def test_api_supports_assign_from_the_person_side(
    signed_in_client: Callable[..., Any], catalog: Catalog
) -> None:
    client, auth = signed_in_client(catalog.settings)
    person = make_person(client, auth)
    asset = create_asset(client, auth, responsible=None)

    assigned = client.post(
        f"/api/v1/people/{person}/assets/{asset['id']}/assign",
        json={"reason": "asignación desde la ficha"},
        headers=auth,
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["responsiblePersonId"] == person

    with catalog.session() as session:
        service = InventoryService(session, catalog.settings)
        stored = service.get(catalog.admin(), asset["id"])
    assert stored.responsible_person_id == person


def test_rest_explicit_clears_and_legacy_switches_keep_the_payload_consistent(
    signed_in_client: Callable[..., Any], catalog: Catalog
) -> None:
    client, auth = signed_in_client(catalog.settings)
    site, _, room = site_tree(client, auth)
    person = make_person(client, auth)
    created = create_asset(
        client, auth, siteId=site, locationId=room, positionX="0.25", positionY="0.5"
    )
    assigned = client.post(
        f"/api/v1/assets/{created['id']}/assign", json={"personId": person}, headers=auth
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["responsible"] == "Ana Pérez (Jefa de infraestructura)"
    updated_at = created["updatedAt"]

    cleared = client.patch(
        f"/api/v1/assets/{created['id']}", json={"responsible": None}, headers=auth
    )
    assert cleared.status_code == 200, cleared.text
    body = cleared.json()
    assert body["responsiblePersonId"] is None
    assert body["responsible"] is None
    assert body["responsibleLabel"] is None
    assert body["locationId"] == room
    assert body["positionX"] == "0.25"

    moved = client.patch(f"/api/v1/assets/{created['id']}", json={"siteId": None}, headers=auth)
    assert moved.status_code == 200, moved.text
    body = moved.json()
    assert body["siteId"] is None
    assert body["site"] is None
    assert body["locationId"] is None
    assert body["location"] is None
    assert body["positionX"] is None
    assert body["positionY"] is None

    entries = history(client, auth, created["id"])["items"]
    assert [item["action"] for item in entries] == ["created", "assigned", "updated", "updated"]
    assert entries[-1]["changes"]["site_id"] == {"old": site, "new": None}
    assert entries[-1]["changes"]["location_id"] == {"old": room, "new": None}
    assert entries[-1]["source"] == "rest"
    assert body["id"] == created["id"]
    assert body["quickCode"] == created["quickCode"]
    assert body["createdAt"] == created["createdAt"]
    assert body["updatedAt"] > updated_at
    assert catalog.asset_count() == 1
    assert [event["action"] for event in catalog.audit()].count("inventory.asset_updated") == 2

    # The same merged pairs behave identically through batch, clone and legacy text.
    second = create_asset(client, auth, quickCode="PH5-REST-2", siteId=site, locationId=room)
    batched = client.post(
        "/api/v1/assets/batch",
        json={"update": [{"id": second["id"], "site": "Sede Norte"}]},
        headers=auth,
    )
    assert batched.status_code == 200, batched.text
    batch_body = batched.json()["updated"][0]
    assert batch_body["siteId"] is None
    assert batch_body["site"] == "Sede Norte"
    assert batch_body["locationId"] is None
    assert batch_body["location"] is None

    cloned = client.post(f"/api/v1/assets/{second['id']}/clone", json={}, headers=auth)
    assert cloned.status_code == 201, cloned.text
    assert cloned.json()["siteId"] is None
    assert cloned.json()["site"] == "Sede Norte"
    assert cloned.json()["locationId"] is None

    # Both references were really released: the directory guards accept the change.
    released_room = client.patch(f"/api/v1/locations/{room}", json={"active": False}, headers=auth)
    assert released_room.status_code == 200, released_room.text
    released_person = client.patch(
        f"/api/v1/people/{person}", json={"status": "inactive"}, headers=auth
    )
    assert released_person.status_code == 200, released_person.text


def test_rest_reads_derive_current_directory_labels(
    signed_in_client: Callable[..., Any], catalog: Catalog
) -> None:
    client, auth = signed_in_client(catalog.settings)
    site, _, room = site_tree(client, auth)
    person = make_person(client, auth)
    created = create_asset(client, auth, siteId=site, locationId=room, responsiblePersonId=person)
    assert created["responsible"] == "Ana Pérez (Jefa de infraestructura)"
    before = history(client, auth, created["id"])

    for path, body in (
        (f"/api/v1/locations/{room}", {"name": "Sala 9"}),
        (f"/api/v1/locations/{site}", {"name": "Sede Sur"}),
        (f"/api/v1/people/{person}", {"jobTitle": "Coordinadora"}),
    ):
        renamed = client.patch(path, json=body, headers=auth)
        assert renamed.status_code == 200, renamed.text

    read = client.get(f"/api/v1/assets/{created['id']}", headers=auth)
    assert read.status_code == 200, read.text
    payload = read.json()
    assert payload["site"] == "Sede Sur"
    assert payload["location"] == "Sala 9"
    assert payload["responsible"] == "Ana Pérez (Coordinadora)"
    assert payload["responsibleLabel"] == payload["responsible"]
    assert payload["siteId"] == site
    assert payload["locationId"] == room
    assert payload["updatedAt"] == created["updatedAt"]

    listed = client.get("/api/v1/assets", params={"siteId": site}, headers=auth)
    assert listed.status_code == 200, listed.text
    assert [item["location"] for item in listed.json()["items"]] == ["Sala 9"]
    searched = client.get("/api/v1/assets/search", params={"query": "Switch"}, headers=auth)
    assert searched.status_code == 200, searched.text
    assert [item["responsible"] for item in searched.json()["items"]] == [
        "Ana Pérez (Coordinadora)"
    ]
    assert history(client, auth, created["id"]) == before
    assert catalog.asset_count() == 1

    # Batch and clone projections derive the same current labels without rewriting
    # the source row: only an explicit pair write refreshes the stored snapshot.
    batched = client.post(
        "/api/v1/assets/batch",
        json={"update": [{"id": created["id"], "description": "actualizado"}]},
        headers=auth,
    )
    assert batched.status_code == 200, batched.text
    batch_body = batched.json()["updated"][0]
    assert batch_body["site"] == "Sede Sur"
    assert batch_body["location"] == "Sala 9"
    assert batch_body["responsible"] == "Ana Pérez (Coordinadora)"

    cloned = client.post(f"/api/v1/assets/{created['id']}/clone", json={}, headers=auth)
    assert cloned.status_code == 201, cloned.text
    assert cloned.json()["site"] == "Sede Sur"
    assert cloned.json()["location"] == "Sala 9"
    assert cloned.json()["responsible"] == "Ana Pérez (Coordinadora)"
    assert cloned.json()["siteId"] == site
    assert [item["action"] for item in history(client, auth, created["id"])["items"]] == [
        "created",
        "updated",
    ]
