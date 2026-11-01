"""Relationship REST adapter: DTOs, Casbin, CSRF/origin, graph bounds and history source."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.inventory.service import InventoryService
from itsm.main import create_app
from itsm.relationships.service import RelationshipService
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import (
    MACHINE_PASSWORD,
    READER,
    Catalog,
    asset_values,
    prepare,
    sign_in_as,
)

SettingsFactory = Callable[..., Settings]

RELATIONSHIP_KEYS = {
    "id",
    "typeKey",
    "forwardLabel",
    "inverseLabel",
    "forwardLabels",
    "inverseLabels",
    "containment",
    "typeActive",
    "sourceId",
    "targetId",
    "reason",
    "notes",
    "effectiveAt",
    "createdAt",
    "updatedAt",
    "direction",
    "label",
}


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


@pytest.fixture
def api(catalog: Catalog) -> Iterator[tuple[TestClient, dict[str, str], TestClient]]:
    # create_app registers the relationship router before the MCP mount at the same
    # prefix, so these routes must answer without any test-side route surgery.
    app = create_app(catalog.settings)
    assert f"{catalog.settings.api_prefix}/relationships" in app.openapi()["paths"]
    with TestClient(app) as client:
        auth = sign_in_as(client, catalog.settings, ADMIN_USERNAME, ADMIN_PASSWORD)
        yield client, auth, TestClient(app)


def create_asset(catalog: Catalog, quick_code: str) -> str:
    with catalog.session() as session:
        service = InventoryService(session, catalog.settings)
        created = service.create(
            catalog.admin(),
            asset_values(quick_code=quick_code, name=f"Equipo {quick_code}"),
        )
        return created.id


def create_edge(
    catalog: Catalog, source_id: str, target_id: str, type_key: str = "connected_to"
) -> str:
    with catalog.session() as session:
        service = RelationshipService(session, catalog.settings, source="agent")
        edge = service.create(
            catalog.admin(),
            source_id=source_id,
            target_id=target_id,
            type_key=type_key,
        )
        return edge.id


def test_relationship_rest_crud_exposes_forward_and_inverse_labels(
    api: tuple[TestClient, dict[str, str], TestClient],
    catalog: Catalog,
) -> None:
    client, auth, _ = api
    prefix = catalog.settings.api_prefix

    types = client.get(f"{prefix}/relationship-types", headers=auth)
    assert types.status_code == 200
    assert [entry["key"] for entry in types.json()][:1] == ["associated_with"]

    created_type = client.post(
        f"{prefix}/relationship-types",
        json={
            "key": "runs_on",
            "forwardLabel": "Se ejecuta en",
            "inverseLabel": "Ejecuta",
        },
        headers=auth,
    )
    assert created_type.status_code == 201
    assert created_type.json()["containment"] is False

    patched_type = client.patch(
        f"{prefix}/relationship-types/runs_on",
        json={"forwardLabel": "Corre en", "active": True},
        headers=auth,
    )
    assert patched_type.status_code == 200
    assert patched_type.json()["forwardLabel"] == "Corre en"

    source = create_asset(catalog, "REST-001")
    target = create_asset(catalog, "REST-002")
    created = client.post(
        f"{prefix}/relationships",
        json={
            "sourceId": source,
            "targetId": target,
            "typeKey": "connected_to",
            "reason": "conexión de prueba",
            "notes": "puerto 10",
        },
        headers=auth,
    )
    assert created.status_code == 201
    edge = created.json()
    assert set(edge) == RELATIONSHIP_KEYS
    assert edge["direction"] == "outgoing"
    assert edge["label"] == "Conectado a"

    outgoing = client.get(f"{prefix}/relationships", params={"assetId": source}, headers=auth)
    assert outgoing.status_code == 200
    assert outgoing.json()["total"] == 1
    assert outgoing.json()["items"][0]["label"] == "Conectado a"

    incoming = client.get(f"{prefix}/relationships", params={"assetId": target}, headers=auth)
    assert incoming.status_code == 200
    assert incoming.json()["items"][0]["direction"] == "incoming"
    assert incoming.json()["items"][0]["label"] == "Conectado desde"

    patched = client.patch(
        f"{prefix}/relationships/{edge['id']}",
        json={"typeKey": "depends_on", "reason": "cambio de tipo"},
        headers=auth,
    )
    assert patched.status_code == 200
    assert patched.json()["typeKey"] == "depends_on"

    removed = client.request(
        "DELETE",
        f"{prefix}/relationships/{edge['id']}",
        json={"reason": "ya no aplica"},
        headers=auth,
    )
    assert removed.status_code == 200
    assert client.get(f"{prefix}/relationships", headers=auth).json()["total"] == 0

    with catalog.session() as session:
        inventory = InventoryService(session, catalog.settings)
        history = inventory.history(catalog.admin(), source)
    assert history.items[-1].source == "rest"
    assert history.items[-1].entity_type == "relationship"


def test_relationship_graph_is_bounded_and_requires_authentication(
    api: tuple[TestClient, dict[str, str], TestClient],
    catalog: Catalog,
) -> None:
    client, auth, anonymous = api
    prefix = catalog.settings.api_prefix
    first = create_asset(catalog, "GRP-001")
    second = create_asset(catalog, "GRP-002")
    third = create_asset(catalog, "GRP-003")
    create_edge(catalog, first, second)
    create_edge(catalog, second, third)

    assert anonymous.get(f"{prefix}/infrastructure/graph").status_code == 401

    graph = client.get(
        f"{prefix}/infrastructure/graph",
        params={"rootId": first, "depth": 1, "direction": "out"},
        headers=auth,
    )
    assert graph.status_code == 200
    payload = graph.json()
    assert {node["id"] for node in payload["nodes"]} == {first, second}
    assert len(payload["edges"]) == 1
    assert payload["depthTruncated"] is True
    assert payload["truncated"] is True

    assert (
        client.get(
            f"{prefix}/infrastructure/graph",
            params={"rootId": first, "depth": 6},
            headers=auth,
        ).status_code
        == 422
    )
    assert (
        client.get(
            f"{prefix}/infrastructure/graph",
            params={"assetIds": [first] * 51},
            headers=auth,
        ).status_code
        == 422
    )

    global_page = client.get(f"{prefix}/infrastructure/graph", params={"limit": 1}, headers=auth)
    assert global_page.status_code == 200
    assert global_page.json()["total"] == 2
    assert len(global_page.json()["edges"]) == 1
    assert len(global_page.json()["nodes"]) == 2


def test_relationship_mutations_require_csrf_origin_and_casbin(
    api: tuple[TestClient, dict[str, str], TestClient],
    catalog: Catalog,
) -> None:
    client, auth, anonymous = api
    prefix = catalog.settings.api_prefix
    source = create_asset(catalog, "GUARD-001")
    target = create_asset(catalog, "GUARD-002")
    body = {"sourceId": source, "targetId": target, "typeKey": "connected_to", "reason": "prueba"}

    assert anonymous.post(f"{prefix}/relationships", json=body).status_code == 401

    catalog.add_user(*READER)
    reader = sign_in_as(client, catalog.settings, READER[0], MACHINE_PASSWORD)
    denied = client.post(f"{prefix}/relationships", json=body, headers=reader)
    assert denied.status_code == 403
    assert client.get(f"{prefix}/relationships", headers=auth).json()["total"] == 0
    assert (
        client.post(
            f"{prefix}/relationship-types",
            json={"key": "guarded", "forwardLabel": "Guardado", "inverseLabel": "Guarda"},
            headers=reader,
        ).status_code
        == 403
    )

    # Signing in as the reader replaced the cookie; restore the administrator
    # before checking the origin/CSRF guards and the allowed mutation.
    auth = sign_in_as(client, catalog.settings, ADMIN_USERNAME, ADMIN_PASSWORD)

    no_origin = client.post(
        f"{prefix}/relationships",
        json=body,
        headers={"X-CSRF-Token": auth["X-CSRF-Token"]},
    )
    assert no_origin.status_code == 403
    no_csrf = client.post(
        f"{prefix}/relationships",
        json=body,
        headers={"Origin": auth["Origin"]},
    )
    assert no_csrf.status_code == 403
    assert client.get(f"{prefix}/relationships", headers=auth).json()["total"] == 0

    allowed = client.post(f"{prefix}/relationships", json=body, headers=auth)
    assert allowed.status_code == 201


def test_host_move_rest_replaces_the_parent_atomically(
    api: tuple[TestClient, dict[str, str], TestClient],
    catalog: Catalog,
) -> None:
    client, auth, _ = api
    prefix = catalog.settings.api_prefix
    child = create_asset(catalog, "VM-100")
    old_host = create_asset(catalog, "HOST-100")
    new_host = create_asset(catalog, "HOST-200")
    create_edge(catalog, child, old_host, "hosted_in")

    moved = client.post(
        f"{prefix}/relationships/host-move",
        json={
            "childId": child,
            "newHostId": new_host,
            "reason": "migración de mantenimiento",
            "notes": "ventana nocturna",
        },
        headers=auth,
    )
    assert moved.status_code == 200
    payload = moved.json()
    assert payload["childId"] == child
    assert payload["oldRelationship"]["targetId"] == old_host
    assert payload["newRelationship"]["targetId"] == new_host
    assert payload["newRelationship"]["sourceId"] == child

    with catalog.session() as session:
        inventory = InventoryService(session, catalog.settings)
        history = inventory.history(catalog.admin(), child)
    assert history.items[-1].action == "host_moved"
    assert history.items[-1].changes["host"] == {"old": old_host, "new": new_host}
    assert history.items[-1].notes == "ventana nocturna"


def test_relationship_reads_require_a_session(
    api: tuple[TestClient, dict[str, str], TestClient],
    catalog: Catalog,
) -> None:
    _, _, anonymous = api
    prefix = catalog.settings.api_prefix
    assert anonymous.get(f"{prefix}/relationships").status_code == 401
    assert anonymous.get(f"{prefix}/relationship-types").status_code == 401
