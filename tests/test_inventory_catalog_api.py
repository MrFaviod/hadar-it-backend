"""Persistent inventory configuration through the authenticated public API."""

from __future__ import annotations

from copy import deepcopy

import pytest
from tests.inventory_support import READER, prepare, sign_in_as


def test_installation_supplies_all_forms_and_persists_edits(signed_in_client):
    client, auth = signed_in_client()
    response = client.get("/api/v1/inventory/config")
    assert response.status_code == 200
    config = response.json()
    assert {item["id"] for item in config["categories"]} >= {
        "computadoras",
        "notebooks",
        "servidores",
        "virtualizacion",
        "docker",
        "lxc",
        "switches",
        "routers",
        "impresoras",
        "ups",
        "camaras",
        "monitores",
        "otros",
    }
    assert {item["id"] for item in config["statuses"]} == {
        "in_use",
        "in_storage",
        "maintenance",
        "retired",
    }
    assert next(item for item in config["categories"] if item["id"] == "camaras")["fov"] is True
    field = {"key": "purchaseDate", "label": "Fecha de compra", "type": "date"}
    saved = client.put("/api/v1/inventory/config/fields/purchaseDate", json=field, headers=auth)
    assert saved.status_code == 200, saved.text
    for category_id in ("computadoras", "notebooks"):
        category = deepcopy(
            next(item for item in config["categories"] if item["id"] == category_id)
        )
        category["tech"].append("purchaseDate")
        result = client.put(
            "/api/v1/inventory/config/categories/" + category_id, json=category, headers=auth
        )
        assert result.status_code == 200, result.text
    after = client.get("/api/v1/inventory/config").json()
    assert next(item for item in after["fields"] if item["key"] == "purchaseDate")["type"] == "date"
    assert all(
        "purchaseDate" in item["tech"]
        for item in after["categories"]
        if item["id"] in ("computadoras", "notebooks")
    )
    renamed = {**saved.json(), "label": "Fecha de adquisición", "active": False}
    assert (
        client.put(
            "/api/v1/inventory/config/fields/purchaseDate", json=renamed, headers=auth
        ).status_code
        == 200
    )
    final = client.get("/api/v1/inventory/config").json()
    assert (
        next(item for item in final["fields"] if item["key"] == "purchaseDate")["active"] is False
    )
    assert (
        next(item for item in final["categories"] if item["id"] == "notebooks")["tech"][-1]
        == "purchaseDate"
    )


def test_config_mutations_are_guarded_and_readers_cannot_write(signed_in_client, settings_factory):
    catalog = prepare(settings_factory)
    catalog.add_user(*READER)
    client, _admin_auth = signed_in_client(catalog.settings)
    before = client.get("/api/v1/inventory/config").json()
    payload = {"key": "secret", "label": "Secret", "type": "text"}
    assert client.put("/api/v1/inventory/config/fields/secret", json=payload).status_code == 403
    reader_auth = sign_in_as(client, catalog.settings, READER[0])
    assert client.get("/api/v1/inventory/config").status_code == 200
    denied = client.put("/api/v1/inventory/config/fields/secret", json=payload, headers=reader_auth)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "forbidden"
    assert client.get("/api/v1/inventory/config").json() == before
    catalog.engine.dispose()


@pytest.mark.parametrize(
    "resource,key,payload",
    [
        ("fields", "invalid", {"key": "invalid", "label": "X", "type": "script"}),
        ("fields", "bad", {"key": "another", "label": "X", "type": "text"}),
        ("fields", "bad", {"key": "bad", "label": "X", "type": "select", "options": []}),
        (
            "fields",
            "bad",
            {"key": "bad", "label": "X", "type": "number", "minimum": 10, "maximum": 1},
        ),
        ("categories", "bad", {"id": "bad", "label": "X", "tech": ["not-registered"]}),
        ("statuses", "bad", {"id": "bad", "label": "X", "tone": "rainbow"}),
        ("rules", "identification", {"quickPad": 99}),
        ("rules", "identification", {"environment": "development"}),
        ("rules", "transitions", {"transitions": {"in_use": ["not-a-status"]}}),
    ],
)
def test_invalid_configuration_is_atomic(signed_in_client, resource, key, payload):
    client, auth = signed_in_client()
    before = client.get("/api/v1/inventory/config").json()
    rejected = client.put(f"/api/v1/inventory/config/{resource}/{key}", json=payload, headers=auth)
    assert rejected.status_code == 422, rejected.text
    assert client.get("/api/v1/inventory/config").json() == before


@pytest.mark.parametrize(
    "resource,key,payload,message",
    [
        ("statuses", "probe", {"label": "Probe", "tone": ["ok"]}, "unsupported status tone"),
        ("rules", "identification", {"separator": ["-"]}, "unsupported quick code separator"),
        ("rules", "identification", {"order": {"a": 1}}, "unsupported code component order"),
    ],
)
def test_malformed_enums_return_422_without_changing_state(
    signed_in_client, resource, key, payload, message
):
    client, auth = signed_in_client()
    config_before = client.get("/api/v1/inventory/config").json()
    assets_before = client.get("/api/v1/assets").json()
    rejected = client.put(f"/api/v1/inventory/config/{resource}/{key}", json=payload, headers=auth)
    assert client.get("/api/v1/inventory/config").json() == config_before
    assert client.get("/api/v1/assets").json() == assets_before
    assert rejected.status_code == 422, rejected.text
    assert rejected.json()["error"] == {"code": "validation_error", "message": message}


def test_field_evolution_never_drops_existing_type_or_options(signed_in_client):
    client, auth = signed_in_client()
    field = {"key": "network", "label": "Red", "type": "select", "options": ["LAN", "WAN"]}
    assert (
        client.put("/api/v1/inventory/config/fields/network", json=field, headers=auth).status_code
        == 200
    )
    before = client.get("/api/v1/inventory/config").json()
    for change in ({"type": "number"}, {"options": ["LAN"]}):
        denied = client.put(
            "/api/v1/inventory/config/fields/network", json={**field, **change}, headers=auth
        )
        assert denied.status_code == 409
        assert client.get("/api/v1/inventory/config").json() == before
    assert (
        client.put(
            "/api/v1/inventory/config/fields/network",
            json={**field, "options": ["LAN", "WAN", "DMZ"]},
            headers=auth,
        ).status_code
        == 200
    )


def test_existing_inventory_still_accepts_sparse_and_legacy_category(signed_in_client):
    client, auth = signed_in_client()
    created = client.post(
        "/api/v1/assets", json={"name": "Legacy", "category": "Red"}, headers=auth
    )
    assert created.status_code == 201
    fetched = client.get("/api/v1/assets/" + created.json()["id"])
    assert fetched.status_code == 200
    assert fetched.json() == created.json()
