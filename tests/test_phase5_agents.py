"""Phase 5 agent and MCP tools: people, locations, relations, history and maps.

Every tool call here runs against the real SQL services and the real transport;
no provider inference is consumed and no tool may invent a principal.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import pydantic_ai.models
import pytest
import uvicorn
from fastmcp.exceptions import ToolError
from itsm.agents.runtime import AgentRuntime
from itsm.config import Settings
from itsm.main import create_app
from pydantic_ai.messages import TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from tests.inventory_support import Catalog, prepare
from tests.test_agent_chat import scripted
from tests.test_mcp_server import McpServer, call_tool, operator


@pytest.fixture
def catalog(settings_factory: Callable[..., Settings]) -> Catalog:
    return prepare(settings_factory)


@pytest.fixture
def mcp(catalog: Catalog, free_tcp_port: int) -> Iterator[McpServer]:
    app = create_app(catalog.settings)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=free_tcp_port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "uvicorn did not start"
    try:
        yield McpServer(f"http://127.0.0.1:{free_tcp_port}/api/v1/mcp", catalog)
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def site_and_room(client: Any, auth: dict[str, str]) -> tuple[str, str]:
    """Create one site and one room through the public REST surface."""
    site = client.post(
        "/api/v1/locations",
        json={"level": "site", "name": "Sede Central", "latitude": -25.286, "longitude": -57.647},
        headers=auth,
    )
    assert site.status_code == 201, site.text
    room = client.post(
        "/api/v1/locations",
        json={"level": "building", "parentId": site.json()["id"], "name": "Edificio A"},
        headers=auth,
    )
    assert room.status_code == 201, room.text
    return site.json()["id"], room.json()["id"]


def person(client: Any, auth: dict[str, str], site_id: str, **overrides: Any) -> str:
    payload = {"name": "Ana Pérez", "jobTitle": "Jefa de infraestructura", "siteId": site_id}
    payload.update(overrides)
    response = client.post("/api/v1/people", json=payload, headers=auth)
    assert response.status_code == 201, response.text
    return response.json()["id"]


def asset(client: Any, auth: dict[str, str], **overrides: Any) -> dict[str, Any]:
    payload = {"name": "Switch de borde", "category": "Red"}
    payload.update(overrides)
    response = client.post("/api/v1/assets", json=payload, headers=auth)
    assert response.status_code == 201, response.text
    return response.json()


def use_model(client: Any, model: FunctionModel) -> None:
    app = client.app
    app.state.agent_runtime = AgentRuntime(
        app.state.settings, app.state.session_factory, model=model
    )


def chat(client: Any, auth: dict[str, str], message: str) -> dict[str, Any]:
    response = client.post("/api/v1/agent/chat", json={"message": message}, headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def test_agent_assigns_transfers_and_reads_relations(signed_in_client, monkeypatch):
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)
    client, auth = signed_in_client()
    site_id, building_id = site_and_room(client, auth)
    room = client.post(
        "/api/v1/locations",
        json={"level": "floor", "parentId": building_id, "name": "Piso 1"},
        headers=auth,
    )
    assert room.status_code == 201, room.text
    floor_id = room.json()["id"]
    person_id = person(client, auth, site_id)
    created = asset(client, auth, locationId=building_id, positionX="0.4", positionY="0.6")
    host = asset(client, auth, name="Servidor físico", category="servidores")

    model = FunctionModel(
        scripted(
            [
                ToolCallPart(
                    "search_locations",
                    {"query": "Piso", "level": "floor"},
                    tool_call_id="t-locations",
                )
            ],
            [
                ToolCallPart(
                    "search_people",
                    {"query": "Ana"},
                    tool_call_id="t-people",
                )
            ],
            [
                ToolCallPart(
                    "assign_asset",
                    {"asset_id": created["id"], "person_id": person_id, "reason": "entrega"},
                    tool_call_id="t-assign",
                )
            ],
            [
                ToolCallPart(
                    "transfer_asset",
                    {
                        "asset_id": created["id"],
                        "location_id": floor_id,
                        "reason": "mudanza de rack",
                    },
                    tool_call_id="t-transfer",
                )
            ],
            [
                ToolCallPart(
                    "create_relationship",
                    {
                        "source_id": created["id"],
                        "target_id": host["id"],
                        "type_key": "hosted_in",
                        "reason": "virtualización",
                    },
                    tool_call_id="t-relation",
                )
            ],
            [
                ToolCallPart(
                    "get_asset_relations",
                    {"asset_ids": [created["id"]]},
                    tool_call_id="t-relations",
                )
            ],
            [ToolCallPart("get_asset_map", {"site_id": site_id}, tool_call_id="t-map")],
            [TextPart("Operaciones aplicadas.")],
        )
    )
    use_model(client, model)
    reply = chat(client, auth, "Asigná y mudá el switch")

    actions = [action["status"] for action in reply["actions"]]
    assert actions == ["completed"] * 7
    results = reply["results"]

    assert results[0]["total"] == 1
    assert results[0]["items"][0]["level"] == "floor"
    assert results[1]["total"] == 1
    assert results[1]["items"][0]["label"] == "Ana Pérez (Jefa de infraestructura)"

    stored = client.get(f"/api/v1/assets/{created['id']}", headers=auth).json()
    assert stored["responsiblePersonId"] == person_id
    assert stored["responsible"] == "Ana Pérez (Jefa de infraestructura)"
    assert stored["locationId"] == floor_id

    relation = results[4]["relationship"]
    assert relation["typeKey"] == "hosted_in"
    assert relation["sourceId"] == created["id"]
    assert relation["targetId"] == host["id"]
    assert relation["label"] == "Alojado en"

    listed = results[5]["items"]
    assert [item["id"] for item in listed] == [relation["id"]]
    assert listed[0]["direction"] == "outgoing"
    assert listed[0]["label"] == "Alojado en"

    assert [site["id"] for site in results[6]["sites"]] == [site_id]
    assert [position["assetId"] for position in results[6]["positions"]] == [created["id"]]

    history = client.get(f"/api/v1/assets/{created['id']}/history?limit=10", headers=auth).json()
    assert {item["action"] for item in history["items"]} >= {"assigned", "transferred"}
    assigned = next(item for item in history["items"] if item["action"] == "assigned")
    assert assigned["source"] == "agent" and assigned["entityType"] == "asset"


def test_agent_denied_relationship_write_changes_nothing(signed_in_client, monkeypatch):
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)
    client, auth = signed_in_client()
    site_id, _ = site_and_room(client, auth)
    first = asset(client, auth, quickCode="AG-DENY-1")
    second = asset(client, auth, quickCode="AG-DENY-2")
    assert site_id

    created_user = client.post(
        "/api/v1/identity/users",
        json={
            "username": "reader-user",
            "name": "Reader User",
            "password": "reader-password-2026",
            "roleId": "reader",
        },
        headers=auth,
    )
    assert created_user.status_code in (200, 201), created_user.text
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "reader-user", "password": "reader-password-2026"},
        headers={"Origin": client.app.state.settings.auth_origin},
    )
    assert login.status_code == 200, login.text
    reader_auth = {
        "X-CSRF-Token": login.json()["csrfToken"],
        "Origin": client.app.state.settings.auth_origin,
    }

    model = FunctionModel(
        scripted(
            [
                ToolCallPart(
                    "create_relationship",
                    {
                        "source_id": first["id"],
                        "target_id": second["id"],
                        "type_key": "connected_to",
                    },
                    tool_call_id="t-denied",
                )
            ],
            [TextPart("No autorizado.")],
        )
    )
    use_model(client, model)
    reply = chat(client, reader_auth, "Conectá los dos switches")

    assert reply["actions"][0]["status"] == "denied"
    listed = client.get(f"/api/v1/assets/{first['id']}/relations", headers=auth).json()
    assert listed["outgoing"] == [] and listed["incoming"] == []
    assert client.get(f"/api/v1/assets/{first['id']}/history", headers=auth).json()["total"] == 1


def test_mcp_exposes_directory_relationship_history_and_map_tools(mcp: McpServer) -> None:
    _, token = operator(mcp)

    def create(name: str, code: str, **extra: Any) -> dict[str, Any]:
        payload = {"name": name, "quick_code": code}
        payload.update(extra)
        return call_tool(mcp, token, "create_asset", payload).structured_content

    child = create("VM contenedora", "MCP-VM-1")
    host = create("Servidor físico", "MCP-SRV-1")
    spare = create("Servidor de repuesto", "MCP-SRV-2")

    empty = call_tool(mcp, token, "search_locations", {"limit": 1}).structured_content
    assert set(empty) == {"total", "limit", "offset", "items"}
    assert empty["total"] == 0

    edge = call_tool(
        mcp,
        token,
        "create_relationship",
        {
            "source_id": child["id"],
            "target_id": host["id"],
            "type_key": "hosted_in",
            "reason": "alta de VM",
            "effective_at": "2026-08-01T12:00:00+00:00",
            "notes": "ventana nocturna",
        },
    ).structured_content
    assert edge["typeKey"] == "hosted_in"
    assert edge["label"] == "Alojado en"

    related = call_tool(
        mcp,
        token,
        "get_asset_relations",
        {"asset_ids": [child["id"], host["id"]]},
    ).structured_content
    assert related["total"] == 1
    assert related["items"][0]["direction"] in {"outgoing", "incoming"}

    moved = call_tool(
        mcp,
        token,
        "move_host",
        {"child_id": child["id"], "new_host_id": spare["id"], "reason": "migración"},
    ).structured_content
    assert moved["childId"] == child["id"]
    assert moved["newRelationship"]["targetId"] == spare["id"]

    history = call_tool(
        mcp, token, "get_asset_history", {"asset_id": child["id"], "limit": 5}
    ).structured_content
    actions = [item["action"] for item in history["items"]]
    assert "relationship_created" in actions and "host_moved" in actions
    event = next(item for item in history["items"] if item["action"] == "relationship_created")
    assert event["source"] == "mcp"
    assert event["entityType"] == "relationship"
    assert event["effectiveAt"] == "2026-08-01T12:00:00+00:00"
    assert event["notes"] == "ventana nocturna"

    mapped = call_tool(mcp, token, "get_asset_map", {"limit": 5}).structured_content
    assert set(mapped) == {"sites", "positions", "limit", "offset", "truncated"}
    assert mapped["truncated"] is False


def test_mcp_denied_relationship_and_directory_writes_change_nothing(mcp: McpServer) -> None:
    _, token = operator(mcp)
    _, reader_token = mcp.catalog.add_machine("mcp-reader-relations", "MCP Reader", "reader")
    first = call_tool(
        mcp, token, "create_asset", {"name": "Switch A", "quick_code": "MCP-DENY-1"}
    ).structured_content
    second = call_tool(
        mcp, token, "create_asset", {"name": "Switch B", "quick_code": "MCP-DENY-2"}
    ).structured_content

    with pytest.raises(ToolError):
        call_tool(
            mcp,
            reader_token,
            "create_relationship",
            {"source_id": first["id"], "target_id": second["id"], "type_key": "connected_to"},
        )
    with pytest.raises(ToolError):
        call_tool(
            mcp,
            reader_token,
            "assign_asset",
            {"asset_id": first["id"], "person_id": "00000000-0000-4000-8000-000000000000"},
        )

    listed = call_tool(
        mcp, token, "get_asset_relations", {"asset_ids": [first["id"]]}
    ).structured_content
    assert listed["total"] == 0
    history = call_tool(
        mcp, token, "get_asset_history", {"asset_id": first["id"]}
    ).structured_content
    assert [item["action"] for item in history["items"]] == ["created"]


def test_mcp_bounds_map_history_and_location_tree(mcp: McpServer) -> None:
    _, token = operator(mcp)

    with pytest.raises(ToolError):
        call_tool(mcp, token, "get_asset_map", {"limit": 0})
    with pytest.raises(ToolError):
        call_tool(
            mcp, token, "get_asset_history", {"asset_id": "00000000-0000-4000-8000-000000000000"}
        )
    with pytest.raises(ToolError):
        call_tool(mcp, token, "search_locations", {"limit": 5000})

    tree = call_tool(
        mcp, token, "search_locations", {"depth": 2, "max_nodes": 5, "tree": True}
    ).structured_content
    assert tree["truncated"] is False
    assert tree["nodeCount"] == 0
