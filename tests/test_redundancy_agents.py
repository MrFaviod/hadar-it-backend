"""Redundancy over the real agent and MCP transports: reuse, denial and trusted source."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import httpx
import pydantic_ai.models
import pytest
import uvicorn
from fastapi.testclient import TestClient
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from itsm.agents import runtime as agent_runtime
from itsm.agents.runtime import AgentRuntime
from itsm.config import Settings
from itsm.inventory.service import InventoryService
from itsm.main import create_app
from pydantic_ai.messages import (
    ModelMessage,
    ModelResponse,
    TextPart,
    ToolCallPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from tests.inventory_support import Catalog, asset_values, prepare, sign_in_as
from tests.test_agent_chat import scripted

SettingsFactory = Callable[..., Settings]

GROUP_TOOLS = ("get_redundancy_group", "list_redundancy_groups", "save_redundancy_group")


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


def use_model(test_client: TestClient, model: FunctionModel) -> None:
    app = test_client.app
    app.state.agent_runtime = AgentRuntime(  # type: ignore[attr-defined]
        app.state.settings,
        app.state.session_factory,
        model=model,
    )


def chat(client: TestClient, auth: dict[str, str], message: str) -> dict[str, Any]:
    response = client.post("/api/v1/agent/chat", json={"message": message}, headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def create_asset(catalog: Catalog, quick_code: str) -> str:
    with catalog.session() as session:
        created = InventoryService(session, catalog.settings).create(
            catalog.admin(),
            asset_values(quick_code=quick_code, name=f"Equipo {quick_code}"),
        )
        return created.id


def group_count(catalog: Catalog) -> int:
    with catalog.engine.connect() as connection:
        return int(
            connection.exec_driver_sql("SELECT COUNT(*) FROM redundancy_groups").scalar_one()
        )


def history_actions(catalog: Catalog, asset_id: str) -> list[str]:
    with catalog.session() as session:
        page = InventoryService(session, catalog.settings).history(catalog.admin(), asset_id)
        return [item.action for item in page.items]


def test_agent_registry_adds_exactly_the_three_group_tools(
    signed_in_client: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)
    client, auth = signed_in_client()
    seen: list[str] = []

    def run(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        seen.extend(tool.name for tool in info.function_tools)
        return ModelResponse(parts=[TextPart("Listo.")])

    use_model(client, FunctionModel(run))
    chat(client, auth, "¿Qué podés hacer?")

    assert len(seen) == len(set(seen)) == 29
    assert set(GROUP_TOOLS) <= set(seen)
    assert set(seen) == set(agent_runtime.TOOL_NAMES)
    for name in seen:
        for forbidden in ("shell", "exec", "sql", "file", "http", "browser", "python"):
            assert forbidden not in name


def test_agent_saves_lists_and_reads_a_group_through_the_canonical_service(
    catalog: Catalog, signed_in_client: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)
    client, auth = signed_in_client(catalog.settings)
    first = create_asset(catalog, "AG-1")
    second = create_asset(catalog, "AG-2")

    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "save_redundancy_group",
                        {
                            "name": "Portal agente",
                            "mode": "active_active",
                            "members": [
                                {"asset_id": first, "share": "40"},
                                {"asset_id": second, "share": "60"},
                            ],
                            "reason": "alta desde el asistente",
                        },
                        tool_call_id="t-save",
                    )
                ],
                [TextPart("Grupo creado.")],
            )
        ),
    )
    reply = chat(client, auth, "Creá el grupo de redundancia 40/60")
    assert reply["actions"][0]["tool"] == "save_redundancy_group"
    assert reply["actions"][0]["status"] == "completed"
    created = reply["results"][0]
    assert created["group"]["memberCount"] == 2

    group_id = created["group"]["id"]
    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "get_redundancy_group", {"group_id": group_id}, tool_call_id="t-get"
                    ),
                    TextPart("Grupo leído."),
                ],
                [TextPart("Grupo leído.")],
            )
        ),
    )
    fetched = chat(client, auth, "Leé el grupo")
    assert fetched["results"][0]["group"]["id"] == group_id

    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "list_redundancy_groups", {"query": "portal"}, tool_call_id="t-list"
                    ),
                    TextPart("Listado."),
                ],
                [TextPart("Listado.")],
            )
        ),
    )
    listed = chat(client, auth, "Listá los grupos")
    page = listed["results"][0]["groups"]
    assert page["total"] == 1
    assert page["items"][0]["id"] == group_id

    rows = history_actions(catalog, first)
    assert "redundancy_group_created" in rows
    with catalog.session() as session:
        entry = next(
            item
            for item in InventoryService(session, catalog.settings)
            .history(catalog.admin(), first)
            .items
            if item.action == "redundancy_group_created"
        )
    assert entry.source == "agent"
    assert entry.entity_type == "redundancy_group"
    assert entry.entity_id == group_id


def test_agent_group_tool_is_denied_for_a_reader_without_writing(
    catalog: Catalog, signed_in_client: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)
    client, _auth = signed_in_client(catalog.settings)
    first = create_asset(catalog, "AG-3")
    second = create_asset(catalog, "AG-4")
    from tests.inventory_support import READER

    catalog.add_user(*READER)
    reader = sign_in_as(client, catalog.settings, READER[0], "machine-identity-password-2026")

    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "save_redundancy_group",
                        {
                            "name": "Intruso",
                            "mode": "active_active",
                            "members": [
                                {"asset_id": first, "share": "40"},
                                {"asset_id": second, "share": "60"},
                            ],
                        },
                        tool_call_id="t-denied",
                    )
                ],
                [TextPart("Sin permiso.")],
            )
        ),
    )
    reply = chat(client, reader, "Creá el grupo")
    assert reply["actions"][0]["status"] == "denied"
    assert group_count(catalog) == 0


@dataclass
class McpServer:
    url: str
    catalog: Catalog

    def transport(self, token: str) -> StreamableHttpTransport:
        return StreamableHttpTransport(self.url, headers={"Authorization": f"Bearer {token}"})


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


def call_tool(server: McpServer, token: str, tool: str, arguments: dict[str, Any]) -> Any:
    async def run() -> Any:
        async with Client(server.transport(token)) as client:
            return await client.call_tool(tool, arguments)

    return asyncio.run(run())


def list_tools(server: McpServer, token: str) -> list[str]:
    async def run() -> list[str]:
        async with Client(server.transport(token)) as client:
            tools = await client.list_tools()
        return sorted(tool.name for tool in tools)

    return asyncio.run(run())


def rest_get(server: McpServer, token: str, path: str) -> httpx.Response:
    base = server.url.removesuffix("/api/v1/mcp")
    return httpx.get(f"{base}{path}", headers={"Authorization": f"Bearer {token}"}, timeout=10)


def operator(server: McpServer) -> tuple[str, str]:
    _, token = server.catalog.add_machine("redundancy-operator", "Redundancy Operator", "operator")
    return "redundancy-operator", token


def test_mcp_exposes_the_three_group_tools_and_keeps_the_rest(mcp: McpServer) -> None:
    _, token = operator(mcp)
    tools = list_tools(mcp, token)
    assert len(tools) == 29
    assert set(GROUP_TOOLS) <= set(tools)
    with httpx.Client(timeout=10) as client:
        anonymous = client.post(
            mcp.url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        cookie = client.post(
            mcp.url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={
                "Accept": "application/json, text/event-stream",
                "Cookie": "itsm_session=not-a-bearer-token",
            },
        )
    assert anonymous.status_code == 401
    assert cookie.status_code == 401


def test_mcp_saves_gets_and_lists_groups_with_the_mcp_source(mcp: McpServer) -> None:
    username, token = operator(mcp)
    first = create_asset(mcp.catalog, "MC-1")
    second = create_asset(mcp.catalog, "MC-2")

    saved = call_tool(
        mcp,
        token,
        "save_redundancy_group",
        {
            "name": "Portal MCP",
            "mode": "active_active",
            "members": [
                {"asset_id": first, "share": "40"},
                {"asset_id": second, "share": "60"},
            ],
            "reason": "alta por herramienta",
        },
    ).structured_content
    group = saved["group"]
    assert group["memberCount"] == 2

    fetched = call_tool(mcp, token, "get_redundancy_group", {"group_id": group["id"]})
    assert fetched.structured_content["group"]["id"] == group["id"]

    listed = call_tool(mcp, token, "list_redundancy_groups", {"query": "mcp"}).structured_content
    assert listed["groups"]["total"] == 1
    assert listed["groups"]["items"][0]["id"] == group["id"]

    rest = rest_get(mcp, token, f"/api/v1/redundancy-groups/{group['id']}")
    assert rest.status_code == 200
    assert rest.json()["members"][0]["assetId"] in {first, second}

    with mcp.catalog.session() as session:
        page = InventoryService(session, mcp.catalog.settings).history(mcp.catalog.admin(), first)
        entry = next(item for item in page.items if item.action == "redundancy_group_created")
    assert entry.source == "mcp"
    assert entry.entity_id == group["id"]
    assert [event["actor"] for event in mcp.catalog.audit("redundancy.group_created")] == [username]
