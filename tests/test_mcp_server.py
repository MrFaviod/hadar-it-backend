"""MCP protocol tests: mounted FastMCP server over the real streamable HTTP transport."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
import uvicorn
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from itsm.config import Settings
from itsm.main import create_app
from mcp.shared.exceptions import MCPError
from tests.inventory_support import Catalog, prepare

TOOL_NAMES = {
    "search_assets",
    "get_asset",
    "create_asset",
    "update_asset",
    "batch_update_assets",
    "clone_asset",
    "archive_asset",
    "restore_asset",
    "retire_asset",
    "get_asset_history",
    "get_inventory_config",
    "get_redundancy_group",
    "list_redundancy_groups",
    "search_locations",
    "search_people",
    "assign_asset",
    "return_asset",
    "transfer_asset",
    "get_asset_relations",
    "create_relationship",
    "remove_relationship",
    "move_host",
    "get_asset_map",
    "save_redundancy_group",
    "prepare_inventory_import",
    "preview_bulk_operation",
    "get_inventory_operation",
    "resolve_import_conflict",
    "apply_inventory_operation",
}


@pytest.fixture
def catalog(settings_factory: Callable[..., Settings]) -> Catalog:
    return prepare(settings_factory)


@dataclass
class McpServer:
    url: str
    catalog: Catalog

    def transport(self, token: str | None = None, **headers: str) -> StreamableHttpTransport:
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        return StreamableHttpTransport(self.url, headers=headers)


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
    _, token = server.catalog.add_machine("mcp-operator", "MCP Operator", "operator")
    return "mcp-operator", token


def test_mcp_requires_bearer_and_rejects_cookie_sessions(mcp: McpServer) -> None:
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


def test_mcp_rejects_invalid_bearer(mcp: McpServer) -> None:
    with httpx.Client(timeout=10) as client:
        response = client.post(
            mcp.url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": "Bearer itsm_invalid_token_value",
            },
        )
    assert response.status_code == 401
    with pytest.raises((MCPError, ToolError)):
        list_tools(mcp, "itsm_invalid_token_value")


def test_mcp_missing_asset_preserves_existing_error(mcp: McpServer) -> None:
    _, token = operator(mcp)
    with pytest.raises(ToolError, match=r"^asset not found$"):
        call_tool(
            mcp,
            token,
            "get_asset",
            {"asset_id": "00000000-0000-4000-8000-000000000000"},
        )


def test_mcp_create_is_visible_through_rest_with_the_same_id(mcp: McpServer) -> None:
    _, token = operator(mcp)

    created = call_tool(
        mcp,
        token,
        "create_asset",
        {
            "name": "Switch Aruba 2930F",
            "quick_code": "SITE-DEMO-001",
            "category": "Red",
            "site": "Example Site",
            "status": "in_use",
        },
    )
    payload = created.structured_content
    assert payload["quickCode"] == "SITE-DEMO-001"

    fetched = rest_get(mcp, token, f"/api/v1/assets/{payload['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == payload["id"]
    assert fetched.json()["quickCode"] == "SITE-DEMO-001"


def test_mcp_update_keeps_id_and_repeat_is_stable(mcp: McpServer) -> None:
    _, token = operator(mcp)
    created = call_tool(mcp, token, "create_asset", {"name": "Notebook", "quick_code": "MCP-NB-1"})
    asset_id = created.structured_content["id"]

    first = call_tool(mcp, token, "update_asset", {"asset_id": asset_id, "quick_code": "MCP-NB-2"})
    second = call_tool(mcp, token, "update_asset", {"asset_id": asset_id, "quick_code": "MCP-NB-2"})

    assert first.structured_content["id"] == asset_id
    assert second.structured_content["id"] == asset_id
    assert second.structured_content["quickCode"] == "MCP-NB-2"


def test_mcp_revoked_bearer_is_revalidated_per_operation(mcp: McpServer) -> None:
    username, token = operator(mcp)

    async def run() -> None:
        async with Client(mcp.transport(token)) as client:
            found = await client.call_tool("search_assets", {"query": "nada"})
            assert found.structured_content["total"] == 0
            mcp.catalog.revoke_machine(username)
            # Revocation is enforced per request (401) and per tool operation.
            with pytest.raises((MCPError, ToolError)):
                await client.call_tool("search_assets", {"query": "nada"})

    asyncio.run(run())


def test_mcp_validation_and_denied_mutation_leave_assets_unchanged(mcp: McpServer) -> None:
    _, token = operator(mcp)
    _, reader_token = mcp.catalog.add_machine("mcp-reader", "MCP Reader", "user")

    with pytest.raises(ToolError):
        call_tool(mcp, token, "create_asset", {"name": "Switch", "custom": "nope"})
    with pytest.raises(ToolError):
        call_tool(mcp, token, "create_asset", {"name": "Switch", "status": "deleted"})
    with pytest.raises(ToolError):
        call_tool(mcp, reader_token, "create_asset", {"name": "Switch"})

    assert mcp.catalog.asset_count() == 0
    denied = [row for row in mcp.catalog.audit() if row["outcome"] == "denied"]
    assert any(row["action"] == "assets.edit" for row in denied)


def test_mcp_batch_is_bounded_atomic_and_compact(mcp: McpServer) -> None:
    _, token = operator(mcp)
    first = call_tool(mcp, token, "create_asset", {"name": "AP Uno", "quick_code": "AP-1"})
    second = call_tool(mcp, token, "create_asset", {"name": "AP Dos", "quick_code": "AP-2"})

    updated = call_tool(
        mcp,
        token,
        "batch_update_assets",
        {
            "updates": [
                {"asset_id": first.structured_content["id"], "site": "Example Site"},
                {"asset_id": second.structured_content["id"], "site": "Example Site"},
            ]
        },
    )
    assert {item["site"] for item in updated.structured_content["updated"]} == {"Example Site"}

    search = call_tool(mcp, token, "search_assets", {"site": "Example Site"})
    assert search.structured_content["total"] == 2
    assert set(search.structured_content["items"][0]) == {
        "id",
        "quickCode",
        "name",
        "category",
        "site",
        "location",
        "responsible",
        "status",
        "ip",
        "archived",
    }

    with pytest.raises(ToolError):
        call_tool(
            mcp,
            token,
            "batch_update_assets",
            {
                "updates": [
                    {"asset_id": first.structured_content["id"], "site": "Otro"},
                    {"asset_id": "00000000-0000-4000-8000-000000000000", "site": "Otro"},
                ]
            },
        )
    assert (
        rest_get(mcp, token, f"/api/v1/assets/{first.structured_content['id']}").json()["site"]
        == "Example Site"
    )


def test_mcp_is_not_a_rest_export(mcp: McpServer) -> None:
    _, token = operator(mcp)

    for tool in ("identity_state", "create_user", "admin_roles", "tasks_demo"):
        with pytest.raises((MCPError, ToolError)):
            call_tool(mcp, token, tool, {})
