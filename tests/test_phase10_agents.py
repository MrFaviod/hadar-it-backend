"""Phase 10 operational tools over the real agent and MCP transports, without inference."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from itsm.agents import runtime as agent_runtime
from itsm.mcp import server as mcp_server
from mcp.shared.exceptions import MCPError
from pydantic_ai.messages import TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from tests.test_agent_chat import scripted
from tests.test_mcp_server import McpServer, call_tool, list_tools, operator
from tests.test_phase7_agents import (
    catalog,
    chat,
    create_asset,
    mcp,
    no_external_model_requests,
    use_model,
)

__all__ = ["catalog", "mcp", "no_external_model_requests"]

PHASE10_TOOLS = {
    "get_operational_summary",
    "search_everything",
    "query_relationships",
    "list_saved_views",
}


def mcp_asset(server: McpServer, token: str, name: str, code: str) -> dict[str, Any]:
    return call_tool(
        server, token, "create_asset", {"name": name, "quick_code": code}
    ).structured_content


def relate(
    client: Any,
    auth: dict[str, str],
    source_id: str,
    target_id: str,
    type_key: str = "depends_on",
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/relationships",
        json={"sourceId": source_id, "targetId": target_id, "typeKey": type_key},
        headers=auth,
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_phase10_tools_are_discoverable_on_agent_and_mcp(mcp: McpServer) -> None:
    assert set(agent_runtime.TOOL_NAMES) >= PHASE10_TOOLS
    assert set(mcp_server.TOOL_NAMES) >= PHASE10_TOOLS

    _, token = operator(mcp)
    assert set(list_tools(mcp, token)) >= PHASE10_TOOLS


def test_mcp_query_relationships_focuses_depth_and_filters(mcp: McpServer) -> None:
    _, token = operator(mcp)
    core = mcp_asset(mcp, token, "Switch núcleo", "P10-CORE")
    upstream = mcp_asset(mcp, token, "Router borde", "P10-EDGE")
    dependents = [
        mcp_asset(mcp, token, f"Servidor {index}", f"P10-SRV-{index}") for index in range(1, 4)
    ]
    for dependent in dependents:
        call_tool(
            mcp,
            token,
            "create_relationship",
            {"source_id": dependent["id"], "target_id": core["id"], "type_key": "depends_on"},
        )
    call_tool(
        mcp,
        token,
        "create_relationship",
        {"source_id": core["id"], "target_id": upstream["id"], "type_key": "depends_on"},
    )

    incoming = call_tool(
        mcp,
        token,
        "query_relationships",
        {
            "asset_id": core["id"],
            "depth": 2,
            "direction": "in",
            "type_key": "depends_on",
            "limit": 50,
        },
    ).structured_content
    assert incoming["focusId"] == core["id"]
    assert incoming["direction"] == "in"
    assert {node["id"] for node in incoming["nodes"]} == {
        core["id"],
        *(dependent["id"] for dependent in dependents),
    }
    assert len(incoming["edges"]) == 3
    assert all(edge["targetId"] == core["id"] for edge in incoming["edges"])
    assert incoming["returned"] == {"nodes": 4, "edges": 3}
    assert incoming["truncated"] is False

    outgoing = call_tool(
        mcp,
        token,
        "query_relationships",
        {"asset_id": core["id"], "depth": 1, "direction": "out", "type_key": "depends_on"},
    ).structured_content
    assert {node["id"] for node in outgoing["nodes"]} == {core["id"], upstream["id"]}

    other_type = call_tool(
        mcp,
        token,
        "query_relationships",
        {"asset_id": core["id"], "depth": 1, "type_key": "hosted_in"},
    ).structured_content
    assert other_type["edges"] == []
    assert {node["id"] for node in other_type["nodes"]} == {core["id"]}


def test_mcp_query_relationships_pages_the_global_graph(mcp: McpServer) -> None:
    _, token = operator(mcp)
    assets = [mcp_asset(mcp, token, f"Nodo {index}", f"P10-NODE-{index}") for index in range(4)]
    for source, target in ((assets[0], assets[1]), (assets[1], assets[2]), (assets[2], assets[3])):
        call_tool(
            mcp,
            token,
            "create_relationship",
            {"source_id": source["id"], "target_id": target["id"], "type_key": "depends_on"},
        )

    first = call_tool(
        mcp, token, "query_relationships", {"limit": 2, "offset": 0}
    ).structured_content
    second = call_tool(
        mcp, token, "query_relationships", {"limit": 2, "offset": 2}
    ).structured_content

    assert first["total"] == 3
    assert first["focusId"] is None
    assert len(first["edges"]) == 2 and len(first["nodes"]) <= 4
    assert second["total"] == 3
    assert len(second["edges"]) == 1
    assert len(first["nodes"]) <= 50 and len(first["edges"]) <= 50


def test_mcp_query_relationships_revalidates_revoked_bearer(mcp: McpServer) -> None:
    username, token = operator(mcp)

    async def run() -> None:
        async with Client(mcp.transport(token)) as client:
            found = await client.call_tool("query_relationships", {"limit": 5})
            assert found.structured_content["limit"] == 5
            mcp.catalog.revoke_machine(username)
            with pytest.raises((MCPError, ToolError)):
                await client.call_tool("query_relationships", {"limit": 5})

    asyncio.run(run())


def test_agent_query_relationships_returns_a_compact_result(
    signed_in_client: Any,
) -> None:
    client, auth = signed_in_client()
    core = create_asset(client, auth, "Switch de planta", quickCode="P10-AG-CORE")
    dependent = create_asset(client, auth, "Servidor de planta", quickCode="P10-AG-SRV")
    relate(client, auth, dependent["id"], core["id"])

    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "query_relationships",
                        {"asset_id": core["id"], "depth": 1, "direction": "in"},
                        tool_call_id="t-phase10-graph",
                    )
                ],
                [TextPart("El servidor depende del switch.")],
            )
        ),
    )
    reply = chat(client, auth, "¿Qué depende del switch de planta?")

    assert reply["actions"] == [
        {"tool": "query_relationships", "status": "completed", "assetIds": []}
    ]
    result = reply["results"][0]
    assert result["focusId"] == core["id"]
    assert {node["id"] for node in result["nodes"]} == {core["id"], dependent["id"]}
    assert len(result["edges"]) == 1
    assert len(result["nodes"]) <= 50 and len(result["edges"]) <= 50


def test_mcp_query_relationships_rejects_malformed_direction(mcp: McpServer) -> None:
    _, token = operator(mcp)
    with pytest.raises((MCPError, ToolError)):
        call_tool(mcp, token, "query_relationships", {"direction": "sideways"})


def test_mcp_operational_tools_require_the_assets_view_scope(mcp: McpServer) -> None:
    with mcp.catalog.session() as session:
        role = mcp.catalog.service(session).create_role(
            mcp.catalog.admin(), name="Phase 10 people only", permissions=["people.view"]
        )
    _, token = mcp.catalog.add_machine("phase10-people", "Phase 10 People", role.id)

    with pytest.raises((MCPError, ToolError)):
        call_tool(mcp, token, "query_relationships", {"limit": 5})


def test_mcp_search_everything_returns_authorized_compact_matches(mcp: McpServer) -> None:
    _, token = operator(mcp)
    asset = mcp_asset(mcp, token, "Impresora láserPhase10", "P10-SEARCH")

    found = call_tool(
        mcp, token, "search_everything", {"query": "Impresora láserPhase10", "kinds": ["asset"]}
    ).structured_content

    assert found["limit"] == 20 and found["offset"] == 0
    assert found["engine"] in {"sql", "meilisearch"}
    assert isinstance(found["fallback"], bool)
    assert len(found["items"]) <= 20
    match = next(item for item in found["items"] if item["type"] == "asset")
    assert match["id"] == asset["id"]
    assert match["key"] == f"asset:{asset['id']}"
    assert match["target"] == {"kind": "asset", "id": asset["id"]}
    assert found["total"] >= 1


def test_mcp_operational_summary_keeps_period_and_bounds(mcp: McpServer) -> None:
    _, token = operator(mcp)
    mcp_asset(mcp, token, "Gateway Phase10", "P10-SUMMARY")

    summary = call_tool(mcp, token, "get_operational_summary", {"period": "7d"}).structured_content

    assert summary["period"] == "7d"
    assert summary["generatedAt"]
    assert set(summary["stats"]) >= {"total", "up", "down", "unmonitored", "criticalAlerts"}
    assert len(summary["rows"]) <= 50
    assert len(summary["activeAlerts"]) <= 20


def test_mcp_saved_views_reads_the_current_identity_state(mcp: McpServer) -> None:
    _, token = operator(mcp)

    state = call_tool(mcp, token, "list_saved_views", {}).structured_content

    assert set(state) == {"views", "favorites", "shortcuts", "themeMode", "truncated"}
    assert state["views"] == [] and state["favorites"] == [] and state["shortcuts"] == []
    assert state["themeMode"] == "auto"
    assert state["truncated"] is False
