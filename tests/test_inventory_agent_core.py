"""F4 typed tools exercise the same SQL service without paid model requests."""

from __future__ import annotations

import asyncio

import pydantic_ai.models
from fastmcp import Client
from itsm.agents.runtime import AgentRuntime
from pydantic_ai.messages import TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from tests.inventory_support import prepare, serve
from tests.test_agent_chat import scripted


def test_agent_creates_typed_fields_and_projects_result(signed_in_client, monkeypatch):
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)
    client, auth = signed_in_client()
    model = FunctionModel(
        scripted(
            [
                ToolCallPart(
                    "create_asset",
                    {
                        "name": "Agent server",
                        "category": "servidores",
                        "site": "DC",
                        "cost": "120.50",
                        "technical": {"ram": 32},
                        "fields": ["id", "quickCode", "cost", "technical"],
                    },
                    tool_call_id="f4-create",
                )
            ],
            [TextPart("Activo creado.")],
        )
    )
    app = client.app
    app.state.agent_runtime = AgentRuntime(
        app.state.settings, app.state.session_factory, model=model
    )
    response = client.post(
        "/api/v1/agent/chat", json={"message": "Registrar servidor"}, headers=auth
    )
    assert response.status_code == 200, response.text
    reply = response.json()
    assert reply["actions"][0]["status"] == "completed"
    asset = reply["results"][0]
    assert set(asset) == {"id", "quickCode", "cost", "technical"}
    assert asset["cost"] == "120.50" and asset["technical"] == {"ram": 32}
    assert client.get("/api/v1/assets/" + asset["id"]).json()["technical"] == {"ram": 32}


def test_mcp_projection_custom_fields_lifecycle_and_unknown_fields(settings_factory, free_tcp_port):
    db = prepare(settings_factory)
    _, token = db.add_machine("f4-tools", "F4 tools", "operator")

    async def exercise(url):
        async with Client(url + "/api/v1/mcp", auth=token) as client:
            created = await client.call_tool(
                "create_asset",
                {
                    "name": "MCP server",
                    "category": "servidores",
                    "site": "DC",
                    "technical": {"ram": 16},
                    "cost": "10.00",
                    "fields": ["id", "technical", "cost"],
                },
            )
            row = created.structured_content
            assert set(row) == {"id", "technical", "cost"}
            assert row["technical"] == {"ram": 16}
            cloned = await client.call_tool("clone_asset", {"asset_id": row["id"]})
            assert cloned.structured_content["id"] != row["id"]
            archived = await client.call_tool("archive_asset", {"asset_id": row["id"]})
            assert archived.structured_content["archived"] is True
            restored = await client.call_tool("restore_asset", {"asset_id": row["id"]})
            assert restored.structured_content["archived"] is False
            import pytest
            from fastmcp.exceptions import ToolError

            with pytest.raises(ToolError):
                await client.call_tool(
                    "create_asset", {"name": "Rejected projection", "fields": ["secrets"]}
                )

    with serve(db.settings, free_tcp_port) as url:
        asyncio.run(exercise(url))
    assert db.asset_count() == 2
    db.engine.dispose()
