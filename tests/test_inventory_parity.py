"""Cross-interface parity: one asset, several front doors, one canonical service."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from itsm.agents.runtime import AgentRuntime, ChatRequest
from itsm.config import Settings
from itsm.identity.service import IdentityService, Principal
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from tests.inventory_support import Catalog, asset_values, prepare, serve


@pytest.fixture(autouse=True)
def no_external_model_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    import pydantic_ai.models

    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)


@pytest.fixture
def catalog(settings_factory: Callable[..., Settings]) -> Catalog:
    return prepare(settings_factory)


def headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def principal_for(catalog: Catalog, token: str) -> Principal:
    with catalog.session() as session:
        return IdentityService(session, catalog.settings).authenticate_token(token).principal


def test_rest_agent_mcp_share_the_same_asset_identity(catalog: Catalog, free_tcp_port: int) -> None:
    _, token = catalog.add_machine("parity-operator", "Parity Operator", "operator")
    values = asset_values(quick_code="PAR-001")
    rest_payload = {
        **{key: value for key, value in values.items() if key != "quick_code"},
        "quickCode": "PAR-001",
    }

    with serve(catalog.settings, free_tcp_port) as base:
        created = httpx.post(
            f"{base}/api/v1/assets", json=rest_payload, headers=headers(token), timeout=10
        )
        assert created.status_code == 201, created.text
        asset_id = created.json()["id"]

        # Agent: reads the REST-created asset through its typed tool.
        def scripted(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
            for message in messages:
                for part in getattr(message, "parts", ()):
                    if type(part).__name__ == "ToolReturnPart":
                        return ModelResponse(parts=[TextPart(content="Activo consultado.")])
            return ModelResponse(
                parts=[ToolCallPart("get_asset", {"asset_id": asset_id}, tool_call_id="c1")]
            )

        runtime = AgentRuntime(catalog.settings, catalog.factory(), model=FunctionModel(scripted))
        reply = runtime.chat(
            principal_for(catalog, token),
            ChatRequest(message="Mostrame este activo", assetId=asset_id),
        )
        assert reply.actions[0].tool == "get_asset"
        assert reply.results[0]["id"] == asset_id
        assert reply.results[0]["quickCode"] == "PAR-001"

        # MCP: reads the same asset and mutates a different field.
        async def mcp_flow() -> tuple[dict[str, Any], dict[str, Any]]:
            transport = StreamableHttpTransport(f"{base}/api/v1/mcp", headers=headers(token))
            async with Client(transport) as client:
                fetched = await client.call_tool("get_asset", {"asset_id": asset_id})
                updated = await client.call_tool(
                    "update_asset", {"asset_id": asset_id, "site": "Sede Norte"}
                )
            return fetched.structured_content, updated.structured_content

        fetched, updated = asyncio.run(mcp_flow())
        assert fetched["id"] == asset_id
        assert updated["id"] == asset_id
        assert updated["quickCode"] == "PAR-001"

        after = httpx.get(f"{base}/api/v1/assets/{asset_id}", headers=headers(token), timeout=10)
        assert after.status_code == 200
        assert after.json()["id"] == asset_id
        assert after.json()["site"] == "Sede Norte"

        # A repeated quickCode update through REST keeps the permanent id.
        repeated = httpx.patch(
            f"{base}/api/v1/assets/{asset_id}",
            json={"quickCode": "PAR-001"},
            headers=headers(token),
            timeout=10,
        )
        assert repeated.status_code == 200
        assert repeated.json()["id"] == asset_id


def test_deactivated_machine_cannot_mutate_through_rest(
    catalog: Catalog, free_tcp_port: int
) -> None:
    _, token = catalog.add_machine("parity-revoked", "Parity Revoked", "operator")
    catalog.deactivate("parity-revoked")

    with serve(catalog.settings, free_tcp_port) as base:
        response = httpx.post(
            f"{base}/api/v1/assets",
            json={"name": "Ghost asset"},
            headers=headers(token),
            timeout=10,
        )
    assert response.status_code == 401
    assert catalog.asset_count() == 0
