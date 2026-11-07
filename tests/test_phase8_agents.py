"""Canonical monitoring tools over the real chat and MCP transports, without inference."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError
from itsm.database import create_engine_from_settings
from mcp.shared.exceptions import MCPError
from pydantic_ai.messages import TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from tests.inventory_support import Catalog, sign_in_as
from tests.test_agent_chat import scripted
from tests.test_mcp_server import call_tool, operator
from tests.test_phase7_agents import (
    catalog,
    chat,
    create_asset,
    mcp,
    no_external_model_requests,
    use_model,
)

# Reuse isolated transport fixtures, not a second runtime/bootstrap convention.
__all__ = ["catalog", "mcp", "no_external_model_requests"]


def test_agent_distinguishes_missing_metrics_and_reports_queried_period(signed_in_client):
    client, auth = signed_in_client()
    asset = create_asset(client, auth, "Monitoring tool target")
    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "get_asset_metrics",
                        {"asset_id": asset["id"], "period": "7d"},
                        tool_call_id="metrics",
                    )
                ],
                [TextPart("Sin datos de métricas.")],
            )
        ),
    )
    reply = chat(client, auth, "Consultá las métricas de los últimos siete días")
    assert reply["actions"] == [
        {"tool": "get_asset_metrics", "status": "completed", "assetIds": []}
    ]
    result = reply["results"][0]
    assert result["status"] in {"no_data", "unavailable", "unmonitored"}
    assert result["provenance"]["source"] == "prometheus"
    assert result["provenance"]["period"]["preset"] == "7d"
    assert result["series"] == []


def test_mcp_monitoring_read_cannot_invent_availability_or_arbitrary_period(mcp):
    _, token = operator(mcp)
    asset = call_tool(
        mcp, token, "create_asset", {"name": "MCP monitored device"}
    ).structured_content
    result = call_tool(
        mcp, token, "get_asset_availability", {"asset_id": asset["id"]}
    ).structured_content
    assert result["status"] in {"no_data", "unavailable", "unmonitored"}
    assert result["uptime"]["percent"] is None
    assert result["provenance"]["source"] == "prometheus"
    with pytest.raises(ToolError):
        call_tool(mcp, token, "get_asset_metrics", {"asset_id": asset["id"], "period": "all-time"})


def test_agent_reader_cannot_acknowledge_and_does_not_resolve_missing_target(signed_in_client):
    client, _ = signed_in_client()
    settings = client.app.state.settings
    isolated = Catalog(settings=settings, engine=create_engine_from_settings(settings))
    try:
        isolated.add_user("phase8-reader", "Phase 8 Reader", "user")
        headers = sign_in_as(client, settings, "phase8-reader")
        use_model(
            client,
            FunctionModel(
                scripted(
                    [
                        ToolCallPart(
                            "acknowledge_alert", {"alert_id": "missing-alert"}, tool_call_id="ack"
                        )
                    ],
                    [TextPart("No autorizado.")],
                )
            ),
        )
        result = chat(client, headers, "Reconocé la alerta indicada")
        assert result["actions"] == [
            {"tool": "acknowledge_alert", "status": "denied", "assetIds": []}
        ]
        with isolated.engine.connect() as connection:
            from sqlalchemy import text

            assert (
                connection.execute(text("SELECT count(*) FROM monitoring_alerts")).scalar_one() == 0
            )
    finally:
        isolated.engine.dispose()


def test_mcp_reader_denial_precedes_target_lookup_and_revocation_is_rechecked(mcp):
    _, token = mcp.catalog.add_machine("phase8-reader-machine", "Phase 8 reader", "user")
    with pytest.raises(ToolError, match="permission"):
        call_tool(mcp, token, "acknowledge_alert", {"alert_id": "missing-alert"})
    mcp.catalog.revoke_machine("phase8-reader-machine")
    with pytest.raises((MCPError, ToolError)):
        call_tool(mcp, token, "list_active_alerts", {})
