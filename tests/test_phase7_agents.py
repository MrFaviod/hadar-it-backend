"""Phase 7 agent and MCP behavior against canonical services and real transports."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pydantic_ai.models
import pytest
import uvicorn
from fastmcp.exceptions import ToolError
from itsm.agents.runtime import AgentRuntime
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.main import create_app
from mcp.shared.exceptions import MCPError
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from tests.inventory_support import Catalog, prepare, sign_in_as
from tests.test_agent_chat import scripted, tool_returns
from tests.test_mcp_server import McpServer, call_tool, operator, rest_get


@pytest.fixture(autouse=True)
def no_external_model_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    """No provider inference may be consumed by these checks."""
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)


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


def use_model(client: Any, model: FunctionModel) -> None:
    app = client.app
    app.state.agent_runtime = AgentRuntime(
        app.state.settings, app.state.session_factory, model=model
    )


def chat(client: Any, auth: dict[str, str], message: str) -> dict[str, Any]:
    response = client.post("/api/v1/agent/chat", json={"message": message}, headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def create_asset(client: Any, auth: dict[str, str], name: str, **overrides: Any) -> dict[str, Any]:
    payload = {"name": name, "category": "Red"}
    payload.update(overrides)
    response = client.post("/api/v1/assets", json=payload, headers=auth)
    assert response.status_code == 201, response.text
    return response.json()


def create_plan(
    client: Any, auth: dict[str, str], asset_id: str, due_on: str = "2026-01-10"
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/maintenance/plans",
        json={
            "assetId": asset_id,
            "maintenanceType": "preventivo",
            "intervalMonths": 6,
            "dueOn": due_on,
            "tasks": ["Revisar UPS y baterías"],
        },
        headers=auth,
    )
    assert response.status_code == 201, response.text
    return response.json()


def rest_post(server: McpServer, token: str, path: str, payload: dict[str, Any]) -> Any:
    base = server.url.removesuffix("/api/v1/mcp")
    return httpx.post(
        f"{base}{path}",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )


def mcp_asset(server: McpServer, token: str, name: str, code: str) -> dict[str, Any]:
    return call_tool(
        server, token, "create_asset", {"name": name, "quick_code": code}
    ).structured_content


def mcp_incident(server: McpServer, token: str, asset_id: str, description: str) -> dict[str, Any]:
    return call_tool(
        server,
        token,
        "create_incident",
        {"primary_asset_id": asset_id, "description": description},
    ).structured_content["incident"]


def test_agent_searches_and_completes_authorized_maintenance(
    signed_in_client: Callable[..., tuple[Any, dict[str, str]]],
) -> None:
    client, auth = signed_in_client()
    asset = create_asset(client, auth, "UPS sala técnica")
    plan = create_plan(client, auth, asset["id"])

    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "search_maintenance",
                        {"state": "overdue", "limit": 5},
                        tool_call_id="t-maintenance-search",
                    )
                ],
                [
                    ToolCallPart(
                        "complete_maintenance",
                        {
                            "plan_id": plan["id"],
                            "completed_on": "2026-01-10",
                            "notes": "Cambio de baterías",
                        },
                        tool_call_id="t-maintenance-complete",
                    )
                ],
                [TextPart("Mantenimiento completado.")],
            )
        ),
    )
    reply = chat(client, auth, "Completá el mantenimiento de la UPS")

    assert [action["tool"] for action in reply["actions"]] == [
        "search_maintenance",
        "complete_maintenance",
    ]
    assert {action["status"] for action in reply["actions"]} == {"completed"}
    assert reply["results"][0]["total"] == 1
    completed = reply["results"][-1]["plan"]
    assert completed["lastCompletedOn"] == "2026-01-10"
    assert completed["dueOn"] == "2026-07-10"

    persisted = client.get(f"/api/v1/maintenance/plans/{plan['id']}", headers=auth)
    assert persisted.status_code == 200, persisted.text
    assert persisted.json()["lastCompletedOn"] == "2026-01-10"
    assert persisted.json()["dueOn"] == "2026-07-10"


def test_agent_records_structured_intervention_incident_and_history(
    signed_in_client: Callable[..., tuple[Any, dict[str, str]]],
) -> None:
    client, auth = signed_in_client()
    primary = create_asset(client, auth, "Servidor de archivos")
    affected = create_asset(client, auth, "Switch de acceso")

    def run(messages: list[ModelMessage], _info: AgentInfo) -> ModelResponse:
        returns = tool_returns(messages)
        if not returns:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "create_incident",
                        {
                            "primary_asset_id": primary["id"],
                            "description": "Sin conectividad con el servidor",
                            "priority": "high",
                            "affected_asset_ids": [affected["id"]],
                        },
                        tool_call_id="t-incident",
                    )
                ]
            )
        if len(returns) == 1:
            payload = returns[0].content
            if isinstance(payload, str):
                payload = json.loads(payload)
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "record_intervention",
                        {
                            "asset_id": primary["id"],
                            "type": "corrective",
                            "description": "Se reemplazó la fuente",
                            "occurred_on": "2026-10-20",
                            "incident_id": payload["incident"]["id"],
                            "parts": [
                                {"name": "Fuente redundante", "quantity": 1, "unit_cost": "120.50"}
                            ],
                            "labor_cost": "80.00",
                        },
                        tool_call_id="t-intervention",
                    )
                ]
            )
        return ModelResponse(parts=[TextPart("Incidente e intervención registrados.")])

    use_model(client, FunctionModel(run))
    reply = chat(client, auth, "Registrá el incidente y la reparación")

    incident = reply["results"][0]["incident"]
    intervention = reply["results"][1]["intervention"]
    assert incident["status"] == "open"
    assert incident["affectedAssetIds"] == [affected["id"]]
    assert intervention["assetId"] == primary["id"]
    assert intervention["partsCost"] == "120.50"
    assert intervention["totalCost"] == "200.50"

    detail = client.get(f"/api/v1/incidents/{incident['id']}", headers=auth)
    assert detail.status_code == 200, detail.text
    assert [item["id"] for item in detail.json()["interventions"]] == [intervention["id"]]
    assert detail.json()["costs"]["totalCost"] == "200.50"


def test_agent_denied_incident_write_changes_nothing(
    signed_in_client: Callable[..., tuple[Any, dict[str, str]]],
) -> None:
    client, auth = signed_in_client()
    settings = client.app.state.settings
    catalog = Catalog(settings=settings, engine=create_engine_from_settings(settings))
    catalog.add_user("reader-phase7", "Reader Phase 7", "reader")
    asset = create_asset(client, auth, "Impresora de planta")
    reader_auth = sign_in_as(client, settings, "reader-phase7")

    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "create_incident",
                        {
                            "primary_asset_id": asset["id"],
                            "description": "No debería crearse",
                        },
                        tool_call_id="t-denied-incident",
                    )
                ],
                [TextPart("No autorizado.")],
            )
        ),
    )
    reply = chat(client, reader_auth, "Creá un incidente")

    assert reply["actions"][0]["status"] == "denied"
    listed = client.get("/api/v1/incidents", headers=auth)
    assert listed.status_code == 200, listed.text
    assert listed.json()["total"] == 0


def test_mcp_maintenance_search_and_complete(mcp: McpServer) -> None:
    _, token = operator(mcp)
    asset = mcp_asset(mcp, token, "UPS datacenter", "MCP-UPS-1")
    created = rest_post(
        mcp,
        token,
        "/api/v1/maintenance/plans",
        {
            "assetId": asset["id"],
            "maintenanceType": "preventivo",
            "intervalMonths": 6,
            "dueOn": "2026-01-10",
        },
    )
    assert created.status_code == 201, created.text
    plan_id = created.json()["id"]

    page = call_tool(
        mcp, token, "search_maintenance", {"state": "overdue", "limit": 1000}
    ).structured_content
    assert page["limit"] == 50
    assert page["total"] == 1
    assert page["items"][0]["id"] == plan_id

    completed = call_tool(
        mcp,
        token,
        "complete_maintenance",
        {"plan_id": plan_id, "completed_on": "2026-01-10", "notes": "Revisión"},
    ).structured_content["plan"]
    assert completed["dueOn"] == "2026-07-10"
    assert rest_get(mcp, token, f"/api/v1/maintenance/plans/{plan_id}").json()["dueOn"] == (
        "2026-07-10"
    )


def test_mcp_intervention_links_and_technical_history(mcp: McpServer) -> None:
    _, token = operator(mcp)
    primary = mcp_asset(mcp, token, "Servidor de base", "MCP-DB-1")
    second = mcp_asset(mcp, token, "Switch de núcleo", "MCP-SW-1")
    incident = mcp_incident(mcp, token, primary["id"], "Caída del servicio")

    linked = call_tool(
        mcp,
        token,
        "link_incident_assets",
        {"incident_id": incident["id"], "affected_asset_ids": [second["id"]]},
    ).structured_content["incident"]
    assert linked["affectedAssetIds"] == [second["id"]]

    intervention = call_tool(
        mcp,
        token,
        "record_intervention",
        {
            "asset_id": primary["id"],
            "type": "corrective",
            "description": "Reinicio controlado",
            "incident_id": incident["id"],
            "parts": [{"name": "Disco SSD", "quantity": 2, "unit_cost": "95.25"}],
            "labor_cost": "40.00",
        },
    ).structured_content["intervention"]
    assert intervention["assetId"] == primary["id"]
    assert intervention["incidentId"] == incident["id"]
    assert intervention["totalCost"] == "230.50"

    history = call_tool(
        mcp, token, "get_technical_history", {"asset_id": primary["id"], "limit": 20}
    ).structured_content
    assert history["assetId"] == primary["id"]
    assert history["total"] >= 1

    incidents = call_tool(
        mcp, token, "search_incidents", {"asset_id": primary["id"], "limit": 5}
    ).structured_content
    assert incidents["total"] == 1
    assert incidents["items"][0]["id"] == incident["id"]


def test_mcp_prepare_and_confirm_revalidate_current_state(mcp: McpServer) -> None:
    _, token = operator(mcp)
    asset = mcp_asset(mcp, token, "Servidor de respaldo", "MCP-BK-1")
    incident = mcp_incident(mcp, token, asset["id"], "Disco degradado")

    first = call_tool(
        mcp, token, "prepare_incident_resolution", {"incident_id": incident["id"]}
    ).structured_content["resolution"]
    second = call_tool(
        mcp,
        token,
        "prepare_incident_resolution",
        {"incident_id": incident["id"], "note": "Se reitera la sugerencia"},
    ).structured_content["resolution"]
    assert first["token"] != second["token"]

    still_open = rest_get(mcp, token, f"/api/v1/incidents/{incident['id']}").json()
    assert still_open["status"] == "open"
    assert "token" not in still_open.get("resolution", {})

    with pytest.raises(ToolError):
        call_tool(
            mcp,
            token,
            "confirm_incident_resolution",
            {"incident_id": incident["id"], "token": first["token"]},
        )
    assert rest_get(mcp, token, f"/api/v1/incidents/{incident['id']}").json()["status"] == "open"

    resolved = call_tool(
        mcp,
        token,
        "confirm_incident_resolution",
        {"incident_id": incident["id"], "token": second["token"]},
    ).structured_content["incident"]
    assert resolved["status"] == "resolved"


def test_mcp_revoked_bearer_cannot_confirm_prepared_resolution(mcp: McpServer) -> None:
    username, token = operator(mcp)
    asset = mcp_asset(mcp, token, "Servidor de monitoreo", "MCP-MON-1")
    incident = mcp_incident(mcp, token, asset["id"], "Latencia elevada")
    prepared = call_tool(
        mcp, token, "prepare_incident_resolution", {"incident_id": incident["id"]}
    ).structured_content["resolution"]

    mcp.catalog.revoke_machine(username)
    with pytest.raises((MCPError, ToolError)):
        call_tool(
            mcp,
            token,
            "confirm_incident_resolution",
            {"incident_id": incident["id"], "token": prepared["token"]},
        )

    _, fresh = mcp.catalog.add_machine("mcp-verifier", "MCP Verifier", "operator")
    assert rest_get(mcp, fresh, f"/api/v1/incidents/{incident['id']}").json()["status"] == "open"


def test_mcp_denied_phase7_writes_change_nothing(mcp: McpServer) -> None:
    _, token = operator(mcp)
    _, reader_token = mcp.catalog.add_machine("mcp-reader-phase7", "MCP Reader 7", "reader")
    asset = mcp_asset(mcp, token, "Impresora fiscal", "MCP-PRN-1")
    created = rest_post(
        mcp,
        token,
        "/api/v1/maintenance/plans",
        {"assetId": asset["id"], "maintenanceType": "preventivo", "intervalMonths": 6},
    )
    assert created.status_code == 201, created.text
    plan_id = created.json()["id"]

    with pytest.raises(ToolError):
        call_tool(
            mcp,
            reader_token,
            "create_incident",
            {"primary_asset_id": asset["id"], "description": "No autorizado"},
        )
    with pytest.raises(ToolError):
        call_tool(mcp, reader_token, "complete_maintenance", {"plan_id": plan_id})

    assert rest_get(mcp, token, "/api/v1/incidents").json()["total"] == 0
    assert (
        rest_get(mcp, token, f"/api/v1/maintenance/plans/{plan_id}").json()["lastCompletedOn"]
        is None
    )
    denied = [row for row in mcp.catalog.audit() if row["outcome"] == "denied"]
    assert any(row["action"] == "assets.edit" for row in denied)


def test_mcp_bounds_phase7_pages_and_rejects_malformed_parts(mcp: McpServer) -> None:
    _, token = operator(mcp)
    asset = mcp_asset(mcp, token, "Servidor de pruebas", "MCP-LAB-1")

    page = call_tool(
        mcp, token, "search_incidents", {"limit": 5000, "offset": -20}
    ).structured_content
    assert page == {"total": 0, "limit": 50, "offset": 0, "items": []}

    with pytest.raises(ToolError):
        call_tool(
            mcp,
            token,
            "record_intervention",
            {
                "asset_id": asset["id"],
                "parts": [{"name": "Cable", "quantity": 1, "unit_cost": "10.00", "extra": 1}],
            },
        )
    history = call_tool(
        mcp, token, "get_technical_history", {"asset_id": asset["id"]}
    ).structured_content
    assert history["total"] == 0
