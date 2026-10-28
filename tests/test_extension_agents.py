"""Real Pydantic AI SDK discovery and independent workspace development."""

from __future__ import annotations

import pydantic_ai.models
from pydantic_ai.messages import TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from tests.test_agent_chat import chat, scripted, use_model


def test_chat_discovers_sdk_and_creates_owned_independent_workspace(
    signed_in_client, settings_factory, tmp_path, monkeypatch
):
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)
    settings = settings_factory(extension_workspace_path=tmp_path / "sdk-workspaces")
    client, headers = signed_in_client(settings)
    use_model(
        client,
        FunctionModel(
            scripted(
                [ToolCallPart("extension_sdk_index", {})],
                [
                    ToolCallPart(
                        "extension_workspace_create",
                        {
                            "id": "chat-records",
                            "name": "Registros",
                            "description": "Registro independiente para validación del SDK.",
                        },
                    )
                ],
                [TextPart("Creé el espacio independiente; falta validarlo y tu aprobación.")],
            )
        ),
    )
    response = chat(client, headers, message="Descubre el SDK y prepara una extensión de registros.")
    assert response.status_code == 200, response.text
    reply = response.json()
    assert [(action["tool"], action["status"]) for action in reply["actions"]] == [
        ("extension_sdk_index", "completed"),
        ("extension_workspace_create", "completed"),
    ]
    assert reply["approvalPending"] is False
    files = list((tmp_path / "sdk-workspaces").rglob("extension.json"))
    assert len(files) == 1
    assert list((tmp_path / "sdk-workspaces").rglob("backend.py"))
    assert list((tmp_path / "sdk-workspaces").rglob("frontend.js"))
    assert client.get("/api/v1/extensions").json()["items"] == []


def test_chat_validation_submission_requires_exact_human_review(
    signed_in_client, settings_factory, tmp_path, monkeypatch
):
    """Actual isolated validation cannot turn a model request into installation."""
    import json

    import pytest
    from pydantic_ai.messages import ModelResponse

    from itsm.extensions.validator import ContainerValidator
    from tests.test_agent_chat import tool_returns

    validator = ContainerValidator(core_permissions=())
    if not validator.available():
        pytest.skip("fixed local extension validator image is unavailable")
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)
    settings = settings_factory(extension_workspace_path=tmp_path / "sdk-workspaces")
    client, headers = signed_in_client(settings)

    def develop(messages, info):
        returns = tool_returns(messages)
        if not returns:
            return ModelResponse(parts=[ToolCallPart("extension_workspace_create", {
                "id": "chat-reviewed", "name": "Registros revisados",
                "description": "Paquete independiente con revisión humana.",
            })])
        created = returns[0].content
        if isinstance(created, str):
            created = json.loads(created)
        assert created["ok"] is True, created
        workspace_id = created["id"]
        if len(returns) == 1:
            return ModelResponse(parts=[ToolCallPart("extension_workspace_validate", {
                "workspace_id": workspace_id,
            })])
        report = returns[1].content
        if isinstance(report, str):
            report = json.loads(report)
        assert report["status"] == "passed", report
        if len(returns) == 2:
            return ModelResponse(parts=[ToolCallPart("extension_workspace_submit", {
                "workspace_id": workspace_id,
            })])
        return ModelResponse(parts=[TextPart("El paquete está validado y pendiente de tu revisión.")])

    use_model(client, FunctionModel(develop))
    response = chat(client, headers, message="Prepara registros y solicita mi revisión, sin instalar.")
    assert response.status_code == 200, response.text
    reply = response.json()
    assert reply["approvalPending"] is True
    assert [row["tool"] for row in reply["actions"]] == [
        "extension_workspace_create", "extension_workspace_validate", "extension_workspace_submit",
    ]
    review = next(row for row in reply["results"] if row.get("type") == "extension_review")
    assert review["extensionId"] == "chat-reviewed"
    candidate = client.get("/api/v1/extensions/candidates/" + review["candidateId"])
    assert candidate.status_code == 200, candidate.text
    assert candidate.json()["digest"] == review["digest"]
    assert candidate.json()["state"] == "pending"
    assert candidate.json()["validation"]["digest"] == review["digest"]
    assert client.get("/api/v1/extensions").json()["items"] == []


def test_mcp_development_rechecks_live_machine_authority(settings_factory, tmp_path, free_tcp_port):
    """The real bearer transport shares bounded workspaces, never approval authority."""
    import asyncio

    import pytest
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport
    from fastmcp.exceptions import ToolError
    from tests.inventory_support import prepare, serve

    catalog = prepare(settings_factory, extension_workspace_path=tmp_path / "mcp-workspaces")
    try:
        with catalog.session() as session:
            identity = catalog.service(session)
            role = identity.create_role(catalog.admin(), name="SDK developer", permissions=["system.modules"])
            machine = identity.create_user(
                catalog.admin(), username="sdk.mcp", name="SDK MCP", role_id=role.id,
                actor_kind="internal_agent", delegated_by_id=catalog.admin().actor_id,
            )
            credential = identity.issue_machine_credential(machine.username)
        with serve(catalog.settings, free_tcp_port) as base:
            async def exercise():
                transport = StreamableHttpTransport(
                    base + "/api/v1/mcp", headers={"Authorization": "Bearer " + credential.token}
                )
                async with Client(transport) as client:
                    with pytest.raises(ToolError):
                        await client.call_tool("extension_workspace_write", {
                            "workspace_id": "missing", "path": "../../core.py", "content": "not allowed",
                        })
                    created = await client.call_tool("extension_workspace_create", {
                        "id": "mcp-records", "name": "Registros MCP", "description": "Desarrollo delegado real.",
                    })
                    assert created.data["id"] == "mcp-records"
                    manifest = await client.call_tool("extension_workspace_read", {
                        "workspace_id": "mcp-records", "path": "extension.json",
                    })
                    import json
                    assert json.loads(manifest.data["content"])["id"] == "mcp-records"
                    with pytest.raises(ToolError):
                        await client.call_tool("extension_workspace_write", {
                            "workspace_id": "mcp-records", "path": "../backend.py", "content": "not allowed",
                        })
                    with catalog.session() as session:
                        catalog.service(session).update_role(
                            catalog.admin(), role.id, name="Revoked SDK developer", permissions=["assets.view"]
                        )
                    with pytest.raises(ToolError, match="permission denied"):
                        await client.call_tool("extension_workspace_read", {
                            "workspace_id": "mcp-records", "path": "backend.py",
                        })
            asyncio.run(exercise())
        assert catalog.asset_count() == 0
    finally:
        catalog.engine.dispose()
