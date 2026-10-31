"""Real Pydantic AI SDK discovery and independent workspace development."""

from __future__ import annotations

import json

import pydantic_ai.models
import pytest
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
    response = chat(
        client, headers, message="Descubre el SDK y prepara una extensión de registros."
    )
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
    # SDK v2 renders declarative views on the host: the workspace carries no
    # same-origin frontend bundle unless an isolated iframe view is declared.
    assert not list((tmp_path / "sdk-workspaces").rglob("frontend.js"))
    manifest = json.loads(files[0].read_text(encoding="utf-8"))
    assert manifest["sdkVersion"] == 2
    assert manifest["runtime"] == "sandboxed"
    assert manifest["frontend"]["pages"][0]["view"]["table"]["operation"] == ("list_records")
    assert client.get("/api/v1/extensions").json()["items"] == []


@pytest.mark.parametrize("core_permission", ["assets.view", "assets.not_a_real_permission"])
def test_chat_validation_submission_requires_exact_human_review(
    signed_in_client, settings_factory, tmp_path, monkeypatch, core_permission
):
    """Known core permissions reach real validation; unknown codes fail closed."""
    import json

    from itsm.extensions.validator import ContainerValidator
    from pydantic_ai.messages import ModelResponse
    from tests.test_agent_chat import tool_returns

    validator = ContainerValidator()
    if not validator.available():
        pytest.skip("fixed local extension validator image is unavailable")
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)
    settings = settings_factory(extension_workspace_path=tmp_path / "sdk-workspaces")
    client, headers = signed_in_client(settings)

    def develop(messages, info):
        returns = tool_returns(messages)
        if not returns:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "extension_workspace_create",
                        {
                            "id": "chat-reviewed",
                            "name": "Registros revisados",
                            "description": "Paquete independiente con revisión humana.",
                        },
                    )
                ]
            )
        results = [
            json.loads(row.content) if isinstance(row.content, str) else row.content
            for row in returns
        ]
        assert results[0]["ok"] is True, results[0]
        workspace_id = results[0]["id"]
        if len(results) == 1:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "extension_workspace_read",
                        {
                            "workspace_id": workspace_id,
                            "path": "extension.json",
                        },
                    )
                ]
            )
        if len(results) == 2:
            manifest = json.loads(results[1]["content"])
            manifest["corePermissions"] = [core_permission]
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "extension_workspace_write",
                        {
                            "workspace_id": workspace_id,
                            "path": "extension.json",
                            "content": json.dumps(manifest),
                        },
                    )
                ]
            )
        if len(results) == 3:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "extension_workspace_validate",
                        {
                            "workspace_id": workspace_id,
                        },
                    )
                ]
            )
        report = results[3]
        if core_permission != "assets.view":
            assert report["status"] == "failed", report
            assert "unknown core permission" in " ".join(report["errors"])
            assert report["container"]["image"] == "not-run"
            return ModelResponse(parts=[TextPart("El permiso desconocido impide la revisión.")])
        assert report["status"] == "passed", report
        if len(results) == 4:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "extension_workspace_submit",
                        {
                            "workspace_id": workspace_id,
                        },
                    )
                ]
            )
        return ModelResponse(
            parts=[TextPart("El paquete está validado y pendiente de tu revisión.")]
        )

    use_model(client, FunctionModel(develop))
    response = chat(
        client, headers, message="Prepara registros y solicita mi revisión, sin instalar."
    )
    assert response.status_code == 200, response.text
    reply = response.json()
    assert [row["tool"] for row in reply["actions"]] == [
        "extension_workspace_create",
        "extension_workspace_read",
        "extension_workspace_write",
        "extension_workspace_validate",
    ] + (["extension_workspace_submit"] if core_permission == "assets.view" else [])
    if core_permission == "assets.view":
        assert reply["approvalPending"] is True
        review = next(row for row in reply["results"] if row.get("type") == "extension_review")
        assert review["extensionId"] == "chat-reviewed"
        candidate = client.get("/api/v1/extensions/candidates/" + review["candidateId"])
        assert candidate.status_code == 200, candidate.text
        assert candidate.json()["digest"] == review["digest"]
        assert candidate.json()["state"] == "pending"
        assert candidate.json()["validation"]["digest"] == review["digest"]
        assert candidate.json()["manifest"]["corePermissions"] == ["assets.view"]
    else:
        assert reply["approvalPending"] is False
        assert client.get("/api/v1/extensions/candidates").json()["items"] == []
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
            role = identity.create_role(
                catalog.admin(), name="SDK developer", permissions=["system.modules"]
            )
            machine = identity.create_user(
                catalog.admin(),
                username="sdk.mcp",
                name="SDK MCP",
                role_id=role.id,
                actor_kind="internal_agent",
                delegated_by_id=catalog.admin().actor_id,
            )
            credential = identity.issue_machine_credential(machine.username)
        with serve(catalog.settings, free_tcp_port) as base:

            async def exercise():
                transport = StreamableHttpTransport(
                    base + "/api/v1/mcp", headers={"Authorization": "Bearer " + credential.token}
                )
                async with Client(transport) as client:
                    with pytest.raises(ToolError):
                        await client.call_tool(
                            "extension_workspace_write",
                            {
                                "workspace_id": "missing",
                                "path": "../../core.py",
                                "content": "not allowed",
                            },
                        )
                    created = await client.call_tool(
                        "extension_workspace_create",
                        {
                            "id": "mcp-records",
                            "name": "Registros MCP",
                            "description": "Desarrollo delegado real.",
                        },
                    )
                    assert created.data["id"] == "mcp-records"
                    manifest = await client.call_tool(
                        "extension_workspace_read",
                        {
                            "workspace_id": "mcp-records",
                            "path": "extension.json",
                        },
                    )
                    import json

                    assert json.loads(manifest.data["content"])["id"] == "mcp-records"
                    with pytest.raises(ToolError):
                        await client.call_tool(
                            "extension_workspace_write",
                            {
                                "workspace_id": "mcp-records",
                                "path": "../backend.py",
                                "content": "not allowed",
                            },
                        )
                    with catalog.session() as session:
                        catalog.service(session).update_role(
                            catalog.admin(),
                            role.id,
                            name="Revoked SDK developer",
                            permissions=["assets.view"],
                        )
                    with pytest.raises(ToolError, match="permission denied"):
                        await client.call_tool(
                            "extension_workspace_read",
                            {
                                "workspace_id": "mcp-records",
                                "path": "backend.py",
                            },
                        )

            asyncio.run(exercise())
        assert catalog.asset_count() == 0
    finally:
        catalog.engine.dispose()
