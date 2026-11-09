"""Personal bearer ceilings over real mounted FastMCP Streamable HTTP."""

import asyncio
from datetime import timedelta

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from itsm.identity.clock import utcnow
from itsm.identity.service import IdentityService
from mcp.shared.exceptions import MCPError
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import prepare, serve


@pytest.fixture
def external(settings_factory, tmp_path, free_tcp_port, monkeypatch):
    catalog = prepare(
        settings_factory,
        attachment_storage_path=tmp_path / "attachments",
        extension_workspace_path=tmp_path / "extension-workspaces",
        extension_data_path=tmp_path / "extension-data",
    )
    from itsm.agent_integrations.extensions import ExtensionRegistry
    from itsm.inventory.service import InventoryService
    from tests.test_agent_catalog import parameters, tools_only_module

    module_catalog = tools_only_module(tmp_path)
    registry = ExtensionRegistry(module_catalog)

    def handler(context):
        return (
            InventoryService(
                context.session,
                context.settings,
                identity=context.identity,
                source=context.source,
            )
            .create(context.principal, {"name": "Extension-created asset"})
            .as_payload()
        )

    registry.register_tool(
        "vendor.demo",
        name="personal_extension_create",
        description="Create through canonical inventory.",
        permissions=("assets.edit",),
        capabilities=("inventory.read",),
        parameters=parameters(),
        handler=handler,
    )
    monkeypatch.setattr(
        "itsm.main._extension_components", lambda settings: (module_catalog, registry)
    )
    with (
        serve(catalog.settings, free_tcp_port) as base,
        httpx.Client(base_url=base, timeout=15) as browser,
    ):
        yield catalog, base, browser
    catalog.engine.dispose()


def personal_key(catalog, browser, username=ADMIN_USERNAME, password=ADMIN_PASSWORD, **body):
    login = browser.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
        headers={"Origin": catalog.settings.auth_origin},
    )
    assert login.status_code == 200
    headers = {"Origin": catalog.settings.auth_origin, "X-CSRF-Token": login.json()["csrfToken"]}
    response = browser.post(
        "/api/v1/auth/api-keys", json={"label": "MCP test", **body}, headers=headers
    )
    assert response.status_code == 201
    return response.json(), headers


def transport(base, key):
    return StreamableHttpTransport(
        base + "/api/v1/mcp", headers={"Authorization": "Bearer " + key["token"]}
    )


def test_personal_mcp_lists_calls_and_matches_rest_ceiling(external):
    catalog, base, browser = external
    writer, _ = personal_key(catalog, browser, permissions=["assets.view", "assets.edit"])
    reader, _ = personal_key(catalog, browser, permissions=["assets.view"])

    async def run():
        async with Client(transport(base, writer)) as client:
            names = {tool.name for tool in await client.list_tools()}
            assert {"search_assets", "personal_extension_create"} <= names
            created = await client.call_tool(
                "create_asset", {"name": "Personal MCP", "quick_code": "PERSONAL-1"}
            )
            asset = created.structured_content
            assert asset["quickCode"] == "PERSONAL-1"
            fetched = httpx.get(
                base + "/api/v1/assets/" + asset["id"],
                headers={"Authorization": "Bearer " + writer["token"]},
            )
            assert fetched.status_code == 200
            assert fetched.json()["id"] == asset["id"]
            extension_asset = await client.call_tool("personal_extension_create", {})
            assert extension_asset.structured_content["name"] == "Extension-created asset"
        async with Client(transport(base, reader)) as client:
            assert "personal_extension_create" not in {
                tool.name for tool in await client.list_tools()
            }
            with pytest.raises(ToolError):
                await client.call_tool("personal_extension_create", {})
            result = await client.call_tool("search_assets", {"query": "Personal MCP"})
            assert result.structured_content["total"] == 1
            with pytest.raises(ToolError):
                await client.call_tool("create_asset", {"name": "Denied key write"})
            # Neither injected actor nor scopes can select a different authority.
            with pytest.raises(ToolError):
                await client.call_tool(
                    "search_assets",
                    {"query": "", "owner": catalog.admin().actor_id, "scopes": ["assets.edit"]},
                )
        assert catalog.asset_count() == 2

    asyncio.run(run())


@pytest.mark.parametrize("change", ["demote", "deactivate", "revoke", "expire"])
def test_open_mcp_connection_revalidates_personal_key(external, change):
    catalog, base, browser = external
    from tests.inventory_support import MACHINE_PASSWORD

    actor = catalog.add_user("external-human", "External Human", "operator")
    extra = (
        {"expiresAt": (utcnow() + timedelta(seconds=6)).isoformat()} if change == "expire" else {}
    )
    key, headers = personal_key(
        catalog,
        browser,
        actor.username,
        MACHINE_PASSWORD,
        permissions=["assets.view", "assets.edit"],
        **extra,
    )

    async def run():
        async with Client(transport(base, key)) as client:
            assert "search_assets" in {tool.name for tool in await client.list_tools()}
            result = await client.call_tool("search_assets", {"query": "nothing"})
            assert result.structured_content["total"] == 0
            if change == "revoke":
                assert (
                    browser.delete(
                        "/api/v1/auth/api-keys/" + key["id"], headers=headers
                    ).status_code
                    == 200
                )
            elif change == "deactivate":
                catalog.deactivate(actor.username)
            elif change == "demote":
                with catalog.session() as session:
                    IdentityService(session, catalog.settings).update_user(
                        catalog.admin(), actor.actor_id, role_id="user"
                    )
            else:
                await asyncio.sleep(6.1)
            with pytest.raises((MCPError, ToolError)):
                await client.call_tool("create_asset", {"name": "Must not exist"})
            with pytest.raises((MCPError, ToolError)):
                await client.call_tool("personal_extension_create", {})
            if change != "demote":
                with pytest.raises((MCPError, ToolError)):
                    await client.call_tool("search_assets", {"query": "nothing"})
            else:
                result = await client.call_tool("search_assets", {"query": "nothing"})
                assert result.structured_content["total"] == 0
        assert catalog.asset_count() == 0
        response = httpx.get(
            base + "/api/v1/assets", headers={"Authorization": "Bearer " + key["token"]}
        )
        assert response.status_code == (200 if change == "demote" else 401)

    asyncio.run(run())


def test_mcp_rejects_real_cookie_and_invalid_personal_key(external):
    catalog, base, browser = external
    key, _ = personal_key(catalog, browser, permissions=[])
    assert browser.cookies
    response = browser.post(
        "/api/v1/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert response.status_code == 401

    async def run():
        with pytest.raises((MCPError, ToolError)):
            async with Client(
                transport(base, {"token": "itsm_pk_invalid-ephemeral-test"})
            ) as client:
                await client.list_tools()
        async with Client(transport(base, key)) as client:
            with pytest.raises(ToolError):
                await client.call_tool("search_assets", {"query": "nothing"})

    asyncio.run(run())


def test_mcp_system_and_sdk_tools_cannot_escape_superadmin_key_ceiling(external):
    catalog, base, browser = external
    limited, _ = personal_key(catalog, browser, permissions=["assets.view"])
    allowed, headers = personal_key(catalog, browser, permissions=["system.view"])

    async def run():
        async with Client(transport(base, limited)) as client:
            with pytest.raises(ToolError):
                await client.call_tool("get_system_status", {})
            with pytest.raises(ToolError):
                await client.call_tool("list_system_modules", {})
            # Core SDK dispatch must authorize before creating a workspace.
            with pytest.raises(ToolError):
                await client.call_tool(
                    "extension_workspace_create",
                    {
                        "id": "limited-key-test",
                        "name": "Limited test",
                        "description": "Must not be created",
                    },
                )
        async with Client(transport(base, allowed)) as client:
            assert (await client.call_tool("get_system_status", {})).structured_content
            assert (
                browser.delete(
                    "/api/v1/auth/api-keys/" + allowed["id"], headers=headers
                ).status_code
                == 200
            )
            with pytest.raises((MCPError, ToolError)):
                await client.call_tool("get_system_status", {})
        assert not catalog.settings.extension_workspace_path.exists() or not any(
            catalog.settings.extension_workspace_path.rglob("workspace.json")
        )

    asyncio.run(run())
