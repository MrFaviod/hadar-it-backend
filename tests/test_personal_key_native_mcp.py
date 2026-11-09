"""Installed namespaced permissions stay bounded over official HTTP MCP."""

import asyncio

import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from tests.inventory_support import serve
from tests.test_native_extensions import MODULE_ID, READ
from tests.test_native_extensions import env as _env
from tests.test_personal_mcp import personal_key, transport

env = _env


def test_installed_permission_does_not_expand_old_key_and_revoke_is_live(env, free_tcp_port):
    with (
        serve(env.settings, free_tcp_port) as base,
        httpx.Client(base_url=base, timeout=15) as browser,
    ):
        old, _ = personal_key(env, browser, permissions=None)
        env.install()
        reader, headers = personal_key(env, browser, permissions=[READ])

        async def exercise():
            async with Client(transport(base, old)) as client:
                with pytest.raises(ToolError):
                    await client.call_tool(
                        "extension_invoke",
                        {"id": MODULE_ID, "operation": "read_records", "arguments": {}},
                    )
            async with Client(transport(base, reader)) as client:
                operations = await client.call_tool("extension_operations", {"id": MODULE_ID})
                assert "read_records" in str(operations.data)
                result = await client.call_tool(
                    "extension_invoke",
                    {"id": MODULE_ID, "operation": "read_records", "arguments": {}},
                )
                assert result.data["result"]["items"] == []
                with pytest.raises(ToolError):
                    await client.call_tool(
                        "extension_invoke",
                        {
                            "id": MODULE_ID,
                            "operation": "put_record",
                            "arguments": {"record_id": "denied", "label": "Denied"},
                        },
                    )
                assert env.records() == []
                assert (
                    browser.delete(
                        "/api/v1/auth/api-keys/" + reader["id"], headers=headers
                    ).status_code
                    == 200
                )
                with pytest.raises((MCPError, ToolError)):
                    await client.call_tool(
                        "extension_invoke",
                        {"id": MODULE_ID, "operation": "read_records", "arguments": {}},
                    )
                assert env.records() == []

        asyncio.run(exercise())
