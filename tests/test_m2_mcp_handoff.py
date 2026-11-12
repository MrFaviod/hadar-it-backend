"""Real MCP calls preserve human approval and persisted machine delegation."""

import httpx
import pytest
from fastmcp.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from tests.test_mcp_server import call_tool, catalog, mcp  # noqa: F401 - fixtures


def test_mcp_handoff_requires_owner_approval_and_current_raw_token(mcp):  # noqa: F811
    owner = mcp.catalog.admin()
    with mcp.catalog.session() as session:
        identity = mcp.catalog.service(session)
        identity.create_user(
            owner,
            username="mcp.delegated",
            name="Delegated",
            role_id="operator",
            actor_kind="external_agent",
            delegated_by_id=owner.actor_id,
        )
        token = identity.issue_machine_credential("mcp.delegated").token
    base = mcp.url.removesuffix("/api/v1/mcp")
    origin = mcp.catalog.settings.auth_origin
    # Human token here is a real session cookie+CSRF, not a supplied actor label.
    with httpx.Client(base_url=base) as browser:
        from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME

        login = browser.post(
            "/api/v1/auth/login",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            headers={"Origin": origin},
        )
        assert login.status_code == 200, login.text
        auth = {"Origin": origin, "X-CSRF-Token": login.json()["csrfToken"]}
        prepared = browser.post(
            "/api/v1/imports/analyze?filename=assets.csv",
            content=b"name\nMCP handoff\n",
            headers={**auth, "Content-Type": "application/octet-stream"},
        )
        assert prepared.status_code == 200, prepared.text
        operation_id = prepared.json()["id"]
        with pytest.raises((MCPError, ToolError)):
            call_tool(mcp, token, "get_inventory_operation", {"operation_id": operation_id})
        approved = browser.post(f"/api/v1/operations/{operation_id}/approve", headers=auth)
        assert approved.status_code == 200, approved.text
        result = call_tool(
            mcp, token, "apply_inventory_operation", {"operation_id": operation_id}
        ).structured_content
        assert result["summary"]["created"] == 1
        assert browser.get("/api/v1/assets/search").json()["total"] == 1
        mcp.catalog.revoke_machine("mcp.delegated")
        with pytest.raises((MCPError, ToolError)):
            call_tool(mcp, token, "get_inventory_operation", {"operation_id": operation_id})
        unchanged = browser.get(f"/api/v1/operations/{operation_id}").json()
        assert unchanged == result
