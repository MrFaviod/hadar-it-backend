"""M3 MCP proof errors never publish remote exception text."""

import asyncio

import fastmcp.client.transports
from itsm.agent_integrations.installer import verify_connection


def test_mcp_proof_error_has_stable_diagnostic(settings_factory, monkeypatch):
    settings = settings_factory(ai_secret_destinations={"M3_TOKEN": ["http://127.0.0.1:9/mcp"]})
    monkeypatch.setenv("M3_TOKEN", "fictitious-token")

    def fail(*args, **kwargs):
        raise RuntimeError("unknown-remote-secret-body")

    monkeypatch.setattr(fastmcp.client.transports, "StreamableHttpTransport", fail)
    result = asyncio.run(
        verify_connection(
            {"url": "http://127.0.0.1:9/mcp", "secretRef": "M3_TOKEN", "identityId": "fake"},
            settings=settings,
        )
    )
    assert result["verified"] is False
    assert "unknown-remote-secret-body" not in str(result)
    assert result["checks"][1]["detail"] == "mcp_connection_failed"
    assert result["toolCount"] == 0
