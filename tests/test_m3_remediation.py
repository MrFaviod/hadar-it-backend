"""M3 audit regressions; fictitious credentials and mock transports only."""

import asyncio
import base64
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from itsm.agent_integrations import installer
from itsm.agent_integrations.models import AgentInstance
from itsm.agent_integrations.service import AgentIntegrationService, _engine_diagnostic
from tests import test_agent_integrations as support
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME

integration_client = support.app_client


@pytest.mark.parametrize("remote", [False, True])
@pytest.mark.parametrize("allowed", [False, True])
def test_install_inspection_rechecks_legacy_destination(
    integration_client, tmp_path, monkeypatch, remote, allowed
):
    catalog, client, settings = integration_client
    machine, token = catalog.add_machine("m3-inspect", "M3 Inspect")
    monkeypatch.setenv("ITSM_TEST_MCP_TOKEN", token)
    monkeypatch.setenv("M3_ENGINE", "fictitious-engine-password")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    settings.ai_secret_destinations["M3_ENGINE"] = ["https://approved.example"]
    headers = support.login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    instance = support.configure_instance(
        client,
        headers,
        baseUrl="https://approved.example",
        secretRef="M3_ENGINE",
        integrationIdentityId=machine.actor_id,
    )
    # A legacy/out-of-band row bypasses API write validation.
    with catalog.session() as db:
        db.get(AgentInstance, instance["id"]).base_url = (
            "https://approved.example" if allowed else "https://evil.example"
        )
        db.commit()
    service = client.app.state.agent_integrations
    seen = []
    clients = []
    real_client = httpx.AsyncClient

    def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "https://redirect.example/stolen"})

    def factory(**kwargs):
        # Capture real transport construction, injecting only a no-network transport.
        kwargs["transport"] = httpx.MockTransport(handler)
        result = real_client(**kwargs)
        clients.append(result)
        return result

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    monkeypatch.setattr(service, "_verify_connection", AsyncMock(return_value={"verified": True}))
    target = tmp_path / "profile"
    target.mkdir()

    class LocalInstaller:
        async def apply(self, target, *, mcp, skills, operation, profile_inspector):
            evidence = await profile_inspector(
                target=target, mcp=mcp, skills=skills, config_digest="sha256:" + "a" * 64
            )
            assert evidence is None  # redirect responses cannot certify a profile
            return {"status": "configured", "verified": False, "configDigest": "sha256:" + "a" * 64}

    service._installer = LocalInstaller()
    body = {
        "instanceId": instance["id"],
        "target": {
            "engine": "opencode",
            "path": str(target),
            "profile": "itsm",
            "version": "2.1.2",
        },
        "mcp": {
            "url": "http://127.0.0.1:18080/api/v1/mcp",
            "secretRef": "ITSM_TEST_MCP_TOKEN",
            "identityId": machine.actor_id,
        },
        "skills": ["itsm-inventory"],
        "operation": "install",
        "mode": "remote" if remote else "local",
    }
    exported = client.post(f"{support.API}/agent/integrations/install", json=body, headers=headers)
    assert exported.status_code == 200, exported.text
    result = exported
    if remote:
        receipt = support._canonical_receipt(exported.json(), machine.actor_id)
        result = client.post(
            f"{support.API}/agent/integrations/receipts",
            json={
                "instanceId": instance["id"],
                "requestDigest": exported.json()["requestDigest"],
                "receipt": receipt,
            },
            headers=headers,
        )
    assert result.status_code == 200, result.text
    assert result.json()["verified"] is False
    assert "fictitious-engine-password" not in result.text
    assert all(not c.trust_env and not c.follow_redirects and not c._mounts for c in clients)
    if allowed:
        assert seen
        assert {r.url.host for r in seen} == {"approved.example"}
        expected = "Basic " + base64.b64encode(b"opencode:fictitious-engine-password").decode()
        assert all(r.headers["Authorization"] == expected for r in seen)
    else:
        assert seen == []
        assert clients == []


def test_mcp_verification_uses_injected_settings(settings_factory, monkeypatch):
    settings = settings_factory(ai_secret_destinations={"M3_MCP": ["https://approved.example/mcp"]})
    seen = []

    async def verify(mcp, settings=None):
        seen.append(settings)
        return {"verified": True, "checks": []}

    monkeypatch.setattr(installer, "verify_connection", verify)
    service = AgentIntegrationService(settings, lambda: None)
    assert asyncio.run(service._verify_connection({"secretRef": "M3_MCP"}))["verified"] is True
    assert seen == [settings]


@pytest.mark.parametrize(
    "code,message",
    [
        ("model_unavailable", "engine model is unavailable"),
        ("unavailable", "engine is unavailable"),
        ("misconfigured", "engine configuration is invalid"),
    ],
)
def test_stable_engine_codes_keep_fixed_public_messages(code, message):
    from itsm.agent_integrations.service import _engine_error

    assert _engine_diagnostic(code) == (code, message)
    error = SimpleNamespace(code=code, message="secret-upstream-body", retryable=False)
    assert _engine_error(error) == (code, message, False)
