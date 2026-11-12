"""M3 credential destinations: fictitious values and mocked transports only."""

import asyncio

import pytest
from itsm.agents.engines import EngineConfig, _HTTPEngine
from tests import test_agent_integrations as support
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.test_agent_integrations import (
    API,
    login,
)

integration_client = support.app_client


def test_engine_secret_requires_exact_operator_destination(integration_client, monkeypatch):
    _, client, settings = integration_client
    monkeypatch.setenv("M3_SECRET", "fictitious-secret")
    object.__setattr__(settings, "ai_secret_destinations", {"M3_SECRET": ["http://127.0.0.1:9"]})
    headers = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    before = client.get(f"{API}/agent/integrations", headers=headers).json()
    payload = {"name": "M3", "engine": "opencode", "secretRef": "M3_SECRET"}
    denied = client.post(
        f"{API}/agent/integrations/instances",
        json={**payload, "baseUrl": "https://other.example"},
        headers=headers,
    )
    assert denied.status_code == 422
    assert "fictitious-secret" not in denied.text
    assert client.get(f"{API}/agent/integrations", headers=headers).json() == before
    allowed = client.post(
        f"{API}/agent/integrations/instances",
        json={**payload, "baseUrl": "http://127.0.0.1:9/"},
        headers=headers,
    )
    assert allowed.status_code == 201, allowed.text
    instance = allowed.json()
    denied = client.put(
        f"{API}/agent/integrations/instances/{instance['id']}",
        json={"baseUrl": "https://other.example"},
        headers=headers,
    )
    assert denied.status_code == 422
    current = client.get(f"{API}/agent/integrations", headers=headers).json()
    assert (
        next(row for row in current["instances"] if row["id"] == instance["id"])["baseUrl"]
        == "http://127.0.0.1:9"
    )


def test_runtime_rechecks_reference_destination_before_secret_use(integration_client, monkeypatch):
    from itsm.agent_integrations.service import InstanceSnapshot, IntegrationUnavailable

    _, client, settings = integration_client
    monkeypatch.setenv("M3_SECRET", "fictitious-secret")
    object.__setattr__(settings, "ai_secret_destinations", {"M3_SECRET": ["http://127.0.0.1:9"]})
    client.get(
        f"{API}/agent/integrations", headers=login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    )
    service = client.app.state.agent_integrations
    row = InstanceSnapshot(
        id="m3",
        name="M3",
        engine="opencode",
        base_url="https://other.example",
        secret_ref="M3_SECRET",
        username=None,
        profile=None,
        directory=None,
        enabled=True,
        default_model=None,
        integration_identity_id=None,
    )
    with pytest.raises(IntegrationUnavailable):
        service._build_engine(row)


def test_engine_transport_disables_environment_proxy_and_redirects(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    engine = _HTTPEngine(EngineConfig(base_url="http://127.0.0.1:9"))

    async def check():
        client = engine._http
        try:
            assert client.trust_env is False
            assert client.follow_redirects is False
            assert not client._mounts
        finally:
            await engine.close()

    asyncio.run(check())


def test_mcp_reference_destination_denied_before_transport(settings_factory, monkeypatch):
    from itsm.agent_integrations.installer import verify_connection

    monkeypatch.setenv("M3_MCP", "fictitious-mcp-secret")
    settings = settings_factory(
        ai_secret_destinations={"M3_MCP": ["http://127.0.0.1:9/api/v1/mcp"]}
    )
    result = asyncio.run(
        verify_connection(
            {"url": "https://other.example/mcp", "secretRef": "M3_MCP", "identityId": "fake"},
            settings=settings,
        )
    )
    assert result == {
        "verified": False,
        "checks": [
            {
                "name": "mcp.destination",
                "status": "fail",
                "detail": "credential destination is not authorized",
            }
        ],
        "toolCount": 0,
    }


def test_provider_destination_change_needs_explicit_credential(integration_client, monkeypatch):
    from unittest.mock import AsyncMock

    from itsm.agent_integrations.providers import ProviderProbe
    from itsm.agent_integrations.service import AgentIntegrationService

    catalog, client, settings = integration_client
    settings.ai_credential_key = __import__("pydantic").SecretStr(
        "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
    )
    service = AgentIntegrationService(settings, catalog.factory())
    monkeypatch.setattr(
        service, "_probe_models", AsyncMock(return_value=ProviderProbe("unreachable"))
    )
    client.app.state.agent_integrations = service
    headers = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    created = client.post(
        f"{API}/agent/providers",
        json={
            "name": "M3",
            "scope": "global",
            "baseUrl": "http://127.0.0.1:9/v1",
            "models": ["fake"],
            "modelSelection": "manual",
            "apiKey": "fake-key",
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    url = f"{API}/agent/providers/{created.json()['id']}"
    service._probe_models.reset_mock()
    denied = client.patch(url, json={"baseUrl": "https://other.example/v1"}, headers=headers)
    assert denied.status_code == 422
    service._probe_models.assert_not_called()
    allowed = client.patch(
        url, json={"baseUrl": "https://other.example/v1", "apiKey": "new-fake-key"}, headers=headers
    )
    assert allowed.status_code == 200, allowed.text
    assert service._probe_models.call_args.args == (
        "https://other.example/v1",
        "new-fake-key",
        "global",
    )


def test_validator_remote_http_is_rejected_but_loopback_and_https_allowed():
    from itsm.extensions.validator import RemoteContainerValidator

    token = "fictitious-validator-token-32-characters"
    for url in ("http://validator.example", "http://10.0.0.2", "http://localhost"):
        with pytest.raises(ValueError, match="HTTPS"):
            RemoteContainerValidator(url, token=token)
    for url in ("http://127.0.0.1:8766", "http://[::1]:8766", "https://validator.example"):
        assert RemoteContainerValidator(url, token=token)


def test_upstream_engine_error_does_not_publish_unknown_secret_body(integration_client):
    from tests.test_agent_integrations import (
        FakeEngine,
        FakeEngineError,
        build_service,
        configure_instance,
    )

    catalog, client, settings = integration_client
    engine = FakeEngine(
        discover_error=FakeEngineError(
            "upstream", "unrecognized-body-credential-and-private-data", True
        )
    )
    build_service(client, catalog, engine_factory=lambda *_: engine)
    headers = login(client, settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    from itsm.agent_integrations.service import InstanceSnapshot, IntegrationUnavailable

    instance = configure_instance(client, headers)
    row = InstanceSnapshot(
        id=instance["id"],
        name="M3",
        engine="opencode",
        base_url="http://127.0.0.1:9",
        secret_ref=None,
        username=None,
        profile=None,
        directory=None,
        enabled=True,
        default_model=None,
        integration_identity_id=None,
    )
    with pytest.raises(IntegrationUnavailable) as raised:
        asyncio.run(client.app.state.agent_integrations._discover(row))
    assert "unrecognized-body-credential-and-private-data" not in str(raised.value)
    assert "upstream" in str(raised.value)
    assert engine.closed == 1


def test_fallback_provider_uses_same_guarded_transport(settings_factory, monkeypatch):
    import itsm.agents.runtime as runtime
    from itsm.agents.runtime import AgentRuntime
    from itsm.system.providers import ProviderSelection
    from pydantic_ai.messages import ModelResponse, TextPart
    from pydantic_ai.models.function import FunctionModel

    seen = []
    client = object()
    monkeypatch.setattr(runtime, "build_provider_http_client", lambda **kwargs: client)

    def resolve(settings, selection, **kwargs):
        seen.append(kwargs.get("http_client"))
        return FunctionModel(lambda messages, info: ModelResponse(parts=[TextPart("ok")]))

    monkeypatch.setattr(runtime, "resolve_model", resolve)
    instance = AgentRuntime(settings_factory(), lambda: None)
    instance._build(ProviderSelection(provider="openai", model="fake", source="environment"))
    assert seen == [client]
