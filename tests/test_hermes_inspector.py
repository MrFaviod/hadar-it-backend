"""Trusted launch proof is independent from an engine or browser claim."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from itsm.agent_integrations.installer import IntegrationTarget
from itsm.agent_integrations.service import AgentIntegrationService
from itsm.config import Settings


def test_inspector_credentials_require_a_complete_safe_pair():
    for values in (
        {"hermes_inspector_url": "http://127.0.0.1:19120"},
        {"hermes_inspector_token": "x" * 40},
        {"hermes_inspector_url": "http://u:p@localhost/", "hermes_inspector_token": "x" * 40},
        {
            "hermes_inspector_url": "http://localhost/?key=private",
            "hermes_inspector_token": "x" * 40,
        },
        {"hermes_inspector_url": "http://localhost/", "hermes_inspector_token": "short"},
    ):
        with pytest.raises(ValueError):
            Settings(**values)


@pytest.mark.parametrize("mutation", ["missing", "home", "endpoint", "digest", "process"])
def test_invalid_trusted_launch_never_contacts_engine(monkeypatch, tmp_path, mutation):
    token = "independent-inspector-token-" + "x" * 32
    settings = Settings(hermes_inspector_url="http://127.0.0.1:19120",
                        hermes_inspector_token=token)
    service = AgentIntegrationService(settings, lambda: None)
    home = str(tmp_path.resolve())
    endpoint = "http://127.0.0.1:19119"
    proof = {"protocol": "itsm-hermes-launch-v1", "profileHome": home,
             "endpoint": endpoint, "launchId": "owned-launch", "processId": 42,
             "configDigest": "a" * 64}
    if mutation == "missing":
        proof.pop("launchId")
    elif mutation == "home":
        proof["profileHome"] = home + "/other"
    elif mutation == "endpoint":
        proof["endpoint"] = "http://127.0.0.1:9999"
    elif mutation == "digest":
        proof["configDigest"] = "b" * 64
    else:
        proof["processId"] = 0
    original = httpx.AsyncClient
    requests = []

    def handler(request):
        requests.append(request)
        assert str(request.url) == "http://127.0.0.1:19120/profile-proof"
        assert request.headers["Authorization"] == "Bearer " + token
        return httpx.Response(200, json=proof)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: original(
        transport=httpx.MockTransport(handler), **kwargs))
    monkeypatch.setattr(service, "_build_engine", lambda instance: pytest.fail(
        "invalid launch must be rejected before native engine access"))
    instance = SimpleNamespace(base_url=endpoint)
    target = IntegrationTarget("hermes", home, "itsm", "0.22.5")
    result = asyncio.run(service._hermes_profile_safety(
        instance, target, {"url": "http://127.0.0.1:19130/api/v1/mcp",
                           "secretRef": "ITSM_MCP", "identityId": "machine"},
        ["itsm-inventory"], {"configDigest": "a" * 64}))
    assert result is None
    assert len(requests) == 1
    assert token in settings.sensitive_values()
