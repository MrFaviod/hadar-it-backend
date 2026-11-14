"""The agent section promotes the verified provider the operator entered.

The setup wizard verifies an early AI key and hands it to a personal provider
record. The configuration section must promote that destination to an
operator-managed global record and link the installation selection to it, so
``AgentRuntime`` can run without ``OPENAI_API_KEY`` in the environment while the
credential stays sealed with the external key. Environment credentials keep
their priority.
"""

# ruff: noqa: F401, F811 - imported pytest fixtures are re-exported for this module

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.agent_integrations.models import AgentProvider
from itsm.agent_integrations.providers import ProviderModelSelection, unseal_credential
from itsm.agents import runtime as runtime_module
from itsm.agents.runtime import AgentRuntime
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.setup import configuration as configuration_module
from itsm.system.models import SystemProviderSettings
from itsm.system.providers import ProviderSelection
from pydantic_ai.models.function import FunctionModel
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from tests.test_setup_configuration import (
    API_KEY,
    CONFIGURATION_PATH,
    ORIGIN,
    PROBE_MODEL,
    app,
    apply_section,
    claim_session,
    clock,
    installation_path,
    post,
    provider,
    reach_owner_ready,
    section_body,
    setup_environment,
    start_configuration,
    state_dir,
    store,
)


@pytest.fixture(autouse=True)
def _environment(setup_environment: Any) -> Iterator[None]:
    yield


def _apply_agent(client: TestClient, csrf: str) -> dict[str, Any]:
    response = apply_section(client, csrf, "agent", {"provider": "openai", "model": PROBE_MODEL})
    return section_body(response)


def _rows(database_url: str) -> tuple[list[AgentProvider], SystemProviderSettings | None]:
    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            providers = list(session.scalars(select(AgentProvider)).all())
            selection = session.get(SystemProviderSettings, 1)
            return providers, selection
    finally:
        engine.dispose()


def _runtime() -> tuple[Any, Any]:
    settings = configuration_module._runtime_settings()
    engine = create_engine_from_settings(settings)
    return settings, create_session_factory(engine)


def _fake_resolve(captured: dict[str, Any]) -> Any:
    def resolve(settings: Any, selection: Any = None, *, http_client: Any = None) -> Any:
        captured["selection"] = selection
        captured["http_client"] = http_client
        return FunctionModel(lambda messages, info: "ok")

    return resolve


def test_agent_apply_promotes_the_verified_provider_to_a_global_record(
    app, store, provider, tmp_path: Path
) -> None:
    with TestClient(app) as client:
        csrf, database_url = reach_owner_ready(client, store, tmp_path, provider=provider)
        assert start_configuration(client, csrf).status_code == 200
        body = _apply_agent(client, csrf)
        assert body["status"] == "passed", body
        receipt = body["receipt"]
        assert receipt["provider_record"] is True
        assert receipt["credential_configured"] is True
        assert receipt["capability"] == "verified"
        assert API_KEY not in str(body)
        assert "OPENAI_API_KEY" not in str(body)

    providers, selection = _rows(database_url)
    assert selection is not None and selection.provider_id
    promoted = [row for row in providers if row.id == selection.provider_id]
    assert len(promoted) == 1
    record = promoted[0]
    assert record.scope == "global"
    assert record.owner_id is None
    assert record.enabled is True
    assert record.base_url.rstrip("/") == provider.base_url.rstrip("/")
    assert PROBE_MODEL in list(record.models or [])
    assert record.api_key_ciphertext
    assert API_KEY not in record.api_key_ciphertext
    settings, _ = _runtime()
    assert unseal_credential(settings, record.api_key_ciphertext) == API_KEY
    # The owner's personal record is left in place; promotion only adds the
    # installation-wide record the runtime reads.
    assert [row.scope for row in providers].count("personal") == 1


def test_agent_apply_reuses_the_promoted_record_on_a_second_apply(
    app, store, provider, tmp_path: Path
) -> None:
    with TestClient(app) as client:
        csrf, database_url = reach_owner_ready(client, store, tmp_path, provider=provider)
        assert start_configuration(client, csrf).status_code == 200
        first = _apply_agent(client, csrf)
        second = _apply_agent(client, csrf)
        assert first["receipt"]["provider_record"] is True
        assert second["status"] == "passed"
        assert second["receipt"]["provider_record"] is True

    providers, selection = _rows(database_url)
    globals_ = [row for row in providers if row.scope == "global"]
    assert len(globals_) == 1
    assert selection is not None and selection.provider_id == globals_[0].id


def test_agent_preview_and_refused_confirmation_never_promote(
    app, store, provider, tmp_path: Path
) -> None:
    with TestClient(app) as client:
        csrf, database_url = reach_owner_ready(client, store, tmp_path, provider=provider)
        assert start_configuration(client, csrf).status_code == 200
        preview = post(
            client,
            f"{CONFIGURATION_PATH}/agent",
            {"values": {"provider": "openai", "model": PROBE_MODEL}},
            csrf,
        )
        body = section_body(preview)
        assert body["preview_only"] is True
        assert body["current"]["provider_record"] is False
        refused = apply_section(
            client, csrf, "agent", {"provider": "openai", "model": PROBE_MODEL}, confirm=False
        )
        assert refused.status_code == 422
        assert refused.json()["error"] == "confirmation_required"

    providers, selection = _rows(database_url)
    assert [row for row in providers if row.scope == "global"] == []
    assert selection is None


def test_agent_read_back_reports_the_promoted_record(app, store, provider, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, _ = reach_owner_ready(client, store, tmp_path, provider=provider)
        assert start_configuration(client, csrf).status_code == 200
        assert _apply_agent(client, csrf)["status"] == "passed"
        current = section_body(client.get(f"{CONFIGURATION_PATH}/agent")).get("current")
        assert current["provider"] == "openai"
        assert current["model"] == PROBE_MODEL
        assert current["persisted"] is True
        assert current["provider_record"] is True
        assert current["credential_configured"] is True


def test_agent_runtime_uses_the_promoted_record_when_environment_is_empty(
    app, store, provider, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with TestClient(app) as client:
        csrf, _ = reach_owner_ready(client, store, tmp_path, provider=provider)
        assert start_configuration(client, csrf).status_code == 200
        assert _apply_agent(client, csrf)["status"] == "passed"

    captured: dict[str, Any] = {}
    monkeypatch.setattr(runtime_module, "resolve_model", _fake_resolve(captured))
    settings, factory = _runtime()
    runtime = AgentRuntime(settings, factory)
    try:
        runtime._ensure()
    finally:
        asyncio.run(runtime.aclose())

    selection = captured["selection"]
    assert isinstance(selection, ProviderModelSelection)
    assert selection.base_url.rstrip("/") == provider.base_url.rstrip("/")
    assert selection.model == PROBE_MODEL
    assert selection.api_key == API_KEY
    assert selection.allow_private is True
    assert captured["http_client"] is not None


def test_agent_runtime_keeps_environment_credentials_first(
    app, store, provider, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with TestClient(app) as client:
        csrf, _ = reach_owner_ready(client, store, tmp_path, provider=provider)
        assert start_configuration(client, csrf).status_code == 200
        assert _apply_agent(client, csrf)["status"] == "passed"

    monkeypatch.setenv("OPENAI_API_KEY", "env-credential")
    captured: dict[str, Any] = {}
    monkeypatch.setattr(runtime_module, "resolve_model", _fake_resolve(captured))
    settings, factory = _runtime()
    runtime = AgentRuntime(settings, factory)
    try:
        runtime._ensure()
    finally:
        asyncio.run(runtime.aclose())

    selection = captured["selection"]
    assert isinstance(selection, ProviderSelection)
    assert not isinstance(selection, ProviderModelSelection)
    assert selection.provider == "openai"
    assert selection.model == PROBE_MODEL
