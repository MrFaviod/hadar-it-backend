"""Two people, one company budget and owner-only personal providers (S13).

Every check runs through the public surface: the HTTP API with real cookie
sessions, CSRF and Origin guards, the real MCP server over loopback, the agent
tool path and the credentials/backup CLIs. Provider credentials are only ever
read from the database column to prove that what is stored is ciphertext, never
plaintext.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pydantic_ai.models
import pytest
from fastapi.testclient import TestClient
from itsm.agent_integrations.providers import (
    DiscoveredModel,
    ProviderProbe,
    credential_fingerprint,
)
from itsm.agents.runtime import TOOL_NAMES, AgentRuntime
from itsm.agents.usage import estimated_usage, measured_usage, unavailable_usage
from itsm.credentials import rotate
from itsm.main import create_app
from itsm.mcp.server import TOOL_NAMES as MCP_TOOL_NAMES
from pydantic import SecretStr
from sqlalchemy import select
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import Catalog, prepare, serve, sign_in_as
from tests.test_agent_chat import chat, use_model
from tests.test_agent_integrations import (
    _managed_setup,
    _personal_provider,
    _second_owner,
    _send,
    _usage_funding,
    build_service,
)
from tests.test_agent_integrations import app_client as managed_client  # noqa: F401 - pytest fixture
from tests.test_ai_isolation import TOKEN as BROKER_TOKEN
from tests.test_ai_isolation import fake_broker as start_broker

API = "/api/v1"

# Fernet keys are deterministic test fixtures; they only encrypt data inside an
# isolated temporary database.
KEY_OLD = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
KEY_NEW = "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE="
KEY_FOREIGN = "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI="

GLOBAL_KEY = "sk-global-company-key"
ADA_KEY = "sk-personal-ada-key"
UGO_KEY = "sk-personal-ugo-key"

GLOBAL_MODEL = "global-model"
PERSONAL_MODEL = "personal-model"
MEASURED_MODEL = "p-measured"
ESTIMATED_MODEL = "p-estimated"
UNAVAILABLE_MODEL = "p-unavailable"

MISSING_ID = "8d3b0deb-1a0e-4e57-9b1f-c9e24b8f0c8e"


@dataclass
class Person:
    """One signed-in human with its own cookie jar and CSRF token."""

    client: TestClient
    headers: dict[str, str]
    actor_id: str = ""

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.client.get(path, headers=self.headers, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.client.post(path, headers=self.headers, **kwargs)

    def put(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.client.put(path, headers=self.headers, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.client.patch(path, headers=self.headers, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.client.delete(path, headers=self.headers, **kwargs)


@dataclass
class Environment:
    """An isolated migrated database with the three identities under test."""

    catalog: Catalog
    settings: Any
    superadmin: Person
    ada: Person
    ugo: Person


@pytest.fixture
def environment(settings_factory: Any) -> Iterator[Callable[..., Environment]]:
    """Build isolated environments and close every client/app on teardown."""
    opened: list[TestClient] = []

    def build(**overrides: Any) -> Environment:
        values: dict[str, Any] = {
            "agent_model": "openai:gpt-4o-mini",
            "ai_credential_keys": KEY_OLD,
            "agent_max_output_tokens": 64,
            "ai_broker_url": "ws://127.0.0.1:9/runs",
            "ai_broker_token": BROKER_TOKEN,
        }
        values.update(overrides)
        catalog = prepare(settings_factory, **values)
        settings = catalog.settings

        def sign_in(username: str, password: str) -> Person:
            client = TestClient(create_app(settings))
            client.__enter__()
            opened.append(client)
            return Person(
                client=client,
                headers=sign_in_as(client, settings, username, password),
            )

        ada = catalog.add_user("ada.admin", "Ada Admin", "admin")
        ugo = catalog.add_user("ugo.user", "Ugo User", "user")

        def person(username: str, password: str, actor_id: str) -> Person:
            signed = sign_in(username, password)
            signed.actor_id = actor_id
            return signed

        return Environment(
            catalog=catalog,
            settings=settings,
            superadmin=sign_in(ADMIN_USERNAME, ADMIN_PASSWORD),
            ada=person("ada.admin", "machine-identity-password-2026", ada.actor_id),
            ugo=person("ugo.user", "machine-identity-password-2026", ugo.actor_id),
        )

    yield build
    for client in opened:
        with ExitStack() as stack:
            stack.callback(client.__exit__, None, None, None)


# --------------------------------------------------------------------- helpers
def create_provider(
    owner: Person,
    *,
    scope: str,
    name: str,
    models: tuple[str, ...] = (GLOBAL_MODEL, PERSONAL_MODEL),
    api_key: str,
    base_url: str | None = None,
) -> dict[str, Any]:
    """Create a provider through the owner-facing endpoint."""
    if base_url is None:
        base_url = (
            "https://api.example.com/v1" if scope == "personal" else "http://127.0.0.1:18081/v1"
        )
    response = owner.post(
        f"{API}/agent/providers",
        json={
            "scope": scope,
            "name": name,
            "baseUrl": base_url,
            "models": list(models),
            "apiKey": api_key,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def set_policy(env: Environment, *, company_limit: int | None) -> None:
    response = env.superadmin.put(
        f"{API}/agent/usage/policy", json={"companyDailyLimit": company_limit}
    )
    assert response.status_code == 200, response.text


def set_override(env: Environment, user_id: str, limit: int | None) -> None:
    response = env.superadmin.put(
        f"{API}/agent/usage/overrides/{user_id}", json={"dailyLimit": limit}
    )
    assert response.status_code == 200, response.text


def start_session(owner: Person, instance_id: str, model: str) -> dict[str, Any]:
    response = owner.post(f"{API}/agent/sessions", json={"instanceId": instance_id, "model": model})
    assert response.status_code == 201, response.text
    return response.json()


def post_message(owner: Person, session_id: str) -> httpx.Response:
    return owner.post(f"{API}/agent/sessions/{session_id}/messages", json={"message": "hola"})


def stream_error(response: httpx.Response) -> dict[str, Any]:
    """Streaming session errors arrive as SSE events on a 200 response."""
    assert response.status_code == 200, response.text
    events = [json.loads(line[len("data: ") :]) for line in response.iter_lines() if line]
    errors = [event for event in events if event["type"] == "error"]
    assert errors, events
    return errors[0]


def turn_reply(events: list[dict[str, Any]]) -> str:
    assert events, "the turn produced no events"
    assert events[-1]["type"] == "done", events
    return "".join(event["text"] for event in events if event["type"] == "delta")


def provider_ciphertexts(catalog: Catalog) -> list[str]:
    """Ciphertext at rest, read only to prove it is not plaintext."""
    from itsm.agent_integrations.models import AgentProvider

    with catalog.session() as session:
        return [row for row in session.scalars(select(AgentProvider.api_key_ciphertext)).all()]


def provider_status(person: Person, provider_id: str) -> dict[str, Any]:
    """Return the owner-visible provider DTO for one stored provider."""
    listing = person.get(f"{API}/agent/providers")
    assert listing.status_code == 200, listing.text
    for item in listing.json()["items"]:
        if item["id"] == provider_id:
            return item
    raise AssertionError("the owner cannot see its own provider")


def visible_provider_ids(person: Person) -> set[str]:
    response = person.get(f"{API}/agent/providers")
    assert response.status_code == 200, response.text
    return {item["id"] for item in response.json()["items"]}


def record_authorization(request: httpx.Request, seen: dict[str, Any]) -> None:
    """Mock upstream that records the secret actually used for each model."""
    model = json.loads(request.content)["model"]
    seen.setdefault("models", []).append(model)
    seen.setdefault("authorizations", []).append(request.headers.get("authorization"))


def use_admin_runtime(
    env: Environment, upstream: Callable[[httpx.Request], httpx.Response]
) -> httpx.AsyncClient:
    """Run the pydantic path against a mocked upstream, never real inference."""
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    runtime = AgentRuntime(env.settings, env.catalog.factory(), provider_http_client=http_client)
    build_service(env.ada.client, env.catalog, runtime=runtime)
    return http_client


def chat_completions(model: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "created": 0,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": f"reply from {model}"},
                }
            ],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
        },
    )


def quota_call(connection: Any, call_id: str, phase: str, evidence: Any = None) -> dict[str, Any]:
    """Speak the worker quota protocol so the ledger sees a real receipt."""
    payload: dict[str, Any] = {"type": "quota.call", "callId": call_id, "phase": phase}
    if evidence is not None:
        payload["evidence"] = evidence
    connection.send(json.dumps(payload))
    return json.loads(connection.recv(timeout=10))


def broker_usage(model: str) -> dict[str, Any]:
    if model == MEASURED_MODEL:
        return measured_usage(
            input_tokens=4,
            output_tokens=2,
            total_tokens=6,
            total_source="provider",
            source="provider",
        ).event()
    if model == ESTIMATED_MODEL:
        return estimated_usage(
            "tokens/4", input_tokens=8, output_tokens=4, total_tokens=12, total_source="derived"
        ).event()
    if model == UNAVAILABLE_MODEL:
        return unavailable_usage(source="engine").event()
    return measured_usage(
        input_tokens=4,
        output_tokens=2,
        total_tokens=6,
        total_source="provider",
        source="provider",
    ).event()


def accountable_script(connection: Any, start: dict[str, Any], broker: Any) -> None:
    """A worker turn that settles real usage (never token-free success)."""
    if start.get("quotaEnabled"):
        assert quota_call(connection, "q1", "reserve").get("ok") is True
        assert (
            quota_call(connection, "q1", "settle", broker_usage(start["provider"]["model"])).get(
                "ok"
            )
            is True
        )
    connection.send(json.dumps({"type": "final", "message": "ok"}))


def forbidden_strings(env: Environment) -> list[str]:
    values = [GLOBAL_KEY, ADA_KEY, UGO_KEY]
    values.extend(provider_ciphertexts(env.catalog))
    return [value for value in values if value]


def assert_no_secret(payload: Any, forbidden: list[str]) -> None:
    rendered = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    for value in forbidden:
        assert value not in rendered, f"secret leaked: {value[:6]}..."


# ----------------------------------------------------- 1. company attribution
def test_company_quota_is_attributed_and_enforced_per_person(environment, monkeypatch) -> None:
    broker = start_broker(accountable_script)
    try:
        env = environment(ai_broker_url=broker.url)
        monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", True)
        http_client = use_admin_runtime(env, lambda request: chat_completions(GLOBAL_MODEL))
        try:
            set_policy(env, company_limit=1000)
            set_override(env, env.ada.actor_id, 68)
            provider = create_provider(
                env.superadmin, scope="global", name="Company provider", api_key=GLOBAL_KEY
            )

            session = start_session(env.ada, provider["id"], GLOBAL_MODEL)
            turn_reply(_send(env.ada.client, env.ada.headers, session["id"]))
            ada_usage = _usage_funding(env.ada.client, env.ada.headers)
            assert ada_usage["company"]["consumedTokens"] == 5
            assert ada_usage["company"]["limitTokens"] == 68
            assert ada_usage["company"]["limitSource"] == "override"
            assert ada_usage["personal"]["consumedTokens"] == 0

            denied = post_message(env.ada, session["id"])
            assert stream_error(denied)["code"] == "quota_exceeded"
            assert _usage_funding(env.ada.client, env.ada.headers)["company"]["consumedTokens"] == 5

            ugo_session = start_session(env.ugo, provider["id"], GLOBAL_MODEL)
            turn_reply(_send(env.ugo.client, env.ugo.headers, ugo_session["id"]))
            ugo_usage = _usage_funding(env.ugo.client, env.ugo.headers)
            assert ugo_usage["company"]["consumedTokens"] == 6
            assert ugo_usage["company"]["limitTokens"] == 1000
            assert ugo_usage["company"]["availableTokens"] == 994

            ada_report = env.superadmin.get(
                f"{API}/agent/usage/report", params={"userId": env.ada.actor_id}
            )
            assert ada_report.status_code == 200, ada_report.text
            ada_items = [item for item in ada_report.json()["items"] if item["state"] == "settled"]
            assert {(item["providerScope"], item["funding"]) for item in ada_items} == {
                ("global", "company")
            }
            assert sum(item["settledTokens"] for item in ada_items) == 5
            ugo_report = env.superadmin.get(
                f"{API}/agent/usage/report", params={"userId": env.ugo.actor_id}
            )
            assert ugo_report.status_code == 200, ugo_report.text
            ugo_items = [item for item in ugo_report.json()["items"] if item["state"] == "settled"]
            assert {(item["providerScope"], item["funding"]) for item in ugo_items} == {
                ("global", "company")
            }
            assert sum(item["settledTokens"] for item in ugo_items) == 6
            assert_no_secret([ada_report.json(), ugo_report.json()], forbidden_strings(env))
        finally:
            asyncio.run(http_client.aclose())
        assert broker.errors == []
    finally:
        broker.close()


# ------------------------------------- 2. personal spending is record-only
def test_personal_provider_is_record_only_and_ignores_the_company_quota(
    environment, monkeypatch
) -> None:
    broker = start_broker(accountable_script)
    try:
        env = environment(ai_broker_url=broker.url)
        monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", True)
        http_client = use_admin_runtime(env, lambda request: chat_completions(PERSONAL_MODEL))
        try:
            set_policy(env, company_limit=1000)
            set_override(env, env.ada.actor_id, 68)
            global_provider = create_provider(
                env.superadmin, scope="global", name="Company provider", api_key=GLOBAL_KEY
            )
            personal = create_provider(
                env.ada,
                scope="personal",
                name="Ada personal",
                models=(PERSONAL_MODEL,),
                api_key=ADA_KEY,
            )
            assert personal["scope"] == "personal"
            assert personal["credentialConfigured"] is True
            assert personal["credentialStatus"] == "primary"
            assert_no_secret(personal, [GLOBAL_KEY, ADA_KEY])

            global_session = start_session(env.ada, global_provider["id"], GLOBAL_MODEL)
            turn_reply(_send(env.ada.client, env.ada.headers, global_session["id"]))
            assert _usage_funding(env.ada.client, env.ada.headers)["company"]["consumedTokens"] == 5

            denied = post_message(env.ada, global_session["id"])
            assert stream_error(denied)["code"] == "quota_exceeded"

            personal_session = start_session(env.ada, personal["id"], PERSONAL_MODEL)
            reply = turn_reply(_send(env.ada.client, env.ada.headers, personal_session["id"]))
            assert PERSONAL_MODEL in reply
            funding = _usage_funding(env.ada.client, env.ada.headers)
            assert funding["personal"]["consumedTokens"] == 5
            assert funding["personal"]["limitTokens"] is None
            assert funding["personal"]["unlimited"] is True
            assert funding["personal"]["precision"]["measured"] == 5
            # The exhausted company budget is neither consumed nor charged.
            assert funding["company"]["consumedTokens"] == 5

            report = env.superadmin.get(f"{API}/agent/usage/report", params={"funding": "personal"})
            assert report.status_code == 200, report.text
            items = [item for item in report.json()["items"] if item["state"] == "settled"]
            assert {item["funding"] for item in items} == {"personal"}
            assert sum(item["settledTokens"] for item in items) == 5
            assert_no_secret(report.json(), forbidden_strings(env))
        finally:
            asyncio.run(http_client.aclose())
        assert broker.errors == []
    finally:
        broker.close()


def test_switching_provider_mid_session_attributes_each_turn_correctly(
    environment, monkeypatch
) -> None:
    broker = start_broker(accountable_script)
    try:
        env = environment(ai_broker_url=broker.url)
        monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", True)
        http_client = use_admin_runtime(
            env, lambda request: chat_completions(json.loads(request.content)["model"])
        )
        try:
            set_policy(env, company_limit=1000)
            global_provider = create_provider(
                env.superadmin, scope="global", name="Company provider", api_key=GLOBAL_KEY
            )
            personal = create_provider(
                env.ada,
                scope="personal",
                name="Ada personal",
                models=(PERSONAL_MODEL,),
                api_key=ADA_KEY,
            )

            session = start_session(env.ada, global_provider["id"], GLOBAL_MODEL)
            turn_reply(_send(env.ada.client, env.ada.headers, session["id"]))
            switched = env.ada.patch(
                f"{API}/agent/sessions/{session['id']}",
                json={"instanceId": personal["id"], "model": PERSONAL_MODEL},
            )
            assert switched.status_code == 200, switched.text
            assert switched.json()["providerId"] is None
            turn_reply(_send(env.ada.client, env.ada.headers, session["id"]))
            back = env.ada.patch(
                f"{API}/agent/sessions/{session['id']}",
                json={"instanceId": global_provider["id"], "model": GLOBAL_MODEL},
            )
            assert back.status_code == 200, back.text
            turn_reply(_send(env.ada.client, env.ada.headers, session["id"]))

            funding = _usage_funding(env.ada.client, env.ada.headers)
            assert funding["company"]["consumedTokens"] == 10
            assert funding["personal"]["consumedTokens"] == 5

            report = env.superadmin.get(
                f"{API}/agent/usage/report", params={"userId": env.ada.actor_id}
            )
            assert report.status_code == 200, report.text
            grouped: dict[tuple[str, str, str], int] = {}
            for item in report.json()["items"]:
                if item["state"] != "settled":
                    continue
                key = (item["providerScope"], item["funding"], item["model"])
                grouped[key] = grouped.get(key, 0) + item["settledTokens"]
            assert grouped == {
                ("global", "company", GLOBAL_MODEL): 10,
                ("personal", "personal", PERSONAL_MODEL): 5,
            }
            assert_no_secret(report.json(), forbidden_strings(env))
        finally:
            asyncio.run(http_client.aclose())
        assert broker.errors == []
    finally:
        broker.close()


# ---------------------------------- 3. S12 precision stays in the receipt
def test_personal_usage_keeps_measured_estimated_and_unavailable(environment) -> None:
    broker = start_broker(accountable_script)
    try:
        env = environment(ai_broker_url=broker.url)
        set_policy(env, company_limit=1000)
        providers = {
            model: create_provider(
                env.ugo,
                scope="personal",
                name=f"Ugo {model}",
                models=(model,),
                api_key=UGO_KEY,
            )
            for model in (MEASURED_MODEL, ESTIMATED_MODEL, UNAVAILABLE_MODEL)
        }
        for model, provider in providers.items():
            session = start_session(env.ugo, provider["id"], model)
            turn_reply(_send(env.ugo.client, env.ugo.headers, session["id"]))

        assert len(broker.starts) == 3
        assert [start["provider"]["apiKey"] for start in broker.starts] == [UGO_KEY] * 3

        funding = _usage_funding(env.ugo.client, env.ugo.headers)
        assert funding["personal"]["consumedTokens"] == 18
        assert funding["personal"]["precision"]["measured"] == 6
        assert funding["personal"]["precision"]["estimated"] == 12
        assert funding["personal"]["precision"]["unavailable"] == 0
        assert funding["company"]["consumedTokens"] == 0

        report = env.superadmin.get(
            f"{API}/agent/usage/report",
            params={"funding": "personal", "userId": env.ugo.actor_id},
        )
        assert report.status_code == 200, report.text
        body = report.json()
        grouped: dict[tuple[str, str], int] = {}
        for item in body["items"]:
            if item["state"] != "settled":
                continue
            key = (item["model"], item["precision"])
            grouped[key] = grouped.get(key, 0) + item["settledTokens"]
        assert grouped == {
            (MEASURED_MODEL, "measured"): 6,
            (ESTIMATED_MODEL, "estimated"): 12,
        }
        unresolved = [
            item
            for item in body["items"]
            if item["state"] == "unresolved" and item["model"] == UNAVAILABLE_MODEL
        ]
        assert len(unresolved) == 1
        assert unresolved[0]["precision"] == "unavailable"
        assert unresolved[0]["unresolvedCount"] == 1
        assert body["precision"]["measured"] == 6
        assert body["precision"]["estimated"] == 12
        assert body["precision"]["unavailable"] == 0
        assert_no_secret(body, forbidden_strings(env))
        assert broker.errors == []
    finally:
        broker.close()


# ---------------------------------------------- 4. non-disclosure (S9, S13)
def test_personal_providers_are_invisible_to_everyone_else(environment, monkeypatch) -> None:
    env = environment()
    set_policy(env, company_limit=1000)
    ada = create_provider(env.ada, scope="personal", name="Ada personal", api_key=ADA_KEY)
    ugo = create_provider(env.ugo, scope="personal", name="Ugo personal", api_key=UGO_KEY)
    global_provider = create_provider(
        env.superadmin, scope="global", name="Company provider", api_key=GLOBAL_KEY
    )

    for person in (env.ada, env.ugo, env.superadmin):
        assert global_provider["id"] in visible_provider_ids(person)
    assert ada["id"] not in visible_provider_ids(env.ugo)
    assert ada["id"] not in visible_provider_ids(env.superadmin)
    assert ugo["id"] not in visible_provider_ids(env.ada)
    assert ada["id"] not in json.dumps(env.superadmin.get(f"{API}/agent/engines").json())
    assert ugo["id"] not in json.dumps(env.ada.get(f"{API}/agent/engines").json())

    views = [
        env.ada.get(f"{API}/agent/providers").json(),
        env.ugo.get(f"{API}/agent/providers").json(),
        env.superadmin.get(f"{API}/agent/providers").json(),
        env.superadmin.get(f"{API}/agent/engines").json(),
        env.ada.get(f"{API}/agent/engines").json(),
    ]
    assert_no_secret(views, [ADA_KEY, UGO_KEY, GLOBAL_KEY, *provider_ciphertexts(env.catalog)])

    async def _must_not_probe(*args: Any, **kwargs: Any) -> tuple[str, int]:
        raise AssertionError("a foreign provider must never be probed")

    monkeypatch.setattr("itsm.agent_integrations.service.discover_provider_models", _must_not_probe)

    def indistinguishable(foreign: Any, absent: Any) -> None:
        assert foreign.status_code == absent.status_code == 404
        assert foreign.text == absent.text

    indistinguishable(
        env.ugo.patch(f"{API}/agent/providers/{ada['id']}", json={"name": "hijack"}),
        env.ugo.patch(f"{API}/agent/providers/{MISSING_ID}", json={"name": "hijack"}),
    )
    indistinguishable(
        env.ugo.delete(f"{API}/agent/providers/{ada['id']}"),
        env.ugo.delete(f"{API}/agent/providers/{MISSING_ID}"),
    )
    indistinguishable(
        env.ugo.post(f"{API}/agent/providers/{ada['id']}/check"),
        env.ugo.post(f"{API}/agent/providers/{MISSING_ID}/check"),
    )
    indistinguishable(
        env.ugo.post(
            f"{API}/agent/sessions", json={"instanceId": ada["id"], "model": PERSONAL_MODEL}
        ),
        env.ugo.post(
            f"{API}/agent/sessions", json={"instanceId": MISSING_ID, "model": PERSONAL_MODEL}
        ),
    )
    indistinguishable(
        env.superadmin.put(
            f"{API}/agent/integrations/defaults", json={"instanceId": ada["id"], "model": None}
        ),
        env.superadmin.put(
            f"{API}/agent/integrations/defaults",
            json={"instanceId": MISSING_ID, "model": None},
        ),
    )

    engines = env.ada.get(f"{API}/agent/engines").json()
    assert all(ADA_KEY not in json.dumps(engine) for engine in engines["instances"])


def test_superadmin_cannot_obtain_any_personal_key_material(
    environment, monkeypatch, caplog
) -> None:
    caplog.set_level(logging.DEBUG)
    env = environment()
    set_policy(env, company_limit=1000)
    ada = create_provider(env.ada, scope="personal", name="Ada personal", api_key=ADA_KEY)
    create_provider(env.ugo, scope="personal", name="Ugo personal", api_key=UGO_KEY)

    async def _ok_probe(*args: Any, **kwargs: Any) -> ProviderProbe:
        return ProviderProbe("ok", (DiscoveredModel(PERSONAL_MODEL),))

    monkeypatch.setattr("itsm.agent_integrations.service.discover_provider_models", _ok_probe)
    own_check = env.ada.post(f"{API}/agent/providers/{ada['id']}/check")
    assert own_check.status_code == 200, own_check.text
    assert own_check.json()["ok"] is True

    bodies: list[Any] = [own_check.json()]
    for person in (env.superadmin, env.ada, env.ugo):
        listing = person.get(f"{API}/agent/providers")
        assert listing.status_code == 200
        bodies.append(listing.json())
        me = person.get(f"{API}/agent/usage/me")
        assert me.status_code == 200
        bodies.append(me.json())
        report = person.get(f"{API}/agent/usage/report")
        assert report.status_code in {200, 403}
        bodies.append(report.json() if report.status_code == 200 else report.text)
    sessions = env.ada.get(f"{API}/agent/sessions")
    assert sessions.status_code == 200
    bodies.append(sessions.json())
    bodies.append(env.superadmin.get(f"{API}/agent/engines").json())

    # There is no AI-usage export endpoint to exercise; assert the absence
    # instead of pretending to cover one.
    export_paths = [
        getattr(route, "path", "")
        for route in env.superadmin.client.app.routes
        if "usage" in getattr(route, "path", "") and "export" in getattr(route, "path", "")
    ]
    assert export_paths == []

    forbidden = forbidden_strings(env)
    for body in bodies:
        assert_no_secret(body, forbidden)
    assert_no_secret(caplog.text, forbidden)


# --------------------------------------- 5. MCP and agent tools are clean
def test_mcp_tools_expose_no_personal_credentials(environment, free_tcp_port: int) -> None:
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport
    from fastmcp.exceptions import ToolError

    env = environment()
    set_policy(env, company_limit=1000)
    create_provider(env.ada, scope="personal", name="Ada personal", api_key=ADA_KEY)
    create_provider(env.ugo, scope="personal", name="Ugo personal", api_key=UGO_KEY)
    create_provider(env.superadmin, scope="global", name="Company", api_key=GLOBAL_KEY)
    _, token = env.catalog.add_machine("mcp-ai-reader", "MCP AI Reader", "user")
    settings = env.settings
    port = free_tcp_port
    url = f"http://127.0.0.1:{port}{settings.api_prefix}/mcp"

    exposed = [
        name
        for name in MCP_TOOL_NAMES
        if any(word in name for word in ("provider", "usage", "session", "credential", "key"))
    ]
    assert exposed == ["list_system_providers", "configure_system_provider"]
    assert [name for name in TOOL_NAMES if "provider" in name] == [
        "list_system_providers",
        "configure_system_provider",
    ]

    async def _run() -> list[Any]:
        transport = StreamableHttpTransport(url, headers={"Authorization": f"Bearer {token}"})
        outputs: list[Any] = []
        async with Client(transport) as client:
            tools = await client.list_tools()
            assert {tool.name for tool in tools} == set(MCP_TOOL_NAMES)
            for name in ("search_assets", "get_system_configuration", "list_system_providers"):
                # A denial is a valid answer here: what matters is that neither a
                # success nor a denial carries key material.
                try:
                    outputs.append(str(await client.call_tool(name, {})))
                except Exception as exc:
                    outputs.append(f"{type(exc).__name__}: {exc}")
            with pytest.raises(ToolError):
                await client.call_tool("list_ai_providers", {})
        return outputs

    with serve(settings, port):
        outputs = asyncio.run(_run())
    forbidden = [ADA_KEY, UGO_KEY, GLOBAL_KEY, *provider_ciphertexts(env.catalog)]
    for output in outputs:
        assert_no_secret(output, forbidden)


def test_agent_tool_outputs_never_contain_personal_credentials(environment) -> None:
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart
    from pydantic_ai.models.function import FunctionModel

    env = environment()
    set_policy(env, company_limit=1000)
    create_provider(env.ada, scope="personal", name="Ada personal", api_key=ADA_KEY)
    create_provider(env.ugo, scope="personal", name="Ugo personal", api_key=UGO_KEY)

    calls = [
        [ToolCallPart("list_system_providers", {})],
        [ToolCallPart("get_system_configuration", {})],
        [TextPart("no provider secrets here")],
    ]
    conversations: list[str] = []

    def scripted(messages: Any, info: Any) -> ModelResponse:
        conversations.append(str(messages))
        returns = [
            part
            for message in messages
            for part in message.parts
            if isinstance(part, ToolReturnPart)
        ]
        return ModelResponse(parts=list(calls[min(len(returns), len(calls) - 1)]))

    # Only the superadmin may read system settings; the point of the check is
    # that even that privileged agent surface exposes no key material.
    use_model(env.superadmin.client, FunctionModel(scripted))
    response = chat(env.superadmin.client, env.superadmin.headers, message="que proveedores hay")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["message"] == "no provider secrets here"
    assert [action["tool"] for action in payload["actions"]] == [
        "list_system_providers",
        "get_system_configuration",
    ]
    forbidden = [ADA_KEY, UGO_KEY, GLOBAL_KEY, *provider_ciphertexts(env.catalog)]
    assert_no_secret(payload, forbidden)
    assert len(conversations) == 3
    for conversation in conversations:
        assert_no_secret(conversation, forbidden)


# ------------------------------- 6. rotation, broken ring and backup manifests
def test_rotation_keeps_both_personal_providers_working(environment, monkeypatch, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    broker = start_broker(accountable_script)
    try:
        env = environment(ai_broker_url=broker.url)
        monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", True)
        seen: dict[str, Any] = {}

        def upstream(request: httpx.Request) -> httpx.Response:
            record_authorization(request, seen)
            return chat_completions(json.loads(request.content)["model"])

        http_client = use_admin_runtime(env, upstream)
        try:
            set_policy(env, company_limit=1000)
            ada = create_provider(
                env.ada,
                scope="personal",
                name="Ada personal",
                models=(PERSONAL_MODEL,),
                api_key=ADA_KEY,
            )
            ugo = create_provider(
                env.ugo,
                scope="personal",
                name="Ugo personal",
                models=(PERSONAL_MODEL,),
                api_key=UGO_KEY,
            )
            before = provider_ciphertexts(env.catalog)
            for person, provider in ((env.ada, ada), (env.ugo, ugo)):
                assert provider_status(person, provider["id"])["credentialStatus"] == "primary"

            env.settings.ai_credential_keys = SecretStr(f"{KEY_NEW},{KEY_OLD}")
            for person, provider in ((env.ada, ada), (env.ugo, ugo)):
                assert provider_status(person, provider["id"])["credentialStatus"] == "older"

            with env.catalog.session() as session:
                rotated = rotate(session, env.settings)
            assert rotated["status"] == "ok"
            assert rotated["rotated"]["providers"] == 2
            assert rotated["pendingRotation"]["providers"] == 2
            assert rotated["providers"]["personal"] == {
                "total": 2,
                "primary": 2,
                "older": 0,
                "unreadable": 0,
            }
            assert rotated["unreadableRows"] == []
            assert provider_ciphertexts(env.catalog) != before

            for person, provider in ((env.ada, ada), (env.ugo, ugo)):
                assert provider_status(person, provider["id"])["credentialStatus"] == "primary"

            ada_session = start_session(env.ada, ada["id"], PERSONAL_MODEL)
            turn_reply(_send(env.ada.client, env.ada.headers, ada_session["id"]))
            ugo_session = start_session(env.ugo, ugo["id"], PERSONAL_MODEL)
            turn_reply(_send(env.ugo.client, env.ugo.headers, ugo_session["id"]))

            # The admin turn runs in-process (MockTransport upstream); the
            # ordinary user turn runs through the isolated broker. Each path
            # receives only its own owner's decrypted key.
            assert seen["models"] == [PERSONAL_MODEL]
            assert seen["authorizations"] == [f"Bearer {ADA_KEY}"]
            assert [start["provider"]["apiKey"] for start in broker.starts] == [UGO_KEY]
            assert (
                _usage_funding(env.ada.client, env.ada.headers)["personal"]["consumedTokens"] == 5
            )
            assert (
                _usage_funding(env.ugo.client, env.ugo.headers)["personal"]["consumedTokens"] == 6
            )
            forbidden = forbidden_strings(env)
            assert_no_secret(_usage_funding(env.ugo.client, env.ugo.headers), forbidden)
            assert_no_secret(caplog.text, forbidden)
        finally:
            asyncio.run(http_client.aclose())
        assert broker.errors == []
    finally:
        broker.close()


def test_provider_with_unreadable_key_is_reported_and_never_crashes(
    environment, monkeypatch
) -> None:
    env = environment()
    set_policy(env, company_limit=1000)
    ada = create_provider(env.ada, scope="personal", name="Ada personal", api_key=ADA_KEY)
    ciphertext = provider_ciphertexts(env.catalog)

    async def _must_not_probe(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("an unreadable credential must not be sent over the network")

    monkeypatch.setattr("itsm.agent_integrations.service.discover_provider_models", _must_not_probe)
    env.settings.ai_credential_keys = SecretStr(KEY_FOREIGN)

    unreadable = provider_status(env.ada, ada["id"])
    assert unreadable["credentialStatus"] == "unreadable"
    assert unreadable["credentialConfigured"] is True
    assert_no_secret(unreadable, [ADA_KEY])

    check = env.ada.post(f"{API}/agent/providers/{ada['id']}/check")
    assert check.status_code == 200, check.text
    assert check.json()["ok"] is False
    assert check.json()["code"] == "credential_unavailable"
    assert set(check.json()) == {"ok", "code", "checkedAt", "provider"}
    assert check.json()["provider"]["id"] == ada["id"]
    assert check.json()["provider"]["credentialStatus"] == "unreadable"
    assert_no_secret(check.json(), [ADA_KEY, KEY_OLD, KEY_FOREIGN, *ciphertext])

    # A turn fails closed before any stream or upstream call starts, and the
    # refusal carries no key material.
    session = start_session(env.ada, ada["id"], PERSONAL_MODEL)
    failed = post_message(env.ada, session["id"])
    assert failed.status_code == 503, failed.text
    error = failed.json()["error"]
    assert error["code"] == "unavailable"
    assert_no_secret(error, [ADA_KEY, *ciphertext])
    funding = _usage_funding(env.ada.client, env.ada.headers)
    assert funding["personal"]["consumedTokens"] == 0
    assert funding["personal"]["reservedTokens"] == 0
    assert funding["company"]["consumedTokens"] == 0
    assert funding["company"]["reservedTokens"] == 0

    env.settings.ai_credential_keys = SecretStr(KEY_OLD)
    assert provider_status(env.ada, ada["id"])["credentialStatus"] == "primary"


def test_backup_manifest_records_fingerprints_and_never_keys(environment, tmp_path: Path) -> None:
    from tests.test_ops_sqlite import payload, run_ops

    env = environment()
    ada = create_provider(env.ada, scope="personal", name="Ada personal", api_key=ADA_KEY)
    create_provider(env.ugo, scope="personal", name="Ugo personal", api_key=UGO_KEY)
    result = run_ops(
        ["backup"],
        env.settings,
        tmp_path / "backups",
        extra_env={"ITSM_AI_CREDENTIAL_KEYS": KEY_OLD},
    )
    assert result.returncode == 0, result.stderr
    body = payload(result)
    manifest_path = Path(body["path"]) / "manifest.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["aiCredentialKeyFingerprints"] == [credential_fingerprint(KEY_OLD)]
    forbidden = [KEY_OLD, ADA_KEY, UGO_KEY, *provider_ciphertexts(env.catalog)]
    assert_no_secret(manifest, forbidden)
    assert_no_secret(manifest_path.read_text(encoding="utf-8"), forbidden)
    assert ada["credentialStatus"] == "primary"


# ------------------------------- 7. managed engine path keeps the same proof
@pytest.mark.usefixtures("managed_client")
def test_managed_engine_switching_keeps_attribution_and_disclosure(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog, client, settings = request.getfixturevalue("managed_client")
    seen: list[str | None] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("authorization"))
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-managed",
                "object": "chat.completion",
                "created": 0,
                "model": "model-a",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "managed reply"},
                    }
                ],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            },
        )

    admin, instance, _service, _leases = _managed_setup(
        catalog, client, settings, monkeypatch, upstream
    )
    personal = _personal_provider(client, admin)
    session = client.post(
        f"{API}/agent/sessions",
        headers=admin,
        json={"instanceId": instance["id"], "model": "model-a"},
    )
    assert session.status_code == 201, session.text
    session_id = session.json()["id"]
    _send(client, admin, session_id)

    switched = client.patch(
        f"{API}/agent/sessions/{session_id}",
        headers=admin,
        json={"providerId": personal["id"], "model": "personal-a"},
    )
    assert switched.status_code == 200, switched.text
    _send(client, admin, session_id)
    back = client.patch(
        f"{API}/agent/sessions/{session_id}",
        headers=admin,
        json={"providerId": None, "model": "model-a"},
    )
    assert back.status_code == 200, back.text
    _send(client, admin, session_id)

    funding = _usage_funding(client, admin)
    assert funding["company"]["consumedTokens"] == 10
    assert funding["personal"]["consumedTokens"] == 5
    assert all(value is not None for value in seen)

    managed_key = "sk-personal-owner-only"
    assert managed_key not in json.dumps(funding)
    assert managed_key not in json.dumps(switched.json())
    assert managed_key not in json.dumps(client.get(f"{API}/agent/providers", headers=admin).json())

    other = _second_owner(catalog, client, settings, "other.owner")
    assert personal["id"] not in {
        item["id"] for item in client.get(f"{API}/agent/providers", headers=other).json()["items"]
    }
    foreign = client.patch(
        f"{API}/agent/sessions/{session_id}",
        headers=other,
        json={"providerId": personal["id"], "model": "personal-a"},
    )
    unknown = client.patch(
        f"{API}/agent/sessions/{session_id}",
        headers=other,
        json={"providerId": MISSING_ID, "model": "personal-a"},
    )
    assert foreign.status_code == unknown.status_code == 404
    assert foreign.json() == unknown.json()
