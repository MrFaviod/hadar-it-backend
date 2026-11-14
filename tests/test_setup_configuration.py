"""Assisted configuration and the verification gate, reusing domain services.

The wizard starts configuration once the first owner exists, previews a change,
applies it only on an explicit human confirmation, reads the effective value
back through the owning service and records a sanitized receipt. ``verify``
advances to ``verifying`` only when every required item is green; postponable
sections stay visibly pending and a missing production backup can only be
accepted as a recorded risk, never as a success.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.setup.api import create_setup_app
from itsm.setup.store import SetupStore
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session
from tests.conftest import running_worker

ORIGIN = "http://testserver"
COOKIE_NAME = "itsm_setup_session"
STATUS_PATH = "/api/setup/v1/status"
CLAIM_PATH = "/api/setup/v1/claim"
STORAGE_PATH = "/api/setup/v1/storage"
OWNER_PATH = "/api/setup/v1/owner"
CONFIGURATION_PATH = "/api/setup/v1/configuration"
VERIFY_PATH = "/api/setup/v1/verify"
TEST_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
API_KEY = "sk-fixture-0000000000000000"
PROBE_MODEL = "probe-model"
OWNER_PASSWORD = "correct-horse-battery-staple"
OWNER_USERNAME = "ada"
OWNER_NAME = "Ada Lovelace"


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 13, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


class ProviderFixture:
    """One OpenAI-compatible provider with a recorded request log."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict[str, str], bytes]] = []
        self.port = 0

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def chat_requests(self) -> list[dict[str, Any]]:
        return [
            json.loads(raw)
            for method, path, _headers, raw in self.requests
            if method == "POST" and path.rstrip("/") == "/v1/chat/completions"
        ]

    def authorization_headers(self) -> list[str]:
        return [
            next(
                (value for name, value in headers.items() if name.lower() == "authorization"),
                "",
            )
            for _method, _path, headers, _raw in self.requests
        ]


class _ProviderHandler(BaseHTTPRequestHandler):
    server_version = "SetupProviderFixture/1.0"

    def log_message(self, *args: object) -> None:
        return

    @property
    def fixture(self) -> ProviderFixture:
        return self.server.fixture  # type: ignore[attr-defined]

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.fixture.requests.append(("GET", self.path, dict(self.headers), b""))
        if self.path.rstrip("/") == "/v1/models":
            self._send(
                200,
                {
                    "object": "list",
                    "data": [{"id": PROBE_MODEL, "object": "model", "owned_by": "fixture"}],
                },
            )
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        self.fixture.requests.append(("POST", self.path, dict(self.headers), raw))
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._send(404, {"error": "not_found"})
            return
        body = json.loads(raw or b"{}")
        model = str(body.get("model") or PROBE_MODEL)
        messages = body.get("messages") or []
        answered = any(isinstance(item, dict) and item.get("role") == "tool" for item in messages)
        wants_tools = bool(body.get("tools"))
        if wants_tools and not answered:
            self._send(200, _tool_call_completion(model))
            return
        self._send(200, _text_completion(model))


def _tool_call_completion(model: str) -> dict[str, Any]:
    return {
        "id": "chatcmpl-probe",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_probe",
                            "type": "function",
                            "function": {"name": "get_setup_status", "arguments": "{}"},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13},
    }


def _text_completion(model: str) -> dict[str, Any]:
    return {
        "id": "chatcmpl-final",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 11, "completion_tokens": 6, "total_tokens": 17},
    }


class _FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


@pytest.fixture
def provider() -> Iterator[ProviderFixture]:
    fixture = ProviderFixture()
    server = _FixtureServer(("127.0.0.1", 0), _ProviderHandler)
    server.fixture = fixture  # type: ignore[attr-defined]
    fixture.port = server.server_address[1]
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield fixture
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    return tmp_path / "private" / "setup-state"


@pytest.fixture
def installation_path(tmp_path: Path) -> Path:
    directory = tmp_path / "installation"
    directory.mkdir(mode=0o700)
    return directory / "installation.json"


@pytest.fixture(autouse=True)
def setup_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state_dir: Path,
    installation_path: Path,
) -> None:
    monkeypatch.setenv("ITSM_SETUP_STATE_DIR", str(state_dir))
    monkeypatch.setenv("RELEASE_MODE", "dev")
    monkeypatch.setenv("ITSM_AUTH_COOKIE_SECURE", "false")
    monkeypatch.setenv("ITSM_AUTH_ORIGIN", ORIGIN)
    monkeypatch.setenv("ITSM_INSTALLATION_CONFIG", str(installation_path))
    monkeypatch.setenv("ITSM_AI_CREDENTIAL_KEYS", TEST_KEY)
    monkeypatch.setenv("ITSM_AI_PERSONAL_PRIVATE_ENDPOINTS", "127.0.0.1/32")
    monkeypatch.setenv("ITSM_ATTACHMENT_STORAGE_PATH", str(tmp_path / "attachments"))
    monkeypatch.setenv("ITSM_TASK_SQLITE_PATH", str(tmp_path / "tasks" / "huey.db"))
    for name in (
        "ITSM_SETUP_ALLOWED_ORIGINS",
        "ITSM_DATABASE_URL",
        "ITSM_AI_CREDENTIAL_KEY",
        "ITSM_DEV_ADMIN_PASSWORD",
        "ITSM_AGENT_MODEL",
        "ITSM_AGENT_OPENAI_BASE_URL",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ITSM_BACKUP_STATUS_PATH",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def store(state_dir: Path, clock: FakeClock) -> SetupStore:
    instance = SetupStore(state_dir, clock=clock)
    instance.ensure_ready()
    return instance


@pytest.fixture
def app(state_dir: Path, clock: FakeClock):
    return create_setup_app(state_dir=state_dir, clock=clock)


def claim_session(client: TestClient, store: SetupStore, *, origin: str = ORIGIN) -> str:
    credential = store.enable_claim()
    response = client.post(CLAIM_PATH, json={"credential": credential}, headers={"Origin": origin})
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def post(
    client: TestClient,
    path: str,
    payload: dict[str, Any],
    csrf: str,
    *,
    cookie: str | None = None,
    origin: str = ORIGIN,
):
    headers = {"Origin": origin, "X-CSRF-Token": csrf}
    cookies = {COOKIE_NAME: cookie} if cookie else None
    return client.post(path, json=payload, headers=headers, cookies=cookies)


def owner_payload() -> dict[str, Any]:
    return {
        "username": OWNER_USERNAME,
        "display_name": OWNER_NAME,
        "email": "ada@example.com",
        "password": OWNER_PASSWORD,
    }


def configure_early_ai(
    client: TestClient, csrf: str, provider: ProviderFixture, *, origin: str = ORIGIN
) -> None:
    response = post(
        client,
        "/api/setup/v1/ai",
        {"base_url": provider.base_url, "model": PROBE_MODEL, "api_key": API_KEY},
        csrf,
        origin=origin,
    )
    assert response.status_code == 200, response.text


def reach_owner_ready(
    client: TestClient,
    store: SetupStore,
    tmp_path: Path,
    *,
    provider: ProviderFixture | None = None,
    database_name: str = "app.db",
    origin: str = ORIGIN,
) -> tuple[str, str]:
    csrf = claim_session(client, store, origin=origin)
    if provider is None:
        assert post(client, "/api/setup/v1/ai/defer", {}, csrf, origin=origin).status_code == 200
    else:
        configure_early_ai(client, csrf, provider, origin=origin)
    database_url = f"sqlite:///{tmp_path / database_name}"
    response = post(client, STORAGE_PATH, {"database_url": database_url}, csrf, origin=origin)
    assert response.status_code == 200, response.text
    response = post(client, OWNER_PATH, owner_payload(), csrf, origin=origin)
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "owner_ready"
    return csrf, database_url


def start_configuration(client: TestClient, csrf: str, *, origin: str = ORIGIN):
    return post(client, CONFIGURATION_PATH, {}, csrf, origin=origin)


def apply_section(
    client: TestClient,
    csrf: str,
    section: str,
    values: dict[str, Any],
    *,
    action: str = "apply",
    confirm: bool = True,
    origin: str = ORIGIN,
):
    return post(
        client,
        f"{CONFIGURATION_PATH}/{section}/apply",
        {"values": values, "action": action, "confirm": confirm},
        csrf,
        origin=origin,
    )


@contextmanager
def worker(database_url: str, *, origin: str = ORIGIN) -> Iterator[None]:
    """Run one real consumer so the setup ping is observed, not assumed."""

    task_path = Path(os.environ["ITSM_TASK_SQLITE_PATH"])
    task_path.parent.mkdir(parents=True, exist_ok=True)
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=database_url,
        task_sqlite_path=os.environ["ITSM_TASK_SQLITE_PATH"],
        attachment_storage_path=os.environ["ITSM_ATTACHMENT_STORAGE_PATH"],
        auth_origin=origin,
        auth_cookie_secure=origin.startswith("https"),
    )
    with running_worker(settings):
        yield


def public_state(state_dir: Path) -> dict[str, Any]:
    return json.loads((state_dir / "state.json").read_text(encoding="utf-8"))


def journal_text(state_dir: Path) -> str:
    path = state_dir / "journal.jsonl"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def section_body(response) -> dict[str, Any]:
    assert response.status_code in {200, 201}, response.text
    return response.json()


def checklist_by_id(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in body["checklist"]}


# ------------------------------------------------------------------ lifecycle
def test_configuration_requires_owner_ready_and_is_idempotent(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        assert post(client, "/api/setup/v1/ai/defer", {}, csrf).status_code == 200
        assert post(client, CONFIGURATION_PATH, {}, csrf).status_code == 409
        database_url = f"sqlite:///{tmp_path / 'app.db'}"
        assert post(client, STORAGE_PATH, {"database_url": database_url}, csrf).status_code == 200
        assert post(client, OWNER_PATH, owner_payload(), csrf).status_code == 200
        assert post(client, VERIFY_PATH, {}, csrf).status_code == 409
        first = start_configuration(client, csrf)
        assert first.status_code == 200, first.text
        assert first.json()["state"] == "configuring"
        again = start_configuration(client, csrf)
        assert again.status_code == 200, again.text
        assert again.json()["state"] == "configuring"
        assert public_state(store.state_dir)["state"] == "configuring"


def test_configuration_reads_require_a_claimed_setup_session(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, _database_url = reach_owner_ready(client, store, tmp_path)
        assert start_configuration(client, csrf).status_code == 200
        assert client.get(CONFIGURATION_PATH).status_code == 200

        anonymous = TestClient(app)
        try:
            overview = anonymous.get(CONFIGURATION_PATH)
            section = anonymous.get(f"{CONFIGURATION_PATH}/appearance")
        finally:
            anonymous.close()

    assert overview.status_code == 401
    assert overview.json()["error"] == "authentication_required"
    assert section.status_code == 401


# ----------------------------------------------------------------- appearance
def test_appearance_preview_does_not_write_and_apply_reads_back(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, database_url = reach_owner_ready(client, store, tmp_path)
        assert start_configuration(client, csrf).status_code == 200

        preview = post(
            client, f"{CONFIGURATION_PATH}/appearance", {"values": {"preset": "forest"}}, csrf
        )
        body = section_body(preview)
        assert body["status"] == "preview"
        assert body["proposed"]["preset"] == "forest"
        assert body["changes"] == [{"field": "preset", "from": "generic", "to": "forest"}]
        assert appearance_rows(database_url) == []

        applied = apply_section(client, csrf, "appearance", {"preset": "blue"})
        body = section_body(applied)
        assert body["status"] == "passed"
        assert body["receipt"]["active_id"] == "blue"
        assert body["receipt"]["source"] == "apply_preset"

        state = appearance_rows(database_url)
        assert len(state) == 1
        assert state[0].active_id == "blue"
        assert state[0].active["branding"]["appName"].startswith("Hadar IT")

        read = client.get(f"{CONFIGURATION_PATH}/appearance")
        assert read.status_code == 200
        section = read.json()
        assert section["status"] == "passed"
        assert section["current"]["preset"] == "blue"

    journal = journal_text(store.state_dir)
    assert "configure-appearance" in journal
    assert API_KEY not in journal and OWNER_PASSWORD not in journal


def test_apply_requires_explicit_confirmation(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, database_url = reach_owner_ready(client, store, tmp_path)
        assert start_configuration(client, csrf).status_code == 200

        refused = apply_section(client, csrf, "appearance", {"preset": "blue"}, confirm=False)
        assert refused.status_code == 422
        assert refused.json()["error"] == "confirmation_required"
        assert appearance_rows(database_url) == []


def test_apply_without_permission_is_refused_and_writes_nothing(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, database_url = reach_owner_ready(client, store, tmp_path)
        assert start_configuration(client, csrf).status_code == 200
        revoke_permission(database_url, "config", "general")

        refused = apply_section(client, csrf, "appearance", {"preset": "blue"})
        assert refused.status_code == 403, refused.text
        assert refused.json()["error"] == "permission_denied"
        assert appearance_rows(database_url) == []

        section = client.get(f"{CONFIGURATION_PATH}/appearance").json()
        assert section["status"] != "passed"


# ------------------------------------------------------------------------ agent
def test_agent_requires_a_provider_row_credential_and_tool_probe(
    app, store, tmp_path: Path, provider: ProviderFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
    monkeypatch.setenv("ITSM_AGENT_OPENAI_BASE_URL", provider.base_url)
    with TestClient(app) as client:
        csrf, database_url = reach_owner_ready(client, store, tmp_path, provider=provider)
        assert start_configuration(client, csrf).status_code == 200

        applied = apply_section(client, csrf, "agent", {"provider": "openai", "model": PROBE_MODEL})
        body = section_body(applied)
        assert body["status"] == "passed", body
        assert body["receipt"]["provider"] == "openai"
        assert body["receipt"]["model"] == PROBE_MODEL
        assert body["receipt"]["tool"] == "get_setup_status"
        assert body["receipt"]["credential_configured"] is True

        rows = provider_rows(database_url)
        assert len(rows) == 1
        assert rows[0].provider == "openai"
        assert rows[0].model == PROBE_MODEL

        assert any(request.get("tools") for request in provider.chat_requests())
        assert API_KEY not in applied.text
        assert "OPENAI_API_KEY" not in applied.text

        checklist = client.get(CONFIGURATION_PATH).json()
        assert checklist_by_id(checklist)["ai_explicit"]["status"] == "passed"


def test_agent_probe_prefers_the_verified_setup_provider_over_ambient_env(
    app, store, tmp_path: Path, provider: ProviderFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ambient OPENAI_BASE_URL must never replace the provider the operator entered."""

    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
    monkeypatch.delenv("ITSM_AGENT_OPENAI_BASE_URL", raising=False)
    with TestClient(app) as client:
        csrf, _database_url = reach_owner_ready(client, store, tmp_path, provider=provider)
        assert start_configuration(client, csrf).status_code == 200

        applied = apply_section(client, csrf, "agent", {"provider": "openai", "model": PROBE_MODEL})
        body = section_body(applied)
        assert body["status"] == "passed", body
        assert body["receipt"]["capability"] == "verified"
        assert body["receipt"]["tool"] == "get_setup_status"
        assert any(request.get("tools") for request in provider.chat_requests())


def test_agent_probe_fails_closed_without_an_operator_destination(
    app, store, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no verified provider and no installation URL the probe makes no request."""

    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
    monkeypatch.delenv("ITSM_AGENT_OPENAI_BASE_URL", raising=False)
    with TestClient(app) as client:
        csrf, _database_url = reach_owner_ready(client, store, tmp_path)
        assert start_configuration(client, csrf).status_code == 200

        applied = apply_section(client, csrf, "agent", {"provider": "openai", "model": PROBE_MODEL})
        body = section_body(applied)
        assert body["status"] == "pending"
        assert body["receipt"]["latency_ms"] is None
        assert body["receipt"]["capability"] == "unverified"


def test_agent_stays_pending_when_ai_was_deferred(
    app, store, tmp_path: Path, provider: ProviderFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
    monkeypatch.setenv("ITSM_AGENT_OPENAI_BASE_URL", provider.base_url)
    with TestClient(app) as client:
        csrf, database_url = reach_owner_ready(client, store, tmp_path)
        assert start_configuration(client, csrf).status_code == 200

        applied = apply_section(client, csrf, "agent", {"provider": "openai", "model": PROBE_MODEL})
        body = section_body(applied)
        assert body["status"] == "pending"
        assert body["receipt"]["reason"] == "ai_deferred"
        assert body["receipt"]["capability"] == "verified"
        assert len(provider_rows(database_url)) == 1

        checklist = client.get(CONFIGURATION_PATH).json()
        items = checklist_by_id(checklist)
        assert items["ai_explicit"]["status"] == "pending"
        assert items["ai_explicit"]["required"] is True


# ---------------------------------------------------------------- postponable
def test_postponed_sections_are_visible_pending_and_never_green(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, _database_url = reach_owner_ready(client, store, tmp_path)
        assert start_configuration(client, csrf).status_code == 200

        for section in ("notifications", "monitoring"):
            response = apply_section(client, csrf, section, {}, action="postpone")
            body = section_body(response)
            assert body["status"] == "postponed"
            assert body["required"] is False
            read = client.get(f"{CONFIGURATION_PATH}/{section}").json()
            assert read["status"] == "postponed"

        checklist = client.get(CONFIGURATION_PATH).json()
        items = checklist_by_id(checklist)
        assert items["smtp"]["status"] == "postponed"
        assert items["monitoring"]["status"] == "postponed"
        for postponed in ("smtp", "monitoring"):
            assert items[postponed]["required"] is False
            assert items[postponed]["postponable"] is True
            assert items[postponed]["status"] != "passed"


# ------------------------------------------------------------------- verify
def prepare_green_configuration(
    client: TestClient, csrf: str, database_url: str, *, origin: str = ORIGIN
) -> None:
    assert start_configuration(client, csrf, origin=origin).status_code == 200
    appearance = apply_section(client, csrf, "appearance", {"preset": "blue"}, origin=origin)
    assert appearance.status_code == 200, appearance.text
    agent = apply_section(
        client, csrf, "agent", {"provider": "openai", "model": PROBE_MODEL}, origin=origin
    )
    assert agent.status_code == 200, agent.text
    for section in ("notifications", "monitoring"):
        postponed = apply_section(client, csrf, section, {}, action="postpone", origin=origin)
        assert postponed.status_code == 200, postponed.text


def test_verify_blocks_while_required_items_are_missing(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, _database_url = reach_owner_ready(client, store, tmp_path)
        assert start_configuration(client, csrf).status_code == 200
        assert apply_section(client, csrf, "appearance", {"preset": "blue"}).status_code == 200

        blocked = post(client, VERIFY_PATH, {}, csrf)
        assert blocked.status_code == 409, blocked.text
        body = blocked.json()
        assert body["error"] == "verification_blocked"
        items = checklist_by_id(body)
        blocking = {item["id"] for item in body["checklist"] if item["blocking"]}
        assert {"ai_explicit", "worker_ready"} <= blocking
        assert items["appearance_decided"]["status"] == "passed"
        assert public_state(store.state_dir)["state"] == "configuring"
        assert post(client, VERIFY_PATH, {}, csrf).status_code == 409


def test_verify_passes_with_every_required_item_green(
    app, store, tmp_path: Path, provider: ProviderFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
    monkeypatch.setenv("ITSM_AGENT_OPENAI_BASE_URL", provider.base_url)
    with TestClient(app) as client:
        csrf, database_url = reach_owner_ready(client, store, tmp_path, provider=provider)
        prepare_green_configuration(client, csrf, database_url)

        with worker(database_url):
            response = post(client, VERIFY_PATH, {}, csrf)
        body = section_body(response)
        assert body["state"] == "verifying"
        items = checklist_by_id(body)
        assert items["ai_explicit"]["status"] == "passed"
        assert items["appearance_decided"]["status"] == "passed"
        assert items["worker_ready"]["status"] == "passed"
        assert items["storage_ready"]["status"] == "passed"
        for item in body["checklist"]:
            if item["required"]:
                assert item["status"] == "passed", item
                assert item["evidence"], item
        assert items["smtp"]["status"] == "postponed"
        assert items["monitoring"]["status"] == "postponed"
        assert items["external_search"]["status"] == "unavailable"
        assert item_status(body, "setup_enabled") == "passed"
        assert public_state(store.state_dir)["state"] == "verifying"

        replay = post(client, VERIFY_PATH, {}, csrf)
        assert replay.status_code == 200, replay.text
        assert replay.json()["state"] == "verifying"

    assert "verify" in journal_text(store.state_dir)


def test_prod_backup_must_be_declared_or_accepted_as_risk(
    store, tmp_path: Path, provider: ProviderFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RELEASE_MODE", "prod")
    monkeypatch.setenv("ITSM_AUTH_ORIGIN", "https://assets.example.com")
    monkeypatch.setenv("ITSM_AUTH_COOKIE_SECURE", "true")
    monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
    monkeypatch.setenv("ITSM_AGENT_OPENAI_BASE_URL", provider.base_url)
    origin = "https://assets.example.com"
    prod_store = SetupStore(store.state_dir, release_mode="prod")
    prod_app = create_setup_app(state_dir=store.state_dir)
    if True:
        with TestClient(prod_app, base_url="https://testserver") as client:
            csrf, database_url = reach_owner_ready(
                client, prod_store, tmp_path, provider=provider, origin=origin
            )
            prepare_green_configuration(client, csrf, database_url, origin=origin)

            blocked = post(client, VERIFY_PATH, {}, csrf, origin=origin)
            assert blocked.status_code == 409, blocked.text
            items = checklist_by_id(blocked.json())
            assert items["backup_policy_declared"]["required"] is True
            assert items["backup_policy_declared"]["status"] == "pending"
            assert public_state(store.state_dir)["state"] == "configuring"

            risk = apply_section(
                client,
                csrf,
                "operational",
                {"item": "backup_policy_declared", "reason": "restore drill scheduled"},
                action="accept_risk",
                origin=origin,
            )
            body = section_body(risk)
            assert body["status"] == "risk"

            with worker(database_url, origin=origin):
                verified = post(client, VERIFY_PATH, {}, csrf, origin=origin)
            body = section_body(verified)
            items = checklist_by_id(body)
            assert body["state"] == "verifying"
            assert items["backup_policy_declared"]["status"] == "risk"
            assert items["backup_policy_declared"]["status"] != "passed"
            assert items["backup_policy_declared"]["acceptedRisk"] is True
            assert body["acceptedRisk"] == ["backup_policy_declared"]


def test_dev_backup_risk_is_refused_before_it_reaches_the_store(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, _ = reach_owner_ready(client, store, tmp_path)
        started = start_configuration(client, csrf)
        assert started.status_code == 200, started.text

        refused = apply_section(
            client,
            csrf,
            "operational",
            {"item": "backup_policy_declared", "reason": "restore drill scheduled"},
            action="accept_risk",
        )
        assert refused.status_code == 422, refused.text
        assert refused.json()["error"] == "configuration_invalid"
        assert public_state(store.state_dir)["state"] == "configuring"


# ------------------------------------------------------------------ assistant
def test_assistant_can_only_propose_configuration() -> None:
    from itsm.setup import assistant

    names = set(assistant.ASSISTANT_TOOLS)
    assert "get_setup_checklist" in names
    assert "propose_configuration" in names
    assert not any("apply" in name or "confirm" in name for name in names)

    proposal = assistant.preview_proposal(
        "appearance", {"preset": "blue"}, mode="dev", state="configuring"
    )
    assert proposal["section"] == "appearance"
    assert proposal["proposed"]["preset"] == "blue"
    assert proposal["preview_only"] is True


def test_no_assistant_route_can_apply(app) -> None:
    paths = {getattr(route, "path", "") for route in app.routes}
    assert not [path for path in paths if "assistant" in path and "apply" in path]


# -------------------------------------------------------------------- helpers
def appearance_rows(database_url: str) -> list[Any]:
    from itsm.appearance.models import AppearanceState

    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            return list(session.scalars(select(AppearanceState)))
    finally:
        engine.dispose()


def provider_rows(database_url: str) -> list[Any]:
    from itsm.system.models import SystemProviderSettings

    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            return list(session.scalars(select(SystemProviderSettings)))
    finally:
        engine.dispose()


def revoke_permission(database_url: str, resource: str, operation: str) -> None:
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            connection.execute(
                text(
                    "delete from identity_role_policies where role_id = 'superadmin' "
                    "and resource = :resource and operation = :operation"
                ),
                {"resource": resource, "operation": operation},
            )
            connection.commit()
    finally:
        engine.dispose()


def item_status(body: dict[str, Any], identifier: str) -> str:
    return checklist_by_id(body)[identifier]["status"]
