"""Early AI provider verification in the database-free setup service.

The provider is a real local HTTP server speaking the OpenAI wire format: the
first completion answers with a ``tool_calls`` payload for ``get_setup_status``
and the second one closes the turn. Nothing here reaches a real provider, and a
fixture is not a provider observation; the tests prove the boundary and the
diagnostics, not that any external model works.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.setup.api import create_setup_app
from itsm.setup.store import SetupStore

ORIGIN = "http://testserver"
COOKIE_NAME = "itsm_setup_session"
STATUS_PATH = "/api/setup/v1/status"
CLAIM_PATH = "/api/setup/v1/claim"
AI_PATH = "/api/setup/v1/ai"
DEFER_PATH = "/api/setup/v1/ai/defer"
ASK_PATH = "/api/setup/v1/assistant/ask"

# 32 zero bytes, a valid Fernet key. The ring is supplied by the operator; the
# setup service never generates one.
TEST_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
API_KEY = "sk-fixture-secret-0123456789"
PROBE_MODEL = "probe-model"


class FakeClock:
    """Controllable UTC clock shared with the setup store."""

    def __init__(self):
        from datetime import UTC, datetime

        self.now = datetime(2026, 1, 13, 12, 0, tzinfo=UTC)

    def __call__(self):
        return self.now


class ProviderFixture:
    """One OpenAI-compatible provider with a recorded request log."""

    def __init__(self) -> None:
        self.mode = "tools"
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
            headers.get("authorization", "")
            for method, _path, headers, _raw in self.requests
        ]


class _ProviderHandler(BaseHTTPRequestHandler):
    server_version = "SetupProviderFixture/1.0"

    def log_message(self, *args: object) -> None:  # noqa: ARG002 - quiet fixture
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

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self.fixture.requests.append(("GET", self.path, dict(self.headers), b""))
        if self.fixture.mode == "deny":
            self._send(401, {"error": "invalid_api_key"})
            return
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

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        self.fixture.requests.append(("POST", self.path, dict(self.headers), raw))
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._send(404, {"error": "not_found"})
            return
        if self.fixture.mode == "deny":
            self._send(401, {"error": "invalid_api_key"})
            return
        body = json.loads(raw or b"{}")
        model = str(body.get("model") or PROBE_MODEL)
        messages = body.get("messages") or []
        answered = any(isinstance(item, dict) and item.get("role") == "tool" for item in messages)
        wants_tools = bool(body.get("tools"))
        if self.fixture.mode != "no_tools" and wants_tools and not answered:
            self._send(200, _tool_call_completion(model))
            return
        self._send(200, _text_completion(model, "The installation is claimed."))


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


def _text_completion(model: str, text: str) -> dict[str, Any]:
    return {
        "id": "chatcmpl-final",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 11, "completion_tokens": 6, "total_tokens": 17},
    }


class _FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> ProviderFixture:
    fixture = ProviderFixture()
    server = _FixtureServer(("127.0.0.1", 0), _ProviderHandler)
    server.fixture = fixture  # type: ignore[attr-defined]
    fixture.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("ITSM_AI_PERSONAL_PRIVATE_ENDPOINTS", "127.0.0.1/32")
    try:
        yield fixture
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    return tmp_path / "private" / "setup-state"


@pytest.fixture(autouse=True)
def setup_environment(monkeypatch: pytest.MonkeyPatch, state_dir: Path) -> None:
    monkeypatch.setenv("ITSM_SETUP_STATE_DIR", str(state_dir))
    monkeypatch.setenv("RELEASE_MODE", "dev")
    monkeypatch.setenv("ITSM_AUTH_COOKIE_SECURE", "false")
    monkeypatch.delenv("ITSM_SETUP_ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("ITSM_AI_PERSONAL_PRIVATE_ENDPOINTS", raising=False)
    monkeypatch.setenv("ITSM_AI_CREDENTIAL_KEYS", TEST_KEY)
    monkeypatch.delenv("ITSM_AI_CREDENTIAL_KEY", raising=False)


@pytest.fixture
def store(state_dir: Path, clock: FakeClock) -> SetupStore:
    instance = SetupStore(state_dir, clock=clock)
    instance.ensure_ready()
    return instance


def build_app(state_dir: Path, clock: FakeClock):
    return create_setup_app(state_dir=state_dir, clock=clock)


def claim(client: TestClient, store: SetupStore) -> str:
    credential = store.enable_claim()
    response = client.post(
        CLAIM_PATH,
        json={"credential": credential},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 200, response.text
    token = response.json()["csrf_token"]
    _ = client.cookies.get(COOKIE_NAME)
    return token


def post(client: TestClient, path: str, payload: dict[str, Any], csrf: str | None):
    headers = {"Origin": ORIGIN}
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    return client.post(path, json=payload, headers=headers)


def configure(client: TestClient, base_url: str, csrf: str, **extra: Any):
    payload = {"base_url": base_url, "model": PROBE_MODEL, "api_key": API_KEY}
    payload.update(extra)
    return post(client, AI_PATH, payload, csrf)


def public_state(state_dir: Path) -> dict[str, Any]:
    return json.loads((state_dir / "state.json").read_text(encoding="utf-8"))


def journal_actions(state_dir: Path) -> list[str]:
    path = state_dir / "journal.jsonl"
    if not path.exists():
        return []
    return [json.loads(line)["action"] for line in path.read_text().splitlines()]


# ------------------------------------------------------------------- success
def test_configure_proves_one_real_tool_call_and_stores_only_ciphertext(
    store: SetupStore,
    state_dir: Path,
    clock: FakeClock,
    provider: ProviderFixture,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        response = configure(client, provider.base_url, csrf)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["state"] == "ai_configured"
        receipt = body["ai"]
        assert receipt["status"] == "configured"
        assert receipt["provider"] == "127.0.0.1"
        assert receipt["model"] == PROBE_MODEL
        assert receipt["tool"] == "get_setup_status"
        assert receipt["input_tokens"] >= 1
        assert receipt["output_tokens"] >= 1
        assert isinstance(receipt["latency_ms"], int)
        assert API_KEY not in response.text

        status = client.get(STATUS_PATH)
        assert status.status_code == 200
        assert status.json()["state"] == "ai_configured"
        assert API_KEY not in status.text

    chats = provider.chat_requests()
    assert len(chats) == 2, provider.requests
    tool_names = [tool["function"]["name"] for tool in chats[0]["tools"]]
    assert "get_setup_status" in tool_names
    assert chats[0]["messages"][0]["role"] == "system"
    assert any(item.get("role") == "tool" for item in chats[1]["messages"])
    assert all(header == f"Bearer {API_KEY}" for header in provider.authorization_headers())

    secrets_text = (state_dir / "secrets.json").read_text(encoding="utf-8")
    state_text = (state_dir / "state.json").read_text(encoding="utf-8")
    journal_text = (state_dir / "journal.jsonl").read_text(encoding="utf-8")
    assert API_KEY not in secrets_text
    assert API_KEY not in state_text
    assert API_KEY not in journal_text
    assert API_KEY not in caplog.text
    assert "gAAAA" in secrets_text
    stored = json.loads(secrets_text)["ai"]
    assert stored["ciphertext"].startswith("gAAAA")
    assert stored["base_url"].startswith("http://127.0.0.1:")
    assert stored["model"] == PROBE_MODEL
    assert stored["scope"] == "personal"
    assert stored["key_fingerprint"]
    assert "ciphertext" not in state_text
    assert "configure-ai" in journal_actions(state_dir)


def test_configured_status_does_not_leak_the_receipt_allowlist(
    store: SetupStore, state_dir: Path, clock: FakeClock, provider: ProviderFixture
) -> None:
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        assert configure(client, provider.base_url, csrf).status_code == 200
        status = client.get(STATUS_PATH).json()
    assert set(status) == {
        "state",
        "mode",
        "release_mode",
        "setup_enabled",
        "claim_available",
        "backend",
        "version",
        "instance_id",
    }


# ------------------------------------------------------------------- failures
def test_provider_down_keeps_the_state_and_reports_unreachable(
    store: SetupStore, state_dir: Path, clock: FakeClock
) -> None:
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        response = configure(client, "http://127.0.0.1:9/v1", csrf)
        assert response.status_code == 502, response.text
        assert response.json() == {"error": "provider_unreachable"}
        status = client.get(STATUS_PATH).json()
        assert status["state"] == "claimed"
    assert public_state(state_dir)["ai"] is None
    assert "configure-ai" not in journal_actions(state_dir)


def test_model_without_tool_calls_is_refused(
    store: SetupStore, state_dir: Path, clock: FakeClock, provider: ProviderFixture
) -> None:
    provider.mode = "no_tools"
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        response = configure(client, provider.base_url, csrf)
        assert response.status_code == 422, response.text
        assert response.json()["error"] in {"tool_not_called", "model_without_tools"}
        assert client.get(STATUS_PATH).json()["state"] == "claimed"
    assert public_state(state_dir)["ai"] is None
    assert len(provider.chat_requests()) >= 1


def test_forbidden_destinations_never_reach_the_network(
    store: SetupStore, state_dir: Path, clock: FakeClock, provider: ProviderFixture
) -> None:
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        for base_url in (
            "http://169.254.169.254/v1",
            "file:///etc/passwd",
            provider.base_url,
        ):
            response = configure(client, base_url, csrf)
            assert response.status_code == 422, (base_url, response.text)
            assert response.json() == {"error": "endpoint_forbidden"}, base_url
        assert client.get(STATUS_PATH).json()["state"] == "claimed"
    assert provider.requests == []


def test_private_destination_requires_the_deployment_allowlist(
    store: SetupStore,
    state_dir: Path,
    clock: FakeClock,
    provider: ProviderFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ITSM_AI_PERSONAL_PRIVATE_ENDPOINTS", raising=False)
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        response = configure(client, provider.base_url, csrf)
        assert response.status_code == 422, response.text
        assert response.json() == {"error": "endpoint_forbidden"}
    assert provider.requests == []


def test_missing_key_ring_blocks_the_form_without_generating_a_key(
    store: SetupStore,
    state_dir: Path,
    clock: FakeClock,
    provider: ProviderFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ITSM_AI_CREDENTIAL_KEYS", raising=False)
    monkeypatch.delenv("ITSM_AI_CREDENTIAL_KEY", raising=False)
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        response = configure(client, provider.base_url, csrf)
        assert response.status_code == 409, response.text
        assert response.json() == {"error": "credential_key_missing"}
        assert client.get(STATUS_PATH).json()["state"] == "claimed"
    secrets_text = (state_dir / "secrets.json").read_text(encoding="utf-8")
    assert "gAAAA" not in secrets_text
    assert provider.requests == []


def test_missing_api_key_is_reported_as_credential_missing(
    store: SetupStore, state_dir: Path, clock: FakeClock, provider: ProviderFixture
) -> None:
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        response = configure(client, provider.base_url, csrf, api_key=None)
        assert response.status_code == 422, response.text
        assert response.json() == {"error": "credential_missing"}
    assert provider.requests == []


def test_upstream_auth_failure_is_sanitized(
    store: SetupStore, state_dir: Path, clock: FakeClock, provider: ProviderFixture
) -> None:
    provider.mode = "deny"
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        response = configure(client, provider.base_url, csrf)
        assert response.status_code == 502, response.text
        assert response.json() == {"error": "auth_failed"}
        assert API_KEY not in response.text
        assert client.get(STATUS_PATH).json()["state"] == "claimed"


# ---------------------------------------------------------------- csrf/origin
def test_ai_mutations_require_origin_and_csrf(
    store: SetupStore, state_dir: Path, clock: FakeClock, provider: ProviderFixture
) -> None:
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        payload = {"base_url": provider.base_url, "model": PROBE_MODEL, "api_key": API_KEY}
        assert client.post(AI_PATH, json=payload).status_code == 403
        no_origin = client.post(AI_PATH, json=payload, headers={"X-CSRF-Token": csrf})
        assert no_origin.status_code == 403
        assert no_origin.json() == {"error": "origin_not_allowed"}
        wrong = client.post(
            AI_PATH,
            json=payload,
            headers={"Origin": ORIGIN, "X-CSRF-Token": "wrong"},
        )
        assert wrong.status_code == 403
        assert wrong.json() == {"error": "csrf_invalid"}
        assert post(client, DEFER_PATH, {}, None).status_code == 403
        assert client.get(STATUS_PATH).json()["state"] == "claimed"
    assert provider.requests == []


# ---------------------------------------------------------------------- defer
def test_defer_records_a_visible_pending_item_and_allows_a_later_retry(
    store: SetupStore, state_dir: Path, clock: FakeClock, provider: ProviderFixture
) -> None:
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        deferred = post(client, DEFER_PATH, {}, csrf)
        assert deferred.status_code == 200, deferred.text
        body = deferred.json()
        assert body["state"] == "ai_deferred"
        assert body["ai"]["status"] == "pending"
        assert body["ai"]["pending"] is True
        assert client.get(STATUS_PATH).json()["state"] == "ai_deferred"

        configured = configure(client, provider.base_url, csrf)
        assert configured.status_code == 200, configured.text
        assert configured.json()["state"] == "ai_configured"
        assert client.get(STATUS_PATH).json()["state"] == "ai_configured"
    actions = journal_actions(state_dir)
    assert "defer-ai" in actions
    assert "configure-ai" in actions
    assert public_state(state_dir)["ai"]["status"] == "configured"


def test_defer_is_refused_outside_claimed(
    store: SetupStore, state_dir: Path, clock: FakeClock, provider: ProviderFixture
) -> None:
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        assert configure(client, provider.base_url, csrf).status_code == 200
        refused = post(client, DEFER_PATH, {}, csrf)
        assert refused.status_code == 409
        assert refused.json() == {"error": "state_refused"}
        assert client.get(STATUS_PATH).json()["state"] == "ai_configured"


# ------------------------------------------------------------------ assistant
def test_assistant_answers_from_read_only_tools_when_configured(
    store: SetupStore, state_dir: Path, clock: FakeClock, provider: ProviderFixture
) -> None:
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        assert configure(client, provider.base_url, csrf).status_code == 200
        response = post(
            client,
            ASK_PATH,
            {"question": "What does the setup still need?"},
            csrf,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["answer"]
        assert "get_setup_status" in body["tools"]
        assert body["latency_ms"] >= 0
        assert API_KEY not in response.text


def test_assistant_is_refused_before_the_provider_is_configured(
    store: SetupStore, state_dir: Path, clock: FakeClock
) -> None:
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        csrf = claim(client, store)
        response = post(client, ASK_PATH, {"question": "status?"}, csrf)
        assert response.status_code == 409
        assert response.json() == {"error": "ai_not_configured"}
