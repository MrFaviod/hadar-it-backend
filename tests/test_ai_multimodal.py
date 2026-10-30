"""Multimodal chat: owner-scoped attachments, capability gating and engine parts.

Every check goes through the public HTTP surface or the documented engine
boundary. No test reaches a provider: the Pydantic AI path uses a real agent
runtime with a deterministic ``FunctionModel`` and the managed path uses the
gateway service with a mock upstream transport.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pydantic_ai.models
import pytest
from fastapi.testclient import TestClient
from itsm.agent_integrations.service import AgentIntegrationService
from itsm.agents.runtime import AgentRuntime, ChatReply
from itsm.config import Settings
from itsm.main import create_app
from pydantic_ai.messages import BinaryContent, ModelResponse, TextPart
from pydantic_ai.models.function import FunctionModel
from sqlalchemy import select
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import MACHINE_PASSWORD, prepare

API = "/api/v1"


@pytest.fixture(autouse=True)
def no_external_model_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deterministic tests must never reach a provider, even by accident."""

    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40
PDF = b"%PDF-1.7\nchat document\n%%EOF"
CSV = b"codigo,nombre\nSW-1,Switch\n"
MASTER_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="


def png(size: int = 0) -> bytes:
    return PNG + b"\x01" * size


def pdf(size: int = 0) -> bytes:
    return b"%PDF-1.7\n" + b"\x02" * size + b"\n%%EOF"


class FakeRuntime:
    """Stand-in for the Pydantic AI runtime with the public chat envelope."""

    configured = True

    def __init__(self, reply: ChatReply) -> None:
        self.reply = reply
        self.requests: list[Any] = []

    def chat_with_usage(
        self,
        principal: Any,
        request: Any,
        *,
        credential_digest: str | None = None,
        usage: Any = None,
        quota: Any = None,
        token_limit: int | None = None,
        provider_selection: Any = None,
        **options: Any,
    ) -> tuple[ChatReply, Any]:
        self.requests.append(request)
        identifier = quota.before_call(8)
        quota.after_call(
            identifier,
            {"type": "usage", "totalTokens": 5, "precision": "measured", "source": "provider"},
        )
        return self.reply, usage


@pytest.fixture
def app_client(
    settings_factory: Callable[..., Settings], tmp_path: Any
) -> Iterator[tuple[Any, TestClient, Settings]]:
    catalog = prepare(
        settings_factory,
        agent_model="openai:gpt-4o-mini",
        ai_broker_url="ws://127.0.0.1:9/runs",
        ai_broker_token="t" * 48,
        attachment_storage_path=tmp_path / "blobs",
        ai_credential_key=MASTER_KEY,
    )
    client = TestClient(create_app(catalog.settings))
    client.__enter__()
    try:
        yield catalog, client, catalog.settings
    finally:
        client.__exit__(None, None, None)
        catalog.engine.dispose()


def login(
    client: TestClient, settings: Settings, username: str, password: str = ADMIN_PASSWORD
) -> dict[str, str]:
    response = client.post(
        f"{API}/auth/login",
        json={"username": username, "password": password},
        headers={"Origin": settings.auth_origin},
    )
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": str(response.json()["csrfToken"]), "Origin": settings.auth_origin}


def build_service(
    client: TestClient, catalog: Any, *, runtime: Any = None
) -> AgentIntegrationService:
    service = AgentIntegrationService(
        catalog.settings,
        catalog.factory(),
        runtime=runtime,
    )
    client.app.state.agent_integrations = service
    if runtime is not None:
        client.app.state.agent_runtime = runtime
        client.app.state.isolated_runtime = runtime
    return service


def create_session(
    client: TestClient,
    headers: dict[str, str],
    *,
    instance_id: str = "pydantic",
    model: str = "openai:gpt-4o-mini",
    provider_id: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"instanceId": instance_id, "model": model}
    if provider_id is not None:
        payload["providerId"] = provider_id
    created = client.post(f"{API}/agent/sessions", json=payload, headers=headers)
    assert created.status_code == 201, created.text
    return created.json()


def upload(
    client: TestClient,
    headers: dict[str, str],
    session_id: str,
    *,
    filename: str = "foto.png",
    data: bytes = PNG,
    content_type: str = "application/octet-stream",
) -> Any:
    return client.post(
        f"{API}/agent/sessions/{session_id}/attachments",
        params={"filename": filename},
        content=data,
        headers={**headers, "Content-Type": content_type},
    )


def read_sse(response: Any) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in response.iter_lines():
        if not line:
            continue
        assert line.startswith("data: "), line
        events.append(json.loads(line[len("data: ") :]))
    return events


def send(
    client: TestClient,
    headers: dict[str, str],
    session_id: str,
    **body: Any,
) -> tuple[int, list[dict[str, Any]]]:
    with client.stream(
        "POST", f"{API}/agent/sessions/{session_id}/messages", json=body, headers=headers
    ) as response:
        return response.status_code, (
            read_sse(response)
            if response.headers.get("content-type", "").startswith("text/event-stream")
            else []
        )


def stored_blobs(settings: Settings) -> list[str]:
    root = settings.attachment_storage_path
    if not root.exists():
        return []
    return sorted(path.name for path in root.rglob("*") if path.is_file())


# ------------------------------------------------------------- chat attachments
def test_chat_attachment_upload_sniffs_content_and_limits_size(app_client) -> None:
    _catalog, client, settings = app_client
    headers = login(client, settings, ADMIN_USERNAME)
    session = create_session(client, headers)

    image = upload(client, headers, session["id"], filename="foto.png", data=png())
    assert image.status_code == 201, image.text
    body = image.json()
    assert body["filename"] == "foto.png"
    assert body["mediaType"] == "image/png"
    assert body["kind"] == "image"
    assert body["size"] == len(png())
    assert set(body) == {"id", "filename", "mediaType", "kind", "size"}
    assert "data" not in body and "path" not in body and "blobKey" not in body

    document = upload(client, headers, session["id"], filename="informe.pdf", data=pdf())
    assert document.status_code == 201, document.text
    assert document.json()["kind"] == "file"
    assert document.json()["mediaType"] == "application/pdf"

    text = upload(client, headers, session["id"], filename="activos.csv", data=CSV)
    assert text.status_code == 201, text.text
    assert text.json()["kind"] == "text"
    assert text.json()["mediaType"] == "text/csv; charset=utf-8"

    # Same sniffing as asset attachments: bytes decide, the extension must agree.
    hidden_html = upload(
        client,
        headers,
        session["id"],
        filename="pagina.png",
        data=b"<html><script>alert(1)</script></html>",
    )
    assert hidden_html.status_code == 422, hidden_html.text
    assert hidden_html.json()["error"]["code"] == "validation_error"

    svg = upload(
        client,
        headers,
        session["id"],
        filename="logo.svg",
        data=b'<svg xmlns="http://www.w3.org/2000/svg"></svg>',
    )
    assert svg.status_code == 422, svg.text

    undersized = upload(client, headers, session["id"], filename="vacio.png", data=b"")
    assert undersized.status_code == 422, undersized.text

    # Per-file bound comes from the deployment maximum for stored documents.
    settings.attachment_max_bytes = 64
    too_big = upload(client, headers, session["id"], filename="grande.png", data=png(128))
    assert too_big.status_code == 413, too_big.text
    assert too_big.json()["error"]["code"] == "payload_too_large"


def test_chat_attachments_are_owner_scoped_and_bounded_per_message(app_client) -> None:
    catalog, client, settings = app_client
    catalog.add_user("reader-one", "Reader One", "user")
    headers = login(client, settings, ADMIN_USERNAME)
    session = create_session(client, headers)
    attachment = upload(client, headers, session["id"]).json()

    outsider = login(client, settings, "reader-one", MACHINE_PASSWORD)
    assert upload(client, outsider, session["id"]).status_code == 404
    assert (
        client.delete(
            f"{API}/agent/sessions/{session['id']}/attachments/{attachment['id']}",
            headers=outsider,
        ).status_code
        == 404
    )

    own_session = create_session(client, outsider)
    assert upload(client, outsider, own_session["id"], filename="ok.png").status_code == 201

    runtime = FakeRuntime(ChatReply(message="ok"))
    build_service(client, catalog, runtime=runtime)
    foreign = send(
        client,
        outsider,
        own_session["id"],
        message="mirá",
        attachmentIds=[attachment["id"]],
    )
    assert foreign[0] == 404, foreign
    headers = login(client, settings, ADMIN_USERNAME)
    status, events = send(
        client, headers, session["id"], message="mirá", attachmentIds=[attachment["id"]] * 9
    )
    assert status == 422, events
    assert runtime.requests == []


def test_chat_attachments_are_removed_with_the_attachment_or_the_session(app_client) -> None:
    _catalog, client, settings = app_client
    headers = login(client, settings, ADMIN_USERNAME)
    session = create_session(client, headers)
    attachment = upload(client, headers, session["id"]).json()
    assert len(stored_blobs(settings)) == 1

    removed = client.delete(
        f"{API}/agent/sessions/{session['id']}/attachments/{attachment['id']}", headers=headers
    )
    assert removed.status_code == 204, removed.text
    assert stored_blobs(settings) == []

    upload(client, headers, session["id"], filename="dos.png")
    assert len(stored_blobs(settings)) == 1
    deleted = client.delete(f"{API}/agent/sessions/{session['id']}", headers=headers)
    assert deleted.status_code == 204, deleted.text
    assert client.get(f"{API}/agent/sessions/{session['id']}", headers=headers).status_code == 404
    assert stored_blobs(settings) == []


# ------------------------------------------------------------ capability gate
def create_provider(
    client: TestClient,
    headers: dict[str, str],
    capabilities: dict[str, dict[str, bool | None]],
) -> dict[str, Any]:
    response = client.post(
        f"{API}/agent/providers",
        headers=headers,
        json={
            "scope": "global",
            "name": "Personal upstream",
            "baseUrl": "http://127.0.0.1:18081/v1",
            "models": ["model-a"],
            "apiKey": "test-only-upstream-key",
            "modelCapabilities": capabilities,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def reservation_rows(catalog: Any) -> list[Any]:
    from itsm.ai_usage.models import AiUsageReservation

    with catalog.session() as db:
        return list(db.scalars(select(AiUsageReservation)).all())


def run_rows(catalog: Any) -> list[Any]:
    from itsm.agent_integrations.models import AgentRun

    with catalog.session() as db:
        return list(db.scalars(select(AgentRun)).all())


def test_capability_refusal_leaves_no_reservation_or_turn(app_client) -> None:
    catalog, client, settings = app_client
    headers = login(client, settings, ADMIN_USERNAME)
    runtime = FakeRuntime(ChatReply(message="ok"))
    build_service(client, catalog, runtime=runtime)
    provider = create_provider(client, headers, {"model-a": {"image": False, "file": None}})
    session = create_session(client, headers, instance_id=provider["id"], model="model-a")
    attachment = upload(client, headers, session["id"]).json()

    status, events = send(
        client, headers, session["id"], message="mirá", attachmentIds=[attachment["id"]]
    )

    assert status == 422, events
    assert events == []
    stored = client.get(f"{API}/agent/sessions/{session['id']}", headers=headers).json()
    assert stored["status"] == "idle"
    assert stored["messages"] == []
    assert runtime.requests == []
    assert run_rows(catalog) == []
    assert reservation_rows(catalog) == []

    # A document needs a positive file mark, not just "unknown".
    document = upload(client, headers, session["id"], filename="informe.pdf", data=pdf())
    document = document.json()
    status, _ = send(client, headers, session["id"], message="mirá", attachmentIds=[document["id"]])
    assert status == 422

    # UTF-8 text is inlined for any model, so it never trips the gate.
    text = upload(client, headers, session["id"], filename="activos.csv", data=CSV).json()
    status, events = send(client, headers, session["id"], message="", attachmentIds=[text["id"]])
    assert status == 200, events
    assert any(item["type"] == "done" for item in events), events
    assert len(runtime.requests) == 1, events
    assert [item.kind for item in runtime.requests[-1].attachments] == ["text"]


def test_capability_refusal_code_is_stable(app_client) -> None:
    _catalog, client, settings = app_client
    headers = login(client, settings, ADMIN_USERNAME)
    provider = create_provider(client, headers, {"model-a": {"image": None, "file": None}})
    session = create_session(client, headers, instance_id=provider["id"], model="model-a")
    attachment = upload(client, headers, session["id"]).json()

    response = client.post(
        f"{API}/agent/sessions/{session['id']}/messages",
        json={"message": "mirá", "attachmentIds": [attachment["id"]]},
        headers=headers,
    )
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "model_modality_unsupported"


# ------------------------------------------------------------- asset documents
def test_asset_attachment_needs_the_view_permission(app_client) -> None:
    catalog, client, settings = app_client
    from tests.test_inventory_api import create_asset

    headers = login(client, settings, ADMIN_USERNAME)
    runtime = FakeRuntime(ChatReply(message="ok"))
    build_service(client, catalog, runtime=runtime)
    asset = create_asset(client, headers)
    stored = client.post(
        f"{API}/assets/{asset['id']}/attachments",
        params={"filename": "foto.png", "category": "photo"},
        content=png(),
        headers={**headers, "Content-Type": "image/png"},
    )
    assert stored.status_code == 201, stored.text
    attachment_id = stored.json()["id"]

    role = client.post(
        f"{API}/identity/roles",
        json={"name": "inventory-blind", "permissions": ["people.view"]},
        headers=headers,
    )
    assert role.status_code == 201, role.text
    created = client.post(
        f"{API}/identity/users",
        json={
            "username": "blind-reader",
            "name": "Blind Reader",
            "password": "blind-reader-password-2026",
            "roleId": role.json()["id"],
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text

    provider = create_provider(client, headers, {"model-a": {"image": True, "file": True}})
    session = create_session(client, headers, instance_id=provider["id"], model="model-a")
    ok = send(
        client,
        headers,
        session["id"],
        message="mirá el activo",
        assetAttachmentIds=[attachment_id],
    )[0]
    assert ok == 200
    received = runtime.requests[-1].attachments
    assert [(item.kind, item.media_type, item.asset_id) for item in received] == [
        ("image", "image/png", asset["id"])
    ]

    denied = login(client, settings, "blind-reader", "blind-reader-password-2026")
    own_session = create_session(client, denied, instance_id=provider["id"], model="model-a")
    status, _ = send(
        client, denied, own_session["id"], message="mirá", assetAttachmentIds=[attachment_id]
    )
    assert status in {403, 404}, status
    assert len(runtime.requests) == 1


# ------------------------------------------------------- pydantic AI parts
def test_pydantic_runtime_receives_binary_content_and_inline_text(
    app_client, caplog: pytest.LogCaptureFixture
) -> None:
    catalog, client, settings = app_client
    headers = login(client, settings, ADMIN_USERNAME)
    provider = create_provider(client, headers, {"model-a": {"image": True, "file": True}})
    session = create_session(client, headers, instance_id=provider["id"], model="model-a")
    image = upload(client, headers, session["id"]).json()
    document = upload(client, headers, session["id"], filename="informe.pdf", data=pdf()).json()
    text = upload(client, headers, session["id"], filename="activos.csv", data=CSV).json()

    seen: list[list[Any]] = []

    def run(messages: list[Any], info: Any) -> Any:
        seen.append(messages)
        return ModelResponse(parts=[TextPart("listo")])

    runtime = AgentRuntime(catalog.settings, catalog.factory(), model=FunctionModel(run))
    build_service(client, catalog, runtime=runtime)

    status, events = send(
        client,
        headers,
        session["id"],
        message="mirá estos adjuntos",
        attachmentIds=[image["id"], document["id"], text["id"]],
    )
    assert status == 200, events
    assert events[-1]["type"] == "done"

    prompt = seen[0][-1].parts[-1]
    content = list(prompt.content)  # type: ignore[arg-type]
    binaries = [part for part in content if isinstance(part, BinaryContent)]
    assert [part.media_type for part in binaries] == ["image/png", "application/pdf"]
    assert binaries[0].data == PNG
    assert binaries[1].data == pdf()
    assert any(isinstance(part, str) and "codigo,nombre" in part for part in content)

    # Bytes and base64 never reach the log or the response envelope.
    blob = base64.b64encode(PNG).decode()
    assert blob not in caplog.text
    assert blob not in json.dumps(events)


# -------------------------------------------------------------- model inputs
def test_engine_listing_exposes_per_model_input_marks(app_client) -> None:
    _catalog, client, settings = app_client
    headers = login(client, settings, ADMIN_USERNAME)
    create_provider(client, headers, {"model-a": {"image": True, "file": None}})

    body = client.get(f"{API}/agent/engines", headers=headers).json()
    builtin = next(item for item in body["instances"] if item["id"] == "pydantic")
    assert builtin["attachmentsSupported"] is False
    assert builtin["models"][0]["inputs"] == {"image": None, "file": None}

    offered = [
        model for item in body["instances"] for model in item["models"] if model["id"] == "model-a"
    ]
    assert offered, body
    assert offered[0]["inputs"] == {"image": True, "file": None}
    provider_instance = next(
        item for item in body["instances"] if any(m["id"] == "model-a" for m in item["models"])
    )
    assert provider_instance["attachmentsSupported"] is True


# ---------------------------------------------------------------- migrations
def test_chat_attachment_migration_round_trips_on_fresh_sqlite(
    settings_factory: Callable[..., Settings], tmp_path: Any
) -> None:
    from sqlalchemy import create_engine, inspect
    from tests.conftest import run_cli, run_migrations

    settings = settings_factory(database_url=f"sqlite:///{tmp_path / 'migration.db'}")
    assert run_migrations(settings).returncode == 0

    def tables() -> set[str]:
        engine = create_engine(settings.database_url)
        try:
            return set(inspect(engine).get_table_names())
        finally:
            engine.dispose()

    assert "agent_chat_attachments" in tables()
    down = run_cli(
        [
            "-m",
            "alembic",
            "-c",
            str(Path(__file__).resolve().parents[1] / "alembic.ini"),
            "downgrade",
            "-1",
        ],
        settings,
    )
    assert down.returncode == 0, down.stderr
    assert "agent_chat_attachments" not in tables()
    assert run_migrations(settings).returncode == 0
    assert "agent_chat_attachments" in tables()
