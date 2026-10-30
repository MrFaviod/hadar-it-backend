"""Public demo: a demonstration administrator, never the installation owner.

Covers S10 (any visitor enters with ``admin/admin`` and behaves as a demo
administrator, not a real Superadmin) and S11 (no deployment operations,
secrets, real providers, code installation, arbitrary execution or internal
server resources). The guard is enforced by the backend, not by hiding UI.

Every assertion goes through the public HTTP surface of an app started in the
real ``demo`` release mode over a migrated, seeded demo installation.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.demo.seed import seed
from itsm.release_mode import RELEASE_MODE_ENV, capabilities_for
from sqlalchemy import text
from sqlalchemy.orm import Session
from tests.conftest import bootstrap_superadmin, run_migrations, sign_in
from tests.identity_support import make_harness

ORIGIN = "http://testserver"
API = "/api/v1"
INSTALLER_PASSWORD = "Demo-Installer-Pass-2026"
DEMO_RESTRICTED = "demo_restricted"


def demo_settings(directory: Path) -> Settings:
    """Isolated demo settings with limits generous enough for a deny-table sweep."""
    (directory / "tasks").mkdir(parents=True, exist_ok=True)
    return Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{directory / 'demo.db'}",
        task_sqlite_path=directory / "tasks" / "huey.db",
        attachment_storage_path=directory / "blobs",
        auth_origin=ORIGIN,
        auth_cookie_secure=False,
        log_level="WARNING",
        demo_rate_limit_per_minute=6000,
        demo_rate_limit_burst=6000,
        demo_login_rate_per_minute=1000,
        demo_login_rate_burst=1000,
    )


@contextmanager
def started(settings: Settings, mode: str) -> Iterator[TestClient]:
    """Start the real app in one release mode without leaking the variable."""
    from itsm.main import create_app

    previous = os.environ.get(RELEASE_MODE_ENV)
    os.environ[RELEASE_MODE_ENV] = mode
    client: TestClient | None = None
    try:
        client = TestClient(create_app(settings))
        client.__enter__()
    finally:
        if previous is None:
            os.environ.pop(RELEASE_MODE_ENV, None)
        else:
            os.environ[RELEASE_MODE_ENV] = previous
    try:
        yield client
    finally:
        client.__exit__(None, None, None)


@dataclass
class Installation:
    settings: Settings
    directory: Path


@pytest.fixture(scope="module")
def demo_installation(tmp_path_factory: pytest.TempPathFactory) -> Installation:
    directory = tmp_path_factory.mktemp("demo-public")
    settings = demo_settings(directory)
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            payload = seed(session, settings, "demo.owner", INSTALLER_PASSWORD)
            assert payload["mode"] == "demo"
    finally:
        engine.dispose()
    return Installation(settings=settings, directory=directory)


@pytest.fixture(scope="module")
def demo_client(demo_installation: Installation) -> Iterator[TestClient]:
    with started(demo_installation.settings, "demo") as client:
        yield client


def login(
    client: TestClient,
    username: str = "admin",
    password: str = "admin",
) -> Response:
    return client.post(
        f"{API}/auth/login",
        json={"username": username, "password": password},
        headers={"Origin": ORIGIN},
    )


def visitor_session(demo_client: TestClient) -> dict[str, str]:
    response = login(demo_client)
    assert response.status_code == 200, response.text
    return {
        "X-CSRF-Token": str(response.json()["csrfToken"]),
        "Origin": ORIGIN,
    }


def test_visitor_enters_as_demo_administrator_not_superadmin(demo_client: TestClient) -> None:
    response = login(demo_client)
    assert response.status_code == 200, response.text
    envelope = response.json()
    assert envelope["user"]["username"] == "admin"
    assert envelope["user"]["roleId"] == "admin"
    assert envelope["demoMode"] is True
    assert sorted(envelope["permissions"]) == sorted(
        {code for code in envelope["permissions"] if not code.startswith("system.")}
    )
    assert "system.view" not in envelope["permissions"]
    assert "agents.providers.personal" not in envelope["permissions"]

    current = demo_client.get(f"{API}/auth/me")
    assert current.status_code == 200, current.text
    assert current.json()["user"]["roleId"] == "admin"


def test_installation_owner_is_internal_and_cannot_be_logged_into(
    demo_client: TestClient, demo_installation: Installation
) -> None:
    """The unavoidable last-superadmin invariant: a secret nobody can use."""
    from itsm.demo.restrictions import INTERNAL_OWNER_USERNAME

    auth = visitor_session(demo_client)
    state = demo_client.get(f"{API}/identity/state", headers=auth)
    assert state.status_code == 200, state.text
    owners = [user for user in state.json()["users"] if user["actorKind"] == "human"]
    internal = [user for user in owners if user["username"] == INTERNAL_OWNER_USERNAME]
    assert len(internal) == 1
    assert internal[0]["roleId"] == "superadmin"

    for guess in ("admin", INSTALLER_PASSWORD, "demo"):
        refused = login(demo_client, INTERNAL_OWNER_USERNAME, guess)
        assert refused.status_code in {401, 429}, refused.text

    # The generated secret is never returned by the CLI payload or stored in SQL.
    engine = create_engine_from_settings(demo_installation.settings)
    try:
        with Session(engine) as session:
            hashes = [
                row[0]
                for row in session.execute(
                    text("SELECT password_hash FROM identity_identities WHERE username = :name"),
                    {"name": INTERNAL_OWNER_USERNAME},
                )
            ]
    finally:
        engine.dispose()
    assert hashes and all(value and value.startswith("$argon2") for value in hashes)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", f"{API}/system/status"),
        ("GET", f"{API}/system/configuration"),
        ("GET", f"{API}/system/modules"),
        ("PATCH", f"{API}/system/modules/backup"),
        ("PUT", f"{API}/system/providers"),
        ("POST", f"{API}/system/operations"),
        ("GET", f"{API}/extensions"),
        ("POST", f"{API}/extensions/candidates"),
        ("POST", f"{API}/extensions/any-extension/enabled"),
        ("POST", f"{API}/extensions/any-extension/rollback"),
        ("GET", f"{API}/extensions/any-extension/frontend.js"),
        ("GET", f"{API}/agent/integrations/modules"),
        ("PUT", f"{API}/agent/integrations/defaults"),
        ("POST", f"{API}/agent/integrations/install"),
        ("GET", f"{API}/agent/providers"),
        ("POST", f"{API}/agent/providers"),
        ("PATCH", f"{API}/agent/providers/any-provider"),
        ("POST", f"{API}/agent/gateway/v1/chat/completions"),
        ("GET", f"{API}/agent/gateway/v1/models"),
        ("POST", f"{API}/agent/chat"),
        ("POST", f"{API}/agent/sessions"),
        ("POST", f"{API}/agent/sessions/any-session/messages"),
        ("POST", f"{API}/notifications/channels"),
        ("POST", f"{API}/notifications/channels/any-channel/test"),
        ("POST", f"{API}/notifications/rules"),
        ("POST", f"{API}/monitoring/exporters"),
        ("PUT", f"{API}/monitoring/profiles/servidores"),
        ("PATCH", f"{API}/monitoring/assets/00000000-0000-0000-0000-000000000000"),
        ("POST", f"{API}/tasks/demo"),
        ("POST", f"{API}/identity/users"),
        ("PUT", f"{API}/identity/users/any-identity"),
        ("PATCH", f"{API}/identity/users/any-identity/active"),
        ("POST", f"{API}/identity/roles"),
        ("PUT", f"{API}/identity/roles/operator"),
        ("DELETE", f"{API}/identity/roles/operator"),
        ("PUT", f"{API}/identity/settings"),
    ],
)
def test_dangerous_surface_is_denied_by_the_backend(
    demo_client: TestClient, method: str, path: str
) -> None:
    visitor_session(demo_client)
    response = demo_client.request(method, path, json={}, headers={"Origin": ORIGIN})
    assert response.status_code == 403, (method, path, response.status_code, response.text)
    assert response.json()["error"]["code"] == DEMO_RESTRICTED


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", f"{API}/system/unpublished"),
        ("POST", f"{API}/system/unpublished/new"),
        ("POST", f"{API}/extensions/not-registered"),
        ("PUT", f"{API}/identity/policies/operator"),
        ("POST", f"{API}/monitoring/exporters/unknown"),
    ],
)
def test_unknown_routes_under_protected_prefixes_fail_closed(
    demo_client: TestClient, method: str, path: str
) -> None:
    visitor_session(demo_client)
    response = demo_client.request(method, path, json={}, headers={"Origin": ORIGIN})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == DEMO_RESTRICTED


def test_ordinary_business_reads_and_writes_stay_available(demo_client: TestClient) -> None:
    auth = visitor_session(demo_client)
    for path in (
        f"{API}/health/live",
        f"{API}/assets",
        f"{API}/people",
        f"{API}/locations",
        f"{API}/dashboard",
        f"{API}/monitoring/alerts",
        f"{API}/monitoring/config",
        f"{API}/notifications/inbox",
        f"{API}/notifications/config",
        f"{API}/reports/templates",
        f"{API}/identity/state",
        f"{API}/identity/catalog",
    ):
        response = demo_client.get(path, headers=auth)
        assert response.status_code == 200, (path, response.status_code, response.text)

    missing = demo_client.get(f"{API}/tasks/unknown-task-id", headers=auth)
    assert missing.status_code == 404

    # The exporter/Prometheus chain is not part of the denied configuration
    # surface: the scrape endpoint may answer for its own auth reason, never
    # because the public demo restricted it.
    metrics = demo_client.get(f"{API}/monitoring/prometheus-metrics")
    assert metrics.json().get("error", {}).get("code") != DEMO_RESTRICTED

    created = demo_client.post(
        f"{API}/assets",
        json={
            "quickCode": "DEMO-VISITOR-001",
            "name": "Activo creado por un visitante",
            "category": "switches",
            "type": "Switch",
            "status": "in_storage",
            "description": "Dato ficticio de demostración.",
        },
        headers=auth,
    )
    assert created.status_code == 201, created.text
    asset_id = created.json()["id"]

    edited = demo_client.patch(
        f"{API}/assets/{asset_id}",
        json={"name": "Activo editado por un visitante"},
        headers=auth,
    )
    assert edited.status_code == 200, edited.text
    assert edited.json()["name"] == "Activo editado por un visitante"

    read = demo_client.get(f"{API}/assets/{asset_id}", headers=auth)
    assert read.status_code == 200, read.text


def test_visitor_cannot_escalate_its_own_role_or_password(demo_client: TestClient) -> None:
    auth = visitor_session(demo_client)
    state = demo_client.get(f"{API}/identity/state", headers=auth)
    visitor = next(user for user in state.json()["users"] if user["username"] == "admin")

    for payload in (
        {"roleId": "superadmin"},
        {"password": "a-new-visitor-chosen-password"},
        {"active": False},
    ):
        denied = demo_client.put(
            f"{API}/identity/users/{visitor['id']}", json=payload, headers=auth
        )
        assert denied.status_code == 403, denied.text
        assert denied.json()["error"]["code"] == DEMO_RESTRICTED

    denied = demo_client.post(
        f"{API}/identity/users",
        json={
            "username": "visitor-made.admin",
            "name": "Visitante",
            "roleId": "admin",
            "password": "visitor-password-2026",
        },
        headers=auth,
    )
    assert denied.status_code == 403

    # The visitor account is unchanged: same role, same password, still active.
    assert login(demo_client, "admin", "admin").status_code == 200
    current = demo_client.get(f"{API}/auth/me").json()
    assert current["user"]["roleId"] == "admin"
    assert current["user"]["active"] is True


def test_provider_credentials_are_irrelevant_in_demo(
    demo_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A configured provider key never becomes reachable from the demo surface."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-demo-should-never-be-used")
    auth = visitor_session(demo_client)
    for path in (f"{API}/agent/chat", f"{API}/agent/gateway/v1/chat/completions"):
        response = demo_client.post(path, json={"message": "hola"}, headers=auth)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == DEMO_RESTRICTED


def test_development_mode_has_no_demo_restriction(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    bootstrap_superadmin(settings)
    with started(settings, "dev") as client:
        assert client.app.state.demo_restrictions is None
        assert client.app.state.demo_limits is None
        auth = sign_in(client, settings)
        response = client.get(f"{API}/system/status", headers=auth)
        assert response.status_code != 403 or response.json()["error"]["code"] != DEMO_RESTRICTED


def test_production_mode_has_no_demo_restriction_and_rejects_the_visitor_password(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    bootstrap_superadmin(settings)
    with started(settings, "prod") as client:
        assert client.app.state.demo_restrictions is None
        assert client.app.state.demo_limits is None
        auth = sign_in(client, settings)
        status = client.get(f"{API}/system/status", headers=auth)
        assert status.status_code != 403 or status.json()["error"]["code"] != DEMO_RESTRICTED
        weak = client.post(
            f"{API}/identity/users",
            json={
                "username": "prod.weak",
                "name": "Weak",
                "roleId": "user",
                "password": "admin",
            },
            headers=auth,
        )
        assert weak.status_code == 422, weak.text
        assert weak.json()["error"]["code"] == "validation_error"


def test_demo_capabilities_alone_enable_the_visitor_login() -> None:
    from itsm.demo import restrictions

    assert restrictions.visitor_password_waiver(capabilities_for("demo")) == "admin"
    assert restrictions.visitor_password_waiver(capabilities_for("prod")) is None
    assert restrictions.visitor_password_waiver(capabilities_for("dev")) is None


def test_service_layer_still_rejects_the_visitor_password_outside_the_demo_waiver(
    settings_factory: Callable[..., Settings],
) -> None:
    from itsm.identity.service import AuthenticationFailed, ValidationFailed

    harness = make_harness(settings_factory)
    try:
        with harness.service() as service:
            service.bootstrap_superadmin("ana.admin", "Ana Admin", INSTALLER_PASSWORD)
            identity = service._identity_by_username("ana.admin")
            assert identity is not None
            principal = service.resolve_actor(identity.id)
            with pytest.raises(ValidationFailed):
                service.create_user(
                    principal,
                    username="weak.identity",
                    name="Weak",
                    role_id="user",
                    password="admin",
                )
            assert service._identity_by_username("weak.identity") is None
            service.create_user(
                principal,
                username="strong.identity",
                name="Strong",
                role_id="user",
                password="a-perfectly-fine-password",
            )
            with pytest.raises(AuthenticationFailed):
                service.login("strong.identity", "admin")
    finally:
        harness.close()


def test_demo_session_envelope_keeps_the_server_derived_flag(demo_client: TestClient) -> None:
    response = login(demo_client)
    assert response.status_code == 200
    assert response.json()["demoMode"] is True
    assert demo_client.get(f"{API}/auth/me").json()["demoMode"] is True
    assert demo_client.post(f"{API}/auth/logout", headers={"Origin": ORIGIN}).status_code in {
        200,
        401,
        403,
    }


def test_demo_guard_is_installed_only_for_the_demo_capability_set(
    demo_client: TestClient, demo_installation: Installation
) -> None:
    from itsm.demo.restrictions import DemoRestrictions, build_demo_restrictions

    assert isinstance(demo_client.app.state.demo_restrictions, DemoRestrictions)
    assert demo_client.app.state.demo_limits is not None
    assert build_demo_restrictions(demo_installation.settings, capabilities_for("prod")) is None
    assert build_demo_restrictions(demo_installation.settings, capabilities_for("dev")) is None
