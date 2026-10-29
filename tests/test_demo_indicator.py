"""Visible demo identity: a server-derived flag on authenticated envelopes only.

The flag is additive and read-only. It never authorizes anything, never comes
from the browser and never changes login, CSRF, origin or permission handling.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.demo.state import DemoInstallation
from itsm.identity.clock import utcnow
from itsm.identity.permissions import ROLE_USER
from itsm.main import create_app
from sqlalchemy.orm import Session
from tests.conftest import run_migrations
from tests.identity_support import Harness

ORIGIN = "http://testserver"
API = "/api/v1"
DEMO_USERNAME = "demo.owner"
DEMO_PASSWORD = "Demo-Indicator-Pass-42"
INSTALLER_PASSWORD = "installer-password-2026"


def demo_environment() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    env.update(ITSM_ENVIRONMENT="test", ITSM_BOOTSTRAP_PASSWORD=DEMO_PASSWORD)
    return env


def initialize_demo(directory: Path) -> None:
    """Create a real marked installation through the public demo CLI."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "itsm.demo",
            "init",
            "--directory",
            str(directory),
            "--username",
            DEMO_USERNAME,
        ],
        env=demo_environment(),
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["mode"] == "demo"


def mark_demo(settings: Settings) -> None:
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            session.add(
                DemoInstallation(id=1, dataset="fictional-infrastructure-v1", created_at=utcnow())
            )
            session.commit()
    finally:
        engine.dispose()


def ordinary_install(
    settings_factory: Callable[..., Settings],
) -> Harness:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    harness = Harness(settings=settings, engine=create_engine_from_settings(settings))
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", INSTALLER_PASSWORD)
    return harness


def login(
    client: TestClient,
    username: str,
    password: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
):
    return client.post(
        f"{API}/auth/login",
        json={"username": username, "password": password},
        headers={"Origin": ORIGIN, **(headers or {})},
        params=params,
    )


def test_marked_demo_installation_exposes_demo_mode_on_login_and_me(
    tmp_path: Path, settings_factory: Callable[..., Settings]
) -> None:
    directory = tmp_path / "demo"
    initialize_demo(directory)
    settings = settings_factory(database_url=f"sqlite:///{directory / 'demo.db'}")
    with TestClient(create_app(settings)) as client:
        response = login(client, DEMO_USERNAME, DEMO_PASSWORD)
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["demoMode"] is True
        assert payload["user"]["username"] == DEMO_USERNAME

        current = client.get(f"{API}/auth/me")
        assert current.status_code == 200, current.text
        assert current.json()["demoMode"] is True
        assert current.headers["cache-control"] == "no-store"


def test_ordinary_installation_reports_demo_mode_false(
    settings_factory: Callable[..., Settings],
) -> None:
    harness = ordinary_install(settings_factory)
    try:
        with TestClient(create_app(harness.settings)) as client:
            response = login(client, "ana.admin", INSTALLER_PASSWORD)
            assert response.status_code == 200, response.text
            assert response.json()["demoMode"] is False

            current = client.get(f"{API}/auth/me")
            assert current.status_code == 200, current.text
            assert current.json()["demoMode"] is False
    finally:
        harness.close()


def test_client_input_never_enables_demo_mode(
    settings_factory: Callable[..., Settings],
) -> None:
    harness = ordinary_install(settings_factory)
    try:
        with TestClient(create_app(harness.settings)) as client:
            response = login(
                client,
                "ana.admin",
                INSTALLER_PASSWORD,
                headers={"X-Demo-Mode": "true", "X-Demo": "1"},
                params={"demoMode": "true"},
            )
            assert response.status_code == 200, response.text
            assert response.json()["demoMode"] is False
            assert client.get(f"{API}/auth/me?demoMode=true").json()["demoMode"] is False
    finally:
        harness.close()


def test_unauthenticated_session_requests_stay_denied(
    settings_factory: Callable[..., Settings],
) -> None:
    harness = ordinary_install(settings_factory)
    try:
        with TestClient(create_app(harness.settings)) as client:
            response = client.get(f"{API}/auth/me")
            assert response.status_code == 401
            body = response.json()
            assert "demoMode" not in body
            assert body["error"]["code"] == "unauthorized"
    finally:
        harness.close()


def test_demo_indicator_keeps_origin_csrf_and_session_guards(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    harness = Harness(settings=settings, engine=create_engine_from_settings(settings))
    try:
        with harness.service() as service:
            service.bootstrap_superadmin("ana.admin", "Ana Admin", INSTALLER_PASSWORD)
        mark_demo(settings)
        with TestClient(create_app(settings)) as client:
            anonymous = client.get(f"{API}/identity/state")
            assert anonymous.status_code == 401

            no_csrf = client.post(f"{API}/auth/logout", headers={"Origin": ORIGIN})
            assert no_csrf.status_code == 401

            granted = login(client, "ana.admin", INSTALLER_PASSWORD)
            assert granted.status_code == 200, granted.text
            envelope = granted.json()
            assert envelope["demoMode"] is True

            blocked = client.post(f"{API}/auth/logout", headers={"Origin": ORIGIN})
            assert blocked.status_code == 403
            assert client.get(f"{API}/auth/me").json()["demoMode"] is True

            closed = client.post(
                f"{API}/auth/logout",
                headers={
                    "Origin": ORIGIN,
                    "X-CSRF-Token": str(envelope["csrfToken"]),
                },
            )
            assert closed.status_code == 200, closed.text
            assert client.get(f"{API}/auth/me").status_code == 401
    finally:
        harness.close()


def test_marker_read_failure_never_pretends_to_be_an_ordinary_installation(
    settings_factory: Callable[..., Settings],
) -> None:
    """A database error is reported as a failure, not as `demoMode: false`.

    Migrations are an explicit prerequisite. If the durable marker cannot be
    read, the envelope would be guessing, so the request fails instead.
    """
    harness = ordinary_install(settings_factory)
    try:
        with TestClient(create_app(harness.settings), raise_server_exceptions=False) as client:
            signed_in = login(client, "ana.admin", INSTALLER_PASSWORD)
            assert signed_in.status_code == 200, signed_in.text
            assert signed_in.json()["demoMode"] is False

            harness.execute("DROP TABLE demo_installation")

            current = client.get(f"{API}/auth/me")
            assert current.status_code == 500, current.text
            denied = current.json()
            assert denied["error"]["code"] == "internal_error"
            assert "demoMode" not in denied

            relogin = login(client, "ana.admin", INSTALLER_PASSWORD)
            assert relogin.status_code == 500, relogin.text
            assert "demoMode" not in relogin.json()

        with TestClient(create_app(harness.settings), raise_server_exceptions=False) as client:
            anonymous = client.get(f"{API}/auth/me")
            assert anonymous.status_code == 401
            assert "demoMode" not in anonymous.json()
    finally:
        harness.close()


def test_demo_mode_does_not_authorize_anything_by_itself(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    harness = Harness(settings=settings, engine=create_engine_from_settings(settings))
    try:
        with harness.service() as service:
            service.bootstrap_superadmin("ana.admin", "Ana Admin", INSTALLER_PASSWORD)
            identity = service._identity_by_username("ana.admin")
            assert identity is not None
            service.create_user(
                service.resolve_actor(identity.id),
                username="demo.reader",
                name="Reader",
                role_id=ROLE_USER,
                password=INSTALLER_PASSWORD,
            )
        mark_demo(settings)
        with TestClient(create_app(settings)) as client:
            reader = login(client, "demo.reader", INSTALLER_PASSWORD).json()
            assert reader["demoMode"] is True
            denied = client.post(
                f"{API}/identity/roles",
                json={"name": "reader-escalation", "permissions": ["users.create"]},
                headers={
                    "Origin": ORIGIN,
                    "X-CSRF-Token": str(reader["csrfToken"]),
                    "X-Demo-Mode": "true",
                },
            )
            assert denied.status_code == 403
            assert denied.json()["error"]["code"] == "forbidden"
    finally:
        harness.close()
