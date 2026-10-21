"""Test-only helpers for inventory, agent and MCP checks: real database, real identities."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import uvicorn
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.identity.service import IdentityService, Principal
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session
from tests.conftest import ADMIN_USERNAME, bootstrap_admin, run_migrations

READER = ("reader-user", "Reader User", "reader")
OPERATOR = ("operator-user", "Operator User", "operator")
MACHINE = ("hermes-client", "Hermes Client")
MACHINE_PASSWORD = "machine-identity-password-2026"


@dataclass
class Catalog:
    """A migrated database with an administrator and optional extra identities."""

    settings: Settings
    engine: Engine

    def factory(self) -> Any:
        return create_session_factory(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        with Session(self.engine) as session:
            yield session

    def service(self, session: Session) -> IdentityService:
        return IdentityService(session, self.settings)

    def admin(self) -> Principal:
        return self.principal(ADMIN_USERNAME)

    def principal(self, username: str) -> Principal:
        with self.session() as session:
            service = self.service(session)
            identity = service._identity_by_username(username)
            assert identity is not None, f"identity {username} is missing"
            return service.resolve_actor(identity.id)

    def add_user(self, username: str, name: str, role_id: str) -> Principal:
        with self.session() as session:
            service = self.service(session)
            service.create_user(
                self.admin(),
                username=username,
                name=name,
                password=MACHINE_PASSWORD,
                role_id=role_id,
            )
        return self.principal(username)

    def add_machine(
        self, username: str, name: str, role_id: str = "reader"
    ) -> tuple[Principal, str]:
        with self.session() as session:
            service = self.service(session)
            service.bootstrap_machine(username, name, "external_client", role_id)
            credential = service.issue_machine_credential(username)
        return self.principal(username), credential.token

    def revoke_machine(self, username: str) -> None:
        with self.session() as session:
            service = self.service(session)
            service.revoke_machine_credentials(username)

    def deactivate(self, username: str) -> None:
        with self.session() as session:
            service = self.service(session)
            identity = service._identity_by_username(username)
            assert identity is not None
            service.set_active(self.admin(), identity.id, active=False)

    def audit(self, action: str | None = None) -> list[dict[str, Any]]:
        statement = (
            "SELECT actor_username, action, resource, outcome FROM identity_audit_events"
            + (" WHERE action = :action" if action else "")
            + " ORDER BY id"
        )
        with self.engine.connect() as connection:
            rows = connection.execute(text(statement), {"action": action} if action else {}).all()
        return [
            {
                "actor": row[0],
                "action": row[1],
                "resource": row[2],
                "outcome": row[3],
            }
            for row in rows
        ]

    def asset_count(self) -> int:
        with self.engine.connect() as connection:
            return int(connection.execute(text("SELECT COUNT(*) FROM assets")).scalar_one())


def prepare(settings_factory: Any, **overrides: Any) -> Catalog:
    """Migrate an isolated SQLite database and install the administrator."""
    settings = settings_factory(**overrides)
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    bootstrap_admin(settings)
    engine = create_engine_from_settings(settings)
    catalog = Catalog(settings=settings, engine=engine)
    with catalog.session() as session:
        session.execute(select(1))
    return catalog


def asset_values(**overrides: Any) -> dict[str, Any]:
    """A complete valid asset payload; tests override only the fields under test."""
    values: dict[str, Any] = {
        "quick_code": "SITE-DEMO-001",
        "name": "Switch Aruba 2930F",
        "category": "Red",
        "type": "Switch",
        "brand": "Aruba",
        "model": "2930F-24G",
        "serial": "AR2930F001",
        "ip": "192.0.2.10",
        "site": "Example Site",
        "location": "Rack 2",
        "responsible": "Matriz NOC",
        "status": "in_use",
        "description": "Switch de acceso del piso 1",
    }
    values.update(overrides)
    return values


@contextmanager
def serve(settings: Settings, port: int) -> Iterator[str]:
    """Run the real ASGI app (with lifespan) on loopback for protocol tests."""
    from itsm.main import create_app

    server = uvicorn.Server(
        uvicorn.Config(create_app(settings), host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "uvicorn did not start"
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def sign_in_as(
    test_client: Any, settings: Settings, username: str, password: str = MACHINE_PASSWORD
) -> dict[str, str]:
    """Log an arbitrary human identity in and return the browser mutation headers."""
    response = test_client.post(
        f"{settings.api_prefix}/auth/login",
        json={"username": username, "password": password},
        headers={"Origin": settings.auth_origin},
    )
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": str(response.json()["csrfToken"]), "Origin": settings.auth_origin}
