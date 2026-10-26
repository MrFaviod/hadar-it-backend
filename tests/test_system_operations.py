"""System operations: canonical service, typed HTTP API and a real bounded executor.

The executor tests start the actual helper process on loopback and execute a
workspace-only action script that creates and restores a disposable archive.
They never contact a production service and never fabricate an execution
result.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.identity.hashing import hash_password
from itsm.identity.models import (
    Identity,
    IdentityAuditEvent,
    IdentityRole,
    IdentityRolePolicy,
)
from itsm.identity.permissions import PERMISSION_CATALOG
from itsm.identity.service import IdentityService
from itsm.main import create_app
from sqlalchemy import select
from sqlalchemy.orm import Session
from tests.conftest import run_cli, run_migrations

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "installer-password-2026"
SYSTEM_PERMISSIONS = (
    "system.view",
    "system.providers",
    "system.modules",
    "system.configure",
    "system.backup",
    "system.update",
)
BUSINESS_PERMISSIONS = tuple(code for code in PERMISSION_CATALOG if code not in SYSTEM_PERMISSIONS)
ACTION_ENV = {
    "deployment.status": "ITSM_EXECUTOR_ACTION_DEPLOYMENT_STATUS",
    "update.prepare": "ITSM_EXECUTOR_ACTION_UPDATE_PREPARE",
    "backup.create": "ITSM_EXECUTOR_ACTION_BACKUP_CREATE",
}


def _prepare_database(settings: Settings) -> None:
    """Apply migrations; tolerate the identity worker's 0021 not being copied yet."""
    identity_migration = BACKEND_ROOT / "migrations" / "versions" / "0021_system_profiles.py"
    if identity_migration.exists():
        applied = run_migrations(settings)
    else:
        applied = run_cli(
            [
                "-m",
                "alembic",
                "-c",
                str(BACKEND_ROOT / "alembic.ini"),
                "upgrade",
                "0020_agent_integrations",
            ],
            settings,
        )
    assert applied.returncode == 0, applied.stderr
    engine = create_engine_from_settings(settings)
    from itsm.system.models import SystemPreference, SystemProviderSettings

    SystemPreference.__table__.create(bind=engine, checkfirst=True)
    SystemProviderSettings.__table__.create(bind=engine, checkfirst=True)
    engine.dispose()


def _role(
    session: Session,
    role_id: str,
    permissions: tuple[str, ...],
    *,
    built_in: bool = False,
) -> None:
    if session.get(IdentityRole, role_id) is None:
        session.add(IdentityRole(id=role_id, name=role_id, built_in=built_in))
    session.flush()
    existing = {
        (row.resource, row.operation)
        for row in session.execute(
            select(IdentityRolePolicy).where(IdentityRolePolicy.role_id == role_id)
        ).scalars()
    }
    for code in permissions:
        resource, operation = code.split(".", 1)
        if (resource, operation) in existing:
            continue
        session.add(IdentityRolePolicy(role_id=role_id, resource=resource, operation=operation))
    session.flush()


def _identity(
    session: Session,
    username: str,
    role_id: str,
    *,
    actor_kind: str = "human",
    delegated_by: str | None = None,
    role_owner: str | None = None,
    active: bool = True,
) -> Identity:
    existing = session.execute(
        select(Identity).where(Identity.username == username)
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    identity = Identity(
        id=str(uuid4()),
        username=username,
        name=username,
        actor_kind=actor_kind,
        active=active,
        password_hash=hash_password(PASSWORD) if actor_kind == "human" else None,
        role_id=role_id,
        delegated_by_id=delegated_by,
        role_owner=role_owner,
    )
    session.add(identity)
    session.flush()
    return identity


class Seeded:
    """Persisted identities and machine tokens for the isolated database."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        engine = create_engine_from_settings(settings)
        factory = create_session_factory(engine)
        self.superadmin_id = ""
        self.admin_id = ""
        self.user_id = ""
        self.auditor_id = ""
        self.machine_token = ""
        self.rogue_token = ""
        self.orphan_token = ""
        self.retired_token = ""
        with factory() as session:
            _role(
                session, "superadmin", (*BUSINESS_PERMISSIONS, *SYSTEM_PERMISSIONS), built_in=True
            )
            _role(session, "admin", BUSINESS_PERMISSIONS, built_in=True)
            _role(session, "user", ("assets.view", "people.view"), built_in=True)
            _role(session, "auditor", ("system.view",))
            _role(
                session,
                "system-agent",
                (
                    "system.view",
                    "system.providers",
                    "system.modules",
                    "system.backup",
                    "system.update",
                ),
            )
            superadmin = _identity(session, "root.super", "superadmin")
            admin = _identity(session, "ana.admin", "admin")
            user = _identity(session, "basic.user", "user")
            auditor = _identity(session, "audit.only", "auditor")
            retired = _identity(session, "retired.super", "superadmin", active=False)
            machine = _identity(
                session,
                "agent.system",
                "system-agent",
                actor_kind="external_agent",
                delegated_by=superadmin.id,
                role_owner="superadmin",
            )
            rogue = _identity(
                session,
                "agent.rogue",
                "system-agent",
                actor_kind="external_agent",
                delegated_by=admin.id,
                role_owner="admin",
            )
            orphan = _identity(
                session,
                "agent.orphan",
                "system-agent",
                actor_kind="internal_agent",
            )
            assert machine.id and rogue.id and orphan.id
            retired_machine = _identity(
                session,
                "agent.retired",
                "system-agent",
                actor_kind="external_agent",
                delegated_by=retired.id,
                role_owner="superadmin",
            )
            session.commit()
            self.superadmin_id = superadmin.id
            self.admin_id = admin.id
            self.user_id = user.id
            self.auditor_id = auditor.id
            identity = IdentityService(session, settings)
            self.machine_token = identity.issue_machine_credential("agent.system").token
            self.rogue_token = identity.issue_machine_credential("agent.rogue").token
            self.orphan_token = identity.issue_machine_credential("agent.orphan").token
            self.retired_token = identity.issue_machine_credential("agent.retired").token
            assert retired_machine.id
        engine.dispose()


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    root = tmp_path / "executor"
    root.mkdir()
    return root


@pytest.fixture
def seed(settings_factory: Callable[..., Settings]) -> Seeded:
    settings = settings_factory()
    _prepare_database(settings)
    return Seeded(settings)


@pytest.fixture
def open_client() -> Iterator[Callable[[Settings], TestClient]]:
    opened: list[TestClient] = []

    def make(settings: Settings) -> TestClient:
        from itsm.main import create_app

        client = TestClient(create_app(settings))
        client.__enter__()
        opened.append(client)
        return client

    try:
        yield make
    finally:
        for client in opened:
            client.__exit__(None, None, None)


def login(client: TestClient, settings: Settings, username: str) -> dict[str, str]:
    response = client.post(
        f"{settings.api_prefix}/auth/login",
        json={"username": username, "password": PASSWORD},
        headers={"Origin": settings.auth_origin},
    )
    assert response.status_code == 200, response.text
    return {
        "X-CSRF-Token": str(response.json()["csrfToken"]),
        "Origin": settings.auth_origin,
    }


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------- executor


def _executor_environment(
    actions: Mapping[str, list[str]], secret: str, *, redact: str | None = None
) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    env["PYTHONPATH"] = str(BACKEND_ROOT)
    env["PYTHONUNBUFFERED"] = "1"
    env["ITSM_EXECUTOR_SECRET"] = secret
    env["ITSM_EXECUTOR_HOST"] = "127.0.0.1"
    env["ITSM_EXECUTOR_PORT"] = "0"
    env["ITSM_EXECUTOR_TIMEOUT_SECONDS"] = "20"
    if redact:
        env["ITSM_EXECUTOR_REDACT"] = redact
    for action, argv in actions.items():
        env[ACTION_ENV[action]] = json.dumps(argv)
    return env


@contextmanager
def running_executor(
    actions: Mapping[str, list[str]], secret: str, *, redact: str | None = None
) -> Iterator[str]:
    process = subprocess.Popen(
        [sys.executable, "-m", "itsm.system.executor"],
        cwd=BACKEND_ROOT,
        env=_executor_environment(actions, secret, redact=redact),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    lines: queue.Queue[str] = queue.Queue()

    def read_ready() -> None:
        assert process.stdout is not None
        lines.put(process.stdout.readline())

    threading.Thread(target=read_ready, daemon=True).start()
    try:
        line = lines.get(timeout=20)
        assert line, process.stderr.read() if process.stderr else ""
        ready = json.loads(line)
        assert ready["event"] == "executor.ready"
        yield f"http://127.0.0.1:{ready['port']}"
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                process.kill()
                process.wait(timeout=5)


def write_action_script(evidence: Path) -> list[str]:
    """A real disposable backup: archive, restore into a fresh tree, verify bytes."""
    source = evidence / "attachments"
    source.mkdir()
    (source / "device.csv").write_text("name,serial\nswitch-1,ABC123\n")
    (source / "settings.json").write_text('{"readonly": false}\n')
    backups = evidence / "backups"
    restored = evidence / "restore"
    script = evidence / "action.py"
    script.write_text(
        "from __future__ import annotations\n"
        "import hashlib, json, shutil, sys, tarfile\n"
        "from datetime import UTC, datetime\n"
        "from pathlib import Path\n"
        f"SOURCE = Path({str(source)!r})\n"
        f"BACKUPS = Path({str(backups)!r})\n"
        f"RESTORE = Path({str(restored)!r})\n"
        "def main():\n"
        "    action = sys.argv[1]\n"
        "    if action == 'deployment.status':\n"
        "        print(json.dumps({'status':'ok','reference':'deployment-status',\n"
        "                          'revision':'test-rev'}))\n"
        "        return 0\n"
        "    if action != 'backup.create':\n"
        "        print(json.dumps({'status':'failed','message':'unsupported action'}))\n"
        "        return 2\n"
        "    BACKUPS.mkdir(parents=True, exist_ok=True)\n"
        "    shutil.rmtree(RESTORE, ignore_errors=True)\n"
        "    stamp = datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')\n"
        "    name = f'itsm-backup-{stamp}.tar.gz'\n"
        "    archive = BACKUPS / name\n"
        "    with tarfile.open(archive, 'w:gz') as bundle:\n"
        "        for path in sorted(SOURCE.rglob('*')):\n"
        "            if path.is_file():\n"
        "                bundle.add(path, arcname='data/' + path.relative_to(SOURCE).as_posix())\n"
        "    RESTORE.mkdir(parents=True)\n"
        "    with tarfile.open(archive, 'r:gz') as bundle:\n"
        "        for member in bundle.getmembers():\n"
        "            target = (RESTORE / member.name).resolve()\n"
        "            assert str(target).startswith(str(RESTORE.resolve()))\n"
        "            if member.isfile():\n"
        "                target.parent.mkdir(parents=True, exist_ok=True)\n"
        "                target.write_bytes(bundle.extractfile(member).read())\n"
        "    originals = {p.relative_to(SOURCE): p.read_bytes()\n"
        "                 for p in SOURCE.rglob('*') if p.is_file()}\n"
        "    copies = {p.relative_to(RESTORE / 'data'): p.read_bytes()\n"
        "              for p in (RESTORE / 'data').rglob('*') if p.is_file()}\n"
        "    verified = originals == copies\n"
        "    digest = hashlib.sha256(archive.read_bytes()).hexdigest()\n"
        "    print(json.dumps({'status':'ok' if verified else 'failed',\n"
        "                      'reference':f'backup-{stamp}',\n"
        "                      'artifact':{'name':name,'bytes':archive.stat().st_size,\n"
        "                                  'sha256':digest,'verified':verified},\n"
        "                      'restored':verified,'files':len(copies),'message':None}))\n"
        "    return 0 if verified else 3\n"
        "raise SystemExit(main())\n"
    )
    return [sys.executable, str(script), "backup.create"]


def write_failing_action(evidence: Path, *, invalid_json: bool = False) -> list[str]:
    script = evidence / ("invalid.py" if invalid_json else "failing.py")
    if invalid_json:
        script.write_text("print('not a bounded result')\n")
    else:
        script.write_text(
            "import json, sys\n"
            "print(json.dumps({'status':'failed','reference':'update-20261026',"
            "'message':'release manifest is not configured'}))\n"
            "raise SystemExit(4)\n"
        )
    return [sys.executable, str(script)]


def write_flooding_action(evidence: Path) -> list[str]:
    script = evidence / "flood.py"
    script.write_text(
        "import json, sys\n"
        "print(json.dumps({'status':'ok','reference':'flood'}))\n"
        "sys.stdout.write('x' * 9000)\n"
    )
    return [sys.executable, str(script)]


def write_inherited_pipe_action(evidence: Path) -> tuple[list[str], Path]:
    marker = evidence / "grandchild-survived"
    grandchild = evidence / "grandchild.py"
    grandchild.write_text(
        "import time\n"
        "from pathlib import Path\n"
        "time.sleep(0.5)\n"
        f"Path({str(marker)!r}).write_text('survived')\n"
    )
    parent = evidence / "inherited.py"
    parent.write_text(
        "import json, subprocess, sys\n"
        f"subprocess.Popen([sys.executable, {str(grandchild)!r}])\n"
        "print(json.dumps({'status':'ok','reference':'inherited'}))\n"
    )
    return [sys.executable, str(parent)], marker


def open_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# ------------------------------------------------------------------------ tests


def test_status_is_redacted_and_denied_to_admin_and_user(
    seed: Seeded, open_client: Callable[[Settings], TestClient]
) -> None:
    settings = seed.settings
    client = open_client(settings)
    headers = login(client, settings, "root.super")
    response = client.get(f"{settings.api_prefix}/system/status", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["app"]["database"] == "sqlite"
    assert body["executor"]["configured"] is False
    assert body["executor"]["available"] is False
    assert body["executor"]["actions"] == []
    assert isinstance(body["ready"], bool)
    text = response.text
    assert settings.database_url not in text
    assert str(settings.task_sqlite_path) not in text

    for username in ("ana.admin", "basic.user"):
        other = open_client(settings)
        denied = other.get(
            f"{settings.api_prefix}/system/status",
            headers=login(other, settings, username),
        )
        assert denied.status_code == 403, denied.text


def test_configuration_preferences_are_finite_and_persisted(
    seed: Seeded, open_client: Callable[[Settings], TestClient]
) -> None:
    settings = seed.settings
    client = open_client(settings)
    headers = login(client, settings, "root.super")
    initial = client.get(f"{settings.api_prefix}/system/configuration", headers=headers)
    assert initial.status_code == 200, initial.text
    assert initial.json()["deployment"] == {
        "classification": "test",
        "maintenanceWindow": "anytime",
        "database": "sqlite",
    }
    updated = client.patch(
        f"{settings.api_prefix}/system/configuration",
        json={
            "deployment": {
                "classification": "production",
                "maintenanceWindow": "outside_business_hours",
            }
        },
        headers=headers,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["deployment"]["classification"] == "production"
    invalid = client.patch(
        f"{settings.api_prefix}/system/configuration",
        json={"deployment": {"classification": "root-shell"}},
        headers=headers,
    )
    assert invalid.status_code == 422, invalid.text
    extra = client.patch(
        f"{settings.api_prefix}/system/configuration",
        json={"deployment": {"hostPath": "/etc"}},
        headers=headers,
    )
    assert extra.status_code == 422, extra.text

    admin = open_client(settings)
    denied = admin.patch(
        f"{settings.api_prefix}/system/configuration",
        json={"deployment": {"classification": "development"}},
        headers=login(admin, settings, "ana.admin"),
    )
    assert denied.status_code == 403, denied.text

    reader = open_client(settings)
    persisted = reader.get(
        f"{settings.api_prefix}/system/configuration",
        headers=login(reader, settings, "root.super"),
    )
    assert persisted.status_code == 200
    assert persisted.json()["deployment"]["classification"] == "production"


def test_provider_selection_is_persisted_and_used_by_the_runtime(
    seed: Seeded,
    open_client: Callable[[Settings], TestClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itsm.agents.runtime import AgentRuntime
    from itsm.system.models import SystemProviderSettings
    from pydantic_ai.messages import ModelResponse, TextPart
    from pydantic_ai.models.function import FunctionModel

    settings = seed.settings
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-provider-secret")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    client = open_client(settings)
    headers = login(client, settings, "root.super")
    listed = client.get(f"{settings.api_prefix}/system/providers", headers=headers)
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert body["selected"] is None
    providers = {item["id"]: item for item in body["providers"]}
    assert providers["openai"]["credentialConfigured"] is True
    assert providers["anthropic"]["credentialConfigured"] is False
    assert "sk-test-provider-secret" not in listed.text

    configured = client.put(
        f"{settings.api_prefix}/system/providers",
        json={"provider": "openai", "model": "gpt-4o-mini"},
        headers=headers,
    )
    assert configured.status_code == 200, configured.text
    assert configured.json()["selected"] == {
        "provider": "openai",
        "model": "gpt-4o-mini",
    }
    assert configured.json()["selection"]["source"] == "installation"

    anonymous = open_client(settings)
    denied = anonymous.put(
        f"{settings.api_prefix}/system/providers",
        json={"provider": "anthropic", "model": "claude-sonnet-4-5"},
        headers=login(anonymous, settings, "ana.admin"),
    )
    assert denied.status_code == 403, denied.text

    calls: list[Any] = []

    def fake_resolve(settings_arg: Settings, selection: Any = None) -> Any:
        calls.append(selection)
        return FunctionModel(lambda messages, info: ModelResponse(parts=[TextPart(content="ok")]))

    monkeypatch.setattr("itsm.agents.runtime.resolve_model", fake_resolve)
    factory = create_session_factory(create_engine_from_settings(settings))
    runtime = AgentRuntime(settings, factory)
    assert runtime.configured is True
    first_agent = runtime._ensure()
    assert calls[-1].provider == "openai"
    assert calls[-1].model == "gpt-4o-mini"

    changed = client.put(
        f"{settings.api_prefix}/system/providers",
        json={"provider": "anthropic", "model": "claude-sonnet-4-5"},
        headers=headers,
    )
    assert changed.status_code == 200, changed.text
    second_agent = runtime._ensure()
    assert calls[-1].provider == "anthropic"
    assert calls[-1].model == "claude-sonnet-4-5"
    assert second_agent is not first_agent

    override = FunctionModel(
        lambda messages, info: ModelResponse(parts=[TextPart(content="override")])
    )
    explicit = AgentRuntime(settings, factory, model=override)
    explicit_agent = explicit._ensure()
    assert explicit_agent is not None
    with factory() as session:
        row = session.get(SystemProviderSettings, 1)
        assert row is not None
        assert (row.provider, row.model) == ("anthropic", "claude-sonnet-4-5")


def test_executor_runs_real_backup_and_status_with_bounded_result(
    evidence: Path,
    settings_factory: Callable[..., Settings],
    open_client: Callable[[Settings], TestClient],
) -> None:
    secret = "executor-secret-" + uuid4().hex
    actions = {
        "deployment.status": [sys.executable, str(evidence / "action.py"), "deployment.status"],
        "backup.create": write_action_script(evidence),
        "update.prepare": write_failing_action(evidence),
    }
    with running_executor(actions, secret) as url:
        settings = settings_factory(
            system_executor_url=url,
            system_executor_token=secret,
            system_executor_timeout_seconds=10,
        )
        _prepare_database(settings)
        Seeded(settings)
        client = open_client(settings)
        headers = login(client, settings, "root.super")

        status = client.get(f"{settings.api_prefix}/system/status", headers=headers)
        assert status.status_code == 200, status.text
        assert status.json()["executor"] == {
            "configured": True,
            "available": True,
            "actions": ["backup.create", "deployment.status", "update.prepare"],
            "detail": None,
        }

        backup = client.post(
            f"{settings.api_prefix}/system/operations",
            json={"action": "backup.create"},
            headers=headers,
        )
        assert backup.status_code == 200, backup.text
        payload = backup.json()
        assert payload["state"] == "completed", payload
        assert payload["result"]["status"] == "ok"
        assert payload["result"]["restored"] is True
        assert payload["result"]["files"] == 2
        artifact = payload["result"]["artifact"]
        assert artifact["verified"] is True
        assert "/" not in payload["reference"]
        archive = evidence / "backups" / artifact["name"]
        assert archive.is_file()
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == artifact["sha256"]
        assert artifact["bytes"] == archive.stat().st_size
        assert secret not in backup.text
        assert str(evidence) not in backup.text

        deployment = client.post(
            f"{settings.api_prefix}/system/operations",
            json={"action": "deployment.status"},
            headers=headers,
        )
        assert deployment.status_code == 200, deployment.text
        assert deployment.json()["state"] == "completed"
        assert deployment.json()["result"]["revision"] == "test-rev"

        seeded_status = client.get(f"{settings.api_prefix}/system/status", headers=headers)
        assert seeded_status.status_code == 200
        assert seeded_status.json()["ready"] is True


def test_executor_failure_and_invalid_output_never_report_success(
    evidence: Path,
    settings_factory: Callable[..., Settings],
    open_client: Callable[[Settings], TestClient],
) -> None:
    secret = "executor-secret-" + uuid4().hex
    actions = {
        "deployment.status": [sys.executable, str(evidence / "action.py"), "deployment.status"],
        "backup.create": write_action_script(evidence),
        "update.prepare": write_failing_action(evidence),
    }
    with running_executor(actions, secret) as url:
        settings = settings_factory(
            system_executor_url=url,
            system_executor_token=secret,
            system_executor_timeout_seconds=10,
        )
        _prepare_database(settings)
        Seeded(settings)
        client = open_client(settings)
        headers = login(client, settings, "root.super")
        failed = client.post(
            f"{settings.api_prefix}/system/operations",
            json={"action": "update.prepare"},
            headers=headers,
        )
        assert failed.status_code == 200, failed.text
        assert failed.json()["state"] == "failed"
        assert failed.json()["result"]["status"] == "failed"
        assert failed.json()["exitCode"] == 4

    invalid = write_failing_action(evidence, invalid_json=True)
    with running_executor(
        {
            "deployment.status": [sys.executable, str(evidence / "action.py"), "deployment.status"],
            "update.prepare": invalid,
        },
        secret,
    ) as url:
        settings = settings_factory(
            system_executor_url=url,
            system_executor_token=secret,
            system_executor_timeout_seconds=10,
        )
        _prepare_database(settings)
        Seeded(settings)
        client = open_client(settings)
        headers = login(client, settings, "root.super")
        result = client.post(
            f"{settings.api_prefix}/system/operations",
            json={"action": "update.prepare"},
            headers=headers,
        )
        assert result.status_code == 200, result.text
        # The second app reused the executor configured above; its URL is the
        # same loopback endpoint. Only a typed failure is acceptable.
        assert result.json()["state"] == "failed"
        assert result.json()["result"] is None
        assert "not a bounded result" not in result.text


def test_executor_unconfigured_unreachable_and_wrong_token_are_honest(
    evidence: Path,
    settings_factory: Callable[..., Settings],
    open_client: Callable[[Settings], TestClient],
) -> None:
    settings = settings_factory()
    _prepare_database(settings)
    Seeded(settings)
    client = open_client(settings)
    headers = login(client, settings, "root.super")
    unavailable = client.post(
        f"{settings.api_prefix}/system/operations",
        json={"action": "backup.create"},
        headers=headers,
    )
    assert unavailable.status_code == 200, unavailable.text
    assert unavailable.json()["state"] == "unavailable"
    assert unavailable.json()["result"] is None
    assert "not configured" in unavailable.json()["message"]

    dead = open_port()
    unreachable = settings_factory(
        system_executor_url=f"http://127.0.0.1:{dead}",
        system_executor_token="unused-secret-value",
        system_executor_timeout_seconds=1,
    )
    _prepare_database(unreachable)
    Seeded(unreachable)
    client = open_client(unreachable)
    headers = login(client, unreachable, "root.super")
    status = client.get(f"{unreachable.api_prefix}/system/status", headers=headers)
    assert status.json()["executor"]["configured"] is True
    assert status.json()["executor"]["available"] is False
    result = client.post(
        f"{unreachable.api_prefix}/system/operations",
        json={"action": "deployment.status"},
        headers=headers,
    )
    assert result.json()["state"] == "unavailable"
    assert "unused-secret" not in result.text

    secret = "executor-secret-" + uuid4().hex
    actions = {
        "deployment.status": [sys.executable, str(evidence / "action.py"), "deployment.status"],
        "backup.create": write_action_script(evidence),
    }
    with running_executor(actions, secret) as url:
        wrong = settings_factory(
            system_executor_url=url,
            system_executor_token="wrong-token-value-123",
            system_executor_timeout_seconds=5,
        )
        _prepare_database(wrong)
        Seeded(wrong)
        client = open_client(wrong)
        headers = login(client, wrong, "root.super")
        denied = client.post(
            f"{wrong.api_prefix}/system/operations",
            json={"action": "deployment.status"},
            headers=headers,
        )
        assert denied.json()["state"] == "unavailable"
        assert "wrong-token-value" not in denied.text
        assert (
            "wrong-token-value"
            not in client.get(f"{wrong.api_prefix}/system/status", headers=headers).text
        )


def test_executor_rejects_arguments_unknown_actions_and_does_not_follow_redirects(
    evidence: Path, settings_factory: Callable[..., Settings]
) -> None:
    secret = "executor-secret-" + uuid4().hex
    actions = {
        "deployment.status": [sys.executable, str(evidence / "action.py"), "deployment.status"],
        "backup.create": write_action_script(evidence),
    }
    with running_executor(actions, secret) as url:
        auth = {"Authorization": f"Bearer {secret}"}
        health = httpx.get(f"{url}/healthz", headers=auth, timeout=5)
        assert health.status_code == 200
        assert health.json()["actions"] == ["backup.create", "deployment.status"]
        assert (
            httpx.get(f"{url}/healthz", headers={"Authorization": "Bearer nope"}).status_code == 401
        )
        extra = httpx.post(
            f"{url}/v1/actions/backup.create",
            headers=auth,
            json={"argv": ["/bin/sh", "-c", "touch pwned"]},
            timeout=5,
        )
        assert extra.status_code == 400
        assert not (BACKEND_ROOT / "pwned").exists()
        unknown = httpx.post(f"{url}/v1/actions/shell.exec", headers=auth, json={}, timeout=5)
        assert unknown.status_code == 404
        missing = httpx.post(f"{url}/v1/actions/update.prepare", headers=auth, json={}, timeout=5)
        assert missing.status_code == 503
        assert "configured" in missing.text

        # A loopback redirector must never be followed by the backend client.
        hits: list[str] = []

        class RedirectHandler:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            def __call__(self, request: Any) -> bytes:
                hits.append(request.path)
                return b'{"redirect": true}'

        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                hits.append(self.path)
                self.send_response(302)
                self.send_header("Location", f"{url}/v1/actions/deployment.status")
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            redirect_url = f"http://127.0.0.1:{server.server_address[1]}"
            settings = settings_factory(
                system_executor_url=redirect_url,
                system_executor_token=secret,
                system_executor_timeout_seconds=5,
            )
            from itsm.system.executor import SystemExecutor

            outcome = SystemExecutor(settings).execute("deployment.status")
            assert outcome.state == "unavailable"
            assert hits == ["/v1/actions/deployment.status"]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def _machine_identity_id(session: Session) -> str:
    row = session.execute(select(Identity).where(Identity.username == "agent.system")).scalar_one()
    return str(row.id)


def _principal(
    factory: Callable[[], Session],
    settings: Settings,
    identity_id: str,
    *,
    scopes: frozenset[str] = frozenset(),
) -> Any:
    with factory() as session:
        return IdentityService(session, settings).resolve_actor(identity_id, scopes=scopes)


def test_executor_bounds_client_and_helper_output(
    evidence: Path, settings_factory: Callable[..., Settings]
) -> None:
    from itsm.system.executor import MAX_RESPONSE_BYTES, SystemExecutor

    secret = "executor-secret-" + uuid4().hex
    inherited, marker = write_inherited_pipe_action(evidence)
    actions = {
        "deployment.status": write_flooding_action(evidence),
        "backup.create": inherited,
    }
    with running_executor(actions, secret) as url:
        settings = settings_factory(
            system_executor_url=url,
            system_executor_token=secret,
            system_executor_timeout_seconds=5,
        )
        executor = SystemExecutor(settings)
        flooded = executor.execute("deployment.status")
        assert flooded.state == "failed"
        assert "output exceeded" in (flooded.message or "")
        assert flooded.result is None

        inherited_outcome = executor.execute("backup.create")
        assert inherited_outcome.state == "completed", inherited_outcome
        assert inherited_outcome.result is not None
        assert inherited_outcome.result["status"] == "ok"
        assert inherited_outcome.result["reference"] == "inherited"
        time.sleep(1)
        assert not marker.exists(), "a grandchild survived the action process group"

        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self._reply()

            def do_POST(self) -> None:
                self._reply()

            def _reply(self) -> None:
                body: bytes = self.server.body  # type: ignore[attr-defined]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                return

        fake = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        fake.body = b"[]"  # type: ignore[attr-defined]
        fake_thread = threading.Thread(target=fake.serve_forever, daemon=True)
        fake_thread.start()
        try:
            fake_url = f"http://127.0.0.1:{fake.server_address[1]}"
            fake_settings = settings_factory(
                system_executor_url=fake_url,
                system_executor_token=secret,
                system_executor_timeout_seconds=5,
            )
            fake_executor = SystemExecutor(fake_settings)
            invalid_health = fake_executor.availability()
            assert invalid_health["configured"] is True
            assert invalid_health["available"] is False
            assert "invalid health response" in invalid_health["detail"]

            fake.body = b"x" * (MAX_RESPONSE_BYTES + 1)  # type: ignore[attr-defined]
            oversized_health = fake_executor.availability()
            assert oversized_health["available"] is False
            assert "oversized" in oversized_health["detail"]
            oversized = fake_executor.execute("deployment.status")
            assert oversized.state == "failed"
            assert "oversized" in (oversized.message or "")
        finally:
            fake.shutdown()
            fake.server_close()
            fake_thread.join(timeout=5)


def test_system_authority_boundary_allows_only_superadmin_or_delegated_machine(
    seed: Seeded,
) -> None:
    from itsm.identity.service import PermissionDenied
    from itsm.system.service import SystemService

    settings = seed.settings
    factory = create_session_factory(create_engine_from_settings(settings))
    service = SystemService(settings, factory)
    superadmin = _principal(factory, settings, seed.superadmin_id)
    admin = _principal(factory, settings, seed.admin_id)
    auditor = _principal(factory, settings, seed.auditor_id)
    with factory() as session:
        machine_id = _machine_identity_id(session)
    machine = _principal(factory, settings, machine_id)

    assert service.status(superadmin)["executor"]["configured"] is False
    assert service.status(machine)["app"]["database"] == "sqlite"

    for principal in (admin, auditor):
        with pytest.raises(PermissionDenied):
            service.status(principal)
    scoped_machine = _principal(factory, settings, machine_id, scopes=frozenset({"assets.view"}))
    with pytest.raises(PermissionDenied):
        service.status(scoped_machine)
    scoped_system = _principal(factory, settings, machine_id, scopes=frozenset({"system.view"}))
    assert service.status(scoped_system)["executor"]["configured"] is False

    # Provider and configuration denials leave persisted state untouched.
    with pytest.raises(PermissionDenied):
        service.set_provider(admin, {"provider": "openai", "model": "gpt-4o-mini"})
    with pytest.raises(PermissionDenied):
        service.update_configuration(admin, {"deployment": {"classification": "production"}})
    assert service.providers(superadmin)["selected"] is None
    assert service.configuration(superadmin)["deployment"]["classification"] == "test"
    with factory() as session:
        denied = list(
            session.execute(
                select(IdentityAuditEvent).where(IdentityAuditEvent.outcome == "denied")
            ).scalars()
        )
        assert denied

    for token in (seed.rogue_token, seed.orphan_token, seed.retired_token):
        with factory() as session:
            context = IdentityService(session, settings).authenticate_token(token)
            with pytest.raises(PermissionDenied):
                service.status(context.principal)


def test_modules_use_system_modules_gate_and_keep_official_protection(
    seed: Seeded,
    open_client: Callable[[Settings], TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    settings = seed.settings
    client = open_client(settings)
    headers = login(client, settings, "root.super")
    listed = client.get(f"{settings.api_prefix}/system/modules", headers=headers)
    assert listed.status_code == 200, listed.text
    modules = listed.json()["modules"]
    assert any(module["id"] == "itsm" and module["official"] for module in modules)
    conflict = client.patch(
        f"{settings.api_prefix}/system/modules/itsm",
        json={"enabled": False},
        headers=headers,
    )
    assert conflict.status_code == 409, conflict.text

    machine_client = open_client(settings)
    delegated = machine_client.patch(
        f"{settings.api_prefix}/system/modules/itsm",
        json={"enabled": False},
        headers=bearer(seed.machine_token),
    )
    assert delegated.status_code == 409, delegated.text

    for username in ("ana.admin", "basic.user"):
        other = open_client(settings)
        denied = other.get(
            f"{settings.api_prefix}/system/modules",
            headers=login(other, settings, username),
        )
        assert denied.status_code == 403, denied.text

    rogue = open_client(settings)
    rogue_denied = rogue.patch(
        f"{settings.api_prefix}/system/modules/itsm",
        json={"enabled": False},
        headers=bearer(seed.rogue_token),
    )
    assert rogue_denied.status_code == 403, rogue_denied.text


def test_operations_deny_non_owner_and_unknown_action_without_execution(
    seed: Seeded, open_client: Callable[[Settings], TestClient]
) -> None:
    settings = seed.settings
    client = open_client(settings)
    headers = login(client, settings, "root.super")
    denied = client.post(
        f"{settings.api_prefix}/system/operations",
        json={"action": "backup.create"},
        headers=login(open_client(settings), settings, "ana.admin"),
    )
    assert denied.status_code == 403, denied.text
    unknown = client.post(
        f"{settings.api_prefix}/system/operations",
        json={"action": "deployment.run-anything"},
        headers=headers,
    )
    assert unknown.status_code == 422, unknown.text
    extra = client.post(
        f"{settings.api_prefix}/system/operations",
        json={"action": "backup.create", "command": "rm -rf /"},
        headers=headers,
    )
    assert extra.status_code == 422, extra.text


def _scripted(*parts: Any) -> Any:
    from pydantic_ai.messages import ModelMessage, ModelResponse, ToolReturnPart
    from pydantic_ai.models.function import AgentInfo

    def run(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        index = len(
            [
                part
                for message in messages
                for part in message.parts
                if isinstance(part, ToolReturnPart)
            ]
        )
        return ModelResponse(parts=list(parts[min(index, len(parts) - 1)]))

    return run


def test_integrated_runtime_tool_allows_owner_and_denies_admin(
    seed: Seeded,
    open_client: Callable[[Settings], TestClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pydantic_ai.models
    from itsm.agents.runtime import AgentRuntime
    from itsm.system.service import SystemService
    from pydantic_ai.messages import TextPart, ToolCallPart
    from pydantic_ai.models.function import FunctionModel

    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)
    settings = seed.settings
    factory = create_session_factory(create_engine_from_settings(settings))
    service = SystemService(settings, factory)

    for username, expected in (("root.super", "completed"), ("ana.admin", "denied")):
        client = open_client(settings)
        model = FunctionModel(
            _scripted(
                [ToolCallPart("get_system_status", {})],
                [TextPart("Listo.")],
            )
        )
        client.app.state.agent_runtime = AgentRuntime(  # type: ignore[attr-defined]
            settings, factory, model=model, system=service
        )
        headers = login(client, settings, username)
        response = client.post(
            f"{settings.api_prefix}/agent/chat",
            json={"message": "Revisá el estado del sistema."},
            headers=headers,
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["actions"] == [
            {"tool": "get_system_status", "status": expected, "assetIds": []}
        ]
        if expected == "completed":
            assert payload["results"][0]["executor"]["configured"] is False
        else:
            assert payload["results"] == []


def test_mounted_mcp_system_tools_revalidate_owner_and_delegated_denial(
    seed: Seeded,
    free_tcp_port: int,
) -> None:
    app = create_app(seed.settings)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=free_tcp_port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "uvicorn did not start"
    url = f"http://127.0.0.1:{free_tcp_port}/api/v1/mcp"

    async def owner_calls() -> tuple[list[str], Any, Any, Any]:
        transport = StreamableHttpTransport(
            url, headers={"Authorization": f"Bearer {seed.machine_token}"}
        )
        async with Client(transport) as client:
            tools = sorted(tool.name for tool in await client.list_tools())
            status = await client.call_tool("get_system_status", {})
            providers = await client.call_tool("list_system_providers", {})
            configured = await client.call_tool(
                "configure_system_provider",
                {"provider": "openai", "model": "gpt-4.1-mini"},
            )
        return tools, status, providers, configured

    async def denied_call() -> str:
        transport = StreamableHttpTransport(
            url, headers={"Authorization": f"Bearer {seed.rogue_token}"}
        )
        async with Client(transport) as client:
            try:
                await client.call_tool("get_system_status", {})
            except ToolError as exc:
                return str(exc)
        raise AssertionError("a machine delegated by a business admin must be denied")

    try:
        tools, status, providers, configured = asyncio.run(owner_calls())
        denied = asyncio.run(denied_call())
    finally:
        server.should_exit = True
        thread.join(timeout=10)
    assert {
        "get_system_status",
        "get_system_configuration",
        "list_system_providers",
        "configure_system_provider",
        "list_system_modules",
        "set_system_module",
        "prepare_system_update",
        "create_system_backup",
    } <= set(tools)
    assert status.data["ready"] is True
    assert providers.data["selected"] is None
    assert configured.data["selected"] == {"provider": "openai", "model": "gpt-4.1-mini"}
    assert "permission denied" in denied


def test_typed_system_tools_are_registered_for_agents_and_mcp() -> None:
    from itsm.agents.runtime import SYSTEM_TOOL_NAMES as RUNTIME_TOOLS
    from itsm.mcp.server import TOOL_NAMES as MCP_TOOLS

    expected = {
        "get_system_status",
        "get_system_configuration",
        "list_system_providers",
        "configure_system_provider",
        "list_system_modules",
        "set_system_module",
        "prepare_system_update",
        "create_system_backup",
    }
    assert set(RUNTIME_TOOLS) == expected
    assert expected <= set(MCP_TOOLS)
