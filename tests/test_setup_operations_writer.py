"""Gap B: the backup policy writer and the operational settings writer.

Two promises are exercised here end to end. A production backup policy can be
*declared* by the operator and read back from the installation database, so
``/verify`` satisfies ``backup_policy_declared`` honestly (the item says
``declared``, never ``observed``). And the operational section really applies a
validated origin/session change through the private installation file, reports
the effective value, says when an environment variable wins over the file, and
tells the operator that backend and worker need a restart.

The refusal paths matter as much as the happy path: an invalid policy, an
unknown setting key, a malformed origin and a planted symbolic link must all be
refused with the installation file and database left untouched.
"""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.setup.api import create_setup_app
from itsm.setup.store import SetupStore
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

ORIGIN = "http://testserver"
PUBLIC_ORIGIN = "https://assets2.example.com"
CLAIM_PATH = "/api/setup/v1/claim"
STORAGE_PATH = "/api/setup/v1/storage"
OWNER_PATH = "/api/setup/v1/owner"
CONFIGURATION_PATH = "/api/setup/v1/configuration"
VERIFY_PATH = "/api/setup/v1/verify"
TEST_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
OWNER_PASSWORD = "correct-horse-battery-staple"
OWNER_USERNAME = "ada"
OWNER_NAME = "Ada Lovelace"

POLICY = {
    "item": "backup_policy_declared",
    "target": "s3://hadar-backups/prod",
    "location_kind": "object_storage",
    "schedule": "daily 02:00 UTC",
    "retention": "30 days",
    "responsible": "platform team",
}


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 13, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


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
    monkeypatch.setenv("ITSM_ATTACHMENT_STORAGE_PATH", str(tmp_path / "attachments"))
    monkeypatch.setenv("ITSM_TASK_SQLITE_PATH", str(tmp_path / "tasks" / "huey.db"))
    for name in (
        "ITSM_SETUP_ALLOWED_ORIGINS",
        "ITSM_DATABASE_URL",
        "ITSM_AI_CREDENTIAL_KEY",
        "ITSM_DEV_ADMIN_PASSWORD",
        "ITSM_AGENT_MODEL",
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
    origin: str = ORIGIN,
):
    return client.post(
        path,
        json=payload,
        headers={"Origin": origin, "X-CSRF-Token": csrf},
    )


def reach_configuring(
    client: TestClient,
    store: SetupStore,
    tmp_path: Path,
    *,
    origin: str = ORIGIN,
    database_name: str = "app.db",
) -> str:
    csrf = claim_session(client, store, origin=origin)
    response = post(client, "/api/setup/v1/ai/defer", {}, csrf, origin=origin)
    assert response.status_code == 200, response.text
    database_url = f"sqlite:///{tmp_path / database_name}"
    response = post(client, STORAGE_PATH, {"database_url": database_url}, csrf, origin=origin)
    assert response.status_code == 200, response.text
    response = post(
        client,
        OWNER_PATH,
        {
            "username": OWNER_USERNAME,
            "display_name": OWNER_NAME,
            "email": "ada@example.com",
            "password": OWNER_PASSWORD,
        },
        csrf,
        origin=origin,
    )
    assert response.status_code == 200, response.text
    response = post(client, CONFIGURATION_PATH, {}, csrf, origin=origin)
    assert response.status_code == 200, response.text
    return csrf


def apply_operational(
    client: TestClient,
    csrf: str,
    values: dict[str, Any],
    *,
    action: str = "apply",
    confirm: bool = True,
    origin: str = ORIGIN,
):
    return post(
        client,
        f"{CONFIGURATION_PATH}/operational/apply",
        {"values": values, "action": action, "confirm": confirm},
        csrf,
        origin=origin,
    )


def preview_operational(
    client: TestClient, csrf: str, values: dict[str, Any], *, origin: str = ORIGIN
):
    return post(
        client, f"{CONFIGURATION_PATH}/operational", {"values": values}, csrf, origin=origin
    )


def installation_values(installation_path: Path) -> dict[str, Any]:
    return json.loads(installation_path.read_text(encoding="utf-8"))


def declared_rows(database_url: str) -> list[dict[str, Any]]:
    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            rows = session.execute(
                text(
                    "select target, location_kind, schedule, retention, responsible, "
                    "declared_by from installation_backup_policy"
                )
            ).mappings()
            return [dict(row) for row in rows]
    finally:
        engine.dispose()


def checklist_by_id(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in body["checklist"]}


# ------------------------------------------------------------------- backup
def test_backup_policy_is_previewed_declared_and_read_back(
    app, store, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RELEASE_MODE", "prod")
    monkeypatch.setenv("ITSM_AUTH_ORIGIN", "https://assets.example.com")
    monkeypatch.setenv("ITSM_AUTH_COOKIE_SECURE", "true")
    origin = "https://assets.example.com"
    prod_store = SetupStore(store.state_dir, release_mode="prod")
    prod_app = create_setup_app(state_dir=store.state_dir)
    with TestClient(prod_app, base_url="https://testserver") as client:
        csrf = reach_configuring(client, prod_store, tmp_path, origin=origin)
        database_url = f"sqlite:///{tmp_path / 'app.db'}"

        read = client.get(f"{CONFIGURATION_PATH}/operational")
        assert read.status_code == 200, read.text
        assert read.json()["current"]["backup_policy"] is None

        preview = preview_operational(client, csrf, POLICY, origin=origin)
        assert preview.status_code == 200, preview.text
        body = preview.json()
        assert body["status"] == "preview"
        assert body["preview_only"] is True
        assert {change["field"] for change in body["changes"]} >= {"target", "retention"}
        assert declared_rows(database_url) == []

        refused = apply_operational(
            client, csrf, POLICY, action="declare", confirm=False, origin=origin
        )
        assert refused.status_code == 422
        assert refused.json()["error"] == "confirmation_required"
        assert declared_rows(database_url) == []

        applied = apply_operational(client, csrf, POLICY, action="declare", origin=origin)
        assert applied.status_code == 200, applied.text
        body = applied.json()
        assert body["status"] == "declared"
        assert body["receipt"]["backup_policy"]["target"] == POLICY["target"]
        assert body["receipt"]["backup_policy"]["declared_by"] == OWNER_USERNAME

        rows = declared_rows(database_url)
        assert len(rows) == 1
        assert rows[0]["target"] == POLICY["target"]
        assert rows[0]["location_kind"] == POLICY["location_kind"]
        assert rows[0]["retention"] == POLICY["retention"]
        assert rows[0]["responsible"] == POLICY["responsible"]
        assert rows[0]["declared_by"] == OWNER_USERNAME

        read = client.get(f"{CONFIGURATION_PATH}/operational")
        assert read.status_code == 200, read.text
        current = read.json()["current"]["backup_policy"]
        assert current["target"] == POLICY["target"]
        assert current["location_kind"] == POLICY["location_kind"]
        assert current["declared_by"] == OWNER_USERNAME
        assert read.json()["status"] == "declared"

        blocked = post(client, VERIFY_PATH, {}, csrf, origin=origin)
        assert blocked.status_code == 409, blocked.text
        items = checklist_by_id(blocked.json())
        assert items["backup_policy_declared"]["required"] is True
        assert items["backup_policy_declared"]["status"] == "declared"
        assert items["backup_policy_declared"]["status"] != "passed"
        assert items["backup_policy_declared"]["blocking"] is False
        assert items["backup_policy_declared"]["acceptedRisk"] is False
        assert items["backup_policy_declared"]["evidence"].startswith("declared:")


def test_backup_policy_rejects_invalid_declarations(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf = reach_configuring(client, store, tmp_path)
        database_url = f"sqlite:///{tmp_path / 'app.db'}"

        for broken in (
            {**POLICY, "target": "   "},
            {**POLICY, "location_kind": "carrier_pigeon"},
            {**POLICY, "retention": "forever"},
            {**POLICY, "schedule": ""},
            {**POLICY, "responsible": "x" * 200},
        ):
            response = apply_operational(client, csrf, broken, action="declare")
            assert response.status_code == 422, (broken, response.text)
            assert response.json()["error"] == "configuration_invalid"
        assert declared_rows(database_url) == []

        no_item = apply_operational(client, csrf, {"target": "s3://x/y"}, action="declare")
        assert no_item.status_code == 422


# -------------------------------------------------------------- operational
def test_operational_apply_writes_file_and_reports_env_override(
    app,
    store,
    tmp_path: Path,
    installation_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with TestClient(app) as client:
        csrf = reach_configuring(client, store, tmp_path)
        database_url = installation_values(installation_path)["database_url"]

        preview = preview_operational(client, csrf, {"auth_origin": PUBLIC_ORIGIN})
        assert preview.status_code == 200, preview.text
        body = preview.json()
        assert body["status"] == "preview"
        assert body["changes"] == [{"field": "auth_origin", "from": ORIGIN, "to": PUBLIC_ORIGIN}]
        assert body["env_override"] == ["ITSM_AUTH_ORIGIN"]

        applied = apply_operational(client, csrf, {"auth_origin": PUBLIC_ORIGIN})
        assert applied.status_code == 200, applied.text
        body = applied.json()
        assert body["status"] == "applied"
        receipt = body["receipt"]
        assert receipt["written"] == ["auth_origin"]
        assert receipt["effective"]["auth_origin"]["value"] == ORIGIN
        assert receipt["effective"]["auth_origin"]["source"] == "env"
        assert receipt["overridden_by"] == ["ITSM_AUTH_ORIGIN"]
        assert receipt["restart_required"] is True
        assert receipt["restart_scope"] == ["backend", "worker"]
        assert "restart" in receipt["note"]

        values = installation_values(installation_path)
        assert values["auth_origin"] == PUBLIC_ORIGIN
        assert values["database_url"] == database_url
        mode = stat.S_IMODE(installation_path.stat().st_mode)
        assert mode == 0o600
        directory_mode = stat.S_IMODE(installation_path.parent.stat().st_mode)
        assert directory_mode == 0o700

        read = client.get(f"{CONFIGURATION_PATH}/operational")
        assert read.status_code == 200, read.text
        current = read.json()["current"]
        assert current["origin"] == ORIGIN
        assert current["settings"]["auth_origin"]["value"] == ORIGIN
        assert current["settings"]["auth_origin"]["source"] == "env"
        assert current["settings"]["auth_origin"]["overridden_by"] == "ITSM_AUTH_ORIGIN"
        assert current["restart_required"] is True
        assert current["restart_scope"] == ["backend", "worker"]

        monkeypatch.delenv("ITSM_AUTH_ORIGIN")
        read = client.get(f"{CONFIGURATION_PATH}/operational")
        assert read.status_code == 200, read.text
        current = read.json()["current"]
        assert current["origin"] == PUBLIC_ORIGIN
        assert current["settings"]["auth_origin"]["value"] == PUBLIC_ORIGIN
        assert current["settings"]["auth_origin"]["source"] == "installation"
        assert current["settings"]["auth_origin"]["overridden_by"] is None


def test_operational_apply_refuses_invalid_values_and_planted_links(
    app, store, tmp_path: Path, installation_path: Path
) -> None:
    with TestClient(app) as client:
        csrf = reach_configuring(client, store, tmp_path)
        original = installation_path.read_bytes()

        bad_origin = apply_operational(
            client, csrf, {"auth_origin": "https://assets.example.com/admin"}
        )
        assert bad_origin.status_code == 422
        assert bad_origin.json()["error"] == "configuration_invalid"

        unknown = apply_operational(client, csrf, {"database_url": "sqlite:///other.db"})
        assert unknown.status_code == 422
        assert installation_path.read_bytes() == original

        elsewhere = tmp_path / "elsewhere.json"
        elsewhere.write_text("{}", encoding="utf-8")
        installation_path.unlink()
        installation_path.symlink_to(elsewhere)
        planted = apply_operational(client, csrf, {"auth_origin": PUBLIC_ORIGIN})
        assert planted.status_code == 503
        assert planted.json()["error"] == "setup_configuration"
        assert elsewhere.read_text(encoding="utf-8") == "{}"
        assert installation_path.is_symlink()
