"""Organization identity: set once in setup, read by the app, never a preset side effect."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from itsm.appearance.api import create_appearance_router
from itsm.appearance.service import build_appearance_service
from itsm.identity.api import create_identity_router, install_error_handlers
from itsm.setup.api import create_setup_app
from itsm.setup.store import SetupStore
from tests.conftest import ADMIN_PASSWORD
from tests.inventory_support import ADMIN_USERNAME, Catalog, prepare, sign_in_as
from tests.test_setup_configuration import (
    CONFIGURATION_PATH,
    ORIGIN,
    TEST_KEY,
    FakeClock,
    appearance_rows,
    apply_section,
    post,
    reach_owner_ready,
    section_body,
    start_configuration,
)


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


@pytest.fixture
def catalog(settings_factory: Any, tmp_path: Path) -> Catalog:
    return prepare(
        settings_factory,
        attachment_storage_path=tmp_path / "blobs",
        auth_origin="http://testserver",
    )


def open_client(catalog: Catalog) -> TestClient:
    application = FastAPI()
    application.state.settings = catalog.settings
    application.state.session_factory = catalog.factory()
    application.state.appearance_service = build_appearance_service(
        catalog.settings, catalog.factory()
    )
    install_error_handlers(application)
    api = APIRouter(prefix=catalog.settings.api_prefix)
    api.include_router(create_identity_router())
    api.include_router(create_appearance_router())
    application.include_router(api)
    client = TestClient(application)
    client.__enter__()
    return client


# ------------------------------------------------------------------- wizard
def test_wizard_sets_organization_name_and_reads_it_back(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, database_url = reach_owner_ready(client, store, tmp_path)
        assert start_configuration(client, csrf).status_code == 200

        preview = post(
            client,
            f"{CONFIGURATION_PATH}/appearance",
            {"values": {"organizationName": "  Hadar\n  IT  "}},
            csrf,
        )
        body = section_body(preview)
        assert body["status"] == "preview"
        assert body["proposed"]["organizationName"] == "Hadar IT"
        assert body["changes"] == [
            {"field": "organizationName", "from": "Operaciones TI", "to": "Hadar IT"}
        ]
        assert appearance_rows(database_url) == []

        applied = apply_section(client, csrf, "appearance", {"organizationName": "Hadar IT"})
        body = section_body(applied)
        assert body["status"] == "passed"
        assert body["receipt"]["source"] == "set_organization"
        assert body["receipt"]["organizationName"] == "Hadar IT"
        assert body["receipt"]["active_id"] == "generic"

        rows = appearance_rows(database_url)
        assert len(rows) == 1
        assert rows[0].organization_name == "Hadar IT"

        read = client.get(f"{CONFIGURATION_PATH}/appearance").json()
        assert read["current"]["preset"] == "generic"
        assert read["current"]["organizationName"] == "Hadar IT"


def test_organization_survives_a_later_preset_change(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, _database_url = reach_owner_ready(client, store, tmp_path)
        assert start_configuration(client, csrf).status_code == 200

        applied = apply_section(
            client, csrf, "appearance", {"preset": "blue", "organizationName": "Hadar IT"}
        )
        body = section_body(applied)
        assert body["receipt"]["source"] == "apply_preset+set_organization"
        assert body["receipt"]["active_id"] == "blue"
        assert body["receipt"]["organizationName"] == "Hadar IT"

        applied = apply_section(client, csrf, "appearance", {"preset": "forest"})
        body = section_body(applied)
        assert body["receipt"]["source"] == "apply_preset"

        read = client.get(f"{CONFIGURATION_PATH}/appearance").json()
        assert read["current"]["preset"] == "forest"
        assert read["current"]["organizationName"] == "Hadar IT"


def test_invalid_organization_names_are_refused_without_writing(app, store, tmp_path: Path) -> None:
    with TestClient(app, raise_server_exceptions=False) as client:
        csrf, database_url = reach_owner_ready(client, store, tmp_path)
        assert start_configuration(client, csrf).status_code == 200

        for value in ("", "   ", "x" * 121, "Hadar <IT>", "Hadar; IT"):
            refused = apply_section(client, csrf, "appearance", {"organizationName": value})
            assert refused.status_code == 422, (value, refused.text)
        refused = apply_section(client, csrf, "appearance", {})
        assert refused.status_code == 422
        assert appearance_rows(database_url) == []

        accepted = apply_section(client, csrf, "appearance", {"organizationName": " Hadar\n\tIT "})
        body = section_body(accepted)
        assert body["receipt"]["organizationName"] == "Hadar IT"


# --------------------------------------------------------------- app reads
def test_authenticated_app_reads_only_the_organization_name(catalog: Catalog) -> None:
    service = build_appearance_service(catalog.settings, catalog.factory())
    service.set_organization(catalog.admin(), "Hadar IT")
    client = open_client(catalog)
    try:
        prefix = catalog.settings.api_prefix
        assert client.get(f"{prefix}/appearance/organization").status_code == 401

        headers = sign_in_as(client, catalog.settings, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.get(f"{prefix}/appearance/organization", headers=headers)
        assert response.status_code == 200, response.text
        assert response.json() == {"organizationName": "Hadar IT"}

        active = client.get(f"{prefix}/appearance/active")
        assert active.status_code == 200
        assert active.json()["active"]["branding"]["organizationName"] == "Hadar IT"
    finally:
        client.__exit__(None, None, None)
