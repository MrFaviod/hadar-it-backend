"""Wizard storage preparation and first-owner bootstrap, without adopting data.

The setup service chooses a database, migrates it, claims it for its own release
mode and creates the first human owner through the existing identity bootstrap.
These tests use a real SQLite file and, when Docker is available, a disposable
real PostgreSQL container. They never present one engine's result as another's.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.config import resolve_settings_sources
from itsm.identity.models import Identity
from itsm.release_identity import claim_identity, read_identity
from itsm.setup.api import create_setup_app
from itsm.setup.store import SetupStore
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

ORIGIN = "http://testserver"
COOKIE_NAME = "itsm_setup_session"
STATUS_PATH = "/api/setup/v1/status"
CLAIM_PATH = "/api/setup/v1/claim"
CHECK_PATH = "/api/setup/v1/storage/check"
STORAGE_PATH = "/api/setup/v1/storage"
OWNER_PATH = "/api/setup/v1/owner"
TEST_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
API_KEY = "sk-test-provider-key-1234567890"
OWNER_PASSWORD = "correct-horse-battery-staple"
OWNER_USERNAME = "ada"
OWNER_NAME = "Ada Lovelace"
PG_IMAGE = "postgres:16.13-bookworm"


class FakeClock:
    """Controllable UTC clock shared with the setup store."""

    def __init__(self) -> None:
        self.now = datetime(2026, 1, 13, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: int) -> None:
        self.now += timedelta(**kwargs)


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
    monkeypatch: pytest.MonkeyPatch, state_dir: Path, installation_path: Path
) -> None:
    monkeypatch.setenv("ITSM_SETUP_STATE_DIR", str(state_dir))
    monkeypatch.setenv("RELEASE_MODE", "dev")
    monkeypatch.setenv("ITSM_AUTH_COOKIE_SECURE", "false")
    monkeypatch.setenv("ITSM_AUTH_ORIGIN", ORIGIN)
    monkeypatch.setenv("ITSM_INSTALLATION_CONFIG", str(installation_path))
    monkeypatch.setenv("ITSM_AI_CREDENTIAL_KEYS", TEST_KEY)
    monkeypatch.setenv("ITSM_AI_PERSONAL_PRIVATE_ENDPOINTS", "127.0.0.1/32")
    for name in (
        "ITSM_SETUP_ALLOWED_ORIGINS",
        "ITSM_DATABASE_URL",
        "ITSM_AI_CREDENTIAL_KEY",
        "ITSM_DEV_ADMIN_PASSWORD",
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


def claim_session(client: TestClient, store: SetupStore) -> str:
    """Claim the installation and return the CSRF value for later mutations."""

    credential = store.enable_claim()
    response = client.post(CLAIM_PATH, json={"credential": credential}, headers={"Origin": ORIGIN})
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def post(
    client: TestClient,
    path: str,
    payload: dict[str, Any],
    csrf: str,
    *,
    cookie: str | None = None,
):
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    cookies = {COOKIE_NAME: cookie} if cookie else None
    return client.post(path, json=payload, headers=headers, cookies=cookies)


def prepare_storage(client: TestClient, csrf: str, database_url: str):
    return post(client, STORAGE_PATH, {"database_url": database_url}, csrf)


def public_state(state_dir: Path) -> dict[str, Any]:
    return json.loads((state_dir / "state.json").read_text(encoding="utf-8"))


def journal_text(state_dir: Path) -> str:
    path = state_dir / "journal.jsonl"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def identity_count(database_url: str) -> tuple[int, int]:
    """Return (identities, deployment identity rows) straight from the database."""

    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            identities = connection.execute(
                text("select count(*) from identity_identities")
            ).scalar_one()
            claimed = connection.execute(
                text("select count(*) from deployment_identity")
            ).scalar_one()
        return int(identities), int(claimed)
    finally:
        engine.dispose()


def owner_rows(database_url: str) -> list[Identity]:
    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            return list(session.scalars(select(Identity)))
    finally:
        engine.dispose()


def create_claimed_database(database_url: str, mode: str = "dev") -> None:
    """A migrated database already claimed by another release mode."""

    from itsm.devtools.database import migrate_to_head

    settings = resolve_settings_sources({"ITSM_DATABASE_URL": database_url, "RELEASE_MODE": "dev"})
    migrate_to_head(settings)
    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            claim_identity(session, mode)
            session.commit()
    finally:
        engine.dispose()


def create_unmarked_nonempty_database(database_url: str) -> None:
    """A database that holds accounts but carries no deployment identity."""

    from itsm.devtools.database import migrate_to_head

    settings = resolve_settings_sources({"ITSM_DATABASE_URL": database_url, "RELEASE_MODE": "dev"})
    migrate_to_head(settings)
    engine = create_engine(database_url)
    now = datetime.now(UTC)
    try:
        connection = engine.connect()
        try:
            connection.execute(
                text(
                    "insert into identity_identities "
                    "(id, username, name, actor_kind, active, password_hash, role_id, "
                    "created_at, updated_at) values "
                    "('existing-1', 'legacy', 'Legacy', 'human', 1, NULL, 'superadmin', "
                    ":now, :now)"
                ),
                {"now": now},
            )
            connection.commit()
        finally:
            connection.close()
    finally:
        engine.dispose()


def seed_configured_ai(store: SetupStore, base_url: str = "http://127.0.0.1:9/v1") -> None:
    """Record a sealed early provider without any network probe."""

    from itsm.setup import assistant
    from itsm.setup.store import SetupSettings

    settings = SetupSettings.from_environ()
    ciphertext = assistant.seal_provider_key(settings, API_KEY)
    store.record_ai_configured(
        ciphertext=ciphertext,
        base_url=base_url,
        model="fixture-model",
        scope="personal",
        key_fingerprint=assistant.key_fingerprint(settings),
        receipt={"status": "configured", "pending": False, "provider": "127.0.0.1"},
        discovered_models=None,
    )


# --------------------------------------------------------------- check: empty
def test_check_reports_an_empty_sqlite_database(app, store, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'new.db'}"
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)
        response = post(client, CHECK_PATH, {"database_url": database_url}, csrf)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["reachable"] is True
        assert body["engine"] == "sqlite"
        assert body["status"] == "empty"
        assert body["adoptable"] is True
        assert body["identity"] is None
        assert str(tmp_path) not in response.text
        assert "password" not in response.text.lower()


def test_check_requires_the_ai_states(app, store, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'new.db'}"
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        response = post(client, CHECK_PATH, {"database_url": database_url}, csrf)
        assert response.status_code == 409
        assert response.json()["error"] == "state_refused"


def test_check_refuses_unsupported_engines(app, store) -> None:
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)
        response = post(client, CHECK_PATH, {"database_url": "mysql+pymysql://u:p@db/x"}, csrf)
        assert response.status_code == 422
        assert response.json()["error"] == "unsupported_engine"
        assert "p@" not in response.text


def test_check_reports_unreachable_without_details(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)
        response = post(
            client,
            CHECK_PATH,
            {"database_url": "postgresql+psycopg://u:topsecret@127.0.0.1:1/itsm"},
            csrf,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["reachable"] is False
        assert body["status"] == "unreachable"
        assert body["adoptable"] is False
        assert "topsecret" not in response.text


# ------------------------------------------------------------------ apply: ok
def test_apply_writes_a_private_file_migrates_and_claims(
    app, store, state_dir: Path, installation_path: Path, tmp_path: Path
) -> None:
    database_url = f"sqlite:///{tmp_path / 'app.db'}"
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)
        response = prepare_storage(client, csrf, database_url)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["state"] == "storage_ready"
        assert body["storage"]["engine"] == "sqlite"
        assert body["storage"]["status"] == "ours"
        assert body["storage"]["config_source"] == "installation"
        assert body["storage"]["migrated"] is True

        status = client.get(STATUS_PATH)
        assert status.json()["state"] == "storage_ready"

    mode = stat.S_IMODE(installation_path.stat().st_mode)
    assert mode == 0o600
    assert stat.S_IMODE(installation_path.parent.stat().st_mode) == 0o700
    payload = json.loads(installation_path.read_text(encoding="utf-8"))
    assert payload == {"database_url": database_url}

    identities, claims = identity_count(database_url)
    assert identities == 0
    assert claims == 1
    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            row = read_identity(session)
            assert row is not None
            assert row.release_mode == "dev"
    finally:
        engine.dispose()

    journal = journal_text(state_dir)
    assert "apply-storage" in journal
    assert database_url not in journal
    assert str(tmp_path) not in journal


def test_a_planted_symlink_at_the_installation_file_is_refused(
    installation_path: Path, tmp_path: Path
) -> None:
    from itsm.setup.storage import write_installation_database_url
    from itsm.setup.store import SetupConfigurationError

    target = tmp_path / "elsewhere.json"
    target.write_text('{"database_url": "sqlite:///planted.db"}\n', encoding="utf-8")
    os.chmod(target, 0o600)
    installation_path.symlink_to(target)

    with pytest.raises(SetupConfigurationError):
        write_installation_database_url(installation_path, "sqlite:///candidate.db")

    assert installation_path.is_symlink()
    assert json.loads(target.read_text(encoding="utf-8")) == {
        "database_url": "sqlite:///planted.db"
    }

    # A dangling link is still a link: it must be refused, never replaced.
    installation_path.unlink()
    missing = tmp_path / "missing.json"
    installation_path.symlink_to(missing)
    with pytest.raises(SetupConfigurationError):
        write_installation_database_url(installation_path, "sqlite:///candidate.db")

    assert installation_path.is_symlink()
    assert not missing.exists()


def test_apply_is_idempotent_and_a_restart_keeps_the_state(
    app, store, state_dir: Path, clock: FakeClock, tmp_path: Path
) -> None:
    database_url = f"sqlite:///{tmp_path / 'app.db'}"
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)
        first = prepare_storage(client, csrf, database_url)
        assert first.status_code == 200
        second = prepare_storage(client, csrf, database_url)
        assert second.status_code == 200, second.text
        assert second.json()["state"] == "storage_ready"

    restarted = create_setup_app(state_dir=state_dir, clock=clock)
    with TestClient(restarted) as client:
        assert client.get(STATUS_PATH).json()["state"] == "storage_ready"


def test_check_reports_ours_after_apply(app, store, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'app.db'}"
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)
        assert prepare_storage(client, csrf, database_url).status_code == 200
        response = post(client, CHECK_PATH, {"database_url": database_url}, csrf)
        assert response.status_code == 200
        assert response.json()["status"] == "ours"
        assert response.json()["identity"] == "dev"
        assert response.json()["adoptable"] is True


def test_environment_database_wins_and_the_file_is_not_written(
    app,
    store,
    monkeypatch: pytest.MonkeyPatch,
    installation_path: Path,
    tmp_path: Path,
) -> None:
    candidate = f"sqlite:///{tmp_path / 'candidate.db'}"
    external = f"sqlite:///{tmp_path / 'external.db'}"
    monkeypatch.setenv("ITSM_DATABASE_URL", external)
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)
        response = prepare_storage(client, csrf, candidate)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["storage"]["config_source"] == "external"
        assert body["state"] == "storage_ready"

    assert not installation_path.exists()
    assert identity_count(external) == (0, 1)
    assert not (tmp_path / "candidate.db").exists()


def test_empty_database_url_is_refused(app, store) -> None:
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)
        response = post(client, STORAGE_PATH, {"database_url": ""}, csrf)
        assert response.status_code == 422
        assert response.json()["error"] == "invalid_request"


# ------------------------------------------------------------- refusals: data
def test_foreign_database_is_never_adopted(
    app, store, installation_path: Path, state_dir: Path, tmp_path: Path
) -> None:
    database_url = f"sqlite:///{tmp_path / 'foreign.db'}"
    create_claimed_database(database_url, mode="prod")
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)
        check = post(client, CHECK_PATH, {"database_url": database_url}, csrf)
        assert check.status_code == 200
        assert check.json()["status"] == "foreign"
        assert check.json()["identity"] == "prod"
        assert check.json()["adoptable"] is False

        response = prepare_storage(client, csrf, database_url)
        assert response.status_code == 409
        body = response.json()
        assert body["error"] == "database_not_adoptable"
        assert body.get("guidance")

    assert not installation_path.exists()
    assert public_state(state_dir)["state"] == "ai_deferred"
    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            assert read_identity(session).release_mode == "prod"
    finally:
        engine.dispose()


def test_unmarked_nonempty_database_is_never_adopted(
    app, store, installation_path: Path, tmp_path: Path
) -> None:
    database_url = f"sqlite:///{tmp_path / 'legacy.db'}"
    create_unmarked_nonempty_database(database_url)
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)
        response = prepare_storage(client, csrf, database_url)
        assert response.status_code == 409
        assert response.json()["error"] == "database_not_adoptable"

    assert not installation_path.exists()
    identities, claims = identity_count(database_url)
    assert identities == 1
    assert claims == 0


# ------------------------------------------------------------ crash: migrate
def test_a_crash_after_migration_is_retried_without_duplicates(
    app, store, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from itsm.setup import storage

    database_url = f"sqlite:///{tmp_path / 'app.db'}"
    with TestClient(app, raise_server_exceptions=False) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)

        def crash(stage: str) -> None:
            if stage == "migrated":
                raise RuntimeError("simulated crash after migrations")

        monkeypatch.setattr(storage, "_checkpoint", crash)
        failed = prepare_storage(client, csrf, database_url)
        assert failed.status_code == 500, failed.text
        assert public_state(store.state_dir)["state"] == "ai_deferred"

        monkeypatch.setattr(storage, "_checkpoint", None)
        retry = prepare_storage(client, csrf, database_url)
        assert retry.status_code == 200, retry.text
        assert retry.json()["state"] == "storage_ready"

    assert identity_count(database_url) == (0, 1)


# ------------------------------------------------------------- settings seam
def test_installation_file_values_lose_to_the_environment(
    installation_path: Path, tmp_path: Path
) -> None:
    installation_path.write_text(
        json.dumps({"database_url": f"sqlite:///{tmp_path / 'file.db'}"}),
        encoding="utf-8",
    )
    os.chmod(installation_path, 0o600)
    from_file = resolve_settings_sources({}, installation_path=installation_path)
    assert from_file.database_url == f"sqlite:///{tmp_path / 'file.db'}"
    override = f"sqlite:///{tmp_path / 'env.db'}"
    from_environment = resolve_settings_sources(
        {"ITSM_DATABASE_URL": override}, installation_path=installation_path
    )
    assert from_environment.database_url == override


def test_empty_environment_value_is_present_and_beats_the_installation_file(
    installation_path: Path, tmp_path: Path
) -> None:
    installation_path.write_text(
        json.dumps({"database_url": f"sqlite:///{tmp_path / 'file.db'}"}),
        encoding="utf-8",
    )
    os.chmod(installation_path, 0o600)
    with pytest.raises(Exception) as caught:
        resolve_settings_sources({"ITSM_DATABASE_URL": ""}, installation_path=installation_path)
    assert "database_url" in str(caught.value)


# --------------------------------------------------------------------- owner
def storage_ready(app, store, tmp_path: Path, client: TestClient) -> tuple[str, str]:
    database_url = f"sqlite:///{tmp_path / 'app.db'}"
    csrf = claim_session(client, store)
    post(client, "/api/setup/v1/ai/defer", {}, csrf)
    response = prepare_storage(client, csrf, database_url)
    assert response.status_code == 200, response.text
    return csrf, database_url


def owner_payload(**overrides: Any) -> dict[str, Any]:
    payload = {
        "username": OWNER_USERNAME,
        "display_name": OWNER_NAME,
        "email": "ada@example.com",
        "password": OWNER_PASSWORD,
    }
    payload.update(overrides)
    return payload


def test_owner_is_created_once_with_the_existing_bootstrap(
    app, store, state_dir: Path, tmp_path: Path
) -> None:
    with TestClient(app) as client:
        csrf, database_url = storage_ready(app, store, tmp_path, client)
        response = post(client, OWNER_PATH, owner_payload(), csrf)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["state"] == "owner_ready"
        assert body["owner"]["username"] == OWNER_USERNAME
        assert body["owner"]["display_name"] == OWNER_NAME

        replay = post(client, OWNER_PATH, owner_payload(), csrf)
        assert replay.status_code == 200, replay.text
        assert replay.json()["state"] == "owner_ready"

        status = client.get(STATUS_PATH)
        assert status.json()["state"] == "owner_ready"

    rows = owner_rows(database_url)
    assert len(rows) == 1
    owner = rows[0]
    assert owner.username == OWNER_USERNAME
    assert owner.name == OWNER_NAME
    assert owner.email == "ada@example.com"
    assert owner.actor_kind == "human"
    assert owner.role_id == "superadmin"
    assert owner.password_hash != OWNER_PASSWORD
    from itsm.identity.hashing import verify_password

    assert verify_password(owner.password_hash, OWNER_PASSWORD)

    secrets_text = (state_dir / "secrets.json").read_text(encoding="utf-8")
    state_text = (state_dir / "state.json").read_text(encoding="utf-8")
    journal = journal_text(state_dir)
    for text_value in (secrets_text, state_text, journal):
        assert OWNER_PASSWORD not in text_value
        assert owner.password_hash not in text_value


def test_owner_refuses_a_short_password(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, database_url = storage_ready(app, store, tmp_path, client)
        response = post(client, OWNER_PATH, owner_payload(password="short"), csrf)
        assert response.status_code == 422
        assert "short" not in response.text
        assert owner_rows(database_url) == []


def test_owner_refuses_when_a_human_already_exists(app, store, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'app.db'}"
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)
        assert prepare_storage(client, csrf, database_url).status_code == 200
        cookie = client.cookies.get(COOKIE_NAME)

    create_unmarked_nonempty_database(database_url)
    with TestClient(app) as client:
        response = post(client, OWNER_PATH, owner_payload(), csrf, cookie=cookie)
        assert response.status_code == 409
        assert response.json()["error"] == "owner_exists"
    assert len(owner_rows(database_url)) == 1


def test_two_concurrent_owner_requests_yield_one_success_one_refusal(
    app, store, tmp_path: Path
) -> None:
    from itsm.setup import owner as owner_service

    with TestClient(app) as client:
        csrf, database_url = storage_ready(app, store, tmp_path, client)
        cookie = client.cookies.get(COOKIE_NAME)

    reached = threading.Event()
    release = threading.Event()

    def hold_after_bootstrap(stage: str) -> None:
        if stage == "owner":
            reached.set()
            release.wait(10)

    owner_service._checkpoint = hold_after_bootstrap
    responses: list[int] = []

    def attempt() -> None:
        with TestClient(app) as worker:
            responses.append(
                post(worker, OWNER_PATH, owner_payload(), csrf, cookie=cookie).status_code
            )

    try:
        first = threading.Thread(target=attempt)
        first.start()
        assert reached.wait(10), "the first owner request never reached bootstrap"
        second = threading.Thread(target=attempt)
        second.start()
        time.sleep(0.2)
        release.set()
        first.join(timeout=20)
        second.join(timeout=20)
    finally:
        owner_service._checkpoint = None

    assert sorted(responses) == [200, 409], responses
    rows = owner_rows(database_url)
    assert len(rows) == 1


# ------------------------------------------------------------- provider move
def configure_ai_without_network(store: SetupStore) -> None:
    seed_configured_ai(store)


def test_provider_transfer_creates_one_canonical_row_then_deletes_the_copy(
    app, store, state_dir: Path, tmp_path: Path
) -> None:
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        configure_ai_without_network(store)
        database_url = f"sqlite:///{tmp_path / 'app.db'}"
        assert prepare_storage(client, csrf, database_url).status_code == 200
        response = post(client, OWNER_PATH, owner_payload(), csrf)
        assert response.status_code == 200, response.text
        assert response.json()["ai"] == "transferred"

        status = client.get(STATUS_PATH)
        assert status.json()["state"] == "owner_ready"
        assert API_KEY not in status.text

        replay = post(client, OWNER_PATH, owner_payload(), csrf)
        assert replay.status_code == 200, replay.text
        assert replay.json()["ai"] == "transferred"

    from itsm.agent_integrations.models import AgentProvider

    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            providers = list(session.scalars(select(AgentProvider)))
            owners = list(session.scalars(select(Identity)))
        assert len(providers) == 1
        provider = providers[0]
        assert provider.scope == "personal"
        assert provider.owner_id == owners[0].id
        assert provider.base_url == "http://127.0.0.1:9/v1"
        from itsm.agent_integrations.providers import unseal_credential
        from itsm.config import resolve_settings_sources as resolve

        runtime = resolve({}, installation_path=Path(os.environ["ITSM_INSTALLATION_CONFIG"]))
        assert unseal_credential(runtime, provider.api_key_ciphertext) == API_KEY
    finally:
        engine.dispose()

    private = json.loads((state_dir / "secrets.json").read_text(encoding="utf-8"))
    assert "ciphertext" not in json.dumps(private["ai"])
    secrets_text = (state_dir / "secrets.json").read_text(encoding="utf-8")
    journal = journal_text(state_dir)
    assert API_KEY not in secrets_text
    assert API_KEY not in journal
    assert API_KEY not in json.dumps(public_state(state_dir))


def test_crash_between_provider_create_and_delete_does_not_duplicate(
    app, store, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from itsm.setup import owner as owner_service

    with TestClient(app, raise_server_exceptions=False) as client:
        csrf = claim_session(client, store)
        configure_ai_without_network(store)
        database_url = f"sqlite:///{tmp_path / 'app.db'}"
        assert prepare_storage(client, csrf, database_url).status_code == 200

        def crash(stage: str) -> None:
            if stage == "provider_verified":
                raise RuntimeError("simulated crash before deleting the transient copy")

        monkeypatch.setattr(owner_service, "_checkpoint", crash)
        failed = post(client, OWNER_PATH, owner_payload(), csrf)
        assert failed.status_code == 500, failed.text

        monkeypatch.setattr(owner_service, "_checkpoint", None)
        retry = post(client, OWNER_PATH, owner_payload(), csrf)
        assert retry.status_code == 200, retry.text
        assert retry.json()["ai"] == "transferred"

    from itsm.agent_integrations.models import AgentProvider

    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            assert len(list(session.scalars(select(AgentProvider)))) == 1
    finally:
        engine.dispose()


def test_deferred_ai_stays_pending_after_the_owner_exists(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, _database_url = storage_ready(app, store, tmp_path, client)
        response = post(client, OWNER_PATH, owner_payload(), csrf)
        assert response.status_code == 200, response.text
        assert response.json()["ai"] == "pending"


def test_secrets_never_reach_the_status_or_the_journal(
    app, store, state_dir: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    database_url = f"sqlite:///{tmp_path / 'app.db'}"
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        configure_ai_without_network(store)
        assert prepare_storage(client, csrf, database_url).status_code == 200
        assert post(client, OWNER_PATH, owner_payload(), csrf).status_code == 200
        status = client.get(STATUS_PATH).text
    combined = "\n".join(
        [
            status,
            (state_dir / "state.json").read_text(encoding="utf-8"),
            journal_text(state_dir),
            caplog.text,
        ]
    )
    assert API_KEY not in combined
    assert OWNER_PASSWORD not in combined
    assert "gAAAA" not in combined


# -------------------------------------------------------------- real postgres
@pytest.fixture(scope="session")
def postgres_admin_url() -> Iterator[str]:
    """A disposable real PostgreSQL 16 container, never a shared service."""

    import shutil

    if shutil.which("docker") is None:
        pytest.skip("Docker is not installed, so real PostgreSQL cannot be exercised")
    name = f"itsm-t3-pg-{uuid.uuid4().hex[:8]}"
    password = uuid.uuid4().hex
    started = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "-e",
            f"POSTGRES_PASSWORD={password}",
            "-p",
            "127.0.0.1::5432",
            PG_IMAGE,
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if started.returncode != 0:
        pytest.skip(f"Docker cannot start PostgreSQL here: {started.stderr.strip()[:300]}")
    try:
        port_result = subprocess.run(
            ["docker", "port", name, "5432/tcp"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert port_result.returncode == 0, port_result.stderr
        port = port_result.stdout.strip().splitlines()[0].rsplit(":", 1)[1]
        admin_url = f"postgresql+psycopg://postgres:{password}@127.0.0.1:{port}/postgres"
        deadline = time.monotonic() + 90
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                engine = create_engine(admin_url)
                try:
                    with engine.connect() as connection:
                        connection.execute(text("select 1"))
                    break
                finally:
                    engine.dispose()
            except Exception as exc:  # the container is still starting
                last_error = exc
                time.sleep(1)
        else:
            pytest.fail(f"PostgreSQL did not become ready: {last_error}")
        yield admin_url
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)


@pytest.fixture
def postgres_url(postgres_admin_url: str) -> Iterator[str]:
    """One fresh database inside the disposable container for one test."""

    database = f"itsm_t3_{uuid.uuid4().hex[:12]}"
    engine = create_engine(postgres_admin_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{database}"'))
    finally:
        engine.dispose()
    return postgres_admin_url.rsplit("/", 1)[0] + "/" + database


def test_postgres_check_apply_and_claim_without_users(
    app, store, state_dir: Path, installation_path: Path, postgres_url: str
) -> None:
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)

        check = post(client, CHECK_PATH, {"database_url": postgres_url}, csrf)
        assert check.status_code == 200, check.text
        assert check.json()["reachable"] is True
        assert check.json()["engine"] == "postgresql"
        assert check.json()["status"] == "empty"
        assert check.json()["version"]

        response = prepare_storage(client, csrf, postgres_url)
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "storage_ready"
        assert response.json()["storage"]["engine"] == "postgresql"

        again = post(client, CHECK_PATH, {"database_url": postgres_url}, csrf)
        assert again.json()["status"] == "ours"
        assert again.json()["identity"] == "dev"

    payload = json.loads(installation_path.read_text(encoding="utf-8"))
    assert payload["database_url"] == postgres_url
    engine = create_engine(postgres_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(text("select count(*) from identity_identities")).scalar_one()
                == 0
            )
            row = connection.execute(
                text("select release_mode from deployment_identity where id = 1")
            ).one()
            assert row[0] == "dev"
    finally:
        engine.dispose()
    assert "apply-storage" in journal_text(state_dir)


def test_postgres_foreign_database_is_refused(
    app, store, installation_path: Path, postgres_url: str
) -> None:
    create_claimed_database(postgres_url, mode="prod")
    with TestClient(app) as client:
        csrf = claim_session(client, store)
        post(client, "/api/setup/v1/ai/defer", {}, csrf)
        check = post(client, CHECK_PATH, {"database_url": postgres_url}, csrf)
        assert check.status_code == 200, check.text
        assert check.json()["status"] == "foreign"
        assert check.json()["adoptable"] is False

        response = prepare_storage(client, csrf, postgres_url)
        assert response.status_code == 409
        assert response.json()["error"] == "database_not_adoptable"

    assert not installation_path.exists()
    engine = create_engine(postgres_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("select release_mode from deployment_identity where id = 1")
                ).scalar_one()
                == "prod"
            )
    finally:
        engine.dispose()
