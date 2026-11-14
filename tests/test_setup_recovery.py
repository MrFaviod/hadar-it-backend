"""Completion marker: finalize, fail-closed restores and recovery limits.

The installation row in the application database is the authority once setup is
complete. These tests pin the contract: /complete re-verifies server-side, the
marker survives a store that was never updated or was restored, the bootstrap
surface refuses every mutation, and the report carries no secrets.
"""

# ruff: noqa: F401, F811 - imported pytest fixtures are re-exported for this module

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.main import create_app
from itsm.release_identity import claim_identity
from itsm.setup.api import create_setup_app
from itsm.setup.store import SetupConfigurationError, SetupStore
from tests.conftest import (
    BACKEND_ROOT,
    bootstrap_superadmin,
    run_cli,
    run_migrations,
    running_worker,
    settings_factory,
)
from tests.test_setup_configuration import (
    API_KEY,
    CLAIM_PATH,
    CONFIGURATION_PATH,
    COOKIE_NAME,
    ORIGIN,
    OWNER_PASSWORD,
    OWNER_PATH,
    STATUS_PATH,
    STORAGE_PATH,
    TEST_KEY,
    VERIFY_PATH,
    app,
    apply_section,
    claim_session,
    clock,
    installation_path,
    owner_payload,
    post,
    prepare_green_configuration,
    provider,
    public_state,
    reach_owner_ready,
    setup_environment,
    start_configuration,
    state_dir,
    store,
)

COMPLETE_PATH = "/api/setup/v1/complete"
REPORT_PATH = "/api/setup/v1/report"
_ACTIVE_PROVIDER: Any = None


@pytest.fixture(autouse=True)
def configured_provider(setup_environment, provider, monkeypatch: pytest.MonkeyPatch):
    """Configure the fixture provider so ``ai_explicit`` can turn green."""

    global _ACTIVE_PROVIDER
    _ACTIVE_PROVIDER = provider
    monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
    monkeypatch.setenv("ITSM_AGENT_OPENAI_BASE_URL", provider.base_url)
    yield provider
    _ACTIVE_PROVIDER = None


def runtime_settings(database_url: str) -> Settings:
    """Settings for the worker and the normal API over the wizard's database."""

    return Settings(
        _env_file=None,
        environment="test",
        database_url=database_url,
        task_sqlite_path=Path(os.environ["ITSM_TASK_SQLITE_PATH"]),
        attachment_storage_path=Path(os.environ["ITSM_ATTACHMENT_STORAGE_PATH"]),
        auth_origin=ORIGIN,
        auth_cookie_secure=False,
    )


@contextmanager
def worker(database_url: str) -> Iterator[None]:
    """Run one real consumer, which must complete the setup ping itself."""

    task_path = Path(os.environ["ITSM_TASK_SQLITE_PATH"])
    task_path.parent.mkdir(parents=True, exist_ok=True)
    with running_worker(runtime_settings(database_url)):
        yield


def setup_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the operator CLI with the test installation environment."""

    return subprocess.run(
        [sys.executable, "-m", "itsm.setup.cli", *arguments],
        cwd=BACKEND_ROOT,
        env=dict(os.environ),
        capture_output=True,
        text=True,
        timeout=60,
    )


def marker_rows(database_url: str) -> list[tuple[Any, ...]]:
    path = database_url.removeprefix("sqlite:///")
    connection = sqlite3.connect(path)
    try:
        return connection.execute(
            "SELECT state, completed_at, completed_by, instance_id, "
            "setup_contract_version, report_digest FROM installation_setup"
        ).fetchall()
    finally:
        connection.close()


def table_names(database_url: str) -> set[str]:
    path = database_url.removeprefix("sqlite:///")
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        return {str(row[0]) for row in rows}
    finally:
        connection.close()


def reach_verifying(client: TestClient, setup_store: SetupStore, tmp_path: Path) -> tuple[str, str]:
    """Walk the wizard with a real worker and stop right after a green verify."""

    csrf, database_url = reach_owner_ready(client, setup_store, tmp_path, provider=_ACTIVE_PROVIDER)
    prepare_green_configuration(client, csrf, database_url)
    with worker(database_url):
        verified = post(client, VERIFY_PATH, {}, csrf)
        assert verified.status_code == 200, verified.text
    assert setup_store.public_state()["state"] == "verifying"
    return csrf, database_url


# ------------------------------------------------------------------ completion
def test_complete_writes_the_marker_and_disables_the_bootstrap(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, database_url = reach_verifying(client, store, tmp_path)
        preview = client.get(REPORT_PATH)
        assert preview.status_code == 200, preview.text
        assert preview.json()["state"] == "verifying"

        with worker(database_url):
            response = post(client, COMPLETE_PATH, {}, csrf)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["state"] == "complete"
        assert len(body["report_digest"]) == 64

        rows = marker_rows(database_url)
        assert len(rows) == 1
        state, completed_at, completed_by, instance_id, contract, digest = rows[0]
        assert state == "complete"
        assert completed_at
        assert completed_by
        assert instance_id
        assert contract == "1"
        assert digest == body["report_digest"]

        status = client.get(STATUS_PATH)
        assert status.status_code == 200
        snapshot = status.json()
        assert snapshot["state"] == "complete"
        assert snapshot["setup_enabled"] is False
        assert snapshot["claim_available"] is False
        assert "completed_by" not in json.dumps(snapshot)

        denied = post(client, "/api/setup/v1/ai", {}, csrf)
        assert denied.status_code == 409
        assert denied.json()["error"] == "setup_complete"
        assert client.get("/api/setup/v1/session").status_code == 401
        # After completion the report is only available through the operator CLI.
        assert client.get(REPORT_PATH).status_code in {401, 409}

    main = TestClient(create_app(runtime_settings(database_url)))
    with main:
        ready = main.get("/api/v1/health/ready")
        assert ready.status_code == 200, ready.text
        payload = ready.json()
    assert payload["installation_complete"] is True
    assert payload["installation_state"] == "complete"


def test_configuration_reads_are_closed_after_completion(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, database_url = reach_verifying(client, store, tmp_path)
        with worker(database_url):
            assert post(client, COMPLETE_PATH, {}, csrf).status_code == 200
        assert client.get(STATUS_PATH).json()["state"] == "complete"

        for path in (CONFIGURATION_PATH, f"{CONFIGURATION_PATH}/notifications"):
            denied = client.get(path)
            assert denied.status_code == 409, denied.text
            assert denied.json() == {"error": "setup_complete"}
            for leaked in ("channels", "secretRef", "chatId", "subjectPrefix", "profiles"):
                assert leaked not in denied.text


def test_complete_requires_a_green_verification(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, database_url = reach_verifying(client, store, tmp_path)

        # No worker is running now, so the server-side re-verification must fail
        # closed instead of trusting the stored receipt.
        refused = post(client, COMPLETE_PATH, {}, csrf)

        assert refused.status_code == 409
        assert refused.json()["error"] == "completion_blocked"
        assert marker_rows(database_url) == []
        assert store.public_state()["state"] == "verifying"


def test_complete_refuses_before_verifying(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, _database_url = reach_owner_ready(client, store, tmp_path)
        assert start_configuration(client, csrf).status_code == 200

        refused = post(client, COMPLETE_PATH, {}, csrf)

    assert refused.status_code == 409
    assert refused.json()["error"] == "state_refused"


def test_a_crash_between_the_row_and_the_store_restarts_complete(
    app, store, state_dir, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from itsm.setup import completion

    with TestClient(app, raise_server_exceptions=False) as client:
        csrf, database_url = reach_verifying(client, store, tmp_path)

        def interrupted(stage: str) -> None:
            if stage == "committed":
                raise RuntimeError("power loss")

        monkeypatch.setattr(completion, "_checkpoint", interrupted)
        with worker(database_url):
            response = post(client, COMPLETE_PATH, {}, csrf)

        assert response.status_code == 500
        assert len(marker_rows(database_url)) == 1
        assert store.public_state()["state"] == "verifying"

        monkeypatch.setattr(completion, "_checkpoint", lambda stage: None)
        restarted = create_setup_app(state_dir=state_dir, clock=clock)
        with TestClient(restarted) as second:
            snapshot = second.get(STATUS_PATH).json()
            assert snapshot["state"] == "complete"
            assert snapshot["setup_enabled"] is False
            denied = second.post(
                CLAIM_PATH, json={"credential": "irrelevant"}, headers={"Origin": ORIGIN}
            )
            assert denied.status_code == 409
            assert denied.json()["error"] == "setup_complete"

    recovered = setup_cli("recover")
    assert recovered.returncode == 1
    assert json.loads(recovered.stderr)["code"] == "installation_complete"


def test_a_restored_pre_complete_snapshot_cannot_reopen_claim_or_recovery(
    app, store, state_dir, tmp_path: Path
) -> None:
    with TestClient(app) as client:
        csrf, database_url = reach_verifying(client, store, tmp_path)
        journal = state_dir / "journal.jsonl"
        snapshot = {
            name: (state_dir / name).read_bytes()
            for name in ("state.json", "secrets.json", "journal.jsonl", "anchor.json")
            if (state_dir / name).exists()
        }
        assert journal.exists()

        with worker(database_url):
            assert post(client, COMPLETE_PATH, {}, csrf).status_code == 200

        for name, raw in snapshot.items():
            (state_dir / name).write_bytes(raw)
        assert public_state(state_dir)["state"] == "verifying"

        restarted = create_setup_app(state_dir=state_dir, clock=clock)
        with TestClient(restarted) as second:
            snapshot_status = second.get(STATUS_PATH).json()
            assert snapshot_status["state"] == "complete"
            assert snapshot_status["claim_available"] is False
            denied = second.post(
                CLAIM_PATH, json={"credential": "restored"}, headers={"Origin": ORIGIN}
            )
            assert denied.status_code == 409
            assert denied.json()["error"] == "setup_complete"
            assert second.get("/api/setup/v1/session").status_code == 401

    recovered = setup_cli("recover")
    assert recovered.returncode == 1
    payload = json.loads(recovered.stderr)
    assert payload["code"] == "installation_complete"
    assert "identity.cli" in payload["message"]


def test_a_database_with_an_owner_and_no_marker_is_installed(
    settings_factory, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clock
) -> None:
    settings = settings_factory()
    assert run_migrations(settings).returncode == 0
    bootstrap_superadmin(settings)
    from itsm.database import create_engine_from_settings, create_session_factory

    engine = create_engine_from_settings(settings)
    try:
        with create_session_factory(engine)() as session:
            claim_identity(session, "dev")
    finally:
        engine.dispose()
    monkeypatch.setenv("ITSM_DATABASE_URL", settings.database_url)

    private = tmp_path / "installed-state"
    local = SetupStore(private, clock=clock)
    local.ensure_ready()
    credential = local.enable_claim()
    setup_app = create_setup_app(state_dir=private, clock=clock)

    with TestClient(setup_app) as client:
        snapshot = client.get(STATUS_PATH).json()
        assert snapshot["state"] == "installed"
        assert snapshot["setup_enabled"] is False
        assert snapshot["claim_available"] is False
        denied = client.post(
            CLAIM_PATH, json={"credential": credential}, headers={"Origin": ORIGIN}
        )
        assert denied.status_code == 409
        assert denied.json()["error"] == "already_claimed"

    main = TestClient(create_app(runtime_settings(settings.database_url)))
    with main:
        ready = main.get("/api/v1/health/ready")
        assert ready.status_code == 200, ready.text
        payload = ready.json()
    assert payload["installation_complete"] is False
    assert payload["installation_state"] == "installed"


def test_repeated_completion_is_idempotent_and_writes_one_row(app, store, tmp_path: Path) -> None:
    from itsm.setup import completion

    with TestClient(app) as client:
        csrf, database_url = reach_verifying(client, store, tmp_path)
        with worker(database_url):
            first = post(client, COMPLETE_PATH, {}, csrf)
            assert first.status_code == 200, first.text
            repeated = post(client, COMPLETE_PATH, {}, csrf)

        assert repeated.status_code in {200, 409}
        assert len(marker_rows(database_url)) == 1

        again = completion.complete(store, "dev", environ=dict(os.environ))
        assert again["completed_at"] == first.json()["completed_at"]
        assert len(marker_rows(database_url)) == 1


def test_two_concurrent_completions_write_one_row(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, database_url = reach_verifying(client, store, tmp_path)

        def finish(_: int) -> int:
            return post(client, COMPLETE_PATH, {}, csrf).status_code

        with worker(database_url), ThreadPoolExecutor(max_workers=2) as pool:
            codes = list(pool.map(finish, range(2)))

        assert 200 in codes
        assert all(code in {200, 409} for code in codes)
        assert len(marker_rows(database_url)) == 1


def test_the_report_carries_no_secrets(app, store, tmp_path: Path) -> None:
    with TestClient(app) as client:
        csrf, database_url = reach_verifying(client, store, tmp_path)
        preview = client.get(REPORT_PATH)
        assert preview.status_code == 200, preview.text
        text = json.dumps(preview.json())
        for secret in (OWNER_PASSWORD, API_KEY, TEST_KEY, database_url):
            assert secret not in text

        with worker(database_url):
            assert post(client, COMPLETE_PATH, {}, csrf).status_code == 200

    reported = setup_cli("report")
    assert reported.returncode == 0, reported.stderr
    payload = json.loads(reported.stdout)
    report = payload["report"]
    assert report["state"] == "complete"
    assert report["report_digest"] == marker_rows(database_url)[0][5]
    for secret in (OWNER_PASSWORD, API_KEY, TEST_KEY, database_url):
        assert secret not in reported.stdout


# -------------------------------------------------------------------- migration
def test_the_installation_setup_migration_upgrades_and_downgrades(settings_factory) -> None:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    assert "installation_setup" in table_names(settings.database_url)

    downgraded = run_cli(
        [
            "-m",
            "alembic",
            "-c",
            str(BACKEND_ROOT / "alembic.ini"),
            "downgrade",
            "0045_machine_expiry",
        ],
        settings,
    )
    assert downgraded.returncode == 0, downgraded.stderr
    assert "installation_setup" not in table_names(settings.database_url)

    upgraded = run_migrations(settings)
    assert upgraded.returncode == 0, upgraded.stderr
    assert "installation_setup" in table_names(settings.database_url)


def test_demo_mode_offers_no_setup(monkeypatch: pytest.MonkeyPatch, state_dir: Path, clock) -> None:
    monkeypatch.setenv("RELEASE_MODE", "demo")

    with pytest.raises(SetupConfigurationError):
        create_setup_app(state_dir=state_dir, clock=clock)
