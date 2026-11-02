"""Real shared demo reset, with isolated owned database and temporary files."""

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from itsm.main import create_app
from tests.conftest import run_migrations


def demo_settings(settings_factory, monkeypatch, tmp_path):
    monkeypatch.setenv("RELEASE_MODE", "demo")
    root = tmp_path / "demo-owned"
    root.mkdir()
    settings = settings_factory(
        database_url=f"sqlite:///{root / 'app.db'}",
        attachment_storage_path=root / "attachments",
        task_sqlite_path=root / "tasks.db",
        demo_data_directory=root,
    )
    assert run_migrations(settings).returncode == 0
    return settings


def test_reset_restores_dataset_files_jobs_and_invalidates_old_session(
    settings_factory, monkeypatch, tmp_path
):
    from itsm.database import create_session_factory
    from itsm.demo.cycle import reset_demo
    from itsm.demo.seed import seed

    settings = demo_settings(settings_factory, monkeypatch, tmp_path)
    with TestClient(create_app(settings)) as client:
        factory = create_session_factory(client.app.state.engine)
        with factory() as session:
            payload = seed(session, settings, "admin", "test-only-password-987")
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"},
            headers={"Origin": settings.auth_origin},
        )
        assert login.status_code == 200, login.text
        first = client.get("/api/v1/demo/status").json()
        settings.attachment_storage_path.mkdir(parents=True, exist_ok=True)
        (settings.attachment_storage_path / "temporary.txt").write_text("temporary")
        stale_blobs = {entry.name for entry in settings.attachment_storage_path.iterdir()}
        with sqlite3.connect(settings.task_sqlite_path) as queue:
            queue.execute("CREATE TABLE queued(value TEXT)")
            queue.execute("INSERT INTO queued VALUES ('pending')")

        async def reset_under_gate():
            gate = client.app.state.demo_controller.gate
            await gate.begin_reset()
            try:
                reset_demo(settings, client.app.state.engine)
            finally:
                gate.end_reset()

        client.portal.call(reset_under_gate)
        fresh_blobs = {entry.name for entry in settings.attachment_storage_path.iterdir()}
        assert fresh_blobs
        assert "temporary.txt" not in fresh_blobs
        assert stale_blobs.isdisjoint(fresh_blobs)
        with sqlite3.connect(settings.task_sqlite_path) as queue:
            assert queue.execute("SELECT count(*) FROM queued").fetchone()[0] == 0
        second = client.get("/api/v1/demo/status").json()
        assert second["generation"] == first["generation"] + 1
        assert second["resetting"] is False
        assert client.get("/api/v1/auth/me").status_code == 401
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"},
            headers={"Origin": settings.auth_origin},
        )
        assert login.status_code == 200, login.text
        assert login.json()["user"]["roleId"] == "admin"
        expected = payload["assets"] + payload["importSummary"]["created"]
        with sqlite3.connect(Path(settings.demo_data_directory) / "app.db") as database:
            assert database.execute("SELECT count(*) FROM assets").fetchone()[0] == expected


def test_reset_refuses_external_path_before_touching_database(
    settings_factory, monkeypatch, tmp_path
):
    from itsm.demo.cycle import reset_demo
    from itsm.release_identity import DeploymentIdentityError

    settings = demo_settings(settings_factory, monkeypatch, tmp_path)
    external = tmp_path / "unrelated"
    external.mkdir()
    sentinel = external / "keep"
    sentinel.write_text("unchanged")
    with TestClient(create_app(settings)) as client:
        client.get("/api/v1/demo/status")
        before = (settings.demo_data_directory / "app.db").read_bytes()
        settings.attachment_storage_path = external
        with pytest.raises(DeploymentIdentityError, match="owned"):
            reset_demo(settings, client.app.state.engine)
        assert (settings.demo_data_directory / "app.db").read_bytes() == before
        assert sentinel.read_text() == "unchanged"


def test_reset_regenerates_attachments_under_a_configured_descendant_path(
    settings_factory, monkeypatch, tmp_path
):
    """The configured owned attachment path is authoritative, not a fixed name."""

    from itsm.database import create_session_factory
    from itsm.demo.controller import DemoRequestGate
    from itsm.demo.cycle import reset_demo
    from itsm.demo.seed import seed

    settings = demo_settings(settings_factory, monkeypatch, tmp_path)
    root = settings.demo_data_directory
    assert root is not None
    blobs = root / "storage" / "blobs"
    configured = settings.model_copy(update={"attachment_storage_path": blobs})
    with TestClient(create_app(configured)) as client:
        engine = client.app.state.engine
        factory = create_session_factory(engine)
        with factory() as session:
            payload = seed(session, configured, "admin", "test-only-password-987")
        assert payload["attachments"] == 3
        assert not (root / "attachments").exists()
        stale = {entry.name for entry in blobs.iterdir()}
        assert stale

        async def run_reset() -> None:
            gate = DemoRequestGate()
            await gate.begin_reset()
            try:
                reset_demo(configured, engine)
            finally:
                gate.end_reset()

        client.portal.call(run_reset)
        fresh = {entry.name for entry in blobs.iterdir()}
        assert fresh
        assert stale.isdisjoint(fresh)


def test_seed_refuses_an_attachment_path_outside_the_demo_directory(
    settings_factory, monkeypatch, tmp_path
):
    """The seed never redirects writes silently, and never writes outside the demo."""
    from itsm.database import create_engine_from_settings, create_session_factory
    from itsm.demo.seed import seed
    from itsm.demo.telemetry import DemoRefused

    settings = demo_settings(settings_factory, monkeypatch, tmp_path)
    root = settings.demo_data_directory
    assert root is not None
    outside = tmp_path / "outside-blobs"
    configured = settings.model_copy(update={"attachment_storage_path": outside})
    engine = create_engine_from_settings(configured)
    try:
        with (
            create_session_factory(engine)() as session,
            pytest.raises(DemoRefused, match="inside the demo directory"),
        ):
            seed(session, configured, "admin", "test-only-password-987")
        assert not outside.exists()
        assert not (root / "attachments").exists()
    finally:
        engine.dispose()
