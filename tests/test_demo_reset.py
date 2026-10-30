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
            seed(session, settings, "admin", "test-only-password-987")
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"},
            headers={"Origin": settings.auth_origin},
        )
        assert login.status_code == 200, login.text
        first = client.get("/api/v1/demo/status").json()
        settings.attachment_storage_path.mkdir(parents=True)
        (settings.attachment_storage_path / "temporary.txt").write_text("temporary")
        with sqlite3.connect(settings.task_sqlite_path) as queue:
            queue.execute("CREATE TABLE queued(value TEXT)")
            queue.execute("INSERT INTO queued VALUES ('pending')")

        async def reset_under_gate():
            async with client.app.state.demo_controller.lock:
                reset_demo(settings, client.app.state.engine)

        client.portal.call(reset_under_gate)
        assert not list(settings.attachment_storage_path.iterdir())
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
        with sqlite3.connect(Path(settings.demo_data_directory) / "app.db") as database:
            assert database.execute("SELECT count(*) FROM assets").fetchone()[0] == 8


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
