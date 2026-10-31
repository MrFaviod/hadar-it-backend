"""Recovery from a reset that failed halfway must be an explicit, working command."""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from itsm.main import create_app
from tests.conftest import run_migrations


def canonical_demo_settings(settings_factory, monkeypatch, tmp_path):
    """The demo layout the compose overlay and the recover command share."""
    monkeypatch.setenv("RELEASE_MODE", "demo")
    root = tmp_path / "demo"
    root.mkdir()
    settings = settings_factory(
        database_url=f"sqlite:///{root / 'demo.db'}",
        task_sqlite_path=root / "tasks" / "huey.db",
        attachment_storage_path=root / "attachments",
        demo_data_directory=root,
    )
    assert run_migrations(settings).returncode == 0
    return settings


def fail_next_reset(monkeypatch):
    """Delete the dataset, then fail before reseeding, like a mid-reset crash."""

    def broken_seed(*args, **kwargs):
        raise RuntimeError("simulated seed failure")

    monkeypatch.setattr("itsm.demo.reset.seed", broken_seed)


def force_due_tick(client) -> None:
    from datetime import datetime, timedelta

    first = client.get("/api/v1/demo/status").json()
    due = datetime.fromisoformat(first["nextResetAt"]) + timedelta(seconds=1)
    client.portal.call(client.app.state.demo_controller.tick, due)


def recover_environment() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    env.pop("RELEASE_MODE", None)
    env.update(PYTHONPATH=str(Path(__file__).resolve().parents[1]), PYTHONDONTWRITEBYTECODE="1")
    return env


def run_recover(directory: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "itsm.demo", "recover", "--directory", str(directory)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_recover_clears_a_stuck_reset_and_the_demo_serves_again(
    settings_factory, monkeypatch, tmp_path, caplog
):
    from itsm.demo.seed import seed

    settings = canonical_demo_settings(settings_factory, monkeypatch, tmp_path)
    with TestClient(create_app(settings)) as client:
        from itsm.database import create_session_factory

        with create_session_factory(client.app.state.engine)() as session:
            seed(session, settings, "admin", "test-only-password-987")
        first = client.get("/api/v1/demo/status").json()
        fail_next_reset(monkeypatch)
        force_due_tick(client)
        assert client.get("/api/v1/demo/status").status_code == 503

    # The stuck flag survives the restart and the log names the exact recovery command.
    caplog.clear()
    with (
        caplog.at_level(logging.ERROR, logger="itsm.demo"),
        TestClient(create_app(settings)) as client,
    ):
        assert client.get("/api/v1/demo/status").status_code == 503
    stuck = [
        record for record in caplog.records if getattr(record, "event", "") == "demo.reset_stuck"
    ]
    assert stuck, caplog.text
    recovery = stuck[0].data["recovery"]
    assert recovery == f"python -m itsm.demo recover --directory {settings.demo_data_directory}"

    result = run_recover(settings.demo_data_directory, recover_environment())
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "recovered", payload
    assert payload["cleared"] is True

    with TestClient(create_app(settings)) as client:
        status = client.get("/api/v1/demo/status")
        assert status.status_code == 200, status.text
        assert status.json()["generation"] == first["generation"] + 1
        assert status.json()["resetting"] is False
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"},
            headers={"Origin": settings.auth_origin},
        )
        assert login.status_code == 200, login.text


def test_recover_refuses_a_database_that_is_not_a_demo_installation(
    settings_factory, monkeypatch, tmp_path
):
    monkeypatch.setenv("RELEASE_MODE", "dev")
    root = tmp_path / "ordinary"
    root.mkdir()
    settings = settings_factory(
        database_url=f"sqlite:///{root / 'demo.db'}",
        task_sqlite_path=root / "tasks" / "huey.db",
        attachment_storage_path=root / "attachments",
        demo_data_directory=root,
    )
    assert run_migrations(settings).returncode == 0
    before = (root / "demo.db").read_bytes()
    result = run_recover(root, recover_environment())
    assert result.returncode == 1
    assert "demonstration" in result.stderr
    assert (root / "demo.db").read_bytes() == before


def test_recover_requires_the_demo_database_to_exist(tmp_path):
    directory = tmp_path / "missing"
    directory.mkdir()
    result = run_recover(directory, recover_environment())
    assert result.returncode == 1
    assert "does not exist" in result.stderr
