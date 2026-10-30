"""Mode preparation through its actual one-shot CLI and isolated SQLite."""

import json
import os
import subprocess
import sys

import pytest


def prepare(tmp_path, mode):
    root = tmp_path / mode
    root.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("ITSM_")}
    env.update(
        RELEASE_MODE=mode,
        ITSM_DATABASE_URL=f"sqlite:///{root / 'app.db'}",
        ITSM_TASK_SQLITE_PATH=str(root / "tasks.db"),
        ITSM_ATTACHMENT_STORAGE_PATH=str(root / "attachments"),
        ITSM_DEMO_DATA_DIRECTORY=str(root),
        ITSM_DEV_ADMIN_PASSWORD="test-only-administrator-password",
        ITSM_OPS_BACKUP_ROOT=str(root / "backups"),
        ITSM_ENVIRONMENT="test",
    )
    return subprocess.run(
        [sys.executable, "-m", "itsm.deployment", "prepare"],
        env=env,
        capture_output=True,
        text=True,
        timeout=45,
    ), root


@pytest.mark.parametrize("mode", ["dev", "prod", "demo"])
def test_prepare_initializes_only_mode_owned_data_and_is_repeatable(tmp_path, mode):
    import sqlite3

    result, root = prepare(tmp_path, mode)
    assert result.returncode == 0, (result.stdout, result.stderr)
    payload = json.loads(result.stdout.splitlines()[-1])
    assert payload["mode"] == mode
    assert "test-only-administrator-password" not in result.stdout + result.stderr
    with sqlite3.connect(root / "app.db") as db:
        assert db.execute("SELECT release_mode FROM deployment_identity").fetchone()[0] == mode
        count = db.execute("SELECT count(*) FROM identity_identities").fetchone()[0]
        assert (count == 0) if mode == "prod" else (count >= 2)
    again, _ = prepare(tmp_path, mode)
    assert again.returncode == 0, (again.stdout, again.stderr)
    with sqlite3.connect(root / "app.db") as db:
        assert db.execute("SELECT count(*) FROM identity_identities").fetchone()[0] == count


def test_scheduled_backup_is_verified_before_retention(tmp_path, monkeypatch):
    from itsm.deployment import backup_cycle

    result, root = prepare(tmp_path, "prod")
    assert result.returncode == 0, result.stderr
    monkeypatch.setenv("RELEASE_MODE", "prod")
    monkeypatch.setenv("ITSM_DATABASE_URL", f"sqlite:///{root / 'app.db'}")
    monkeypatch.setenv("ITSM_OPS_BACKUP_ROOT", str(root / "backups"))
    outcome = backup_cycle()
    assert outcome["status"] == "ok"
    manifest = json.loads((root / "backups" / outcome["backupId"] / "manifest.json").read_text())
    assert manifest["verified"] is True
    assert manifest["size"] > 0


def test_prepare_invalid_mode_does_not_create_sqlite_file(tmp_path):
    result, root = prepare(tmp_path, "invalid")
    assert result.returncode != 0
    assert not (root / "app.db").exists()
