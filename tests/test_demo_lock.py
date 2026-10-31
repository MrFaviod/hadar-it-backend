"""One demo API process per owned directory, enforced by an advisory lock."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from itsm.main import create_app
from tests.test_demo_recover import canonical_demo_settings, recover_environment, run_recover


def test_second_api_process_on_the_same_directory_is_refused(
    settings_factory, monkeypatch, tmp_path
):
    settings = canonical_demo_settings(settings_factory, monkeypatch, tmp_path)
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/demo/status").status_code == 200
        with pytest.raises(RuntimeError) as refused, TestClient(create_app(settings)):
            pytest.fail("a second API process must not serve the same demo directory")
        message = str(refused.value)
        assert "another demo process" in message
        assert str(settings.demo_data_directory) in message
    # The lock is released with the process that owned it.
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/demo/status").status_code == 200


def test_recover_refuses_while_the_api_owns_the_directory(settings_factory, monkeypatch, tmp_path):
    settings = canonical_demo_settings(settings_factory, monkeypatch, tmp_path)
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/demo/status").status_code == 200
        result = run_recover(settings.demo_data_directory, recover_environment())
        assert result.returncode == 1
        payload = json.loads(result.stderr)
        assert payload["code"] == "demo_refused"
        assert "another demo process" in payload["message"]
        # The live process keeps serving; recovery touched nothing.
        assert client.get("/api/v1/demo/status").status_code == 200


def test_recover_works_after_the_api_stops(settings_factory, monkeypatch, tmp_path):
    settings = canonical_demo_settings(settings_factory, monkeypatch, tmp_path)
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/demo/status").status_code == 200
    result = run_recover(settings.demo_data_directory, recover_environment())
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "recovered"


def test_lock_file_is_created_inside_the_owned_directory(tmp_path: Path):
    from itsm.demo.lock import DemoDirectoryLock

    directory = tmp_path / "owned"
    directory.mkdir()
    lock = DemoDirectoryLock(directory)
    lock.acquire()
    try:
        assert (directory / "api.lock").read_text().strip() == str(os.getpid())
        with pytest.raises(RuntimeError):
            DemoDirectoryLock(directory).acquire()
    finally:
        lock.release()
    replacement = DemoDirectoryLock(directory)
    replacement.acquire()
    replacement.release()
