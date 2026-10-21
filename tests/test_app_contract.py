"""Deployment contract: ASGI export, queue directory creation, storage errors."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.main import app as module_app
from itsm.tasks import create_task_queue


def test_module_exposes_the_asgi_app_for_uvicorn() -> None:
    assert isinstance(module_app, FastAPI)


def test_sqlite_queue_directory_is_created_on_demand(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    nested = tmp_path / "persistent" / "tasks" / "huey.db"
    queue = create_task_queue(settings_factory(task_sqlite_path=nested))

    status = queue.submit_demo("mkdir")

    assert nested.parent.is_dir()
    assert queue.get_status(status.task_id) is not None


def test_unusable_queue_storage_returns_service_unavailable(
    client: Callable[..., TestClient], settings_factory: Callable[..., Settings]
) -> None:
    # /proc cannot be created or written, so the queue directory is unusable.
    settings = settings_factory(task_sqlite_path=Path("/proc/itsm-tasks/huey.db"))
    test_client = client(settings)

    response = test_client.post("/api/v1/tasks/demo", json={"message": "ping"})

    assert response.status_code == 503, response.text
    assert response.json()["error"]["code"] == "unavailable"
    assert "itsm-tasks" not in response.text
