"""Delayed jobs: bounded scheduling, persistence and execution after restart."""

from __future__ import annotations

import time
from collections.abc import Callable

from fastapi.testclient import TestClient
from itsm.config import Settings
from tests.conftest import running_worker, wait_for_status


def test_delayed_job_survives_worker_restart(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(demo_max_delay_seconds=10)
    test_client = client(settings)

    response = test_client.post(
        "/api/v1/tasks/demo",
        json={"message": "diferido", "delay_seconds": 2},
    )

    assert response.status_code == 202, response.text
    accepted = response.json()
    assert accepted["state"] == "scheduled"
    task_id = accepted["task_id"]
    pending = test_client.get(f"/api/v1/tasks/{task_id}")
    assert pending.json()["state"] == "scheduled"

    # No worker is running: the schedule must live in the persistent queue file.
    time.sleep(2.5)
    assert test_client.get(f"/api/v1/tasks/{task_id}").json()["state"] == "scheduled"

    with running_worker(settings):
        completed = wait_for_status(test_client, task_id, {"complete"})

    assert completed["result"] == {"message": "diferido"}


def test_delay_above_the_configured_bound_is_rejected(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    test_client = client(settings_factory(demo_max_delay_seconds=5))

    response = test_client.post(
        "/api/v1/tasks/demo",
        json={"message": "demasiado tarde", "delay_seconds": 6},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_negative_delay_is_rejected(
    client: Callable[..., TestClient], settings_factory: Callable[..., Settings]
) -> None:
    test_client = client(settings_factory())

    response = test_client.post(
        "/api/v1/tasks/demo",
        json={"message": "ahora", "delay_seconds": -1},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
