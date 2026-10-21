"""Demo task submission, execution and result retrieval through the public API."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from tests.conftest import EventCollector, run_migrations, running_worker, wait_for_status


def submit_demo(test_client: TestClient, message: str) -> dict[str, object]:
    response = test_client.post("/api/v1/tasks/demo", json={"message": message})
    assert response.status_code == 202, response.text
    return response.json()


def test_submit_accepts_bounded_echo_and_reports_pending_state(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
    events: EventCollector,
) -> None:
    test_client = client(settings_factory())

    accepted = submit_demo(test_client, "diagnostico")

    assert accepted["state"] == "pending"
    assert isinstance(accepted["task_id"], str) and accepted["task_id"]
    status = test_client.get(f"/api/v1/tasks/{accepted['task_id']}")
    assert status.status_code == 200
    assert status.json()["state"] == "pending"
    submitted = [event for event in events.events if event["event"] == "task.submitted"]
    assert submitted and submitted[-1]["task_id"] == accepted["task_id"]
    assert "message" not in submitted[-1]


def test_real_worker_executes_echo_and_result_survives_repeated_reads(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    migrated = run_migrations(settings)
    assert migrated.returncode == 0, migrated.stderr
    test_client = client(settings)
    task_id = str(submit_demo(test_client, "ping")["task_id"])

    with running_worker(settings):
        completed = wait_for_status(test_client, task_id, {"complete"})

    assert completed["result"] == {"message": "ping"}
    first = test_client.get(f"/api/v1/tasks/{task_id}")
    second = test_client.get(f"/api/v1/tasks/{task_id}")
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json() == completed


def test_unknown_task_returns_a_standard_error(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    test_client = client(settings_factory())

    response = test_client.get("/api/v1/tasks/0123456789abcdef0123456789abcdef")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


@pytest.mark.parametrize(
    "payload",
    [
        {"message": ""},
        {"message": "x" * 51},
        {"message": "hi", "task": "shell"},
        {"message": 17},
    ],
)
def test_invalid_payloads_are_rejected_without_queue_side_effects(
    payload: dict[str, object],
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
    events: EventCollector,
) -> None:
    test_client = client(settings_factory())

    response = test_client.post("/api/v1/tasks/demo", json=payload)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert not [event for event in events.events if event["event"] == "task.submitted"]
