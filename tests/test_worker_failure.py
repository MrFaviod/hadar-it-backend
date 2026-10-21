"""Failed jobs: bounded retries, safe error reporting and CLI diagnostics."""

from __future__ import annotations

import json
import time
from collections.abc import Callable

from fastapi.testclient import TestClient
from itsm.config import Settings
from tests.conftest import run_cli, running_worker, wait_for_status


def submit_failure(settings: Settings, message: str) -> str:
    result = run_cli(
        ["-m", "itsm.tasks.cli", "submit-demo-failure", message],
        settings,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["state"] == "pending"
    return str(payload["task_id"])


def task_state(test_client: TestClient, task_id: str) -> dict[str, object]:
    response = test_client.get(f"/api/v1/tasks/{task_id}")
    assert response.status_code == 200, response.text
    return response.json()


def test_failing_job_retries_bounded_and_reports_a_safe_error(
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(task_retries=2, task_retry_delay_seconds=2.0)
    test_client, _ = signed_in_client(settings)
    task_id = submit_failure(settings, "fallo controlado")

    observed: list[str] = []
    with running_worker(settings):
        final = wait_for_status(test_client, task_id, {"error"}, seen=observed)

    assert "retrying" in observed
    assert final["error"] == "fallo controlado"
    assert final["retries_remaining"] == 0
    assert final["result"] is None
    assert "Traceback" not in json.dumps(final)
    assert "itsm.tasks.runtime" not in json.dumps(final)

    # Bounded retries: the state stays terminal instead of cycling again.
    time.sleep(2.5)
    assert task_state(test_client, task_id) == final


def test_cli_reports_persisted_status_for_the_failed_job(
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(task_retries=0, task_retry_delay_seconds=0.0)
    test_client, _ = signed_in_client(settings)
    task_id = submit_failure(settings, "sin reintentos")

    with running_worker(settings):
        wait_for_status(test_client, task_id, {"error"})

    status = run_cli(["-m", "itsm.tasks.cli", "status", task_id], settings)

    assert status.returncode == 0, status.stderr
    payload = json.loads(status.stdout)
    assert payload["task_id"] == task_id
    assert payload["state"] == "error"
    assert payload["retries_remaining"] == 0
