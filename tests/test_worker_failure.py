"""Failed jobs: bounded retries, safe error reporting and CLI diagnostics."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

from fastapi.testclient import TestClient
from itsm.config import Settings
from tests.conftest import (
    BACKEND_ROOT,
    run_cli,
    run_migrations,
    running_worker,
    wait_for_status,
    worker_environment,
)


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


def worker_check(settings: Settings, log_path: Path, timeout: float = 20.0) -> int:
    """Run one real consumer and return its exit code, never leaving it running."""
    environment = worker_environment(settings)
    with log_path.open("w") as log:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "huey.bin.huey_consumer",
                "itsm.tasks.runtime.huey",
                "-w",
                "1",
                "-k",
                "thread",
            ],
            cwd=BACKEND_ROOT,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise AssertionError(
                "the consumer kept running against a database the code cannot use: "
                + log_path.read_text()
            ) from None


def test_the_worker_refuses_to_consume_an_unmigrated_database(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = settings_factory()
    log_path = tmp_path / "worker-unmigrated.log"

    returncode = worker_check(settings, log_path)

    assert returncode == 2
    log = log_path.read_text()
    assert "worker.refused" in log
    assert "migrat" in log.lower()


def test_the_worker_refuses_a_database_behind_the_code_head(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    connection = sqlite3.connect(settings.database_url.removeprefix("sqlite:///"))
    try:
        connection.execute("UPDATE alembic_version SET version_num = '0035_extension_isolation'")
        connection.commit()
    finally:
        connection.close()
    log_path = tmp_path / "worker-stale.log"

    returncode = worker_check(settings, log_path)

    assert returncode == 2
    log = log_path.read_text()
    assert "worker.refused" in log
    assert "migrat" in log.lower()
