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
    sign_in,
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
    test_client, auth = signed_in_client(settings)
    # Exercise the authenticated submit path: it records the actual caller's
    # durable owner. Only the bounded test task implementation is substituted.
    queue = test_client.app.state.task_queue
    original = queue.submit_demo
    queue.submit_demo = lambda message, delay_seconds=0: queue.submit_demo_failure(message)
    try:
        accepted = test_client.post(
            "/api/v1/tasks/demo", json={"message": "fallo controlado"}, headers=auth
        )
    finally:
        queue.submit_demo = original
    assert accepted.status_code == 202, accepted.text
    task_id = accepted.json()["task_id"]
    assert task_state(test_client, task_id)["state"] == "pending"
    other_password = "other-worker-reader-2026"
    created = test_client.post(
        "/api/v1/identity/users",
        json={
            "username": "worker.other",
            "name": "Other reader",
            "roleId": "user",
            "password": other_password,
        },
        headers=auth,
    )
    assert created.status_code == 201, created.text
    login = test_client.post(
        "/api/v1/auth/login",
        json={"username": "worker.other", "password": other_password},
        headers={"Origin": settings.auth_origin},
    )
    assert login.status_code == 200, login.text
    denied = test_client.get(f"/api/v1/tasks/{task_id}")
    assert denied.status_code == 404
    assert denied.json()["error"]["key"] == "api.tasks.not_found"
    sign_in(test_client, settings)
    assert task_state(test_client, task_id)["state"] == "pending"

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

    # A local CLI submission has no authenticated HTTP owner. Never invent one.
    assert test_client.get(f"/api/v1/tasks/{task_id}").status_code == 404
    with running_worker(settings):
        deadline = time.monotonic() + 20
        while True:
            status = run_cli(["-m", "itsm.tasks.cli", "status", task_id], settings)
            assert status.returncode == 0, status.stderr
            if json.loads(status.stdout)["state"] == "error":
                break
            assert time.monotonic() < deadline, status.stdout
            time.sleep(0.1)
    assert test_client.get(f"/api/v1/tasks/{task_id}").status_code == 404

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


def test_the_worker_reconciles_a_task_a_crashed_worker_left_running(
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    settings_factory: Callable[..., Settings],
) -> None:
    """R4-F7: a task whose worker died must not stay "running" forever."""
    import subprocess
    import sys

    from itsm.tasks.adapter import INTERRUPTED_ERROR, record_task_owner
    from itsm.tasks.runtime import build_runtime

    settings = settings_factory()
    test_client, auth = signed_in_client(settings)

    finished = subprocess.Popen([sys.executable, "-c", "pass"])
    finished.wait(timeout=30)
    crashed_pid = finished.pid

    runtime = build_runtime(settings)
    accepted = test_client.post(
        "/api/v1/tasks/demo", json={"message": "Interrupted owned task"}, headers=auth
    )
    assert accepted.status_code == 202, accepted.text
    task_id = accepted.json()["task_id"]
    # Simulate the worker claiming this real API-created job before dying.
    claimed = runtime.huey.dequeue()
    assert claimed is not None
    assert claimed.id == task_id
    # Exactly what a worker writes when it starts a task and then dies.
    runtime.huey.put_result(task_id, {"state": "running"})
    record_task_owner(runtime.huey, task_id, pid=crashed_pid)

    before = test_client.get(f"/api/v1/tasks/{task_id}")
    assert before.status_code == 200
    assert before.json()["state"] == "running"

    with running_worker(settings):
        reconciled = wait_for_status(test_client, task_id, {"error"}, timeout=30)

    assert reconciled["error"] == INTERRUPTED_ERROR
    assert reconciled["result"] is None
    assert reconciled["retries_remaining"] == 0


def test_reconciliation_never_overwrites_a_finished_task(
    settings_factory: Callable[..., Settings],
) -> None:
    """A stale owner marker must not turn a completed task into an error."""

    import subprocess
    import sys
    import uuid

    from itsm.tasks.adapter import reconcile_interrupted_tasks
    from itsm.tasks.runtime import build_runtime

    settings = settings_factory()
    runtime = build_runtime(settings)
    finished = subprocess.Popen([sys.executable, "-c", "pass"])
    finished.wait(timeout=30)

    completed = uuid.uuid4().hex
    runtime.huey.put_result(completed, {"state": "complete", "result": {"message": "x"}})
    # The marker survives when a worker is killed between the result write and
    # any cleanup, so reconciliation has to trust the stored state, not the key.
    from itsm.tasks.adapter import record_task_owner

    record_task_owner(runtime.huey, completed, pid=finished.pid)

    assert reconcile_interrupted_tasks(runtime.huey) == 0
    stored = runtime.huey.result(completed, preserve=True)
    assert stored["state"] == "complete"
    assert stored["result"] == {"message": "x"}
