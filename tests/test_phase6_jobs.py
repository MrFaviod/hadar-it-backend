"""Dispatch claims, a real Huey consumer and idempotent operation receipts."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.identity.service import IdentityService
from itsm.tasks.adapter import TaskState, TaskStatus
from itsm.workflows import jobs
from itsm.workflows.models import Operation
from itsm.workflows.service import WorkflowService
from tests.conftest import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    BACKEND_ROOT,
    running_worker,
    worker_environment,
    worker_events,
)
from tests.test_inventory_api import create_asset
from tests.test_phase6_workflows import analyze

FAULT_LAUNCHER = '''"""Real Huey consumer with one injected transient failure at the job seam."""

import os

from itsm.workflows import jobs

_fault = jobs.execute_job
_marker = os.environ["ITSM_TEST_TRANSIENT_FAULT"]


def flaky_execute_job(session, settings, operation_id):
    if not os.path.exists(_marker):
        with open(_marker, "w", encoding="utf-8") as handle:
            handle.write("injected transient failure")
        raise RuntimeError("injected transient failure")
    return _fault(session, settings, operation_id)


jobs.execute_job = flaky_execute_job

from itsm.tasks.runtime import huey  # noqa: E402 - patch before the worker starts
from huey.consumer import Consumer  # noqa: E402

Consumer(huey, workers=1, worker_type="thread").run()
'''


class RecordingQueue:
    """Queue boundary double: records dispatch and simulates stored task state."""

    def __init__(self) -> None:
        self.submitted: list[tuple[str, str]] = []
        self.stored: set[str] = set()
        self._lock = threading.Lock()

    def forget(self, task_id: str) -> None:
        """Simulate a dispatch lost between the state commit and queue storage."""
        self.stored.discard(task_id)

    def probe(self) -> None:
        return None

    def submit_demo(self, message: str, delay_seconds: int = 0) -> TaskStatus:
        raise AssertionError("the demo task must not be submitted here")

    def submit_demo_failure(self, message: str) -> TaskStatus:
        raise AssertionError("the demo task must not be submitted here")

    def submit_operation(self, operation_id: str, task_id: str) -> TaskStatus:
        with self._lock:
            self.submitted.append((operation_id, task_id))
            self.stored.add(task_id)
        return TaskStatus(task_id=task_id, state=TaskState.PENDING)

    def get_status(self, task_id: str) -> TaskStatus | None:
        if task_id in self.stored:
            return TaskStatus(task_id=task_id, state=TaskState.PENDING)
        return None


def approved_operation(client: TestClient, auth: dict[str, str], data: bytes) -> str:
    """Create an approved import operation and return its id."""
    preview = analyze(client, auth, data).json()
    approved = client.post(f"/api/v1/operations/{preview['id']}/approve", headers=auth)
    assert approved.status_code == 200, approved.text
    return preview["id"]


def admin_principal(settings: Settings) -> Any:
    """A resolved administrator principal for direct service-level dispatch."""
    engine = create_engine_from_settings(settings)
    session = create_session_factory(engine)()
    try:
        return IdentityService(session, settings).login(ADMIN_USERNAME, ADMIN_PASSWORD).principal
    finally:
        session.close()
        engine.dispose()


@contextmanager
def workflow_session(settings: Settings) -> Iterator[WorkflowService]:
    engine = create_engine_from_settings(settings)
    session = create_session_factory(engine)()
    try:
        yield WorkflowService(session, settings)
    finally:
        session.close()
        engine.dispose()


def test_real_huey_job_is_observable_and_retry_does_not_duplicate(
    signed_in_client, settings_factory
):
    settings = settings_factory()
    client, auth = signed_in_client(settings)
    create_asset(client, auth)
    preview = analyze(client, auth, b"name,serial\nQueued one,J1\nQueued two,J2\n").json()
    assert (
        client.post(f"/api/v1/operations/{preview['id']}/enqueue", headers=auth).status_code == 409
    )
    assert (
        client.post(f"/api/v1/operations/{preview['id']}/approve", headers=auth).status_code == 200
    )
    queued = client.post(f"/api/v1/operations/{preview['id']}/enqueue", headers=auth)
    assert queued.status_code == 202, queued.text
    job = queued.json()
    assert job["jobId"] and job["state"] == "queued"
    with running_worker(settings):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = client.get(f"/api/v1/operations/{preview['id']}").json()
            if result["state"] == "complete":
                break
            time.sleep(0.1)
        else:
            raise AssertionError(f"worker did not complete: {result}")
    assert result["processed"] == 2 and result["summary"]["created"] == 2
    assert client.get(f"/api/v1/tasks/{job['jobId']}").json()["state"] == "complete"
    retry = client.post(f"/api/v1/operations/{preview['id']}/execute", headers=auth)
    assert retry.status_code == 200
    assert retry.json()["summary"]["created"] == 2
    assert client.get("/api/v1/assets/search").json()["total"] == 3


def test_enqueue_is_idempotent_and_recovers_a_lost_dispatch(signed_in_client, settings_factory):
    settings = settings_factory()
    client, auth = signed_in_client(settings)
    create_asset(client, auth)
    operation_id = approved_operation(client, auth, b"name,serial\nRecovered,R-1\n")
    principal = admin_principal(settings)
    queue = RecordingQueue()

    with workflow_session(settings) as workflow:
        first = jobs.enqueue(workflow, principal, operation_id, queue)
        assert first["state"] == "queued"
        job_id = first["jobId"]
        assert queue.submitted == [(operation_id, job_id)]

        repeated = jobs.enqueue(workflow, principal, operation_id, queue)
        assert repeated["jobId"] == job_id
        assert len(queue.submitted) == 1

        queue.forget(job_id)
        recovered = jobs.enqueue(workflow, principal, operation_id, queue)
        assert recovered["jobId"] == job_id
        assert recovered["state"] == "queued"
        assert queue.submitted == [(operation_id, job_id), (operation_id, job_id)]


def test_concurrent_enqueue_dispatches_exactly_one_task(signed_in_client, settings_factory):
    settings = settings_factory()
    client, auth = signed_in_client(settings)
    create_asset(client, auth)
    operation_id = approved_operation(client, auth, b"name,serial\nRaced,R-2\n")
    principal = admin_principal(settings)
    queue = RecordingQueue()
    barrier = threading.Barrier(4)
    views: list[dict[str, Any]] = []
    failures: list[BaseException] = []
    guard = threading.Lock()

    def attempt() -> None:
        engine = create_engine_from_settings(settings)
        session = create_session_factory(engine)()
        try:
            workflow = WorkflowService(session, settings)
            barrier.wait(timeout=20)
            view = jobs.enqueue(workflow, principal, operation_id, queue)
            with guard:
                views.append(view)
        except BaseException as exc:  # recorded, then asserted below
            with guard:
                failures.append(exc)
        finally:
            session.close()
            engine.dispose()

    threads = [threading.Thread(target=attempt) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not failures
    assert len(queue.submitted) == 1
    assert {view["jobId"] for view in views} == {queue.submitted[0][1]}
    with workflow_session(settings) as workflow:
        stored = workflow._session.get(Operation, operation_id)
        assert stored.state == "queued" and stored.job_id == queue.submitted[0][1]


def test_stale_state_observation_never_claims_a_dispatch(signed_in_client, settings_factory):
    settings = settings_factory()
    client, auth = signed_in_client(settings)
    operation_id = approved_operation(client, auth, b"name,serial\nStale,S-1\n")
    first_engine = create_engine_from_settings(settings)
    second_engine = create_engine_from_settings(settings)
    first = WorkflowService(create_session_factory(first_engine)(), settings)
    second = WorkflowService(create_session_factory(second_engine)(), settings)
    try:
        stale = second._session.get(Operation, operation_id)
        assert stale is not None and stale.state == "approved"
        assert jobs._claim(first, operation_id, "approved", "job-first", {"kind": "import"})
        first._session.commit()
        assert not jobs._claim(second, operation_id, "approved", "job-second", {"kind": "import"})
        second._session.expire_all()
        stored = second._session.get(Operation, operation_id)
        assert stored.job_id == "job-first" and stored.state == "queued"
    finally:
        first._session.close()
        second._session.close()
        first_engine.dispose()
        second_engine.dispose()


@contextmanager
def fault_worker(settings: Settings, launcher: Path, marker: Path) -> Iterator[Path]:
    """Run the real Huey consumer with one injected transient job failure."""
    log_path = Path(settings.task_sqlite_path).parent / "fault-worker.log"
    environment = worker_environment(settings)
    environment["PYTHONPATH"] = str(BACKEND_ROOT)
    environment["ITSM_TEST_TRANSIENT_FAULT"] = str(marker)
    with log_path.open("wb") as log_file:
        process = subprocess.Popen(
            [sys.executable, str(launcher)],
            cwd=BACKEND_ROOT,
            env=environment,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            yield log_path
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                    process.kill()
                    process.wait(timeout=5)


def test_real_huey_retry_after_a_transient_failure_applies_once(
    signed_in_client, settings_factory, tmp_path: Path
):
    settings = settings_factory()
    client, auth = signed_in_client(settings)
    create_asset(client, auth)
    preview = analyze(client, auth, b"name,serial\nRetry one,T1\nRetry two,T2\n").json()
    assert (
        client.post(f"/api/v1/operations/{preview['id']}/approve", headers=auth).status_code == 200
    )
    queued = client.post(f"/api/v1/operations/{preview['id']}/enqueue", headers=auth)
    assert queued.status_code == 202, queued.text
    job_id = queued.json()["jobId"]
    launcher = tmp_path / "fault_worker.py"
    launcher.write_text(FAULT_LAUNCHER, encoding="utf-8")
    marker = tmp_path / "transient.marker"

    with fault_worker(settings, launcher, marker) as log_path:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            task = client.get(f"/api/v1/tasks/{job_id}").json()
            if task["state"] == "complete":
                break
            time.sleep(0.1)
        else:
            raise AssertionError(f"worker did not complete after retry: {task}")

    # Huey emits SIGNAL_RETRYING before decrementing, so the single configured
    # retry is reported as one event with the configured budget still visible.
    retries = worker_events(log_path, "task.retrying")
    assert marker.exists()
    assert [(event["task_id"], event["retries_remaining"]) for event in retries] == [
        (job_id, settings.task_retries)
    ], log_path.read_text()[-2000:]
    operation = client.get(f"/api/v1/operations/{preview['id']}").json()
    assert operation["state"] == "complete"
    assert operation["summary"] == {"created": 2, "modified": 0, "omitted": 0, "failed": 0}
    assert [row["result"] for row in operation["rows"]] == ["created", "created"]
    assert client.get("/api/v1/assets/search").json()["total"] == 3
