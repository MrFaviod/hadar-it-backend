"""Shared fixtures: isolated files, real Alembic CLI and a real Huey worker process."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings

BACKEND_ROOT = Path(__file__).resolve().parents[1]
WORKER_BOOT_TIMEOUT = 20.0
POLL_INTERVAL = 0.1


@pytest.fixture
def settings_factory(tmp_path: Path) -> Callable[..., Settings]:
    """Build test settings backed by isolated SQLite files."""

    (tmp_path / "tasks").mkdir(exist_ok=True)

    def make(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "environment": "test",
            "database_url": f"sqlite:///{tmp_path / 'app.db'}",
            "task_sqlite_path": tmp_path / "tasks" / "huey.db",
            "task_retries": 2,
            "task_retry_delay_seconds": 1.0,
            "demo_max_delay_seconds": 15,
            "demo_message_max_length": 50,
            "log_level": "INFO",
        }
        values.update(overrides)
        return Settings(_env_file=None, **values)

    return make


def worker_environment(settings: Settings) -> dict[str, str]:
    """Environment for subprocesses (worker, Alembic, task CLI)."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    env.update(
        {
            "PYTHONPATH": str(BACKEND_ROOT),
            "PYTHONUNBUFFERED": "1",
            "ITSM_ENVIRONMENT": settings.environment,
            "ITSM_LOG_LEVEL": settings.log_level,
            "ITSM_DATABASE_URL": settings.database_url,
            "ITSM_TASK_STORAGE": settings.task_storage,
            "ITSM_TASK_SQLITE_PATH": str(settings.task_sqlite_path),
            "ITSM_TASK_REDIS_URL": settings.task_redis_url,
            "ITSM_TASK_POSTGRES_DSN": settings.task_postgres_dsn,
            "ITSM_TASK_RETRIES": str(settings.task_retries),
            "ITSM_TASK_RETRY_DELAY_SECONDS": str(settings.task_retry_delay_seconds),
            "ITSM_DEMO_MESSAGE_MAX_LENGTH": str(settings.demo_message_max_length),
            "ITSM_DEMO_MAX_DELAY_SECONDS": str(settings.demo_max_delay_seconds),
            "ITSM_DEMO_PERIODIC_MINUTES": str(settings.demo_periodic_minutes),
        }
    )
    return env


def run_cli(
    args: list[str], settings: Settings, timeout: float = 60.0
) -> subprocess.CompletedProcess[str]:
    """Run a real CLI command in a subprocess with the test settings."""
    return subprocess.run(
        [sys.executable, *args],
        cwd=BACKEND_ROOT,
        env=worker_environment(settings),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_migrations(settings: Settings) -> subprocess.CompletedProcess[str]:
    """Apply migrations through the explicit Alembic CLI."""
    return run_cli(
        ["-m", "alembic", "-c", str(BACKEND_ROOT / "alembic.ini"), "upgrade", "head"],
        settings,
    )


@contextmanager
def running_worker(
    settings: Settings, log_path: Path | None = None
) -> Iterator[subprocess.Popen[bytes]]:
    """Start the real Huey consumer in its own process and stop it on exit."""
    command = [
        sys.executable,
        "-m",
        "huey.bin.huey_consumer",
        "itsm.tasks.runtime.huey",
        "-w",
        "1",
        "-k",
        "thread",
    ]
    if log_path is None:
        log_path = Path(settings.task_sqlite_path).parent / "worker.log"
    with log_path.open("wb") as log_file:
        process = subprocess.Popen(
            command,
            cwd=BACKEND_ROOT,
            env=worker_environment(settings),
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                    process.kill()
                    process.wait(timeout=5)


def wait_for_status(
    client: TestClient,
    task_id: str,
    states: set[str],
    timeout: float = WORKER_BOOT_TIMEOUT,
    seen: list[str] | None = None,
) -> dict[str, Any]:
    """Poll the public status endpoint until one of ``states`` is reached."""
    deadline = time.monotonic() + timeout
    payload: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/tasks/{task_id}")
        assert response.status_code == 200, response.text
        payload = response.json()
        if seen is not None and payload["state"] not in seen:
            seen.append(payload["state"])
        if payload["state"] in states:
            return payload
        time.sleep(POLL_INTERVAL)
    raise AssertionError(
        f"task {task_id} did not reach {sorted(states)} within {timeout}s: {payload}"
    )


class EventCollector(logging.Handler):
    """Collect structured events emitted through ``itsm.logging.log_event``."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.events: list[dict[str, Any]] = []

    def emit(self, record: logging.LogRecord) -> None:
        event = getattr(record, "event", None)
        if event:
            data = getattr(record, "data", {}) or {}
            self.events.append({"event": event, **data})


@pytest.fixture
def events() -> Iterator[EventCollector]:
    collector = EventCollector()
    root = logging.getLogger()
    previous_level = root.level
    root.addHandler(collector)
    root.setLevel(logging.DEBUG)
    try:
        yield collector
    finally:
        root.removeHandler(collector)
        root.setLevel(previous_level)


@pytest.fixture
def client(settings_factory: Callable[..., Settings]) -> Iterator[Callable[..., TestClient]]:
    """Factory for an in-process API client sharing the isolated settings."""
    opened: list[TestClient] = []

    def make(settings: Settings) -> TestClient:
        from itsm.main import create_app

        test_client = TestClient(create_app(settings))
        test_client.__enter__()
        opened.append(test_client)
        return test_client

    try:
        yield make
    finally:
        for test_client in opened:
            test_client.__exit__(None, None, None)


def read_worker_log(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(errors="replace")


def worker_events(path: Path, event: str) -> list[dict[str, Any]]:
    """Parse structured worker log lines for one event name."""
    matches: list[dict[str, Any]] = []
    for line in read_worker_log(path).splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if payload.get("event") == event:
            matches.append(payload)
    return matches
