"""Internal task queue interface.

Business code talks to :class:`TaskQueue` only. Huey types stay inside this
package so the execution backend can be replaced without touching callers.

State markers are stored in the queue's own result storage under the task id:

* the API writes ``pending``/``scheduled`` before enqueueing;
* the worker writes ``running`` when execution starts;
* Huey stores the final result or the error metadata when execution ends.

Reads always peek, so ``GET`` never consumes a stored result.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from huey.exceptions import TaskException

from itsm.config import Settings
from itsm.logging import sanitize_text

if TYPE_CHECKING:  # pragma: no cover - typing only
    from itsm.tasks.runtime import TaskRuntime


class TaskStorageUnavailable(RuntimeError):
    """Raised when the configured queue storage cannot accept work."""


class TaskState(StrEnum):
    PENDING = "pending"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    RETRYING = "retrying"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass(frozen=True)
class TaskStatus:
    task_id: str
    state: TaskState
    result: dict[str, Any] | None = None
    error: str | None = None
    retries_remaining: int | None = None


class TaskQueue(Protocol):
    """Internal, backend-agnostic task queue interface."""

    def probe(self) -> None:
        """Raise :class:`TaskStorageUnavailable` when storage is unusable."""

    def submit_demo(self, message: str, delay_seconds: int = 0) -> TaskStatus:
        """Enqueue the bounded echo demo task."""

    def submit_demo_failure(self, message: str) -> TaskStatus:
        """Enqueue the bounded failing demo task (dev diagnostics)."""

    def submit_operation(self, operation_id: str, task_id: str) -> TaskStatus:
        """Enqueue one approved durable inventory operation."""

    def submit_monitoring(self) -> TaskStatus:
        """Enqueue one configured native-monitoring synchronization."""

    def submit_notifications(self) -> TaskStatus:
        """Enqueue one SQL-backed notification dispatch pass."""

    def submit_report(self, job_id: str, task_id: str) -> TaskStatus:
        """Enqueue a durable document job; SQL owns its progress and access."""

    def submit_search_sync(self) -> TaskStatus:
        """Enqueue a committed search outbox synchronization pass."""

    def submit_search_rebuild(self) -> TaskStatus:
        """Enqueue an atomic canonical search-index rebuild."""

    def get_status(self, task_id: str) -> TaskStatus | None:
        """Return the stored state without consuming it; ``None`` if unknown."""


def write_task_state(huey: Any, task_id: str, state: TaskState) -> None:
    """Persist an execution state marker in the queue's result storage."""
    huey.put_result(task_id, {"state": state.value})


class HueyTaskQueue:
    """Task queue backed by Huey (SQLite by default, Redis/PostgreSQL optional)."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._runtime: TaskRuntime | None = None

    @property
    def runtime(self) -> TaskRuntime:
        if self._runtime is None:
            from itsm.tasks.runtime import build_runtime

            self._runtime = build_runtime(self._settings)
        return self._runtime

    def probe(self) -> None:
        if self._settings.task_storage == "sqlite":
            self._probe_sqlite(Path(self._settings.task_sqlite_path))
        elif self._settings.task_storage == "redis":
            self._probe_redis(self._settings.task_redis_url)
        elif self._settings.task_storage == "postgres":
            self._probe_postgres(self._settings.task_postgres_dsn)
        else:  # pragma: no cover - guarded by settings validation
            raise TaskStorageUnavailable("unsupported task storage")

    @staticmethod
    def _probe_sqlite(path: Path) -> None:
        directory = path.parent
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TaskStorageUnavailable("task storage directory is not creatable") from exc
        if not directory.is_dir():
            raise TaskStorageUnavailable("task storage directory does not exist")
        if not os.access(directory, os.W_OK):
            raise TaskStorageUnavailable("task storage directory is not writable")
        if path.exists() and not os.access(path, os.W_OK):
            raise TaskStorageUnavailable("task storage file is not writable")

    @staticmethod
    def _probe_redis(url: str) -> None:
        # Redis-backed storage is configured but not validated by automated
        # tests yet; see docs/foundation.md for the pending-validation matrix.
        from redis import Redis

        try:
            Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2).ping()
        except Exception as exc:
            raise TaskStorageUnavailable("redis task storage is unreachable") from exc

    @staticmethod
    def _probe_postgres(dsn: str) -> None:
        # PostgreSQL-backed Huey storage additionally requires psycopg>=3.2.
        try:
            import psycopg

            with psycopg.connect(dsn, connect_timeout=2):
                pass
        except Exception as exc:
            raise TaskStorageUnavailable("postgres task storage is unreachable") from exc

    def submit_demo(self, message: str, delay_seconds: int = 0) -> TaskStatus:
        state = TaskState.SCHEDULED if delay_seconds > 0 else TaskState.PENDING
        task_id = uuid.uuid4().hex
        task = self.runtime.demo.echo.s(
            message,
            delay=delay_seconds if delay_seconds > 0 else None,
            id=task_id,
        )
        return self._enqueue(task, task_id, state)

    def submit_demo_failure(self, message: str) -> TaskStatus:
        task_id = uuid.uuid4().hex
        task = self.runtime.demo.failure.s(message, id=task_id)
        return self._enqueue(task, task_id, TaskState.PENDING)

    def submit_operation(self, operation_id: str, task_id: str) -> TaskStatus:
        task = self.runtime.operation.s(operation_id, id=task_id)
        return self._enqueue(task, task_id, TaskState.PENDING)

    def submit_monitoring(self) -> TaskStatus:
        task_id = uuid.uuid4().hex
        return self._enqueue(self.runtime.monitoring.s(id=task_id), task_id, TaskState.PENDING)

    def submit_notifications(self) -> TaskStatus:
        task_id = uuid.uuid4().hex
        return self._enqueue(self.runtime.notifications.s(id=task_id), task_id, TaskState.PENDING)

    def submit_report(self, job_id: str, task_id: str) -> TaskStatus:
        return self._enqueue(self.runtime.report.s(job_id, id=task_id), task_id, TaskState.PENDING)

    def submit_search_sync(self) -> TaskStatus:
        task_id = uuid.uuid4().hex
        return self._enqueue(self.runtime.search_sync.s(id=task_id), task_id, TaskState.PENDING)

    def submit_search_rebuild(self) -> TaskStatus:
        task_id = uuid.uuid4().hex
        return self._enqueue(self.runtime.search_rebuild.s(id=task_id), task_id, TaskState.PENDING)

    def _enqueue(self, task: Any, task_id: str, state: TaskState) -> TaskStatus:
        runtime = self.runtime
        write_task_state(runtime.huey, task_id, state)
        try:
            runtime.huey.enqueue(task)
        except Exception as exc:
            runtime.huey.delete(task_id)
            raise TaskStorageUnavailable("could not enqueue demo task") from exc
        return TaskStatus(task_id=task_id, state=state)

    def get_status(self, task_id: str) -> TaskStatus | None:
        try:
            stored = self.runtime.huey.result(task_id, preserve=True)
        except TaskException as exc:
            return self._error_status(task_id, exc.metadata or {})
        except TaskStorageUnavailable:
            raise
        except Exception as exc:
            raise TaskStorageUnavailable("task storage is unavailable") from exc
        if not isinstance(stored, dict):
            return None
        state = stored.get("state")
        if state == TaskState.COMPLETE.value:
            # Internal state markers never leak into the public result payload.
            result = {key: value for key, value in stored.items() if key != "state"}
            return TaskStatus(task_id=task_id, state=TaskState.COMPLETE, result=result)
        if state in {
            TaskState.PENDING.value,
            TaskState.SCHEDULED.value,
            TaskState.RUNNING.value,
        }:
            return TaskStatus(task_id=task_id, state=TaskState(state))
        return None

    def _error_status(self, task_id: str, metadata: dict[str, Any]) -> TaskStatus:
        remaining = metadata.get("retries")
        error = sanitize_text(
            str(metadata.get("error") or "task failed"),
            self._settings.sensitive_values(),
        )
        if remaining:
            return TaskStatus(
                task_id=task_id,
                state=TaskState.RETRYING,
                error=error,
                retries_remaining=int(remaining),
            )
        return TaskStatus(
            task_id=task_id,
            state=TaskState.ERROR,
            error=error,
            retries_remaining=0,
        )


def create_task_queue(settings: Settings) -> TaskQueue:
    """Build the configured queue adapter."""
    return HueyTaskQueue(settings)
