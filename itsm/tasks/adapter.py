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

import contextlib
import os
import sqlite3
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

    def submit_setup_ping(self) -> TaskStatus:
        """Enqueue the harmless round-trip that proves a worker is alive."""
        ...

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


OWNER_PREFIX = "itsm:owner:"
INTERRUPTED_ERROR = "worker_interrupted"


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def record_task_owner(huey: Any, task_id: str, pid: int | None = None) -> None:
    """Remember which worker process is executing a task."""
    owner = os.getpid() if pid is None else pid
    with contextlib.suppress(Exception):
        huey.storage.put_data(f"{OWNER_PREFIX}{task_id}", str(owner).encode())


def _owner_pid(huey: Any, key: str) -> int | None:
    try:
        raw = huey.storage.peek_data(key)
    except Exception:
        return None
    if not isinstance(raw, (bytes, bytearray)):
        return None
    try:
        return int(bytes(raw).decode())
    except ValueError:
        return None


def _owned_task_keys(storage: Any) -> list[str]:
    """List owner markers on a SQLite-backed queue; other backends keep order."""
    if not hasattr(storage, "filename") or not hasattr(storage, "sql"):
        return []
    try:
        rows = storage.sql(
            "select key from kv where key like ?",
            (f"{OWNER_PREFIX}%",),
            results=True,
        )
    except Exception:
        return []
    return [str(row[0]) for row in rows]


def _stored_state(huey: Any, task_id: str) -> str | None:
    """Read the persisted state without consuming it, if the queue can answer."""
    try:
        stored = huey.result(task_id, preserve=True)
    except Exception:
        return None
    if isinstance(stored, dict):
        state = stored.get("state")
        return str(state) if state is not None else None
    return None


def reconcile_interrupted_tasks(huey: Any) -> int:
    """Fail tasks a dead worker left behind; returns how many were reconciled.

    The owner marker is written before a task starts and may survive a kill that
    happens after the result was stored, so the persisted state is authoritative:
    a finished task keeps its result and its marker is simply dropped.
    """
    reconciled = 0
    for key in _owned_task_keys(huey.storage):
        pid = _owner_pid(huey, key)
        if pid is not None and _process_alive(pid):
            continue
        task_id = key[len(OWNER_PREFIX) :]
        state = _stored_state(huey, task_id)
        terminal = {TaskState.COMPLETE.value, TaskState.ERROR.value}
        if state in terminal or state is None:
            with contextlib.suppress(Exception):
                huey.storage.delete_data(key)
            continue
        huey.put_result(task_id, {"state": TaskState.ERROR.value, "error": INTERRUPTED_ERROR})
        with contextlib.suppress(Exception):
            huey.storage.delete_data(key)
        reconciled += 1
    return reconciled


def write_task_state(huey: Any, task_id: str, state: TaskState) -> None:
    """Persist an execution state marker in the queue's result storage."""
    huey.put_result(task_id, {"state": state.value})
    if state is TaskState.RUNNING:
        record_task_owner(huey, task_id)


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
        if path.exists():
            try:
                connection = sqlite3.connect(f"file:{path}?mode=rw", uri=True, timeout=2.0)
                try:
                    row = connection.execute("PRAGMA quick_check(1)").fetchone()
                finally:
                    connection.close()
            except sqlite3.DatabaseError as exc:
                raise TaskStorageUnavailable("task storage file is not a usable database") from exc
            if not row or row[0] != "ok":
                raise TaskStorageUnavailable("task storage file failed its integrity check")

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
        delay = delay_seconds if delay_seconds > 0 else None
        return self._enqueue(
            lambda runtime: runtime.demo.echo.s(message, delay=delay, id=task_id), task_id, state
        )

    def submit_setup_ping(self) -> TaskStatus:
        task_id = uuid.uuid4().hex
        return self._enqueue(
            lambda runtime: runtime.setup_ping.s(id=task_id), task_id, TaskState.PENDING
        )

    def submit_demo_failure(self, message: str) -> TaskStatus:
        task_id = uuid.uuid4().hex
        return self._enqueue(
            lambda runtime: runtime.demo.failure.s(message, id=task_id), task_id, TaskState.PENDING
        )

    def submit_operation(self, operation_id: str, task_id: str) -> TaskStatus:
        return self._enqueue(
            lambda runtime: runtime.operation.s(operation_id, id=task_id),
            task_id,
            TaskState.PENDING,
        )

    def submit_monitoring(self) -> TaskStatus:
        task_id = uuid.uuid4().hex
        return self._enqueue(
            lambda runtime: runtime.monitoring.s(id=task_id), task_id, TaskState.PENDING
        )

    def submit_notifications(self) -> TaskStatus:
        task_id = uuid.uuid4().hex
        return self._enqueue(
            lambda runtime: runtime.notifications.s(id=task_id), task_id, TaskState.PENDING
        )

    def submit_report(self, job_id: str, task_id: str) -> TaskStatus:
        return self._enqueue(
            lambda runtime: runtime.report.s(job_id, id=task_id), task_id, TaskState.PENDING
        )

    def submit_search_sync(self) -> TaskStatus:
        task_id = uuid.uuid4().hex
        return self._enqueue(
            lambda runtime: runtime.search_sync.s(id=task_id), task_id, TaskState.PENDING
        )

    def submit_search_rebuild(self) -> TaskStatus:
        task_id = uuid.uuid4().hex
        return self._enqueue(
            lambda runtime: runtime.search_rebuild.s(id=task_id), task_id, TaskState.PENDING
        )

    def _enqueue(self, build: Any, task_id: str, state: TaskState) -> TaskStatus:
        """Build and enqueue inside the guard: an unusable queue must answer 503."""
        try:
            runtime = self.runtime
            task = build(runtime)
            write_task_state(runtime.huey, task_id, state)
            runtime.huey.enqueue(task)
        except Exception as exc:
            with contextlib.suppress(Exception):
                self.runtime.huey.delete(task_id)
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
        if state == TaskState.ERROR.value:
            error = stored.get("error")
            return TaskStatus(
                task_id=task_id,
                state=TaskState.ERROR,
                result=None,
                error=str(error) if error else None,
                retries_remaining=0,
            )
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
