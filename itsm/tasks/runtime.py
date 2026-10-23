"""Huey runtime: instance construction, registered tasks and execution logging.

Only this module (and the queue adapter) knows about Huey. Task bodies are
bounded demo work: no arbitrary callables or task names are accepted.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from huey import Huey, PostgresHuey, RedisHuey, SqliteHuey, crontab
from huey.signals import SIGNAL_ERROR, SIGNAL_RETRYING

from itsm.config import Settings, get_settings
from itsm.logging import configure_logging, log_event
from itsm.tasks.adapter import TaskState, TaskStorageUnavailable, write_task_state

logger = logging.getLogger("itsm.tasks")

TASK_NAME_ECHO = "demo_echo"
TASK_NAME_FAILURE = "demo_failure"
TASK_NAME_PERIODIC = "demo_periodic"
TASK_QUEUE_NAME = "itsm"


class DemoTaskFailure(RuntimeError):
    """Deterministic, bounded failure used to exercise retry handling."""

    def __repr__(self) -> str:  # keep the stored error message free of tracebacks
        return str(self)


@dataclass(frozen=True)
class DemoTasks:
    echo: Any
    failure: Any
    periodic: Any | None


@dataclass(frozen=True)
class TaskRuntime:
    huey: Huey
    demo: DemoTasks
    operation: Any


def build_huey(settings: Settings) -> Huey:
    """Create the Huey instance for the configured storage backend."""
    if settings.task_storage == "sqlite":
        path = Path(settings.task_sqlite_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TaskStorageUnavailable("task storage directory is not creatable") from exc
        return SqliteHuey(TASK_QUEUE_NAME, filename=str(path))
    if settings.task_storage == "redis":
        return RedisHuey(TASK_QUEUE_NAME, url=settings.task_redis_url)
    return PostgresHuey(TASK_QUEUE_NAME, dsn=settings.task_postgres_dsn)


def register_demo_tasks(huey: Huey, settings: Settings) -> DemoTasks:
    """Register the bounded demo tasks and structured execution logging."""

    @huey.task(
        context=True,
        retries=settings.task_retries,
        retry_delay=settings.task_retry_delay_seconds,
    )
    def demo_echo(message: str, task: Any = None) -> dict[str, Any]:
        write_task_state(huey, task.id, TaskState.RUNNING)
        started = time.perf_counter()
        log_event(logger, "task.started", task_id=task.id, task_name=TASK_NAME_ECHO)
        result = {"state": TaskState.COMPLETE.value, "message": message}
        log_event(
            logger,
            "task.completed",
            task_id=task.id,
            task_name=TASK_NAME_ECHO,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        return result

    @huey.task(
        context=True,
        retries=settings.task_retries,
        retry_delay=settings.task_retry_delay_seconds,
    )
    def demo_failure(message: str, task: Any = None) -> dict[str, Any]:
        write_task_state(huey, task.id, TaskState.RUNNING)
        log_event(logger, "task.started", task_id=task.id, task_name=TASK_NAME_FAILURE)
        raise DemoTaskFailure(message)

    # Huey receivers are called as ``receiver(signal, task, *args)``; the signal
    # name is the first positional argument, not the task.
    @huey.signal(SIGNAL_ERROR)
    def on_task_error(_signal: str, task: Any, exc: BaseException | None = None, *_: Any) -> None:
        log_event(
            logger,
            "task.failed",
            level=logging.ERROR,
            task_id=_task_id(task),
            task_name=_task_name(task),
            retries_remaining=getattr(task, "retries", None),
            error=repr(exc),
        )

    @huey.signal(SIGNAL_RETRYING)
    def on_task_retrying(_signal: str, task: Any, *_: Any) -> None:
        log_event(
            logger,
            "task.retrying",
            task_id=_task_id(task),
            task_name=_task_name(task),
            retries_remaining=getattr(task, "retries", None),
        )

    @huey.on_startup()
    def on_worker_startup() -> None:
        configure_logging(settings.log_level, secrets=settings.sensitive_values())
        log_event(
            logger,
            "worker.started",
            app=settings.app_name,
            task_storage=settings.task_storage,
        )

    @huey.on_shutdown()
    def on_worker_shutdown() -> None:
        log_event(logger, "worker.stopped", app=settings.app_name)

    periodic = None
    if settings.demo_periodic_minutes > 0:
        minute = f"*/{settings.demo_periodic_minutes}"

        @huey.periodic_task(crontab(minute=minute), name=TASK_NAME_PERIODIC)
        def demo_periodic() -> None:
            # Huey cron granularity is one minute; the interval is opt-in.
            log_event(logger, "task.periodic_tick", task_name=TASK_NAME_PERIODIC)

        periodic = demo_periodic

    return DemoTasks(echo=demo_echo, failure=demo_failure, periodic=periodic)


def _task_name(task: Any) -> str:
    return getattr(task, "name", None) or type(task).__name__


def _task_id(task: Any) -> str:
    return str(getattr(task, "id", task))


def register_operation_task(huey: Huey, settings: Settings):
    """Register the fixed business task; payload contains only a SQL locator."""

    @huey.task(
        context=True, retries=settings.task_retries, retry_delay=settings.task_retry_delay_seconds
    )
    def inventory_operation(operation_id: str, task: Any = None):
        from itsm.database import create_engine_from_settings, create_session_factory
        from itsm.workflows.jobs import execute_job

        engine = create_engine_from_settings(settings)
        try:
            write_task_state(huey, task.id, TaskState.RUNNING)
            with create_session_factory(engine)() as session:
                result = execute_job(session, settings, operation_id)
                return {
                    "state": "complete",
                    "operationId": operation_id,
                    "summary": result["summary"],
                }
        finally:
            engine.dispose()

    return inventory_operation


def build_runtime(settings: Settings) -> TaskRuntime:
    """Used by the API process; the consumer imports the module-level instance."""
    configure_logging(settings.log_level, secrets=settings.sensitive_values())
    huey = build_huey(settings)
    return TaskRuntime(
        huey=huey,
        demo=register_demo_tasks(huey, settings),
        operation=register_operation_task(huey, settings),
    )


# Consumer entrypoint: huey_consumer itsm.tasks.runtime.huey -w 1 -k thread
#
# The instance is built on first attribute access so importing this module (for
# example from the API process) never touches queue storage.
def _consumer_huey() -> Huey:
    settings = get_settings()
    huey_instance = build_huey(settings)
    register_demo_tasks(huey_instance, settings)
    register_operation_task(huey_instance, settings)
    return huey_instance


def __getattr__(name: str) -> Any:
    if name == "huey":
        instance = _consumer_huey()
        globals()["huey"] = instance
        return instance
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
