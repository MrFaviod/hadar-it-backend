"""Huey runtime: instance construction, registered tasks and execution logging.

Business work uses fixed registered tasks: approved inventory operations and
periodic maintenance reminder preparation. Arbitrary task names are not accepted.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from huey import Huey, PostgresHuey, RedisHuey, SqliteHuey, crontab
from huey.signals import SIGNAL_ERROR, SIGNAL_RETRYING

from itsm.config import Settings, get_settings
from itsm.database import check_readiness, create_engine_from_settings
from itsm.logging import configure_logging, log_event
from itsm.release_identity import enforce_startup
from itsm.release_mode import ReleaseModeError
from itsm.tasks.adapter import (
    TaskState,
    TaskStorageUnavailable,
    reconcile_interrupted_tasks,
    write_task_state,
)

logger = logging.getLogger("itsm.tasks")

TASK_NAME_ECHO = "demo_echo"
TASK_NAME_FAILURE = "demo_failure"
TASK_NAME_PERIODIC = "demo_periodic"
TASK_QUEUE_NAME = "itsm"

#: Process exit code when the release mode or the database owner is refused.
WORKER_REFUSED_EXIT_CODE = 2


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
    monitoring: Any
    notifications: Any
    report: Any
    search_sync: Any
    search_rebuild: Any


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
        # The worker refuses to consume work in an invalid mode or against a
        # database owned by another mode, before any task is dequeued.
        try:
            release = enforce_startup(settings, require_identity=True)
            if release.mode == "demo" and settings.demo_data_directory is not None:
                raise ReleaseModeError(
                    "external consumers are forbidden for an automatically resetting demo"
                )
            # The worker writes the same schema the API reads, so it refuses a
            # database that is behind the code head instead of retrying every
            # task against an unknown schema.
            engine = create_engine_from_settings(settings)
            try:
                readiness = check_readiness(engine, settings, task_storage_ok=True)
            finally:
                engine.dispose()
            reconciled = reconcile_interrupted_tasks(huey)
            if reconciled:
                log_event(logger, "worker.reconciled", count=reconciled)
            if not readiness.is_ready:
                migrations = readiness.migrations
                raise ReleaseModeError(
                    "the database is not ready for this release: migrations "
                    f"{migrations.status if migrations else 'unavailable'}, "
                    f"revision {migrations.current if migrations else None}, "
                    f"head {migrations.head if migrations else None}; "
                    "run `python -m itsm.ops upgrade` before starting the worker"
                )
        except ReleaseModeError as exc:
            log_event(logger, "worker.refused", level=logging.ERROR, reason=str(exc))
            # Huey logs startup-hook exceptions and keeps consuming, and hooks run
            # in the worker thread or child process, so an exception cannot stop
            # the consumer. Ending the process is the only refusal huey cannot
            # swallow; with ``-k thread`` this stops the whole consumer.
            os._exit(WORKER_REFUSED_EXIT_CODE)
        log_event(
            logger,
            "worker.started",
            app=settings.app_name,
            release_mode=release.mode,
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


def register_maintenance_task(huey: Huey, settings: Settings):
    """Prepare due reminders periodically; domain uniqueness makes retries safe."""

    @huey.periodic_task(
        crontab(minute="*/5"),
        name="maintenance_due_scan",
        retries=settings.task_retries,
        retry_delay=settings.task_retry_delay_seconds,
    )
    def maintenance_due_scan() -> None:
        from itsm.maintenance.scheduler import prepare_reminders

        result = prepare_reminders(settings)
        log_event(logger, "maintenance.reminders_prepared", **result)

    return maintenance_due_scan


def register_monitoring_task(huey: Huey, settings: Settings):
    """Sync native alerts and window occurrences; Prometheus remains the metrics engine."""

    @huey.periodic_task(
        lambda timestamp: (
            int(timestamp.timestamp() // 60) % ((settings.monitoring_poll_seconds + 59) // 60) == 0
        ),
        name="monitoring_sync",
        retries=settings.task_retries,
        retry_delay=settings.task_retry_delay_seconds,
        context=True,
    )
    def monitoring_sync(task: Any = None) -> dict[str, Any]:
        from itsm.monitoring.scheduler import sync_from_prometheus
        from itsm.notifications.service import record_alert_event

        write_task_state(huey, task.id, TaskState.RUNNING)
        result = sync_from_prometheus(settings, notifier=record_alert_event)
        log_event(logger, "monitoring.synchronized", **result)
        payload = {"state": TaskState.COMPLETE.value, "summary": result}
        huey.put_result(task.id, payload)
        return payload

    return monitoring_sync


def register_notification_task(huey: Huey, settings: Settings):
    """Dispatch SQL-backed deliveries/retries/escalation and retention through Huey."""

    @huey.periodic_task(
        crontab(minute="*"),
        name="notification_dispatch",
        retries=settings.task_retries,
        retry_delay=settings.task_retry_delay_seconds,
        context=True,
    )
    def notification_dispatch(task: Any = None) -> dict[str, Any]:
        from itsm.notifications.service import process_notifications

        write_task_state(huey, task.id, TaskState.RUNNING)
        result = process_notifications(settings)
        log_event(logger, "notifications.processed", **result)
        payload = {"state": TaskState.COMPLETE.value, "summary": result}
        huey.put_result(task.id, payload)
        return payload

    return notification_dispatch


def register_extension_task(huey: Huey, settings: Settings):
    """Run only installed declared schedules; SQL owns due state and live authority."""

    @huey.periodic_task(
        crontab(minute="*"),
        name="extension_schedules",
        retries=settings.task_retries,
        retry_delay=settings.task_retry_delay_seconds,
        context=True,
    )
    def extension_schedules(task: Any = None) -> dict[str, Any]:
        from itsm.extensions.scheduler import process_extension_schedules

        write_task_state(huey, task.id, TaskState.RUNNING)
        result = process_extension_schedules(settings)
        log_event(logger, "extensions.schedules.processed", **result)
        payload = {"state": TaskState.COMPLETE.value, "summary": result}
        huey.put_result(task.id, payload)
        return payload

    return extension_schedules


def register_extension_events_task(huey: Huey, settings: Settings):
    """Deliver core entity events and run due reconciliations every minute."""

    @huey.periodic_task(
        crontab(minute="*"),
        name="extension_events",
        retries=settings.task_retries,
        retry_delay=settings.task_retry_delay_seconds,
        context=True,
    )
    def extension_events(task: Any = None) -> dict[str, Any]:
        from itsm.extensions.events import process_extension_events

        write_task_state(huey, task.id, TaskState.RUNNING)
        result = process_extension_events(settings)
        log_event(logger, "extensions.events.processed", **result)
        payload = {"state": TaskState.COMPLETE.value, "summary": result}
        huey.put_result(task.id, payload)
        return payload

    return extension_events


def register_report_task(huey: Huey, settings: Settings):
    """Render durable document jobs using only a server-side SQL locator."""

    def report_service(operation):
        from itsm.database import create_engine_from_settings, create_session_factory
        from itsm.reports.service import build_report_service

        engine = create_engine_from_settings(settings)
        try:
            service = build_report_service(settings, create_session_factory(engine))
            return operation(service)
        finally:
            engine.dispose()

    @huey.task(
        context=True, retries=settings.task_retries, retry_delay=settings.task_retry_delay_seconds
    )
    def report_generate(job_id: str, task: Any = None) -> dict[str, Any]:
        write_task_state(huey, task.id, TaskState.RUNNING)
        result = report_service(lambda service: service.execute(job_id))
        payload = {"state": TaskState.COMPLETE.value, "jobId": job_id, "status": result["status"]}
        huey.put_result(task.id, payload)
        return payload

    @huey.periodic_task(
        crontab(minute="0"),
        name="report_retention",
        retries=settings.task_retries,
        retry_delay=settings.task_retry_delay_seconds,
    )
    def report_retention() -> None:
        report_service(lambda service: service.cleanup())

    return report_generate


def register_search_tasks(huey: Huey, settings: Settings) -> tuple[Any, Any]:
    """Run committed outbox synchronization and explicit atomic rebuilds."""
    from itsm.search.indexer import (
        install_search_sync,
        process_search_rebuild,
        process_search_sync,
    )

    install_search_sync(settings)

    @huey.periodic_task(
        crontab(minute="*"),
        name="search_sync",
        context=True,
        retries=settings.task_retries,
        retry_delay=settings.task_retry_delay_seconds,
    )
    def search_sync(task: Any = None) -> dict[str, Any]:
        if task is not None:
            write_task_state(huey, task.id, TaskState.RUNNING)
        result = process_search_sync(settings)
        if task is not None:
            huey.put_result(task.id, {"state": TaskState.COMPLETE.value, "result": result})
        return result

    @huey.task(
        name="search_rebuild",
        context=True,
        retries=settings.task_retries,
        retry_delay=settings.task_retry_delay_seconds,
    )
    def search_rebuild(task: Any = None) -> dict[str, Any]:
        if task is not None:
            write_task_state(huey, task.id, TaskState.RUNNING)
        result = process_search_rebuild(settings)
        if task is not None:
            huey.put_result(task.id, {"state": TaskState.COMPLETE.value, "result": result})
        return result

    return search_sync, search_rebuild


def build_runtime(settings: Settings) -> TaskRuntime:
    """Used by the API process; the consumer imports the module-level instance."""
    configure_logging(settings.log_level, secrets=settings.sensitive_values())
    huey = build_huey(settings)
    register_maintenance_task(huey, settings)
    register_extension_task(huey, settings)
    register_extension_events_task(huey, settings)
    search_sync, search_rebuild = register_search_tasks(huey, settings)
    return TaskRuntime(
        huey=huey,
        demo=register_demo_tasks(huey, settings),
        operation=register_operation_task(huey, settings),
        monitoring=register_monitoring_task(huey, settings),
        notifications=register_notification_task(huey, settings),
        report=register_report_task(huey, settings),
        search_sync=search_sync,
        search_rebuild=search_rebuild,
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
    register_maintenance_task(huey_instance, settings)
    register_monitoring_task(huey_instance, settings)
    register_notification_task(huey_instance, settings)
    register_extension_task(huey_instance, settings)
    register_extension_events_task(huey_instance, settings)
    register_report_task(huey_instance, settings)
    register_search_tasks(huey_instance, settings)
    return huey_instance


def __getattr__(name: str) -> Any:
    if name == "huey":
        instance = _consumer_huey()
        globals()["huey"] = instance
        return instance
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
