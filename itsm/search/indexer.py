"""Durable synchronization between canonical SQL and the optional engine.

A single class-level SQLAlchemy ``before_flush`` listener writes an outbox row
inside the same transaction as every ORM mutation of an indexed entity.  The
outbox therefore commits with the domain write (including the existing
``record_operation`` commit path) and survives a crash between commit and
indexing.  A sync run rehydrates the current SQL state, re-authorizes nothing
(index documents carry no authority), retries with backoff and drains rows
only after the engine confirms the task.

Full rebuilds build a temporary index and swap it atomically, so readers keep
seeing the previous index until the new one is complete.
"""

from __future__ import annotations

from contextlib import suppress
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import delete as sql_delete
from sqlalchemy import event, func, inspect, select
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.identity.clock import as_utc, utcnow
from itsm.search import documents
from itsm.search.engine import SearchEngineError, engine_from_settings
from itsm.search.models import (
    OPERATION_DELETE,
    OPERATION_UPSERT,
    STATUS_FAILED,
    STATUS_PENDING,
    SearchIndexState,
    SearchSyncOutbox,
)

DEFAULT_BATCH = 100
MAX_BACKOFF_SECONDS = 3600
_TASK_TIMEOUT = 15.0

_INSTALLED = False
_CONFIGURED_DATABASES: dict[str, bool] = {}
_READY: set[str] = set()
_MODEL_TYPES: dict[type, str] = {}


def _register_models() -> None:
    if _MODEL_TYPES:
        return
    from itsm.directory.models import DirectoryLocation, DirectoryPerson
    from itsm.interventions.models import Incident
    from itsm.inventory.catalog_models import InventoryCatalogEntry
    from itsm.inventory.models import Asset
    from itsm.maintenance.models import MaintenancePlan

    _MODEL_TYPES.update(
        {
            Asset: "asset",
            DirectoryPerson: "person",
            DirectoryLocation: "location",
            Incident: "incident",
            MaintenancePlan: "maintenance",
            InventoryCatalogEntry: "category",
        }
    )
    from itsm.workspace.models import WorkspaceView

    _MODEL_TYPES[WorkspaceView] = "view"


def _outbox_ready(session: Session) -> bool:
    bind = session.get_bind()
    key = str(bind.url)
    if key in _READY:
        return True
    try:
        ready = inspect(bind).has_table(SearchSyncOutbox.__tablename__)
    except Exception:  # pragma: no cover - defensive for odd binds
        return False
    if ready:
        _READY.add(key)
    return ready


def _entity_type(obj: Any) -> str | None:
    if obj is None:
        return None
    for model, name in _MODEL_TYPES.items():
        if isinstance(obj, model):
            if name == "category":
                kind = getattr(obj, "kind", None)
                return "category" if kind == "categories" else None
            return name
    return None


def _entity_id(obj: Any) -> str | None:
    # InventoryCatalogEntry uses a composite (kind, key) primary key.
    value = (
        getattr(obj, "key", None) if _entity_type(obj) == "category" else getattr(obj, "id", None)
    )
    return str(value) if value else None


def _before_flush(session: Session, _context: Any, _instances: Any) -> None:
    if not (session.new or session.dirty or session.deleted):
        return
    if not _CONFIGURED_DATABASES.get(str(session.get_bind().url), True):
        return
    if not _outbox_ready(session):
        return
    now = utcnow()
    queued: set[tuple[str, str]] = set()
    for obj in [*session.new, *session.dirty, *session.deleted]:
        entity_type = _entity_type(obj)
        if entity_type is None:
            continue
        entity_id = _entity_id(obj)
        if not entity_id:
            continue
        operation = OPERATION_DELETE if obj in session.deleted else OPERATION_UPSERT
        if obj not in session.deleted and not session.is_modified(obj, include_collections=False):
            continue
        key = (entity_type, str(entity_id))
        if key in queued:
            continue
        queued.add(key)
        session.add(
            SearchSyncOutbox(
                entity_type=entity_type,
                entity_id=str(entity_id),
                operation=operation,
                created_at=now,
                available_at=now,
            )
        )


def install_search_sync(settings: Settings | None = None) -> None:
    """Install the outbox hook once; optionally bind it to live settings.

    Passing the application settings lets the hook stay silent on installations
    that never configured an engine, so the outbox cannot grow unbounded in a
    SQL-only deployment.  Without settings the hook always records, which is
    what tests and offline bootstrap tooling want.
    """
    global _INSTALLED
    _register_models()
    if settings is not None:
        _CONFIGURED_DATABASES[settings.database_url] = bool(settings.meilisearch_url)
    if _INSTALLED:
        return
    event.listen(Session, "before_flush", _before_flush)
    _INSTALLED = True


def _state(session: Session) -> SearchIndexState:
    state = session.get(SearchIndexState, 1)
    if state is None:
        state = SearchIndexState(id=1)
        session.add(state)
    return state


def _batch(settings: Settings) -> int:
    value = getattr(settings, "search_sync_batch_size", DEFAULT_BATCH)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 500:
        return DEFAULT_BATCH
    return value


def _retry_delay(attempts: int) -> timedelta:
    return timedelta(seconds=min(30 * (2 ** max(attempts - 1, 0)), MAX_BACKOFF_SECONDS))


def _pending(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(SearchSyncOutbox)) or 0)


def execute_sync(
    session: Session,
    settings: Settings,
    as_of: datetime | None = None,
) -> dict[str, Any]:
    """Drain due outbox rows; safe to call repeatedly and from any worker."""
    engine = engine_from_settings(settings)
    if engine is None:
        return {
            "configured": False,
            "processed": 0,
            "synced": 0,
            "failed": 0,
            "pending": _pending(session),
        }
    moment = as_utc(as_of or utcnow())
    batch = _batch(settings)
    state = _state(session)
    processed = synced = failed = 0
    last_error: str | None = None
    index_ready = False
    try:
        rows = list(
            session.scalars(
                select(SearchSyncOutbox)
                .where(SearchSyncOutbox.status.in_((STATUS_PENDING, STATUS_FAILED)))
                .order_by(SearchSyncOutbox.available_at, SearchSyncOutbox.created_at)
                .limit(batch * 5)
            )
        )
        due = [row for row in rows if as_utc(row.available_at) <= moment]
        latest: dict[tuple[str, str], SearchSyncOutbox] = {}
        for row in due:
            key = (row.entity_type, row.entity_id)
            current = latest.get(key)
            if current is None or as_utc(row.created_at) >= as_utc(current.created_at):
                latest[key] = row
        for (entity_type, entity_id), row in list(latest.items())[:batch]:
            if processed >= batch:
                break
            processed += 1
            session.execute(
                sql_delete(SearchSyncOutbox)
                .where(
                    SearchSyncOutbox.entity_type == entity_type,
                    SearchSyncOutbox.entity_id == entity_id,
                    SearchSyncOutbox.created_at <= row.created_at,
                    SearchSyncOutbox.id != row.id,
                )
                .execution_options(synchronize_session=False)
            )
            expected = f"{entity_type}:{entity_id}"
            try:
                if not index_ready:
                    engine.create_index()
                    engine.set_filterable()
                    index_ready = True
                document = documents.build_document(session, entity_type, entity_id)
                if document is None:
                    engine.wait_task(engine.delete_documents([expected]), timeout=_TASK_TIMEOUT)
                else:
                    if document["id"] != expected:
                        engine.wait_task(engine.delete_documents([expected]), timeout=_TASK_TIMEOUT)
                    engine.wait_task(engine.upsert_documents([document]), timeout=_TASK_TIMEOUT)
                session.execute(
                    sql_delete(SearchSyncOutbox)
                    .where(SearchSyncOutbox.id == row.id)
                    .execution_options(synchronize_session=False)
                )
                synced += 1
            except SearchEngineError as exc:
                row.attempts += 1
                row.status = STATUS_FAILED
                row.last_error = str(exc)[:500]
                row.available_at = moment + _retry_delay(row.attempts)
                last_error = row.last_error
                failed += 1
        state.last_sync_at = moment
        state.last_error = last_error
        session.commit()
    finally:
        engine.close()
    return {
        "configured": True,
        "processed": processed,
        "synced": synced,
        "failed": failed,
        "pending": _pending(session),
    }


def execute_rebuild(session: Session, settings: Settings) -> dict[str, Any]:
    """Rebuild the whole index into a temporary index and swap it atomically."""
    engine = engine_from_settings(settings)
    if engine is None:
        return {"configured": False, "rebuilt": 0, "index": None, "status": "disabled"}
    base = getattr(settings, "search_index_name", "itsm_entities") or "itsm_entities"
    temporary = f"{str(base)[:40]}_rb_{uuid4().hex[:10]}"
    started = utcnow()
    state = _state(session)
    state.status = "rebuilding"
    state.last_error = None
    session.commit()
    batch_size = _batch(settings)
    count = 0
    batch: list[dict[str, Any]] = []
    try:
        engine.create_index(temporary)
        for document in documents.iter_documents(session):
            batch.append(document)
            if len(batch) >= batch_size:
                engine.wait_task(
                    engine.upsert_documents(batch, index=temporary), timeout=_TASK_TIMEOUT
                )
                count += len(batch)
                batch = []
        if batch:
            engine.wait_task(engine.upsert_documents(batch, index=temporary), timeout=_TASK_TIMEOUT)
            count += len(batch)
        engine.set_filterable(temporary)
        engine.create_index()
        engine.swap(base, temporary)
        engine.delete_index(temporary)
        # The rebuilt index already reflects these rows; keep changes that
        # committed after the rebuild started for the next incremental sync.
        session.execute(
            sql_delete(SearchSyncOutbox)
            .where(SearchSyncOutbox.created_at <= started)
            .execution_options(synchronize_session=False)
        )
    except SearchEngineError as exc:
        with suppress(SearchEngineError):
            engine.delete_index(temporary)
        state.status = "failed"
        state.last_error = str(exc)[:500]
        session.commit()
        engine.close()
        return {
            "configured": True,
            "rebuilt": count,
            "index": base,
            "status": "failed",
            "error": state.last_error,
        }
    finally:
        engine.close()
    state.status = "idle"
    state.last_rebuild_at = utcnow()
    state.document_count = count
    state.last_error = None
    session.commit()
    return {"configured": True, "rebuilt": count, "index": base, "status": "idle"}


def _run(settings: Settings, operation: Any) -> dict[str, Any]:
    engine = create_engine_from_settings(settings)
    factory = create_session_factory(engine)
    session = factory()
    try:
        return operation(session, settings)
    finally:
        session.close()
        engine.dispose()


def process_search_sync(settings: Settings, as_of: datetime | None = None) -> dict[str, Any]:
    """No-argument-extra entry point for the task queue / Huey."""
    return _run(settings, lambda session, current: execute_sync(session, current, as_of))


def process_search_rebuild(settings: Settings) -> dict[str, Any]:
    """No-argument-extra entry point for the task queue / Huey."""
    return _run(settings, execute_rebuild)


__all__ = [
    "execute_rebuild",
    "execute_sync",
    "install_search_sync",
    "process_search_rebuild",
    "process_search_sync",
]
