"""Write the outbox row in the same flush as the history row it describes.

The mapping is deliberately derived from the existing append-only history rather
than from a second call site: every asset or incident mutation already inserts
``asset_history`` or ``technical_incident_events`` in its own transaction, so the
outbox inherits that atomicity for free. A rollback removes the history row and
the event together; nothing is published for work that never committed.

History rows that mirror an incident onto an asset (``entity_type`` other than
``asset``) are skipped: the incident's own history already produced the incident
event, and the asset did not change.
"""

from __future__ import annotations

import weakref
from typing import Any, Final
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

from itsm.events.models import MAX_CHANGED_FIELDS, MAX_FIELD_NAME, EntityChangeEvent
from itsm.identity.clock import utcnow
from itsm.interventions.models import IncidentEvent
from itsm.inventory.models import AssetHistory

OUTBOX_TABLE: Final[str] = "entity_change_events"
_EMITTED_KEY: Final[str] = "itsm.entity_events.emitted"

# Asset history actions that describe more than a plain update.
_ASSET_EVENTS: Final[dict[str, str]] = {
    "created": "asset.created",
    "cloned": "asset.created",
    "archived": "asset.archived",
    "restored": "asset.restored",
    "purged": "asset.deleted",
}
_ASSET_FALLBACK: Final[str] = "asset.updated"

_INCIDENT_EVENTS: Final[dict[str, str]] = {"created": "incident.created"}
_INCIDENT_FALLBACK: Final[str] = "incident.updated"

_AVAILABILITY: weakref.WeakKeyDictionary[Any, bool] = weakref.WeakKeyDictionary()
_INSTALLED = False


def _outbox_present(session: Session) -> bool:
    """Whether the bound database already has the outbox table.

    A focused test or a maintenance script may build metadata without the full
    migration chain; the listener then has nothing to write to and stays inert.
    The application always runs against the migrated schema (readiness refuses
    to serve otherwise), so this only covers explicitly partial schemas.
    """
    try:
        bind = session.get_bind()
    except Exception:  # an unbound session cannot flush at all
        return False
    engine = getattr(bind, "engine", bind)
    try:
        cached = _AVAILABILITY.get(engine)
    except TypeError:  # not weak-referenceable
        return _has_table(bind)
    if cached is None:
        cached = _has_table(bind)
        _AVAILABILITY[engine] = cached
    return cached


def _has_table(bind: Any) -> bool:
    try:
        return bool(inspect(bind).has_table(OUTBOX_TABLE))
    except Exception:  # a broken connection is reported by the flush itself
        return False


def _field_names(names: Any, extra: tuple[str, ...] = ()) -> list[str]:
    collected = {
        name[:MAX_FIELD_NAME] for name in names or () if isinstance(name, str) and name.strip()
    }
    collected.update(extra)
    return sorted(collected)[:MAX_CHANGED_FIELDS]


def _asset_event(row: AssetHistory) -> EntityChangeEvent | None:
    if (row.entity_type or "asset") != "asset":
        return None
    changes = row.changes if isinstance(row.changes, dict) else {}
    extra: list[str] = []
    if row.status_old != row.status_new:
        extra.append("status")
    if row.archived_old != row.archived_new:
        extra.append("archived")
    if row.quick_code_old != row.quick_code_new:
        extra.append("quickCode")
    return EntityChangeEvent(
        id=_event_id(row.id),
        entity_type="asset",
        entity_id=row.asset_id,
        event_type=_ASSET_EVENTS.get(row.action, _ASSET_FALLBACK),
        occurred_at=row.created_at or utcnow(),
        actor_id=row.actor_id,
        changed_fields=_field_names(changes.keys(), tuple(extra)),
    )


def _incident_event(row: IncidentEvent) -> EntityChangeEvent:
    changes = row.changes if isinstance(row.changes, dict) else {}
    extra = ("status",) if row.from_status != row.to_status else ()
    return EntityChangeEvent(
        id=_event_id(row.id),
        entity_type="incident",
        entity_id=row.incident_id,
        event_type=_INCIDENT_EVENTS.get(row.action, _INCIDENT_FALLBACK),
        occurred_at=row.created_at or utcnow(),
        actor_id=row.actor_id,
        changed_fields=_field_names(changes.keys(), extra),
    )


def _event_id(history_id: str) -> str:
    """Deterministic UUID-shaped id derived from the history row id.

    Deriving it keeps the outbox idempotent if a caller retries the same
    history insert (for example during a deferred receipt bridge).
    """
    return str(uuid5(NAMESPACE_URL, f"itsm:entity-change:{history_id}"))


def _emit(session: Session, flush_context: Any, instances: Any) -> None:
    source = [row for row in session.new if isinstance(row, (AssetHistory, IncidentEvent))]
    if not source:
        return
    if not _outbox_present(session):
        return
    seen: set[str] = session.info.setdefault(_EMITTED_KEY, set())
    for row in source:
        if row.id in seen:
            continue
        pending = _asset_event(row) if isinstance(row, AssetHistory) else _incident_event(row)
        if pending is None:
            continue
        seen.add(row.id)
        session.add(pending)


def _forget(session: Session, *args: Any) -> None:
    session.info.pop(_EMITTED_KEY, None)


def install_event_listeners() -> None:
    """Install the flush hook exactly once for this process."""
    global _INSTALLED
    if _INSTALLED:
        return
    event.listen(Session, "before_flush", _emit)
    event.listen(Session, "after_commit", _forget)
    event.listen(Session, "after_rollback", _forget)
    _INSTALLED = True


__all__ = ["OUTBOX_TABLE", "install_event_listeners"]
