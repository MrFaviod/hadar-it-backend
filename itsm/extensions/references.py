"""Host-applied reference policy for declarative extension collections.

A declarative module cannot execute code, so it declares which of its fields
hold a permanent core id and what should happen when that entity is archived or
deleted. The host applies that policy to the module's own SQLite file: it never
writes core tables, and it stores the outcome as host-managed ``_references``
metadata next to the module's data. Every operation is idempotent so an
at-least-once event delivery or a repeated reconciliation never duplicates work.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

from itsm.extensions.runtime import sqlite_store

REFERENCE_KEY = "_references"
REFERENCE_STATES = frozenset({"archived", "missing"})
_PAGE = 200
_MAX_SCAN = 20_000


def _collections(manifest: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
    for collection in manifest.get("collections") or []:
        if collection.get("references"):
            yield collection


def _records(connection: Any, collection: str) -> Iterator[tuple[str, dict[str, Any]]]:
    offset = 0
    while offset < _MAX_SCAN:
        page = sqlite_store.list_records(
            connection, collection, limit=_PAGE, offset=offset, filters=None
        )
        items = page["items"]
        if not items:
            return
        for item in items:
            data = item["data"]
            if isinstance(data, dict):
                yield item["id"], data
        offset += len(items)


def _write(
    connection: Any,
    collection: str,
    record_id: str,
    data: Mapping[str, Any],
    states: Mapping[str, str],
) -> bool:
    updated = {key: value for key, value in data.items() if key != REFERENCE_KEY}
    if states:
        updated[REFERENCE_KEY] = dict(sorted(states.items()))
    if dict(updated) == dict(data):
        return False
    current = sqlite_store.get(connection, collection, record_id)
    expected = None if current is None else current["version"]
    sqlite_store.put(connection, collection, record_id, updated, expected)
    return True


def referenced_ids(
    connection: Any,
    manifest: Mapping[str, Any],
    entity_type: str,
    *,
    limit: int = 200,
) -> list[str]:
    """Collect the first ``limit`` distinct ids a module holds for one entity."""
    found: list[str] = []
    seen: set[str] = set()
    for collection in _collections(manifest):
        fields = [
            reference["field"]
            for reference in collection["references"]
            if reference["entity"] == entity_type
        ]
        if not fields:
            continue
        for _, data in _records(connection, collection["name"]):
            for field in fields:
                value = data.get(field)
                if isinstance(value, str) and value and value not in seen:
                    seen.add(value)
                    found.append(value)
                    if len(found) >= limit:
                        return found
    return found


def apply_event(
    connection: Any,
    manifest: Mapping[str, Any],
    *,
    entity_type: str,
    entity_id: str,
    event_type: str,
) -> int:
    """Apply archive/delete/restore policy for one delivered core event."""
    changed = 0
    for collection in _collections(manifest):
        references = [
            reference
            for reference in collection["references"]
            if reference["entity"] == entity_type
        ]
        if not references:
            continue
        records = [
            (record_id, data)
            for record_id, data in _records(connection, collection["name"])
            if any(data.get(reference["field"]) == entity_id for reference in references)
        ]
        for record_id, data in records:
            states = {
                key: value
                for key, value in dict(data.get(REFERENCE_KEY) or {}).items()
                if isinstance(value, str) and value in REFERENCE_STATES
            }
            remove = False
            for reference in references:
                if data.get(reference["field"]) != entity_id:
                    continue
                field = reference["field"]
                if event_type == f"{entity_type}.archived" and reference["onArchive"] == "flag":
                    states[field] = "archived"
                elif event_type == f"{entity_type}.restored":
                    states.pop(field, None)
                elif event_type == f"{entity_type}.deleted":
                    if reference["onDelete"] == "delete":
                        remove = True
                    else:
                        states[field] = "missing"
            if remove:
                if sqlite_store.delete(connection, collection["name"], record_id):
                    changed += 1
                continue
            if _write(connection, collection["name"], record_id, data, states):
                changed += 1
    return changed


def apply_states(
    connection: Any,
    manifest: Mapping[str, Any],
    *,
    entity_type: str,
    states: Mapping[str, str],
) -> int:
    """Reconcile stored references with fresh ``active|archived|missing`` states."""
    changed = 0
    for collection in _collections(manifest):
        references = [
            reference
            for reference in collection["references"]
            if reference["entity"] == entity_type
        ]
        if not references:
            continue
        records = [
            (record_id, data)
            for record_id, data in _records(connection, collection["name"])
            if any(data.get(reference["field"]) in states for reference in references)
        ]
        for record_id, data in records:
            desired = {
                key: value
                for key, value in dict(data.get(REFERENCE_KEY) or {}).items()
                if isinstance(value, str) and value in REFERENCE_STATES
            }
            remove = False
            for reference in references:
                field = reference["field"]
                state = states.get(data.get(field))
                if state is None:
                    continue
                if state == "active":
                    desired.pop(field, None)
                elif state == "archived" and reference["onArchive"] == "flag":
                    desired[field] = "archived"
                elif state == "missing":
                    if reference["onDelete"] == "delete":
                        remove = True
                    else:
                        desired[field] = "missing"
            if remove:
                if sqlite_store.delete(connection, collection["name"], record_id):
                    changed += 1
                continue
            if _write(connection, collection["name"], record_id, data, desired):
                changed += 1
    return changed


def references_for(manifest: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Flatten declared references so callers can discover work cheaply."""
    return [
        reference for collection in _collections(manifest) for reference in collection["references"]
    ]


__all__ = [
    "REFERENCE_KEY",
    "REFERENCE_STATES",
    "apply_event",
    "apply_states",
    "referenced_ids",
    "references_for",
]
