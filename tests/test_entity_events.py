"""Reliable entity-change feed: transactional outbox, consumer cursors, references.

Every check uses the canonical services over a migrated, isolated SQLite file;
no fixture fakes the outbox or the history rows it is derived from. Rolled-back
work must leave no event, sequences must never reorder a late commit, and the
reference resolver must keep the existing Casbin authority instead of adding a
second one.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any
from uuid import uuid4

import pytest
from itsm.config import Settings
from itsm.events.feed import EntityEventFeed, UnknownConsumer
from itsm.events.models import EntityChangeEvent
from itsm.events.references import resolve_entities
from itsm.identity.clock import utcnow
from itsm.identity.service import PermissionDenied, ValidationFailed
from itsm.interventions.service import InterventionService
from itsm.inventory.models import Asset, AssetHistory
from itsm.inventory.service import InventoryService
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from tests.inventory_support import READER, Catalog, asset_values, prepare

SettingsFactory = Callable[..., Settings]


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


def inventory(catalog: Catalog, session: Session) -> InventoryService:
    return InventoryService(session, catalog.settings)


def interventions(catalog: Catalog, session: Session) -> InterventionService:
    return InterventionService(session, catalog.settings)


def feed(catalog: Catalog, *, lag: int = 0, grace_seconds: float = 0.0) -> EntityEventFeed:
    """A feed with the holdback window disabled unless a test opts into it."""
    return EntityEventFeed(catalog.factory(), lag=lag, grace_seconds=grace_seconds)


def events(catalog: Catalog) -> list[dict[str, Any]]:
    """Read the outbox through SQL so the assertion never trusts the writer."""
    with catalog.engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT id, sequence, entity_type, entity_id, event_type, actor_id,"
                " changed_fields FROM entity_change_events ORDER BY sequence"
            )
        ).all()
    return [
        {
            "id": row[0],
            "sequence": int(row[1]),
            "entity_type": row[2],
            "entity_id": row[3],
            "event_type": row[4],
            "actor_id": row[5],
            "changed_fields": row[6],
        }
        for row in rows
    ]


def create_asset(catalog: Catalog, session: Session) -> str:
    created = inventory(catalog, session).create(catalog.admin(), asset_values())
    return created.id


def create_incident(catalog: Catalog, session: Session, asset_id: str) -> str:
    created = interventions(catalog, session).create_incident(
        catalog.admin(),
        {"primaryAssetId": asset_id, "description": "Switch con puerto caido"},
    )
    return created.id


# ----------------------------------------------------------------- the outbox


def test_asset_create_writes_exactly_one_event_for_the_new_asset(catalog: Catalog) -> None:
    with catalog.session() as session:
        asset_id = create_asset(catalog, session)

    stored = events(catalog)
    assert len(stored) == 1
    event = stored[0]
    assert event["entity_type"] == "asset"
    assert event["entity_id"] == asset_id
    assert event["event_type"] == "asset.created"
    assert event["actor_id"] == catalog.admin().actor_id
    assert isinstance(event["changed_fields"], str) and "name" in event["changed_fields"]


def test_asset_update_records_the_changed_field_names_only(catalog: Catalog) -> None:
    with catalog.session() as session:
        asset_id = create_asset(catalog, session)
    with catalog.session() as session:
        inventory(catalog, session).update(catalog.admin(), asset_id, {"location": "Rack 9"})

    stored = events(catalog)
    assert [event["event_type"] for event in stored] == ["asset.created", "asset.updated"]
    assert "location" in stored[1]["changed_fields"]
    assert "secret-value" not in stored[1]["changed_fields"]


def test_asset_lifecycle_actions_map_to_lifecycle_events(catalog: Catalog) -> None:
    with catalog.session() as session:
        asset_id = create_asset(catalog, session)
    with catalog.session() as session:
        inventory(catalog, session).archive(catalog.admin(), asset_id, reason="baja")
    with catalog.session() as session:
        inventory(catalog, session).restore(catalog.admin(), asset_id)
    with catalog.session() as session:
        inventory(catalog, session).purge(
            catalog.admin(), asset_id, confirm=True, reason="fin de vida"
        )

    assert [event["event_type"] for event in events(catalog)] == [
        "asset.created",
        "asset.archived",
        "asset.restored",
        "asset.deleted",
    ]
    assert events(catalog)[-1]["entity_id"] == asset_id


def test_retire_is_an_update_because_the_mapping_has_no_retired_event(catalog: Catalog) -> None:
    with catalog.session() as session:
        asset_id = create_asset(catalog, session)
    with catalog.session() as session:
        inventory(catalog, session).retire(catalog.admin(), asset_id, reason="retiro")

    stored = events(catalog)
    assert stored[-1]["event_type"] == "asset.updated"
    assert "status" in stored[-1]["changed_fields"]


def test_incident_create_and_update_emit_one_event_each(catalog: Catalog) -> None:
    with catalog.session() as session:
        asset_id = create_asset(catalog, session)
        incident_id = create_incident(catalog, session, asset_id)
    with catalog.session() as session:
        second = inventory(catalog, session).create(catalog.admin(), asset_values(quick_code="A-2"))
    with catalog.session() as session:
        interventions(catalog, session).update_incident_assets(
            catalog.admin(), incident_id, [second.id]
        )

    incidents = [event for event in events(catalog) if event["entity_type"] == "incident"]
    assert [event["event_type"] for event in incidents] == [
        "incident.created",
        "incident.updated",
    ]
    assert all(event["entity_id"] == incident_id for event in incidents)
    # The incident history mirrored on the primary asset is not an asset change.
    asset_events = [event for event in events(catalog) if event["entity_type"] == "asset"]
    assert [event["event_type"] for event in asset_events] == ["asset.created", "asset.created"]


def test_rolled_back_mutation_leaves_no_event(catalog: Catalog) -> None:
    """The event shares the transaction: a rollback removes history and event."""
    session = catalog.factory()()
    try:
        asset = Asset(
            id=str(uuid4()),
            quick_code="RB-1",
            quick_code_key="rb-1",
            name="Rolled back",
            status="in_use",
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        session.add(asset)
        session.add(
            AssetHistory(
                id=str(uuid4()),
                sequence=1,
                asset_id=asset.id,
                action="created",
                changes={"name": {"old": None, "new": "Rolled back"}},
                source="internal",
                entity_type="asset",
                created_at=utcnow(),
            )
        )
        session.flush()
        # Staged by the same flush as the history row it derives from...
        assert session.execute(select(EntityChangeEvent)).scalars().all()
        session.rollback()
    finally:
        session.close()

    assert events(catalog) == []
    assert catalog.asset_count() == 0


def test_denied_mutation_and_tombstone_purge_keep_the_outbox_consistent(catalog: Catalog) -> None:
    catalog.add_user(*READER)
    reader = catalog.principal(READER[0])
    with catalog.session() as session:
        asset_id = create_asset(catalog, session)

    with pytest.raises(PermissionDenied), catalog.session() as session:
        inventory(catalog, session).archive(reader, asset_id)
    assert [event["event_type"] for event in events(catalog)] == ["asset.created"]

    with catalog.session() as session:
        inventory(catalog, session).archive(catalog.admin(), asset_id)
    with catalog.session() as session:
        inventory(catalog, session).purge(catalog.admin(), asset_id, confirm=True, reason="scrap")
    assert [event["event_type"] for event in events(catalog)][-1] == "asset.deleted"


# --------------------------------------------------------- consumer semantics


def test_poll_returns_events_after_the_cursor_and_ack_is_monotonic(catalog: Catalog) -> None:
    for index in range(3):
        with catalog.session() as session:
            inventory(catalog, session).create(
                catalog.admin(), asset_values(quick_code=f"A-{index}", name=f"Asset {index}")
            )

    stream = feed(catalog)
    first = stream.poll("license-extension", 2)
    assert [event.sequence for event in first] == [1, 2]
    assert stream.status("license-extension").last_sequence == 0

    stream.ack("license-extension", first[1].sequence)
    status = stream.status("license-extension")
    assert status.last_sequence == 2
    assert status.state == "active"

    # Idempotent and monotonic: a lower ack never rewinds the cursor.
    stream.ack("license-extension", first[0].sequence)
    stream.ack("license-extension", first[1].sequence)
    assert stream.status("license-extension").last_sequence == 2

    second = stream.poll("license-extension", 10)
    assert [event.sequence for event in second] == [3]
    assert second[0].event_type == "asset.created"


def test_poll_tolerates_a_permanent_gap_and_validates_input(catalog: Catalog) -> None:
    for index in range(2):
        with catalog.session() as session:
            inventory(catalog, session).create(
                catalog.admin(), asset_values(quick_code=f"G-{index}", name=f"Gap {index}")
            )
    stream = feed(catalog)
    stream.poll("worker", 10)  # registers the cursor at zero
    # Simulate an aborted allocation: sequence 2 will never be committed.
    with catalog.engine.begin() as connection:
        connection.execute(text("DELETE FROM entity_change_events WHERE sequence = 2"))

    delivered = stream.poll("worker", 10)
    assert [event.sequence for event in delivered] == [1]
    stream.ack("worker", 2)
    assert stream.poll("worker", 10) == []
    with pytest.raises(ValidationFailed):
        stream.poll("worker", 0)
    with pytest.raises(ValidationFailed):
        stream.poll("x" * 97, 10)
    with pytest.raises(UnknownConsumer):
        stream.status("never-registered")


def test_fail_counts_attempts_then_stalls_and_reset_recovers(catalog: Catalog) -> None:
    stream = feed(catalog)
    stream.poll("worker", 10)

    failed = stream.fail("worker", "handler_error", max_attempts=2)
    assert failed.attempts == 1
    assert failed.state == "active"
    assert failed.last_error == "handler_error"
    assert failed.retry_after is not None

    stalled = stream.fail("worker", "handler_error", max_attempts=2)
    assert stalled.attempts == 2
    assert stalled.state == "stalled"
    assert stream.status("worker").state == "stalled"

    recovered = stream.reset("worker")
    assert recovered.state == "active"
    assert recovered.attempts == 0
    assert recovered.last_error is None
    assert recovered.retry_after is None


def test_unknown_failure_code_is_refused(catalog: Catalog) -> None:
    stream = feed(catalog)
    stream.poll("worker", 10)
    with pytest.raises(ValidationFailed):
        stream.fail("worker", "Traceback: secret detail", max_attempts=3)


def test_late_committed_lower_sequence_is_not_skipped(catalog: Catalog) -> None:
    """SQLite allows one writer at a time, so the two sessions write in order.

    The observable state is what the feed must survive: a higher sequence is
    visible before a lower one. Session 2 holds sequence 1 back until after
    session 1 commits sequence 2.
    """
    older = EntityChangeEvent(
        id=str(uuid4()),
        sequence=1,
        entity_type="asset",
        entity_id=str(uuid4()),
        event_type="asset.created",
        occurred_at=utcnow(),
        actor_id=None,
        changed_fields=["name"],
    )
    newer = EntityChangeEvent(
        id=str(uuid4()),
        sequence=2,
        entity_type="asset",
        entity_id=str(uuid4()),
        event_type="asset.updated",
        occurred_at=utcnow(),
        actor_id=None,
        changed_fields=["location"],
    )
    with Session(catalog.engine) as first_session:
        first_session.add(newer)
        first_session.commit()

    stream = feed(catalog, lag=1, grace_seconds=3600)
    assert stream.poll("worker", 10) == []

    with Session(catalog.engine) as second_session:
        second_session.add(older)
        second_session.commit()

    # A newer commit advances the window; the late event is still first.
    with Session(catalog.engine) as third_session:
        third_session.add(
            EntityChangeEvent(
                id=str(uuid4()),
                sequence=3,
                entity_type="asset",
                entity_id=str(uuid4()),
                event_type="asset.updated",
                occurred_at=utcnow(),
                actor_id=None,
                changed_fields=["status"],
            )
        )
        third_session.commit()

    delivered = stream.poll("worker", 10)
    assert [event.sequence for event in delivered] == [1, 2]
    # Poll alone never advances the cursor: replay is at-least-once by design.
    assert [event.id for event in stream.poll("worker", 10)] == [event.id for event in delivered]
    stream.ack("worker", delivered[-1].sequence)
    # Sequence 3 is still inside the held tail and is not delivered yet.
    assert stream.poll("worker", 10) == []


def test_grace_release_delivers_low_volume_events_without_newer_ones(catalog: Catalog) -> None:
    with catalog.session() as session:
        create_asset(catalog, session)

    held = feed(catalog, lag=8, grace_seconds=3600)
    assert held.poll("worker", 10) == []

    released = feed(catalog, lag=8, grace_seconds=-1.0)
    assert [event.sequence for event in released.poll("worker", 10)] == [1]


def test_prune_never_deletes_events_an_active_consumer_has_not_acked(catalog: Catalog) -> None:
    for index in range(4):
        with catalog.session() as session:
            inventory(catalog, session).create(
                catalog.admin(), asset_values(quick_code=f"P-{index}", name=f"Prune {index}")
            )
    stream = feed(catalog)
    delivered = stream.poll("license-extension", 10)
    stream.poll("second-extension", 10)
    stream.ack("license-extension", delivered[0].sequence)

    # A second consumer still sits at zero: nothing is deletable yet.
    assert stream.prune(utcnow() + timedelta(minutes=1)) == 0
    assert [event["sequence"] for event in events(catalog)] == [1, 2, 3, 4]

    stream.ack("second-extension", 1)
    stream.ack("license-extension", 3)
    assert stream.prune(utcnow() + timedelta(minutes=1)) == 1
    assert [event["sequence"] for event in events(catalog)] == [2, 3, 4]

    # keep_after_min_cursor is an extra floor the operator can raise.
    stream.ack("second-extension", 4)
    assert stream.prune(utcnow() + timedelta(minutes=1), keep_after_min_cursor=3) == 2
    assert [event["sequence"] for event in events(catalog)] == [4]

    # A past cutoff prunes nothing regardless of the cursor.
    assert stream.prune(utcnow() - timedelta(days=1)) == 0


# ---------------------------------------------------------------- references


def test_resolve_entities_reports_active_archived_and_missing(catalog: Catalog) -> None:
    with catalog.session() as session:
        active_id = create_asset(catalog, session)
    with catalog.session() as session:
        archived_id = (
            inventory(catalog, session)
            .create(catalog.admin(), asset_values(quick_code="AR-1", name="Archivado"))
            .id
        )
    with catalog.session() as session:
        inventory(catalog, session).archive(catalog.admin(), archived_id)
    with catalog.session() as session:
        incident_id = create_incident(catalog, session, active_id)
    missing = str(uuid4())

    with catalog.session() as session:
        resolved = resolve_entities(
            catalog.admin(),
            "asset",
            [active_id, archived_id, missing, active_id],
            session=session,
            settings=catalog.settings,
        )
        assert resolved == {
            active_id: "active",
            archived_id: "archived",
            missing: "missing",
        }

    with catalog.session() as session:
        incidents = resolve_entities(
            catalog.admin(),
            "incident",
            [incident_id, missing],
            session=session,
            settings=catalog.settings,
        )
    assert incidents == {incident_id: "active", missing: "missing"}


def test_resolve_entities_keeps_the_existing_authorization(catalog: Catalog) -> None:
    with catalog.session() as session:
        asset_id = create_asset(catalog, session)
    with catalog.session() as session:
        identity = catalog.service(session)
        role = identity.create_role(catalog.admin(), name="sin-inventario", permissions=[])
    catalog.add_user("blind-user", "Blind User", role.id)
    blind = catalog.principal("blind-user")

    with catalog.session() as session, pytest.raises(PermissionDenied):
        resolve_entities(blind, "asset", [asset_id], session=session, settings=catalog.settings)

    with catalog.session() as session, pytest.raises(ValidationFailed):
        resolve_entities(
            catalog.admin(), "user", [asset_id], session=session, settings=catalog.settings
        )
    with catalog.session() as session, pytest.raises(ValidationFailed):
        resolve_entities(
            catalog.admin(),
            "asset",
            [str(uuid4()) for _ in range(201)],
            session=session,
            settings=catalog.settings,
        )
    with catalog.session() as session:
        assert (
            resolve_entities(
                catalog.admin(), "asset", [], session=session, settings=catalog.settings
            )
            == {}
        )
