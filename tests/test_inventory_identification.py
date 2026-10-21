"""Configured quick codes are allocated atomically through the public service."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import UUID

import pytest
from itsm.identity.service import Conflict, ValidationFailed
from itsm.inventory.catalog import InventoryCatalog
from itsm.inventory.service import InventoryService
from tests.inventory_support import prepare


def configure(db):
    with db.session() as session:
        InventoryCatalog(session, db.settings).put(
            db.admin(),
            "rules",
            "identification",
            {
                "siteCodes": {"Datacenter": "DC", "Branch": "BR"},
                "quickPad": 2,
                "separator": "-",
                "siteCodeLength": 3,
                "includeSite": True,
                "order": "site-type",
            },
        )


def create(db, **values):
    with db.session() as session:
        return InventoryService(session, db.settings).create(
            db.admin(), {"name": "Server", "category": "servidores", "site": "Datacenter", **values}
        )


def test_configured_example_collision_location_change_and_history(settings_factory):
    db = prepare(settings_factory)
    configure(db)
    first = create(db)
    second = create(db)
    assert first.quick_code == "DC-SER-01"
    assert second.quick_code == "DC-SER-02"
    assert str(UUID(first.id)) == first.id
    with db.session() as session:
        assets = InventoryService(session, db.settings)
        moved = assets.update(db.admin(), first.id, {"site": "Branch"})
        assert moved.id == first.id
        assert moved.quick_code == "BR-SER-01"
        entries = assets.history(db.admin(), first.id).items
        assert entries[-1].quick_code_old == "DC-SER-01"
        assert entries[-1].quick_code_new == "BR-SER-01"
        assets.purge(db.admin(), second.id, confirm=True)
    assert create(db).quick_code == "DC-SER-03"  # Never rewind the allocator after purge.
    db.engine.dispose()


def test_explicit_collision_advances_only_numeric_suffix(settings_factory):
    db = prepare(settings_factory)
    configure(db)
    assert create(db, quick_code="DC-SER-01").quick_code == "DC-SER-01"
    assert create(db, quick_code="dc-ser-01").quick_code == "dc-ser-02"
    create(db, quick_code="MANUAL")
    with pytest.raises(Conflict):
        create(db, quick_code="manual")
    db.engine.dispose()


def test_concurrent_creation_returns_unique_sequential_codes(settings_factory):
    db = prepare(settings_factory)
    configure(db)
    barrier = Barrier(4)

    def operation(index):
        barrier.wait(timeout=10)
        return create(db, name=f"Concurrent {index}")

    with ThreadPoolExecutor(max_workers=4) as workers:
        rows = list(workers.map(operation, range(4)))
    assert {row.quick_code for row in rows} == {f"DC-SER-{i:02d}" for i in range(1, 5)}
    assert len({row.id for row in rows}) == 4
    db.engine.dispose()


def test_rejected_batch_does_not_advance_sequence(settings_factory):
    db = prepare(settings_factory)
    configure(db)
    with db.session() as session, pytest.raises(ValidationFailed):
        InventoryService(session, db.settings).batch(
            db.admin(),
            create=[
                {"name": "Valid", "category": "servidores", "site": "Datacenter"},
                {
                    "name": "Invalid",
                    "category": "servidores",
                    "site": "Datacenter",
                    "ip": "bad",
                },
            ],
        )
    assert db.asset_count() == 0
    assert create(db).quick_code == "DC-SER-01"
    db.engine.dispose()


def test_catalog_custom_values_transitions_and_disabled_preservation(settings_factory):
    db = prepare(settings_factory)
    with db.session() as session:
        catalog = InventoryCatalog(session, db.settings)
        catalog.put(
            db.admin(), "rules", "transitions", {"transitions": {"in_use": ["maintenance"]}}
        )
    row = create(db, technical={"ram": 16})
    with db.session() as session:
        assets = InventoryService(session, db.settings)
        with pytest.raises(ValidationFailed):
            assets.update(db.admin(), row.id, {"technical": {"ram": "sixteen"}})
        with pytest.raises(ValidationFailed):
            assets.update(db.admin(), row.id, {"status": "retired"})
        unchanged = assets.get(db.admin(), row.id)
        assert unchanged.technical == {"ram": 16}
        assert unchanged.status == "in_use"
        changed = assets.update(db.admin(), row.id, {"status": "maintenance"})
        assert changed.site == row.site and changed.responsible == row.responsible
    db.engine.dispose()
