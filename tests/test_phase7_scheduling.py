"""Periodic preparation is durable, retry-safe and never completes maintenance."""

from datetime import date

from itsm.maintenance.scheduler import prepare_reminders
from sqlalchemy import text


def test_repeated_scan_prepares_each_due_stage_once(settings_factory, tmp_path):
    from itsm.inventory.service import InventoryService
    from itsm.maintenance.service import MaintenanceService
    from tests.inventory_support import asset_values, prepare

    catalog = prepare(settings_factory)
    settings, engine = catalog.settings, catalog.engine
    try:
        factory = catalog.factory()
        principal = catalog.admin()
        with factory() as session:
            inventory = InventoryService(session, settings)
            asset = inventory.create(principal, asset_values(name="Periodic maintenance"))
            maintenance = MaintenanceService(session, settings)
            plan = maintenance.create_plan(
                principal,
                asset_id=asset.id,
                maintenance_type="periodic_probe",
                interval_months=6,
                due_on=date(2026, 10, 24),
            )
            plan_id = plan.id
        first = prepare_reminders(settings, as_of=date(2026, 10, 23))
        second = prepare_reminders(settings, as_of=date(2026, 10, 23))
        assert first["created"] >= 1
        assert second["created"] == 0
        with factory() as session:
            reminders = (
                session.execute(
                    text("SELECT stage FROM maintenance_reminders WHERE plan_id = :id"),
                    {"id": plan_id},
                )
                .scalars()
                .all()
            )
            assert reminders == ["upcoming"]
        prepare_reminders(settings, as_of=date(2026, 10, 25))
        prepare_reminders(settings, as_of=date(2026, 10, 25))
        with factory() as session:
            stages = (
                session.execute(
                    text(
                        "SELECT stage FROM maintenance_reminders WHERE plan_id = :id ORDER BY stage"
                    ),
                    {"id": plan_id},
                )
                .scalars()
                .all()
            )
            assert stages == ["overdue", "upcoming"]
            current = MaintenanceService(session, settings).get_plan(principal, plan_id)
            assert current.last_completed_on is None
            assert current.due_on == date(2026, 10, 24)
    finally:
        engine.dispose()


def test_failed_scan_retry_preserves_unique_reminders(settings_factory, monkeypatch):
    import pytest
    from itsm.inventory.service import InventoryService
    from itsm.maintenance.service import MaintenanceService
    from sqlalchemy.orm import Session
    from tests.inventory_support import asset_values, prepare

    catalog = prepare(settings_factory)
    try:
        factory = catalog.factory()
        principal = catalog.admin()
        with factory() as session:
            asset = InventoryService(session, catalog.settings).create(principal, asset_values())
            plan = MaintenanceService(session, catalog.settings).create_plan(
                principal,
                asset_id=asset.id,
                maintenance_type="retry_probe",
                interval_months=6,
                due_on=date(2026, 10, 20),
            )
        original_commit = Session.commit
        with monkeypatch.context() as patch:

            def unavailable_commit(session):
                raise RuntimeError("injected commit interruption")

            patch.setattr(Session, "commit", unavailable_commit)
            with pytest.raises(RuntimeError, match="injected commit interruption"):
                prepare_reminders(catalog.settings, as_of=date(2026, 10, 23))
        assert Session.commit is original_commit
        prepare_reminders(catalog.settings, as_of=date(2026, 10, 23))
        assert prepare_reminders(catalog.settings, as_of=date(2026, 10, 23))["created"] == 0
        with factory() as session:
            assert (
                session.scalar(
                    text(
                        "SELECT count(*) FROM maintenance_reminders "
                        "WHERE plan_id = :id AND stage = 'overdue'"
                    ),
                    {"id": plan.id},
                )
                == 1
            )
            current = MaintenanceService(session, catalog.settings).get_plan(principal, plan.id)
            assert current.last_completed_on is None
            assert current.due_on == date(2026, 10, 20)
    finally:
        catalog.engine.dispose()
