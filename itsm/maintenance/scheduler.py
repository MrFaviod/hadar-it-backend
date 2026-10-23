"""Trusted periodic read of due plans; persist preparation, never deliver messages."""

from datetime import date, datetime
from uuid import uuid4

from sqlalchemy import Date, DateTime, String, UniqueConstraint, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.identity.clock import utcnow
from itsm.inventory.codes import InventoryCodeSequence
from itsm.inventory.models import InventoryBase


class MaintenanceReminder(InventoryBase):
    __tablename__ = "maintenance_reminders"
    __table_args__ = (
        UniqueConstraint("plan_id", "due_on", "stage", name="uq_maintenance_reminder_due_stage"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    plan_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    due_on: Mapped[date] = mapped_column(Date, nullable=False)
    stage: Mapped[str] = mapped_column(String(16), nullable=False)
    prepared_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


def prepare_reminders(settings: Settings, *, as_of: date | None = None) -> dict[str, int]:
    """Prepare each due-date stage once, including after retries or competing scans."""
    from itsm.maintenance.service import iter_due_plans

    today = as_of or date.today()
    engine = create_engine_from_settings(settings)
    created = 0
    scanned = 0
    try:
        with create_session_factory(engine)() as session:
            offset = 0
            while True:
                # Share the domain write mutex so completion/cancellation cannot
                # race a preparation based on a stale due date.
                session.execute(
                    update(InventoryCodeSequence)
                    .where(InventoryCodeSequence.key == "__lock__")
                    .values(next_value=InventoryCodeSequence.next_value)
                )
                page = iter_due_plans(
                    session, settings, as_of=today, horizon_days=30, limit=200, offset=offset
                )
                plans = page.items
                if not plans:
                    break
                for plan in plans:
                    scanned += 1
                    stage = "overdue" if plan.due_on < today else "upcoming"
                    existing = session.scalar(
                        select(MaintenanceReminder.id).where(
                            MaintenanceReminder.plan_id == plan.id,
                            MaintenanceReminder.due_on == plan.due_on,
                            MaintenanceReminder.stage == stage,
                        )
                    )
                    if existing is not None:
                        continue
                    try:
                        with session.begin_nested():
                            session.add(
                                MaintenanceReminder(
                                    id=str(uuid4()),
                                    plan_id=plan.id,
                                    asset_id=plan.asset_id,
                                    due_on=plan.due_on,
                                    stage=stage,
                                    prepared_at=utcnow().replace(tzinfo=None),
                                )
                            )
                            session.flush()
                    except IntegrityError:
                        # A concurrent scan may win the same durable unique key.
                        winner = session.scalar(
                            select(MaintenanceReminder.id).where(
                                MaintenanceReminder.plan_id == plan.id,
                                MaintenanceReminder.due_on == plan.due_on,
                                MaintenanceReminder.stage == stage,
                            )
                        )
                        if winner is None:
                            raise
                    else:
                        created += 1
                offset += len(plans)
            session.commit()
        return {"created": created, "scanned": scanned}
    finally:
        engine.dispose()
