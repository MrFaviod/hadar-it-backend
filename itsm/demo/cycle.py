"""Server-owned cycle state for one shared demonstration installation."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import Boolean, DateTime, Engine, Integer
from sqlalchemy.orm import Mapped, Session, mapped_column

from itsm.config import Settings
from itsm.identity.clock import utcnow
from itsm.release_identity import DeploymentBase, DeploymentIdentityError, read_identity


class DemoCycle(DeploymentBase):
    """Singleton deadline surviving API restarts; only a demo owner may create it."""

    __tablename__ = "demo_cycle"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    next_reset_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resetting: Mapped[bool] = mapped_column(Boolean, nullable=False)


def reset_demo(settings: Settings, engine: Engine) -> None:
    """Reset under the caller's exclusive request gate."""
    from itsm.demo.reset import reset_demo as perform_reset

    perform_reset(settings, engine)


def cycle_status(session: Session) -> dict:
    """Read the persistent deadline, initializing it only in a claimed demo DB."""
    owner = read_identity(session)
    if owner is None or owner.release_mode != "demo":
        raise DeploymentIdentityError("demo cycle requires a demo-owned database")
    now = utcnow()
    row = session.get(DemoCycle, 1)
    if row is None:
        row = DemoCycle(
            id=1, generation=1, next_reset_at=now + timedelta(minutes=60), resetting=False
        )
        session.add(row)
        session.commit()
    deadline = row.next_reset_at
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    return {
        "enabled": True,
        "serverTime": now.isoformat(),
        "nextResetAt": deadline.isoformat(),
        "generation": row.generation,
        "resetting": row.resetting,
    }
