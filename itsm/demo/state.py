"""Durable installation identity; no API permits removing the demo marker."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


class DemoBase(DeclarativeBase):
    pass


class DemoInstallation(DemoBase):
    __tablename__ = "demo_installation"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dataset: Mapped[str] = mapped_column(String(48), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def is_demo(session: Session) -> bool:
    """Read persisted identity on every dispatch; process flags cannot undo it."""
    return session.scalar(select(DemoInstallation.id).where(DemoInstallation.id == 1)) == 1
