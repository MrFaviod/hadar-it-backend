"""The declared production backup policy, owned by the setup process.

Setup never writes a domain setting directly. The backup policy an operator
declares here is *installation metadata*: a durable record of what the operator
says will protect this installation, with who declared it and when. The runtime
backup state keeps its own owner: ``SystemService.backup_status`` still reports
the observed/published status, and setup reads that first. A declaration is
therefore labelled ``declared`` everywhere, never ``observed``.

One singleton row lives in ``installation_backup_policy`` so the declaration
outlives the private setup state directory and the wizard itself.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Integer, String, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

TABLE_NAME = "installation_backup_policy"
LOCATION_KINDS: tuple[str, ...] = (
    "local",
    "remote",
    "object_storage",
    "managed_service",
    "other",
)
FIELDS: tuple[str, ...] = ("target", "location_kind", "schedule", "retention", "responsible")
MAX_FIELD = 200
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_DIGIT = re.compile(r"\d")


class BackupPolicyInvalid(ValueError):
    """The proposed declaration is not a usable policy; messages carry no values."""


class BackupPolicyBase(DeclarativeBase):
    """Declarative base kept private to the installation-level declaration."""


class InstallationBackupPolicy(BackupPolicyBase):
    """One row: the policy the operator declared for this installation."""

    __tablename__ = TABLE_NAME
    __table_args__ = (CheckConstraint("id = 1", name="ck_installation_backup_policy_singleton"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    target: Mapped[str] = mapped_column(String(MAX_FIELD), nullable=False)
    location_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    schedule: Mapped[str] = mapped_column(String(120), nullable=False)
    retention: Mapped[str] = mapped_column(String(120), nullable=False)
    responsible: Mapped[str] = mapped_column(String(120), nullable=False)
    declared_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    declared_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def _clean(name: str, value: Any, limit: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise BackupPolicyInvalid(f"a backup policy needs a {name.replace('_', ' ')}")
    if len(text) > limit:
        raise BackupPolicyInvalid(f"the backup policy {name.replace('_', ' ')} is too long")
    if _CONTROL.search(text):
        raise BackupPolicyInvalid(
            f"the backup policy {name.replace('_', ' ')} has control characters"
        )
    return text


def normalize(values: dict[str, Any]) -> dict[str, str]:
    """Validate the operator's declaration and return a clean policy body."""

    if not isinstance(values, dict):
        raise BackupPolicyInvalid("a backup policy declaration is required")
    target = _clean("target", values.get("target"), MAX_FIELD)
    location_kind = _clean("location_kind", values.get("location_kind"), 32).lower()
    if location_kind not in LOCATION_KINDS:
        raise BackupPolicyInvalid(
            "the backup location kind must be one of " + ", ".join(LOCATION_KINDS)
        )
    schedule = _clean("schedule", values.get("schedule"), 120)
    retention = _clean("retention", values.get("retention"), 120)
    if not _DIGIT.search(retention):
        raise BackupPolicyInvalid("the backup retention must state a bounded period, not unlimited")
    responsible = _clean("responsible", values.get("responsible"), 120)
    return {
        "target": target,
        "location_kind": location_kind,
        "schedule": schedule,
        "retention": retention,
        "responsible": responsible,
    }


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def as_body(row: InstallationBackupPolicy) -> dict[str, Any]:
    """Public declaration body: fields plus the identity that declared them."""

    return {
        "target": row.target,
        "location_kind": row.location_kind,
        "schedule": row.schedule,
        "retention": row.retention,
        "responsible": row.responsible,
        "declared_by": row.declared_by,
        "declared_at": _iso(row.declared_at),
        "source": "declaration",
    }


def read_policy(session: Session) -> InstallationBackupPolicy | None:
    return session.scalar(select(InstallationBackupPolicy).where(InstallationBackupPolicy.id == 1))


def declare(
    session: Session,
    policy: dict[str, str],
    *,
    declared_by: str | None,
    declared_at: datetime | None = None,
) -> InstallationBackupPolicy:
    """Insert or replace the singleton declaration and return the stored row."""

    moment = declared_at or datetime.now(UTC)
    row = read_policy(session)
    if row is None:
        row = InstallationBackupPolicy(id=1, **policy, declared_by=declared_by, declared_at=moment)
        session.add(row)
    else:
        for key, value in policy.items():
            setattr(row, key, value)
        row.declared_by = declared_by
        row.declared_at = moment
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        existing = read_policy(session)
        if existing is None:  # pragma: no cover - defensive re-read
            raise
        return existing
    session.refresh(row)
    return row


__all__ = [
    "FIELDS",
    "LOCATION_KINDS",
    "TABLE_NAME",
    "BackupPolicyInvalid",
    "InstallationBackupPolicy",
    "as_body",
    "declare",
    "normalize",
    "read_policy",
]
