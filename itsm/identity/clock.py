"""Small UTC clock helpers shared by the identity module.

SQLite and MySQL return naive datetimes for timezone-aware columns, so every
timestamp read back from storage goes through :func:`as_utc` before it is
compared with :func:`utcnow`.
"""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
