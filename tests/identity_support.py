"""Test-only helpers for the identity module: a real database and a movable clock."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.identity.service import IdentityService
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session
from tests.conftest import run_migrations

PASSWORD = "installer-password-2026"
START = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)


@dataclass
class Harness:
    """One isolated database plus an explicit clock for expiry/throttle tests."""

    settings: Settings
    engine: Engine
    clock: datetime = field(default=START)

    def tick(self, minutes: int) -> datetime:
        self.clock = self.clock + timedelta(minutes=minutes)
        return self.clock

    def now(self) -> datetime:
        return self.clock

    @contextmanager
    def service(self) -> Iterator[IdentityService]:
        with Session(self.engine) as session:
            yield IdentityService(session, self.settings, now=self.now)

    def sql(self, statement: str) -> list[Any]:
        with self.engine.connect() as connection:
            return list(connection.execute(text(statement)))

    def scalar(self, statement: str) -> Any:
        rows = self.sql(statement)
        return None if not rows else rows[0][0]

    def execute(self, statement: str, params: dict[str, Any] | None = None) -> None:
        with self.engine.begin() as connection:
            connection.execute(text(statement), params or {})

    def close(self) -> None:
        self.engine.dispose()


def make_harness(settings_factory: Any) -> Harness:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    return Harness(settings=settings, engine=create_engine_from_settings(settings))
