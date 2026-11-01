"""The i18n preference migration upgrades and downgrades on SQLite."""

from __future__ import annotations

from collections.abc import Callable

from itsm.config import Settings
from sqlalchemy import create_engine, inspect
from tests.conftest import BACKEND_ROOT, run_cli, run_migrations


def columns(settings: Settings, table: str) -> set[str]:
    engine = create_engine(settings.database_url)
    try:
        return {column["name"] for column in inspect(engine).get_columns(table)}
    finally:
        engine.dispose()


def test_i18n_preferences_migration_upgrades_and_downgrades(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    assert run_migrations(settings).returncode == 0

    assert "locale" in columns(settings, "identity_identities")
    assert {"default_locale", "timezone", "currency"} <= columns(
        settings, "identity_security_settings"
    )

    downgrade = run_cli(
        ["-m", "alembic", "-c", str(BACKEND_ROOT / "alembic.ini"), "downgrade", "-1"],
        settings,
    )
    assert downgrade.returncode == 0, downgrade.stderr
    assert "locale" not in columns(settings, "identity_identities")
    assert "default_locale" not in columns(settings, "identity_security_settings")

    assert run_migrations(settings).returncode == 0
    assert "locale" in columns(settings, "identity_identities")
