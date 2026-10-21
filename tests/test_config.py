"""Tests for the environment-driven settings surface."""

from __future__ import annotations

import pytest
from itsm.config import Settings
from pydantic import ValidationError


def make_settings(**overrides: object) -> Settings:
    """Build settings without touching the ambient environment or any .env file."""
    values: dict[str, object] = {
        "database_url": "sqlite:////data/app/itsm.db",
        "task_sqlite_path": "/data/tasks/huey.db",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_defaults_use_postgresql_and_isolated_sqlite_queue() -> None:
    settings = Settings(_env_file=None)

    assert settings.database_url.startswith("postgresql+psycopg://")
    assert settings.task_storage == "sqlite"
    assert str(settings.task_sqlite_path) == "/data/tasks/huey.db"
    assert settings.task_retries == 2
    assert settings.demo_periodic_minutes == 0


def test_environment_prefix_overrides_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ITSM_DATABASE_URL", "sqlite:////tmp/app.db")
    monkeypatch.setenv("ITSM_TASK_SQLITE_PATH", "/tmp/tasks.db")
    monkeypatch.setenv("ITSM_TASK_RETRIES", "1")

    settings = Settings(_env_file=None)

    assert settings.database_url == "sqlite:////tmp/app.db"
    assert str(settings.task_sqlite_path) == "/tmp/tasks.db"
    assert settings.task_retries == 1


def test_database_driver_must_be_supported() -> None:
    with pytest.raises(ValidationError, match="database_url"):
        make_settings(database_url="mysql+mysqlconnector://u:p@h/db")


def test_queue_file_must_not_reuse_the_sqlite_application_database() -> None:
    with pytest.raises(ValidationError, match="same file"):
        make_settings(
            database_url="sqlite:////data/app/itsm.db",
            task_sqlite_path="/data/app/itsm.db",
        )


def test_postgres_task_storage_requires_a_dsn() -> None:
    with pytest.raises(ValidationError, match="task_postgres_dsn"):
        make_settings(task_storage="postgres", task_postgres_dsn="")


def test_redis_task_storage_requires_a_redis_url() -> None:
    with pytest.raises(ValidationError, match="task_redis_url"):
        make_settings(task_storage="redis", task_redis_url="")


def test_unsupported_task_storage_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_settings(task_storage="memory")


def test_retries_are_bounded() -> None:
    with pytest.raises(ValidationError, match="task_retries"):
        make_settings(task_retries=50)


def test_safe_database_url_hides_credentials() -> None:
    settings = make_settings(
        database_url="postgresql+psycopg://itsm:supersecret@db.example:5432/itsm",
    )

    safe = settings.safe_database_url()

    assert "supersecret" not in safe
    assert "db.example" in safe
    assert "supersecret" in settings.sensitive_values()


def test_sensitive_values_include_queue_credentials() -> None:
    settings = make_settings(
        task_storage="redis",
        task_redis_url="redis://:queuepassword@redis.example:6379/0",
    )

    values = settings.sensitive_values()

    assert "queuepassword" in values
    assert "redis://:queuepassword@redis.example:6379/0" in values
