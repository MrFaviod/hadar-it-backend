"""Tests for the environment-driven settings surface."""

from __future__ import annotations

import pytest
from itsm.config import Settings, parse_personal_private_endpoints
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


@pytest.mark.parametrize("url", [
    "http://user:password@localhost:8766", "http://localhost:8766/validate",
    "http://localhost:8766?command=run", "http://localhost:8766#target", "file:///tmp/validator",
])
def test_extension_validator_rejects_nonfixed_base_urls(url: str) -> None:
    with pytest.raises(ValidationError, match="extension_validator_url"):
        make_settings(extension_validator_url=url, extension_validator_token="test-token-" * 4)


def test_extension_validator_requires_paired_redacted_secret() -> None:
    token = "local-validator-test-token-" * 2
    with pytest.raises(ValidationError, match="configured together"):
        make_settings(extension_validator_url="http://127.0.0.1:8766")
    with pytest.raises(ValidationError, match="configured together"):
        make_settings(extension_validator_token=token)
    configured = make_settings(
        extension_validator_url="http://127.0.0.1:8766/", extension_validator_token=token,
    )
    assert token in configured.sensitive_values()
    assert token not in repr(configured)
    # Empty Compose variables leave validation unavailable, not a malformed credential.
    make_settings(extension_validator_url="", extension_validator_token="")


def test_personal_private_endpoints_default_to_disabled() -> None:
    settings = make_settings()

    assert settings.ai_personal_private_endpoints == ""
    assert parse_personal_private_endpoints(settings.ai_personal_private_endpoints) == ()
    # An exactly blank value (for example an exported Compose variable) is
    # disabled configuration, not a malformed entry.
    assert parse_personal_private_endpoints("   ") == ()


def test_personal_private_endpoints_accept_cidrs_and_exact_hosts() -> None:
    settings = make_settings(
        ai_personal_private_endpoints="10.0.0.0/8, 192.168.60.5,models.internal:8443,fd00::/8"
    )

    entries = parse_personal_private_endpoints(settings.ai_personal_private_endpoints)

    assert [entry.describe() for entry in entries] == [
        "10.0.0.0/8",
        "192.168.60.5/32",
        "models.internal:8443",
        "fd00::/8",
    ]
    assert entries[0].contains("10.4.5.6") is True
    assert entries[1].contains("10.4.5.6") is False
    assert entries[2].matches_host("Models.Internal.", 8443) is True
    assert entries[2].matches_host("models.internal", 9000) is False
    assert entries[3].contains("fd00::1") is True


def test_personal_private_endpoints_follow_the_environment_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ITSM_AI_PERSONAL_PRIVATE_ENDPOINTS", "192.168.50.0/24")

    settings = Settings(_env_file=None)

    assert settings.ai_personal_private_endpoints == "192.168.50.0/24"


@pytest.mark.parametrize(
    "raw",
    [
        "10.0.0.0/33",
        "models.internal:0",
        "models.internal:70000",
        "http://models.internal/",
        "bad host",
        "*.local",
        "10.0.0.0/8,,models.internal",
        "models.internal,",
        "[::1]:8080",
    ],
)
def test_malformed_personal_private_endpoints_fail_configuration(raw: str) -> None:
    with pytest.raises(ValidationError, match="ai_personal_private_endpoints"):
        make_settings(ai_personal_private_endpoints=raw)
