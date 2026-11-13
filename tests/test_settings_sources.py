"""Installation-file settings sources below the operator environment.

The onboarding contract makes ``get_settings`` the single builder, with an
optional JSON installation file named by ``ITSM_INSTALLATION_CONFIG``. The file
sits below the process environment and above defaults, is only accepted from a
private regular file, and never has its values echoed by diagnostics.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from itsm.config import (
    INSTALLATION_CONFIG_ENV,
    InstallationConfigError,
    describe_settings_sources,
    get_settings,
    resolve_settings_sources,
)

PRIVATE_DIRECTORY = 0o700
PRIVATE_FILE = 0o600


def private_directory(tmp_path: Path, name: str = "private") -> Path:
    directory = tmp_path / name
    directory.mkdir(mode=PRIVATE_DIRECTORY, exist_ok=True)
    os.chmod(directory, PRIVATE_DIRECTORY)
    return directory


def installation_file(
    directory: Path,
    payload: object,
    *,
    mode: int = PRIVATE_FILE,
    name: str = "installation.json",
) -> Path:
    path = directory / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, mode)
    return path


@pytest.fixture
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Remove every ITSM_* variable so a developer shell cannot leak settings."""
    for name in list(os.environ):
        if name.startswith("ITSM_"):
            monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_installation_file_supplies_values_below_the_environment(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = installation_file(
        private_directory(tmp_path),
        {
            "database_url": "sqlite:////data/installation/app.db",
            "auth_origin": "http://installation.example",
            "auth_cookie_secure": False,
            "auth_cookie_name": "install_session",
            "auth_session_minutes_default": 120,
            "task_storage": "sqlite",
            "agent_model": "openai:installation-model",
        },
    )

    settings = resolve_settings_sources({}, installation_path=path)

    assert settings.database_url == "sqlite:////data/installation/app.db"
    assert settings.auth_origin == "http://installation.example"
    assert settings.auth_cookie_secure is False
    assert settings.auth_cookie_name == "install_session"
    assert settings.auth_session_minutes_default == 120
    assert settings.task_storage == "sqlite"
    assert settings.agent_model == "openai:installation-model"


def test_environment_wins_even_when_set_to_an_explicit_empty_value(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = installation_file(
        private_directory(tmp_path),
        {
            "database_url": "sqlite:////data/installation/app.db",
            "auth_origin": "http://installation.example",
            "agent_model": "openai:installation-model",
        },
    )

    settings = resolve_settings_sources(
        {
            "ITSM_DATABASE_URL": "sqlite:////data/environment/app.db",
            "ITSM_AGENT_MODEL": "",
        },
        installation_path=path,
    )

    assert settings.database_url == "sqlite:////data/environment/app.db"
    assert settings.agent_model == ""
    assert settings.auth_origin == "http://installation.example"


def test_missing_file_means_no_persisted_value(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = resolve_settings_sources(
        {}, installation_path=private_directory(tmp_path) / "absent.json"
    )

    assert settings.database_url.startswith("postgresql+psycopg://")
    assert settings.auth_origin == "http://localhost:18080"


def test_empty_pointer_means_no_persisted_value(
    clean_environment: pytest.MonkeyPatch,
) -> None:
    settings = resolve_settings_sources({INSTALLATION_CONFIG_ENV: ""})

    assert settings.database_url.startswith("postgresql+psycopg://")


def test_relative_pointer_is_refused(clean_environment: pytest.MonkeyPatch) -> None:
    with pytest.raises(InstallationConfigError, match="absolute"):
        resolve_settings_sources({INSTALLATION_CONFIG_ENV: "installation.json"})


def test_get_settings_reads_the_installation_file_named_by_the_pointer(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = installation_file(
        private_directory(tmp_path),
        {
            "database_url": "sqlite:////data/installation/app.db",
            "auth_origin": "http://installation.example",
        },
    )
    clean_environment.setenv(INSTALLATION_CONFIG_ENV, str(path))

    settings = get_settings()

    assert settings.database_url == "sqlite:////data/installation/app.db"
    assert settings.auth_origin == "http://installation.example"


def test_describe_reports_source_and_tri_state_without_values(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path, settings_factory
) -> None:
    path = installation_file(
        private_directory(tmp_path),
        {"agent_model": "", "auth_cookie_name": "install_session"},
    )
    clean_environment.setenv("ITSM_AUTH_ORIGIN", "")
    clean_environment.setenv(INSTALLATION_CONFIG_ENV, str(path))

    described = describe_settings_sources(settings_factory())

    assert described["auth_origin"] == {"source": "env", "state": "empty", "secret": False}
    assert described["agent_model"] == {
        "source": "installation",
        "state": "empty",
        "secret": False,
    }
    assert described["auth_cookie_name"] == {
        "source": "installation",
        "state": "applied",
        "secret": False,
    }
    assert described["database_url"] == {
        "source": "default",
        "state": "unset",
        "secret": True,
    }


def test_describe_never_echoes_secret_values(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = installation_file(
        private_directory(tmp_path),
        {
            "database_url": "postgresql+psycopg://itsm:supersecret@db.example/itsm",
        },
    )
    clean_environment.setenv(INSTALLATION_CONFIG_ENV, str(path))
    clean_environment.setenv("ITSM_AI_CREDENTIAL_KEYS", "fernet-secret-value")

    rendered = json.dumps(describe_settings_sources())

    assert "supersecret" not in rendered
    assert "fernet-secret-value" not in rendered
    assert "database_url" in rendered


def test_symlinked_installation_file_is_refused(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = installation_file(private_directory(tmp_path), {"auth_cookie_name": "install_session"})
    link = target.parent / "linked.json"
    link.symlink_to(target)

    with pytest.raises(InstallationConfigError, match="symbolic link"):
        resolve_settings_sources({}, installation_path=link)


def test_non_regular_installation_path_is_refused(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    directory = private_directory(tmp_path)

    with pytest.raises(InstallationConfigError, match="regular file"):
        resolve_settings_sources({}, installation_path=directory)


def test_group_or_world_readable_file_is_refused(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = installation_file(
        private_directory(tmp_path), {"auth_cookie_name": "install_session"}, mode=0o644
    )

    with pytest.raises(InstallationConfigError, match="group or world"):
        resolve_settings_sources({}, installation_path=path)


def test_group_or_world_accessible_directory_is_refused(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    directory = tmp_path / "wide"
    directory.mkdir()
    os.chmod(directory, 0o755)
    path = installation_file(directory, {"auth_cookie_name": "install_session"})

    with pytest.raises(InstallationConfigError, match="directory"):
        resolve_settings_sources({}, installation_path=path)


def test_unknown_installation_key_is_refused(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = installation_file(private_directory(tmp_path), {"not_a_setting": "value"})

    with pytest.raises(InstallationConfigError, match="unknown installation setting"):
        resolve_settings_sources({}, installation_path=path)


def test_setting_owned_by_another_owner_is_refused(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = installation_file(private_directory(tmp_path), {"smtp_host": "smtp.example"})

    with pytest.raises(InstallationConfigError, match="not owned by the installation"):
        resolve_settings_sources({}, installation_path=path)


@pytest.mark.parametrize("payload", ["not an object", ["database_url"]])
def test_non_object_document_is_refused(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path, payload: object
) -> None:
    path = installation_file(private_directory(tmp_path), payload)

    with pytest.raises(InstallationConfigError, match="one JSON object"):
        resolve_settings_sources({}, installation_path=path)


def test_invalid_json_is_refused_without_echoing_content(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = private_directory(tmp_path) / "installation.json"
    path.write_text('{"database_url": "postgresql://u:supersecret@h/db",}', encoding="utf-8")
    os.chmod(path, PRIVATE_FILE)

    with pytest.raises(InstallationConfigError, match="not valid JSON") as caught:
        resolve_settings_sources({}, installation_path=path)

    assert "supersecret" not in str(caught.value)


def test_invalid_file_value_is_refused_without_echoing_the_secret(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = installation_file(
        private_directory(tmp_path),
        {"database_url": "mysql+mysqlconnector://user:supersecret@db.example/itsm"},
    )

    with pytest.raises(
        InstallationConfigError, match="installation settings are invalid"
    ) as caught:
        resolve_settings_sources({}, installation_path=path)

    assert "supersecret" not in str(caught.value)


def test_worker_projection_still_strips_the_installation_pointer(
    clean_environment: pytest.MonkeyPatch, tmp_path: Path, settings_factory
) -> None:
    from tests.conftest import worker_environment

    path = installation_file(
        private_directory(tmp_path),
        {"database_url": "sqlite:////data/installation/app.db"},
    )
    clean_environment.setenv(INSTALLATION_CONFIG_ENV, str(path))
    settings = settings_factory()

    env = worker_environment(settings)

    assert INSTALLATION_CONFIG_ENV not in env
    assert env["ITSM_DATABASE_URL"] == settings.database_url
