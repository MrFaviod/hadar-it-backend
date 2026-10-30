"""Release mode and deployment identity through the public startup interfaces.

Covers spec S1 (one codebase, ``RELEASE_MODE`` selects the mode), S2 (the mode is
validated at startup by the API and the worker; absent or invalid refuses to
start), S5 (dev mode cannot reach a production database) and S19 (a database is
only reachable from the mode that owns it).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.demo.state import DemoInstallation
from itsm.identity.clock import utcnow
from itsm.release_identity import (
    DeploymentIdentityError,
    StartupMode,
    claim_identity,
    enforce_startup,
    read_identity,
)
from itsm.release_mode import (
    RELEASE_MODE_ENV,
    ModeCapabilities,
    ReleaseModeError,
    capabilities_for,
    read_release_mode,
)
from itsm.tasks.runtime import WORKER_REFUSED_EXIT_CODE
from sqlalchemy.orm import Session
from tests.conftest import (
    bootstrap_superadmin,
    read_worker_log,
    run_migrations,
    running_worker,
    worker_events,
)

MODES = ("dev", "prod", "demo")
API = "/api/v1"
REMOTE_DATABASE_URL = "postgresql+psycopg://itsm:secret-value@db.example.invalid:5432/itsm"


def apply_mode(monkeypatch: pytest.MonkeyPatch, mode: str | None) -> None:
    """Set the unprefixed release mode for the process under test."""
    if mode is None:
        monkeypatch.delenv(RELEASE_MODE_ENV, raising=False)
    else:
        monkeypatch.setenv(RELEASE_MODE_ENV, mode)


@contextmanager
def started(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, mode: str | None
) -> Iterator[TestClient]:
    """Start the real API application in one release mode."""
    from itsm.main import create_app

    apply_mode(monkeypatch, mode)
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def startup_refusal(settings: Settings, monkeypatch: pytest.MonkeyPatch, mode: str | None) -> str:
    """Assert that starting the API is refused and return the operator message."""
    from itsm.main import create_app

    apply_mode(monkeypatch, mode)
    with pytest.raises(ReleaseModeError) as excinfo, TestClient(create_app(settings)):
        pass
    return str(excinfo.value)


def identity_row(settings: Settings):
    """Read the persisted identity row with an independent connection."""
    engine = create_engine_from_settings(settings)
    try:
        with create_session_factory(engine)() as session:
            return read_identity(session)
    finally:
        engine.dispose()


def claim_for(settings: Settings, mode: str) -> None:
    """Write the marker the way an installation of ``mode`` would."""
    engine = create_engine_from_settings(settings)
    try:
        with create_session_factory(engine)() as session:
            claim_identity(session, mode)
            session.commit()
    finally:
        engine.dispose()


def mark_demo(settings: Settings) -> None:
    """Write the durable demo dataset marker used by an initialized demo."""
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            session.add(
                DemoInstallation(id=1, dataset="fictional-infrastructure-v1", created_at=utcnow())
            )
            session.commit()
    finally:
        engine.dispose()


def migrated(settings_factory: Callable[..., Settings]) -> Settings:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    return settings


# --- S1/S2: parsing the unprefixed variable ---------------------------------


@pytest.mark.parametrize("mode", MODES)
def test_release_mode_is_read_from_the_unprefixed_variable(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(RELEASE_MODE_ENV, mode)

    assert read_release_mode() == mode


def test_release_mode_ignores_the_prefixed_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(RELEASE_MODE_ENV, raising=False)
    monkeypatch.setenv("ITSM_RELEASE_MODE", "dev")

    with pytest.raises(ReleaseModeError) as excinfo:
        read_release_mode()

    assert RELEASE_MODE_ENV in str(excinfo.value)


@pytest.mark.parametrize("value", [None, "", " ", "DEV", "Prod", "staging", "demo "])
def test_absent_invalid_or_empty_mode_grants_no_capability(
    value: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    apply_mode(monkeypatch, value)

    with pytest.raises(ReleaseModeError) as excinfo:
        read_release_mode()

    message = str(excinfo.value)
    assert "RELEASE_MODE" in message
    assert "dev, prod, demo" in message


# --- S2: frozen capability matrix per mode ----------------------------------


@pytest.mark.parametrize(
    "mode,expected",
    [
        (
            "dev",
            {
                "allow_system_operations": True,
                "allow_extension_install": True,
                "allow_external_notifications": True,
                "allow_ai_providers": True,
                "allow_agents_dev": True,
                "allow_seed": True,
                "allow_destructive_reset": True,
                "auto_migrate": True,
            },
        ),
        (
            "prod",
            {
                "allow_system_operations": True,
                "allow_extension_install": True,
                "allow_external_notifications": True,
                "allow_ai_providers": True,
                "allow_agents_dev": False,
                "allow_seed": False,
                "allow_destructive_reset": False,
                "auto_migrate": False,
            },
        ),
        (
            "demo",
            {
                "allow_system_operations": False,
                "allow_extension_install": False,
                "allow_external_notifications": False,
                "allow_ai_providers": False,
                "allow_agents_dev": False,
                "allow_seed": True,
                "allow_destructive_reset": True,
                "auto_migrate": False,
            },
        ),
    ],
)
def test_capability_matrix_per_mode(mode: str, expected: dict[str, bool]) -> None:
    assert capabilities_for(mode) == ModeCapabilities(**expected)


def test_demo_disables_every_dangerous_capability() -> None:
    demo = capabilities_for("demo")

    assert demo.allow_system_operations is False
    assert demo.allow_extension_install is False
    assert demo.allow_external_notifications is False
    assert demo.allow_ai_providers is False
    assert demo.allow_agents_dev is False
    assert demo.auto_migrate is False


def test_capabilities_are_frozen() -> None:
    with pytest.raises(FrozenInstanceError):
        capabilities_for("dev").allow_seed = False  # type: ignore[misc]


def test_deployment_refusal_is_one_release_mode_error() -> None:
    assert issubclass(DeploymentIdentityError, ReleaseModeError)


# --- S2: startup gate refuses absent or invalid modes -----------------------


@pytest.mark.parametrize("value", [None, "staging"])
def test_invalid_mode_refuses_api_startup(
    value: str | None,
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)

    message = startup_refusal(settings, monkeypatch, value)

    assert "RELEASE_MODE" in message
    assert identity_row(settings) is None


def test_invalid_mode_refuses_worker_startup(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
    tmp_path: Path,
) -> None:
    settings = migrated(settings_factory)
    apply_mode(monkeypatch, "staging")
    log_path = tmp_path / "worker.log"

    with running_worker(settings, log_path) as process:
        deadline = time.monotonic() + 20.0
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
        returncode = process.poll()

    log = read_worker_log(log_path)
    assert returncode == WORKER_REFUSED_EXIT_CODE, log
    assert worker_events(log_path, "worker.refused") != []
    assert worker_events(log_path, "worker.started") == []
    assert "Executing " not in log


def test_worker_starts_in_a_valid_mode(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
    tmp_path: Path,
) -> None:
    settings = migrated(settings_factory)
    apply_mode(monkeypatch, "dev")
    log_path = tmp_path / "worker.log"

    with running_worker(settings, log_path) as process:
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            if worker_events(log_path, "worker.started"):
                break
            time.sleep(0.1)
        assert process.poll() is None, read_worker_log(log_path)

    started = worker_events(log_path, "worker.started")
    assert started and started[0]["release_mode"] == "dev"


def test_startup_gate_is_callable_without_the_api(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)

    result = enforce_startup(settings, environ={RELEASE_MODE_ENV: "dev"})

    assert isinstance(result, StartupMode)
    assert result.mode == "dev"
    assert result.capabilities == capabilities_for("dev")


def test_startup_gate_refuses_an_invalid_mode_without_the_api(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)

    with pytest.raises(ReleaseModeError):
        enforce_startup(settings, environ={})


# --- S19: one database, one owning mode -------------------------------------


def test_empty_database_is_claimed_for_the_current_mode(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)

    with started(settings, monkeypatch, "dev") as client:
        assert client.get(f"{API}/health/live").status_code == 200

    row = identity_row(settings)
    assert row is not None
    assert row.release_mode == "dev"
    assert row.instance_id


def test_claimed_database_starts_again_in_the_same_mode(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    with started(settings, monkeypatch, "dev"):
        pass
    first = identity_row(settings)

    with started(settings, monkeypatch, "dev") as client:
        assert client.get(f"{API}/health/live").status_code == 200

    second = identity_row(settings)
    assert second is not None
    assert second.created_at == first.created_at


@pytest.mark.parametrize(
    "marked,current",
    [(marked, current) for marked in MODES for current in MODES if marked != current],
)
def test_database_owned_by_another_mode_is_refused(
    marked: str,
    current: str,
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    claim_for(settings, marked)

    message = startup_refusal(settings, monkeypatch, current)

    assert f"'{marked}'" in message
    assert f"'{current}'" in message
    assert identity_row(settings).release_mode == marked


def test_prod_adopts_an_unmarked_non_empty_database(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    bootstrap_superadmin(settings)

    with started(settings, monkeypatch, "prod") as client:
        assert client.get(f"{API}/health/live").status_code == 200

    row = identity_row(settings)
    assert row is not None
    assert row.release_mode == "prod"


def test_demo_refuses_an_unmarked_non_empty_database(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    bootstrap_superadmin(settings)

    message = startup_refusal(settings, monkeypatch, "demo")

    assert "demo" in message
    assert "empty" in message
    assert identity_row(settings) is None


def test_demo_claims_a_database_marked_demo(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    mark_demo(settings)

    with started(settings, monkeypatch, "demo") as client:
        assert client.get(f"{API}/health/live").status_code == 200

    row = identity_row(settings)
    assert row is not None
    assert row.release_mode == "demo"


def test_prod_refuses_a_database_marked_demo(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    mark_demo(settings)

    message = startup_refusal(settings, monkeypatch, "prod")

    assert "'demo'" in message
    assert "'prod'" in message
    assert identity_row(settings) is None


def test_dev_refuses_a_database_outside_loopback(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(database_url=REMOTE_DATABASE_URL)

    message = startup_refusal(settings, monkeypatch, "dev")

    assert "dev" in message
    assert "loopback" in message
    assert "secret-value" not in message


def test_dev_starts_on_a_local_unmarked_installation_without_claiming_it(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
) -> None:
    """The documented installer flow creates the first administrator before startup."""
    settings = migrated(settings_factory)
    bootstrap_superadmin(settings)

    with started(settings, monkeypatch, "dev") as client:
        assert client.get(f"{API}/health/live").status_code == 200

    assert identity_row(settings) is None


def test_dev_starts_on_a_locally_marked_demo_without_rewriting_it(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    mark_demo(settings)

    with started(settings, monkeypatch, "dev") as client:
        assert client.get(f"{API}/health/live").status_code == 200

    assert identity_row(settings) is None


# --- Readiness exposes the effective mode -----------------------------------


def test_readiness_reports_the_effective_release_mode(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)

    with started(settings, monkeypatch, "dev") as client:
        response = client.get(f"{API}/health/ready")

    assert response.status_code == 200, response.text
    assert response.json()["releaseMode"] == "dev"


# --- Migrations remain an explicit prerequisite -----------------------------


def test_gate_defers_identity_to_pending_migrations(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()

    result = enforce_startup(settings, environ={RELEASE_MODE_ENV: "dev"})

    assert result.mode == "dev"


def test_gate_does_not_hide_an_unreachable_database_from_readiness(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(database_url="sqlite:////nonexistent-directory/itsm.db")

    result = enforce_startup(settings, environ={RELEASE_MODE_ENV: "dev"})

    assert result.mode == "dev"
