"""Probe a candidate database and prepare it without adopting foreign data.

The setup service is the only component that may prepare storage before the API
exists. It validates a narrow URL allowlist, connects with a short timeout, and
reports a sanitized ownership verdict. ``apply_storage`` writes the private
installation file, applies the canonical migrations and claims the deployment
identity for this release mode. It never seeds an account and never calls
``ensure_identity``: an unmarked non-empty database is refused, not adopted.

Every database import stays inside a function so importing the setup app keeps
working with no database driver, engine or connection.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from itsm.setup.store import (
    DatabaseNotAdoptable,
    DatabaseUnreachable,
    DatabaseUrlInvalid,
    InstallationConfigUnavailable,
    SetupConfigurationError,
    SetupSettings,
    SetupStore,
    UnsupportedEngine,
)

PROBE_TIMEOUT_SECONDS = 3
SQLITE_MEMORY_TARGETS = {"", ":memory:", "file::memory:"}
ENGINE_LABELS = {
    "postgresql+psycopg": "postgresql",
    "sqlite": "sqlite",
    "sqlite+pysqlite": "sqlite",
}
FOREIGN_GUIDANCE = (
    "this database already belongs to another installation or release mode; "
    "choose an empty database or restore a backup through the operator CLI"
)
UNMARKED_GUIDANCE = (
    "this database already holds accounts but carries no deployment identity; "
    "setup never adopts an existing installation. Use a dedicated empty database"
)
OTHER_MODE_GUIDANCE = (
    "this database is claimed by the {other} release mode, not {mode}; "
    "start setup with the matching release mode or choose an empty database"
)

# Tests replace this hook to stop between durable steps and simulate a crash.
_checkpoint: Callable[[str], None] | None = None


@dataclass(frozen=True)
class DatabaseProbe:
    """Sanitized probe result: no URL, host, user or password."""

    reachable: bool
    engine: str | None
    version: str | None
    status: str
    identity: str | None
    adoptable: bool
    guidance: str | None = None

    def as_receipt(self) -> dict[str, Any]:
        return {
            "reachable": self.reachable,
            "engine": self.engine,
            "version": self.version,
            "status": self.status,
            "identity": self.identity,
            "adoptable": self.adoptable,
            "guidance": self.guidance,
        }


def _mark(stage: str) -> None:
    if _checkpoint is not None:
        _checkpoint(stage)


def _engine_label(raw_url: str) -> tuple[str, str]:
    """Validate the URL allowlist and return ``(url, engine label)``."""

    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import ArgumentError

    if not isinstance(raw_url, str) or not raw_url.strip():
        raise DatabaseUrlInvalid("a database URL is required")
    try:
        url = make_url(raw_url.strip())
    except (ArgumentError, ValueError) as exc:
        raise DatabaseUrlInvalid("the database URL is not valid") from exc
    label = ENGINE_LABELS.get(url.drivername)
    if label is None:
        raise UnsupportedEngine(
            "only postgresql+psycopg and sqlite URLs are supported by this installation"
        )
    if url.drivername == "sqlite":
        target = (url.database or "").strip()
        if target in SQLITE_MEMORY_TARGETS:
            raise DatabaseUrlInvalid("an in-memory SQLite database cannot hold an installation")
    else:
        if not url.host or not (url.database or "").strip():
            raise DatabaseUrlInvalid("the PostgreSQL URL must name a host and a database")
    return url.render_as_string(hide_password=False), label


def _connect_args(drivername: str) -> dict[str, Any]:
    if drivername == "sqlite":
        return {"timeout": PROBE_TIMEOUT_SECONDS}
    return {"connect_timeout": PROBE_TIMEOUT_SECONDS}


def probe_database(raw_url: str, *, release_mode: str) -> DatabaseProbe:
    """Connect briefly and report whether the database is empty, ours or foreign."""

    url, engine_name = _engine_label(raw_url)

    from sqlalchemy import create_engine, inspect, text
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.orm import Session

    from itsm.release_identity import database_is_empty, read_identity

    try:
        engine = create_engine(url, connect_args=_connect_args(engine_name))
    except SQLAlchemyError, ValueError:
        return DatabaseProbe(False, engine_name, None, "unreachable", None, False)
    try:
        try:
            with engine.connect() as connection:
                if engine_name == "sqlite":
                    version = connection.execute(text("select sqlite_version()")).scalar_one()
                else:
                    version = connection.execute(text("show server_version")).scalar_one()
            tables = set(inspect(engine).get_table_names())
            identity_mode: str | None = None
            if "deployment_identity" in tables:
                with Session(engine) as session:
                    row = read_identity(session)
                    identity_mode = row.release_mode if row is not None else None
            if identity_mode is not None:
                if identity_mode == release_mode:
                    return DatabaseProbe(
                        True, engine_name, str(version), "ours", identity_mode, True
                    )
                guidance = OTHER_MODE_GUIDANCE.format(other=identity_mode, mode=release_mode)
                return DatabaseProbe(
                    True, engine_name, str(version), "foreign", identity_mode, False, guidance
                )
            with Session(engine) as session:
                empty = database_is_empty(session)
            if empty:
                return DatabaseProbe(True, engine_name, str(version), "empty", None, True)
            return DatabaseProbe(
                True, engine_name, str(version), "foreign", None, False, UNMARKED_GUIDANCE
            )
        except SQLAlchemyError:
            return DatabaseProbe(False, engine_name, None, "unreachable", None, False)
    finally:
        engine.dispose()


def _read_installation_values(path: Path) -> dict[str, Any]:
    """Read existing installation keys so an apply never drops a neighbour."""

    from itsm.config import InstallationConfigError, _load_installation_values

    try:
        return dict(_load_installation_values(path))
    except InstallationConfigError as exc:
        raise SetupConfigurationError(
            "the installation file cannot be read safely; fix or remove it before retrying"
        ) from exc


def _existing_installation_values(path: Path) -> dict[str, Any]:
    """Read the current neighbours only from a regular file, never a planted link.

    ``os.replace`` swaps the destination itself, so a symbolic link left at the
    path would be replaced instead of written through and setup would only fail
    later in the reader; refuse it here with one clear message.
    """

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise SetupConfigurationError(
            "the installation path cannot be inspected; fix or remove it before retrying"
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        detail = "a symbolic link" if stat.S_ISLNK(info.st_mode) else "not a regular file"
        raise SetupConfigurationError(
            f"the installation path is {detail}; remove it and let setup create a regular file"
        )
    return _read_installation_values(path)


def _validate_candidate_file(path: Path) -> None:
    from itsm.config import InstallationConfigError, resolve_settings_sources

    try:
        resolve_settings_sources({}, installation_path=path)
    except InstallationConfigError as exc:
        raise SetupConfigurationError(
            "the installation values were refused by the settings contract"
        ) from exc


def write_installation_values(path: Path, updates: Mapping[str, Any]) -> None:
    """Atomically merge ``updates`` into the private installation file.

    The guarantees are the ones storage already needed for the database URL: the
    directory stays 0700, the file is written 0600 through a private temporary
    file, a planted symbolic link is refused instead of written through, existing
    keys survive, and the candidate document must pass the settings contract
    before it replaces the live file.
    """

    if not updates:
        raise SetupConfigurationError("no installation values were proposed")
    parent = path.parent
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        current = stat.S_IMODE(parent.stat().st_mode)
        if current & 0o077:
            os.chmod(parent, 0o700)
    except OSError as exc:
        raise InstallationConfigUnavailable(
            "the installation directory cannot be created or secured"
        ) from exc
    values = _existing_installation_values(path)
    values.update(updates)
    encoded = json.dumps(values, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".installation-", dir=parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        candidate = Path(temporary)
        _validate_candidate_file(candidate)
        os.replace(candidate, path)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def write_installation_database_url(path: Path, database_url: str) -> None:
    """Atomically publish ``database_url`` in the private installation file."""

    write_installation_values(path, {"database_url": database_url})


def _installation_file(environ: Mapping[str, str]) -> Path | None:
    from itsm.config import InstallationConfigError, installation_config_path

    try:
        return installation_config_path(environ)
    except InstallationConfigError as exc:
        raise InstallationConfigUnavailable(
            "ITSM_INSTALLATION_CONFIG must be an absolute private file path"
        ) from exc


def _claim_storage(settings: Any, release_mode: str, instance_id: str | None) -> bool:
    """Migrate already happened; claim only an empty or already-ours database."""

    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.orm import Session

    from itsm.database import create_engine_from_settings
    from itsm.release_identity import (
        DeploymentIdentityError,
        ReleaseMode,
        claim_identity,
        database_is_empty,
        read_identity,
    )

    mode: ReleaseMode = "dev" if release_mode == "dev" else "prod"
    engine = create_engine_from_settings(settings)
    try:
        try:
            with Session(engine) as session:
                existing = read_identity(session)
                if existing is not None:
                    if existing.release_mode != mode:
                        raise DatabaseNotAdoptable(FOREIGN_GUIDANCE)
                    return False
                if not database_is_empty(session):
                    raise DatabaseNotAdoptable(UNMARKED_GUIDANCE)
                claim_identity(session, mode, instance_id=instance_id)
                session.commit()
                return True
        except DeploymentIdentityError as exc:
            raise DatabaseNotAdoptable(FOREIGN_GUIDANCE) from exc
    except SQLAlchemyError as exc:
        raise DatabaseUnreachable("the database stopped answering during preparation") from exc
    finally:
        engine.dispose()


def apply_storage(
    store: SetupStore,
    setup_settings: SetupSettings,
    database_url: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Write the file, migrate and claim identity for this release mode."""

    source = dict(os.environ if environ is None else environ)
    candidate, _engine = _engine_label(database_url)
    external = (source.get("ITSM_DATABASE_URL") or "").strip()
    if external:
        config_source = "external"
        effective = external
    else:
        config_source = "installation"
        effective = candidate

    probe = probe_database(effective, release_mode=setup_settings.release_mode)
    if not probe.reachable:
        raise DatabaseUnreachable("the candidate database did not answer a short probe")
    if probe.status not in {"empty", "ours"}:
        raise DatabaseNotAdoptable(probe.guidance or FOREIGN_GUIDANCE)

    path: Path | None = None
    if config_source == "installation":
        path = _installation_file(source)
        if path is None:
            raise InstallationConfigUnavailable(
                "ITSM_INSTALLATION_CONFIG is not set, so no private "
                "installation file can be written"
            )
        write_installation_database_url(path, candidate)

    from itsm.config import resolve_settings_sources
    from itsm.devtools.database import migrate_to_head

    settings = resolve_settings_sources(source, installation_path=path)
    migrate_to_head(settings)
    _mark("migrated")
    instance_id = store.public_state().get("instance_id")
    claimed = _claim_storage(settings, setup_settings.release_mode, instance_id)
    _mark("claimed")

    receipt = {
        "engine": probe.engine or _engine,
        "version": probe.version,
        "status": "ours",
        "identity": setup_settings.release_mode,
        "config_source": config_source,
        "migrated": True,
        "identity_claimed": claimed,
    }
    return store.record_storage_ready(receipt=receipt)
