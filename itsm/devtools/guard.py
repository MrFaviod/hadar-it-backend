"""Safety gates for the development maintenance CLI (S5).

Every gate raises :class:`DevToolsRefused` with one actionable line: what was
refused, which database or directory it refers to, and the next step. The gates
are read-only and run before any side effect, so a refused command leaves the
database file, its rows and the data directories untouched.

Gate order, applied by :mod:`itsm.devtools.operations`:

1. ``RELEASE_MODE`` must be exactly ``dev`` (a typo never enables a reset).
2. The database must be local: a SQLite file or a loopback host.
3. For reset/regenerate, the database must carry the ``dev`` deployment
   identity: an unmarked database, or one marked ``prod``/``demo``, is refused
   even when it is local.
4. The explicit ``--yes-reset-dev-database`` flag and a ``--confirm`` value that
   matches the redacted target name.
5. Existing attachment and task state may only be cleared strictly inside the
   explicitly selected ``ITSM_DEV_DATA_DIR``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Engine, inspect
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.release_identity import (
    DeploymentIdentity,
    DeploymentIdentityError,
    StartupMode,
    database_is_empty,
    enforce_startup,
    identity_table_available,
    read_identity,
    require_local_database,
)
from itsm.release_mode import ReleaseMode, ReleaseModeError, read_release_mode

DEV_MODE: ReleaseMode = "dev"

#: Environment variable holding the explicit dev data directory.
DATA_DIR_ENV = "ITSM_DEV_DATA_DIR"

#: Environment variable holding the dev administrator password (unprefixed on
#: purpose: it is a local installer input, never a container secret).
PASSWORD_ENV = "ITSM_DEV_ADMIN_PASSWORD"

#: The destructive confirmation flag.
RESET_FLAG = "--yes-reset-dev-database"


class DevToolsRefused(RuntimeError):
    """The command was refused and nothing was changed.

    The message is one line for the operator: it says what was refused, where,
    and the next step. It never contains credentials.
    """


@dataclass(frozen=True)
class DatabaseTarget:
    """The database a command would touch, described without credentials."""

    kind: str
    name: str
    display: str
    file: Path | None

    @property
    def is_sqlite(self) -> bool:
        return self.file is not None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "kind": self.kind,
            "name": self.name,
            "url": self.display,
            "file": None if self.file is None else str(self.file),
        }


def require_dev_mode(environ: Mapping[str, str] | None = None) -> ReleaseMode:
    """Refuse every command outside ``RELEASE_MODE=dev`` (S1, S5)."""
    source = os.environ if environ is None else environ
    try:
        mode = read_release_mode(source)
    except ReleaseModeError as exc:
        raise DevToolsRefused(f"{exc}; next: export RELEASE_MODE=dev") from None
    if mode != DEV_MODE:
        raise DevToolsRefused(
            f"release mode is '{mode}' but the development tools only run in 'dev'; "
            "next: export RELEASE_MODE=dev (nothing was changed)"
        )
    return mode


def require_local(settings: Settings) -> None:
    """Refuse a non-local database before any connection is opened (S5)."""
    try:
        require_local_database(settings, DEV_MODE)
    except DeploymentIdentityError as exc:
        raise DevToolsRefused(
            f"{exc}; next: use a sqlite file or a loopback host in ITSM_DATABASE_URL"
        ) from None


def require_dev_startup(settings: Settings) -> StartupMode:
    """Apply the canonical startup gate and its frozen capabilities (S2)."""
    try:
        startup = enforce_startup(settings)
    except ReleaseModeError as exc:
        raise DevToolsRefused(f"{exc}; next: inspect the database with 'status'") from None
    if not startup.capabilities.allow_destructive_reset:
        raise DevToolsRefused(
            "release mode 'dev' does not carry the destructive-reset capability; "
            "next: use a database created by this tool"
        )
    return startup


def database_target(settings: Settings) -> DatabaseTarget:
    """Describe the configured database without echoing any credential."""
    url = make_url(settings.database_url)
    if url.drivername.startswith("sqlite"):
        raw = url.database or ""
        file = None if raw in {"", ":memory:"} else _absolute(Path(raw))
        name = "" if file is None else file.name
        kind = "sqlite"
    else:
        file = None
        name = url.database or ""
        kind = url.get_backend_name()
    return DatabaseTarget(kind=kind, name=name, display=settings.safe_database_url(), file=file)


def require_confirmation(
    target: DatabaseTarget,
    *,
    confirm: str | None,
    reset_flag: bool,
) -> None:
    """Require the explicit flag and a matching confirmation of the target (S5)."""
    if not reset_flag:
        raise DevToolsRefused(
            f"{RESET_FLAG} is required to delete data in {target.display}; "
            f"next: re-run with {RESET_FLAG} --confirm {target.name} after verifying "
            "the target is a development database (nothing was changed)"
        )
    if confirm is None:
        raise DevToolsRefused(
            f"--confirm {target.name} is required to name the reset target; "
            "next: verify the target and pass the database name explicitly "
            "(nothing was changed)"
        )
    if confirm != target.name:
        raise DevToolsRefused(
            f"--confirm {confirm!r} does not match the reset target {target.name!r} "
            f"({target.display}); next: pass --confirm {target.name} only if this is "
            "the intended development database (nothing was changed)"
        )


def require_dev_identity(engine: Engine) -> DeploymentIdentity:
    """Refuse a database that dev did not claim itself (S5, log L3)."""
    if not identity_table_available(engine):
        raise DevToolsRefused(
            "database has no deployment identity table; next: run "
            "'python -m itsm.devtools init' for a new development database "
            "(nothing was changed)"
        )
    with create_session_factory(engine)() as session:
        identity = read_identity(session)
    if identity is None:
        raise DevToolsRefused(
            "database carries no deployment identity, so it was not claimed by a dev "
            "installation; next: run init for a new development database or point "
            "ITSM_DATABASE_URL at one (nothing was changed)"
        )
    if identity.release_mode != DEV_MODE:
        raise DevToolsRefused(
            f"database is marked '{identity.release_mode}' and reset only applies to a "
            "'dev' database; next: use the mode that owns it or a different "
            "ITSM_DATABASE_URL (nothing was changed)"
        )
    return identity


def require_initialisable(engine: Engine) -> None:
    """Refuse to initialise a database that already holds unrelated data (S5)."""
    if identity_table_available(engine):
        with create_session_factory(engine)() as session:
            identity = read_identity(session)
            if identity is not None:
                if identity.release_mode != DEV_MODE:
                    raise DevToolsRefused(
                        f"database is marked '{identity.release_mode}' and cannot be "
                        "initialised as 'dev'; next: use a different ITSM_DATABASE_URL "
                        "(nothing was changed)"
                    )
                return
            if not database_is_empty(session):
                raise DevToolsRefused(
                    "database already contains data but carries no deployment identity; "
                    "next: run init against a new empty sqlite file (nothing was changed)"
                )
        return
    try:
        existing = inspect(engine).get_table_names()
    except SQLAlchemyError as exc:
        raise DevToolsRefused(
            f"database is unreachable ({type(exc).__name__}); next: verify "
            "ITSM_DATABASE_URL and that the server is running (nothing was changed)"
        ) from None
    if existing:
        raise DevToolsRefused(
            f"database already contains {len(existing)} tables but no deployment "
            "identity; next: initialise a new empty sqlite file (nothing was changed)"
        )


def reset_blockers(settings: Settings, engine: Engine, data_dir: Path | None) -> list[str]:
    """Return the reasons a reset would be refused right now, without changing anything."""
    blockers: list[str] = []
    if not identity_table_available(engine):
        blockers.append("database has no deployment identity table; run init first")
        return blockers
    with create_session_factory(engine)() as session:
        identity = read_identity(session)
    if identity is None:
        blockers.append("database carries no dev deployment identity; run init on a dev database")
    elif identity.release_mode != DEV_MODE:
        blockers.append(f"database is marked '{identity.release_mode}', not 'dev'")
    try:
        require_dev_data_paths(settings, data_dir)
    except DevToolsRefused as exc:
        blockers.append(str(exc))
    return blockers


def dev_data_dir(environ: Mapping[str, str] | None = None) -> Path | None:
    """Return the explicit dev data directory, if the operator configured one."""
    source = os.environ if environ is None else environ
    raw = source.get(DATA_DIR_ENV, "").strip()
    return _absolute(Path(raw)) if raw else None


def require_dev_data_paths(settings: Settings, data_dir: Path | None) -> tuple[Path, ...]:
    """Return the existing attachment and task paths a reset may clear.

    Existing paths must resolve strictly inside the explicitly selected root;
    a directory name is never authority to delete it. Missing paths have nothing
    to clear. This preflight rejects existing symlink escapes, not concurrent
    filesystem replacement by another local writer.
    """
    allowed: list[Path] = []
    root = _resolve(data_dir) if data_dir is not None else None
    candidates = (
        ("attachments", Path(settings.attachment_storage_path)),
        ("tasks", Path(settings.task_sqlite_path)),
    )
    for label, candidate in candidates:
        resolved = _resolve(candidate)
        if not resolved.exists():
            continue
        inside = root is not None and root in resolved.parents
        if not inside:
            raise DevToolsRefused(
                f"{label} path {resolved} is outside the development data directory; "
                f"next: set {DATA_DIR_ENV} to the explicit parent root and keep state "
                "strictly inside it (nothing was changed)"
            )
        allowed.append(resolved)
    return tuple(allowed)


@contextmanager
def engine_for(settings: Settings) -> Iterator[Engine]:
    """Open the application engine and always dispose it."""
    engine = create_engine_from_settings(settings)
    try:
        yield engine
    finally:
        engine.dispose()


def _resolve(path: Path) -> Path:
    return path.expanduser().resolve()


def _absolute(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_absolute():
        return expanded
    return (Path.cwd() / expanded).resolve()
