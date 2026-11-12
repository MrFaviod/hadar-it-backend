"""Backup, verification, restore, retention and status for supported engines.

The service is deliberately small: it reads the configured database URL through
the application settings seam, builds a tool command through
``itsm.ops.engines`` (never with a credential in argv), runs it with a bounded
timeout and records the outcome in the artifact directory.

SQLite uses the online ``Connection.backup`` API and ``PRAGMA integrity_check``;
PostgreSQL uses ``pg_dump -Fc``/``pg_restore``; MySQL/MariaDB use
``mariadb-dump``/``mysqldump --single-transaction`` plus the client restore;
MSSQL uses ``sqlcmd`` with ``BACKUP DATABASE``/``RESTORE``. Only SQLite is
verified live by the test suite on this host.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sqlite3
import subprocess
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import inspect
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

from itsm import __version__
from itsm.agent_integrations.providers import credential_key_fingerprints
from itsm.config import Settings, settings_for
from itsm.database import (
    DatabaseUnavailable,
    create_engine_from_settings,
    current_revision,
    probe_database,
)
from itsm.ops import attachments, engines, extensions, quiesce, store
from itsm.ops import sqlite as sqlite_ops
from itsm.ops.engines import DatabaseTarget, OpsError, ToolCommand

TOOL_TIMEOUT_SECONDS = 3600.0
MYSQL_DUMP_COMPLETION_MARKER = "Dump completed"
MIN_FREE_BYTES = 32 * 1024 * 1024
SOURCE_SPACE_MULTIPLIER = 3


class UsageError(OpsError):
    """Raised for an incomplete or invalid command request."""


class RestoreRefused(OpsError):
    """Raised when a restore target is unsafe or requires explicit confirmation."""


@dataclass(frozen=True)
class OpsContext:
    """Settings plus the operator-selected backup root.

    ``status_path`` is the optional external copy of the published summary: a
    separate, deployment-provisioned file the API can mount read-only without
    exposing the private backup volume. The backup root always keeps its own
    private ``status.json``.
    """

    settings: Settings
    backup_root: Path
    status_path: Path | None = None

    def target(self) -> DatabaseTarget:
        return engines.database_target(self.settings.database_url)


def _secrets(target: DatabaseTarget) -> tuple[str, ...]:
    return (target.password,) if target.password else ()


def _record_failure(
    root: Path,
    *,
    operation: str,
    reason: str,
    target: DatabaseTarget,
) -> None:
    with contextlib.suppress(OpsError, OSError):
        store.record_failure(
            root,
            operation=operation,
            reason=reason,
            engine=target.engine,
            database=target.describe(),
            secrets=_secrets(target),
        )


# --------------------------------------------------------------------------- #
# Snapshots and revision detection
# --------------------------------------------------------------------------- #


def try_revision(settings: Settings, target: DatabaseTarget) -> str | None:
    """Read the applied Alembic revision, returning ``None`` when unreadable."""
    if target.engine == "sqlite":
        snapshot = sqlite_ops.snapshot(Path(target.database))
        return None if snapshot is None else snapshot["revision"]
    engine = create_engine_from_settings(settings)
    try:
        probe_database(engine)
        return current_revision(engine)
    except DatabaseUnavailable, SQLAlchemyError, OSError:
        return None
    finally:
        engine.dispose()


def database_revision(settings: Settings) -> str | None:
    engine = create_engine_from_settings(settings)
    try:
        probe_database(engine)
        return current_revision(engine)
    except (DatabaseUnavailable, SQLAlchemyError, OSError) as exc:
        raise OpsError("database is not reachable") from exc
    finally:
        engine.dispose()


def revision_for_database_url(url: str) -> str | None:
    """Read the revision of a restore target without touching the live settings."""
    target = engines.database_target(url)
    if target.engine == "sqlite":
        snapshot = sqlite_ops.snapshot(Path(target.database))
        return None if snapshot is None else snapshot["revision"]
    engine = create_engine_from_settings(settings_for(database_url=url))
    try:
        probe_database(engine)
        return current_revision(engine)
    except DatabaseUnavailable, SQLAlchemyError, OSError:
        return None
    finally:
        engine.dispose()


def source_size(target: DatabaseTarget) -> int:
    """Best-effort size of the live database, used for disk-space preflight."""
    if target.engine != "sqlite":
        return 0
    path = Path(target.database)
    return path.stat().st_size if path.is_file() else 0


# --------------------------------------------------------------------------- #
# Tool execution
# --------------------------------------------------------------------------- #


@contextlib.contextmanager
def _temporary_option_directory() -> Iterator[Path]:
    directory = tempfile.TemporaryDirectory(prefix="itsm-ops-")
    try:
        os.chmod(directory.name, 0o700)
        yield Path(directory.name)
    finally:
        directory.cleanup()


def _write_option_file(option: engines.OptionFile) -> None:
    option.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(option.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(option.content)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(option.path, 0o600)


def _run_tool(
    command: ToolCommand, target: DatabaseTarget, *, timeout: float = TOOL_TIMEOUT_SECONDS
) -> subprocess.CompletedProcess[str]:
    """Run one external tool with bounded time, private credentials and no shell."""
    environment = {**os.environ, **command.env}
    stdin_stream: Any = subprocess.DEVNULL
    try:
        if command.option_file is not None:
            _write_option_file(command.option_file)
        if command.stdin is not None:
            stdin_stream = command.stdin.open("rb")
        completed = subprocess.run(
            list(command.argv),
            env=environment,
            stdin=stdin_stream,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise OpsError(f"{command.argv[0]} is not available on this host") from exc
    except subprocess.TimeoutExpired as exc:
        raise OpsError(f"{command.argv[0]} timed out after {int(timeout)} seconds") from exc
    finally:
        if command.stdin is not None and stdin_stream is not subprocess.DEVNULL:
            stdin_stream.close()
        if command.option_file is not None:
            with contextlib.suppress(FileNotFoundError):
                command.option_file.path.unlink()
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        reason = detail[-1] if detail else "no diagnostic output"
        raise OpsError(
            store.sanitize(
                f"{command.argv[0]} failed for {target.describe()}: {reason}",
                _secrets(target),
            )
        )
    return completed


def _tool_version(argv: tuple[str, ...]) -> str:
    try:
        completed = subprocess.run(
            list(argv), capture_output=True, text=True, timeout=30, check=False
        )
    except OSError, subprocess.TimeoutExpired:
        return "unavailable"
    lines = (completed.stdout or completed.stderr or "").strip().splitlines()
    return lines[0].strip()[:120] if lines else "unavailable"


def _mysql_dump_tool() -> str:
    for candidate in engines.MYSQL_DUMP_TOOLS:
        if shutil.which(candidate):
            return candidate
    return "mysqldump"


def _mysql_client_tool() -> str:
    for candidate in engines.MYSQL_CLIENT_TOOLS:
        if shutil.which(candidate):
            return candidate
    return "mysql"


def _tool_versions(target: DatabaseTarget) -> dict[str, str]:
    if target.engine == "sqlite":
        return {"sqlite": f"sqlite {sqlite3.sqlite_version}"}
    if target.engine == "postgresql":
        return {"pg_dump": _tool_version(("pg_dump", "--version"))}
    if target.engine == "mysql":
        tool = _mysql_dump_tool()
        return {tool: _tool_version((tool, "--version"))}
    return {"sqlcmd": _tool_version(("sqlcmd", "-?"))}


def _client_version(target: DatabaseTarget) -> str | None:
    versions = _tool_versions(target)
    return next(iter(versions.values()), None)


def _server_version(settings: Settings, target: DatabaseTarget) -> str | None:
    """Read the server version string, or ``None`` when it cannot be read.

    The record is diagnostic metadata, never a reason to fail a backup that the
    engine itself completed; a missing major is handled as "unknown" by verify.
    """
    if target.engine == "sqlite":
        return f"sqlite {sqlite3.sqlite_version}"
    statement = {
        "postgresql": "SHOW server_version",
        "mysql": "SELECT VERSION()",
    }.get(target.engine)
    if statement is None:
        return None
    engine = create_engine_from_settings(settings)
    try:
        with engine.connect() as connection:
            value = connection.exec_driver_sql(statement).scalar()
        return None if value is None else str(value)[:120]
    except DatabaseUnavailable, SQLAlchemyError, OSError:
        return None
    finally:
        engine.dispose()


def _engine_versions(settings: Settings, target: DatabaseTarget) -> dict[str, Any]:
    """Record the client and server majors beside the backup they describe."""
    client = _client_version(target)
    server = _server_version(settings, target)
    return {
        "client": client,
        "clientMajor": engines.version_major(client),
        "server": server,
        "serverMajor": engines.version_major(server),
    }


# --------------------------------------------------------------------------- #
# Backup
# --------------------------------------------------------------------------- #


def _sqlite_dump(source_path: Path, destination: Path) -> None:
    sqlite_ops.copy_online(source_path, destination)


def _write_dump(context: OpsContext, target: DatabaseTarget, dump_path: Path) -> None:
    if target.engine == "sqlite":
        _sqlite_dump(Path(target.database), dump_path)
        return
    if target.engine == "postgresql":
        _run_tool(engines.postgres_backup_command(target, dump_path), target)
        return
    if target.engine == "mysql":
        with _temporary_option_directory() as directory:
            command = engines.mysql_backup_command(
                target,
                dump_path,
                option_file=directory / "client.cnf",
                tool=_mysql_dump_tool(),
            )
            _run_tool(command, target)
        return
    _run_tool(engines.mssql_backup_command(target, dump_path), target)


def backup(context: OpsContext) -> store.BackupArtifact:
    """Create one verified-input artifact for the configured database."""
    target = context.target()
    root = context.backup_root
    try:
        store.prepare_root(root)
        artifact = store.create_artifact(
            root,
            engine=target.engine,
            database=target.describe(),
            alembic_revision=try_revision(context.settings, target),
            app_version=__version__,
            dump_file=engines.dump_filename(target.engine),
            tool_versions=_tool_versions(target),
            version_info=_engine_versions(context.settings, target),
            write_dump=lambda path: _write_dump(context, target, path),
            write_extensions=lambda directory: extensions.archive(
                context.settings.extension_data_path, directory / extensions.DATA_ROOT_DIR
            ),
            write_attachments=lambda directory: attachments.archive(
                context.settings.attachment_storage_path, directory / attachments.DATA_ROOT_DIR
            ),
            credential_key_fingerprints=credential_key_fingerprints(context.settings),
        )
    except OpsError as exc:
        _record_failure(root, operation="backup", reason=str(exc), target=target)
        raise
    return artifact


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


class TrialRestoreUnavailable(OpsError):
    """The trial restore could not run, so restorability stays unproven."""


class TrialRestoreFailed(OpsError):
    """The trial restore ran and failed: the artifact is not restorable."""


def _scratch_database_url(settings: Settings, database: str) -> str:
    return (
        make_url(settings.database_url).set(database=database).render_as_string(hide_password=False)
    )


def _drop_scratch_database(settings: Settings, database: str) -> None:
    """Best-effort removal of a trial database; never masks the trial outcome."""
    engine = create_engine_from_settings(settings)
    try:
        with engine.connect() as connection:
            connection = connection.execution_options(isolation_level="AUTOCOMMIT")
            with contextlib.suppress(SQLAlchemyError):
                connection.exec_driver_sql(f'DROP DATABASE IF EXISTS "{database}"')
    except DatabaseUnavailable, SQLAlchemyError, OSError:
        return
    finally:
        engine.dispose()


def _postgres_trial_restore(
    context: OpsContext, target: DatabaseTarget, dump_path: Path
) -> dict[str, Any]:
    """Restore the archive into a throwaway database and drop it.

    ``pg_restore --list`` reads the archive header without a server and therefore
    certifies archives a server cannot accept. The only honest proof that a
    PostgreSQL backup is restorable is a real restore; this runs one against a
    scratch database and reports how many tables it produced.
    """
    scratch = f"itsm_verify_{uuid4().hex[:12]}"
    engine = create_engine_from_settings(context.settings)
    try:
        with engine.connect() as connection:
            connection = connection.execution_options(isolation_level="AUTOCOMMIT")
            try:
                connection.exec_driver_sql(f'CREATE DATABASE "{scratch}"')
            except SQLAlchemyError as exc:
                raise TrialRestoreUnavailable(
                    "the database role cannot create a scratch database for a trial restore; "
                    "grant CREATEDB to the ops role (or run the trial restore where it is "
                    f"allowed) ({type(exc).__name__})"
                ) from exc
    except TrialRestoreUnavailable:
        raise
    except (DatabaseUnavailable, SQLAlchemyError, OSError) as exc:
        raise TrialRestoreUnavailable(
            f"the database server is not reachable for a trial restore ({type(exc).__name__})"
        ) from exc
    finally:
        engine.dispose()
    tables = 0
    try:
        try:
            _run_tool(engines.postgres_restore_command(target, dump_path, scratch), target)
        except OpsError as exc:
            raise TrialRestoreFailed(f"the trial restore failed: {exc}") from exc
        try:
            scratch_engine = create_engine_from_settings(
                settings_for(database_url=_scratch_database_url(context.settings, scratch))
            )
            try:
                tables = len(inspect(scratch_engine).get_table_names())
            finally:
                scratch_engine.dispose()
        except (DatabaseUnavailable, SQLAlchemyError, OSError) as exc:
            raise TrialRestoreUnavailable(
                f"the trial restore could not be inspected ({type(exc).__name__})"
            ) from exc
    finally:
        _drop_scratch_database(context.settings, scratch)
    return {"status": "ok", "tables": tables}


def _postgres_integrity(
    context: OpsContext,
    target: DatabaseTarget,
    dump_path: Path,
    manifest: store.BackupManifest,
) -> tuple[str, dict[str, Any]]:
    """Compare the recorded majors, then prove restorability with a real restore."""
    client_major = manifest.version_info.get("clientMajor")
    server_major = manifest.version_info.get("serverMajor")
    installed = engines.version_major(_tool_version(("pg_restore", "--version")))
    detail: dict[str, Any] = {
        "compatibility": {
            "clientMajor": client_major,
            "serverMajor": server_major,
            "installedClientMajor": installed,
        }
    }
    mismatch = engines.postgres_major_mismatch(client_major, server_major)
    if mismatch is not None:
        return "incompatible", {**detail, "error": mismatch}
    if installed is None:
        return "incompatible", {
            **detail,
            "error": (
                "pg_restore is not available on this host; install the PostgreSQL "
                f"{server_major} client tools to verify that this backup is restorable"
            ),
        }
    installed_error = engines.postgres_major_mismatch(installed, server_major, tool="pg_restore")
    if installed_error is not None:
        return "incompatible", {**detail, "error": installed_error}
    try:
        trial = _postgres_trial_restore(context, target, dump_path)
    except TrialRestoreUnavailable as exc:
        return "unavailable", {
            **detail,
            "trialRestore": {"status": "unavailable", "reason": str(exc)},
            "error": f"restorability cannot be proven: {exc}",
        }
    except TrialRestoreFailed as exc:
        return "failed", {
            **detail,
            "trialRestore": {"status": "failed", "reason": str(exc)},
            "error": str(exc),
        }
    return "ok", {**detail, "trialRestore": trial}


def _integrity(
    context: OpsContext,
    target: DatabaseTarget,
    dump_path: Path,
    manifest: store.BackupManifest,
) -> tuple[str, dict[str, Any]]:
    if target.engine == "sqlite":
        return sqlite_ops.integrity(dump_path), {}
    if target.engine == "postgresql":
        return _postgres_integrity(context, target, dump_path, manifest)
    if target.engine == "mysql":
        try:
            with dump_path.open("r", encoding="utf-8", errors="replace") as stream:
                tail = stream.read()[-4096:]
        except OSError:
            return "failed", {}
        return ("ok" if MYSQL_DUMP_COMPLETION_MARKER in tail else "failed"), {}
    _run_tool(engines.mssql_verify_command(target, dump_path), target)
    return "ok", {}


def _verify_artifact(context: OpsContext, artifact: store.BackupArtifact) -> dict[str, Any]:
    target = context.target()
    dump_path = artifact.dump_path
    checks: dict[str, Any] = {"checksum": False, "size": False, "integrity": "skipped"}
    detail: dict[str, Any] = {}
    error: str | None = None
    if dump_path.is_file():
        digest, size = store.digest_file(dump_path)
        checks["checksum"] = digest == artifact.manifest.sha256
        checks["size"] = size == artifact.manifest.size
    else:
        error = "backup dump file is missing"
    if checks["checksum"] and checks["size"]:
        try:
            checks["integrity"], detail = _integrity(context, target, dump_path, artifact.manifest)
        except OpsError as exc:
            checks["integrity"] = "unavailable"
            error = str(exc)
        else:
            if detail.get("error"):
                error = str(detail["error"])
            elif checks["integrity"] != "ok":
                error = "backup failed the engine integrity check"
    elif error is None:
        error = "backup checksum or size does not match the manifest"
    extensions_ok, extension_reports, extension_errors = extensions.verify(
        artifact.directory, artifact.manifest.extensions
    )
    if extension_errors:
        combined = "; ".join(extension_errors)
        error = combined if error is None else f"{error}; {combined}"
    attachments_ok, attachment_report, attachment_errors = attachments.verify(
        artifact.directory, artifact.manifest.attachments
    )
    if attachment_errors:
        combined = "; ".join(attachment_errors)
        error = combined if error is None else f"{error}; {combined}"
    integrity_verified = (
        checks["checksum"]
        and checks["size"]
        and checks["integrity"] == "ok"
        and extensions_ok
        and attachments_ok
    )
    # A missing key ring does not damage the artifact, so recovery must stay
    # possible: it is reported, and it fails verification so backup automation
    # cannot publish or prune over an installation that cannot read its secrets.
    key_report = _credential_key_report(context, artifact)
    if key_report["missing"]:
        checks["credentialKeys"] = "missing"
        if error is None:
            error = str(key_report["error"])
    verified = integrity_verified and not key_report["missing"]
    store.update_verification(artifact, verified=verified)
    if not verified:
        _record_failure(
            context.backup_root,
            operation="verify",
            reason=error or "verification failed",
            target=target,
        )
    payload: dict[str, Any] = {
        "status": "ok" if verified else "failed",
        "backupId": artifact.manifest.id,
        "checks": checks,
        "extensions": extension_reports,
        "attachments": attachment_report,
        "integrityVerified": integrity_verified,
        "verified": verified,
        "error": None if verified else (error or "verification failed"),
    }
    for key in ("compatibility", "trialRestore"):
        if key in detail:
            payload[key] = detail[key]
    return _attach_credential_report(context, artifact, payload)


def _credential_key_report(context: OpsContext, artifact: store.BackupArtifact) -> dict[str, Any]:
    """Compare the ring recorded in the backup with the ring this process has.

    Only fingerprints travel in a manifest, so this is a readability warning, not
    key recovery: a missing fingerprint means the saved credentials written with
    that key cannot be decrypted until the operator restores the key itself.
    """
    recorded = list(artifact.manifest.credential_key_fingerprints)
    current = credential_key_fingerprints(context.settings)
    missing = [fingerprint for fingerprint in recorded if fingerprint not in current]
    warning: str | None = None
    if missing:
        warning = (
            "the current AI credential key ring lacks "
            f"{len(missing)} recorded fingerprint(s): {', '.join(missing)}; "
            "provider credentials sealed with those keys stay unreadable until the key is "
            "restored"
        )
    if missing:
        status = "missing"
        error = (
            f"the current AI credential key ring lacks {len(missing)} recorded "
            f"fingerprint(s): {', '.join(missing)}; provider credentials sealed with those "
            "keys stay unreadable until ITSM_AI_CREDENTIAL_KEYS contains the recorded key"
        )
    elif recorded:
        status = "ok"
        error = None
    else:
        status = "unrecorded"
        error = None
        warning = (
            "the backup records no AI credential key fingerprint; provider credentials "
            "cannot be proven readable after a restore. Configure ITSM_AI_CREDENTIAL_KEYS "
            "and take a new backup so the ring is recorded"
        )
    return {
        "status": status,
        "recorded": recorded,
        "current": current,
        "missing": missing,
        "warning": warning,
        "error": error,
    }


def _attach_credential_report(
    context: OpsContext, artifact: store.BackupArtifact, payload: dict[str, Any]
) -> dict[str, Any]:
    report = _credential_key_report(context, artifact)
    payload["credentialKeys"] = report
    payload["warnings"] = [report["warning"]] if report["warning"] else []
    return payload


def verify(context: OpsContext, identifier: str) -> dict[str, Any]:
    """Check checksum, size and engine-level integrity of one backup."""
    store.prepare_root(context.backup_root)
    artifact = store.load_artifact(context.backup_root, identifier)
    return _verify_artifact(context, artifact)


# --------------------------------------------------------------------------- #
# Restore
# --------------------------------------------------------------------------- #


def _copy_private(source: Path, destination: Path) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent, prefix=".restore-", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as target_stream, source.open("rb") as source_stream:
            shutil.copyfileobj(source_stream, target_stream, length=1024 * 1024)
            target_stream.flush()
            os.fsync(target_stream.fileno())
        os.chmod(temporary, 0o600)
        return temporary
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _restore_sqlite(
    context: OpsContext,
    artifact: store.BackupArtifact,
    *,
    target_file: str | None,
    target_database: str | None,
    replace_live: bool,
    confirm: str | None,
) -> dict[str, Any]:
    if target_database is not None:
        raise UsageError("sqlite restores use --target-file, not --target-database")
    if not target_file:
        raise UsageError("sqlite restores require --target-file")
    live = Path(Path(context.settings.database_url.removeprefix("sqlite:///")).resolve())
    destination = Path(target_file).expanduser().resolve()
    is_live = destination == live
    if is_live:
        if not replace_live:
            raise RestoreRefused(
                "restore target is the live database; pass --replace-live and "
                "--confirm <backup id> to overwrite it"
            )
        if confirm != artifact.manifest.id:
            raise RestoreRefused(
                "--confirm must repeat the backup id to overwrite the live database"
            )
        in_use = quiesce.refusal(context.settings)
        if in_use is not None:
            raise RestoreRefused(f"restore refused: {in_use}")
    else:
        if replace_live:
            raise RestoreRefused("--replace-live only applies to the live database path")
        if destination.exists():
            raise RestoreRefused(f"restore target already exists: {destination}")
    if not destination.parent.is_dir():
        raise OpsError(f"restore target directory does not exist: {destination.parent}")
    source_snapshot = sqlite_ops.snapshot(live) if live.is_file() else None
    temporary = _copy_private(artifact.dump_path, destination)
    try:
        if sqlite_ops.integrity(temporary) != "ok":
            raise OpsError("restored copy failed the sqlite integrity check")
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    os.chmod(destination, 0o600)
    if is_live:
        for suffix in ("-wal", "-shm"):
            with contextlib.suppress(FileNotFoundError, OSError):
                Path(str(destination) + suffix).unlink()
    return {
        "status": "ok",
        "backupId": artifact.manifest.id,
        "engine": "sqlite",
        "target": str(destination),
        "live": is_live,
        "source": source_snapshot,
        "restored": sqlite_ops.snapshot(destination),
    }


def _restore_external(
    context: OpsContext,
    artifact: store.BackupArtifact,
    target: DatabaseTarget,
    *,
    target_file: str | None,
    target_database: str | None,
    replace_live: bool,
    confirm: str | None,
) -> dict[str, Any]:
    if target_file is not None:
        raise UsageError(f"{target.engine} restores use --target-database, not --target-file")
    if replace_live:
        if target.engine != "postgresql":
            raise RestoreRefused(
                f"{target.engine} cannot safely replace the live database; restore into a new "
                "database and point the application at it"
            )
        if confirm != artifact.manifest.id:
            raise RestoreRefused("--confirm must repeat the backup id to replace the live database")
        database = target.database
    else:
        if not target_database:
            raise UsageError(f"{target.engine} restores require --target-database")
        database = target_database
    if target.engine == "postgresql":
        command = engines.postgres_restore_command(
            target, artifact.dump_path, database, replace_live=replace_live
        )
    elif target.engine == "mysql":
        with _temporary_option_directory() as directory:
            command = engines.mysql_restore_command(
                target,
                artifact.dump_path,
                database,
                option_file=directory / "client.cnf",
                tool=_mysql_client_tool(),
            )
            _run_tool(command, target)
        return _external_payload(context, artifact, database, target)
    else:
        command = engines.mssql_restore_command(target, artifact.dump_path, database)
    _run_tool(command, target)
    return _external_payload(context, artifact, database, target)


def _external_payload(
    context: OpsContext, artifact: store.BackupArtifact, database: str, target: DatabaseTarget
) -> dict[str, Any]:
    # ``str(URL)`` hides the password behind ``***``; the revision probe needs the
    # real credential, and the string never leaves this function.
    restored_url = (
        make_url(context.settings.database_url)
        .set(database=database)
        .render_as_string(hide_password=False)
    )
    return {
        "status": "ok",
        "backupId": artifact.manifest.id,
        "engine": target.engine,
        "target": database,
        "live": database == target.database,
        "restored": {
            "revision": revision_for_database_url(restored_url),
            "tables": None,
            "rows": None,
        },
    }


def _attachment_target(
    destination: Path, artifact: store.BackupArtifact, *, replace_live: bool, confirm: str | None
) -> bool:
    """Decide whether the attachment storage target may be written.

    A missing directory is created. An existing *empty* directory is the normal
    fresh-install case and needs no consent; an existing populated directory may
    hold blobs that are not in the artifact, so it follows the same explicit
    consent rule as the live database.
    """
    if not destination.exists():
        if replace_live:
            raise RestoreRefused("--replace-live only applies to an existing attachment target")
        return False
    if destination.is_symlink() or not destination.is_dir():
        raise RestoreRefused(f"attachment restore target is not a directory: {destination}")
    if not any(destination.iterdir()):
        return False
    if not replace_live:
        raise RestoreRefused(
            "attachment restore target already contains files; pass --replace-live and "
            "--confirm <backup id> to write the archived blobs into it"
        )
    if confirm != artifact.manifest.id:
        raise RestoreRefused(
            "--confirm must repeat the backup id to write into the attachment storage target"
        )
    return True


def _extension_target(
    destination: Path, artifact: store.BackupArtifact, *, replace_live: bool, confirm: str | None
) -> bool:
    """Decide whether the extension data target may be written.

    An existing target follows the same explicit consent rule as the live core
    database: ``--replace-live`` plus the repeated backup id. A new target is
    created, never implicitly overwritten.
    """
    if not destination.exists():
        if replace_live:
            raise RestoreRefused("--replace-live only applies to an existing extension data target")
        return False
    if destination.is_symlink() or not destination.is_dir():
        raise RestoreRefused(f"extension restore target is not a directory: {destination}")
    if not replace_live:
        raise RestoreRefused(
            "extension restore target already exists; pass --replace-live and "
            "--confirm <backup id> to write into it"
        )
    if confirm != artifact.manifest.id:
        raise RestoreRefused(
            "--confirm must repeat the backup id to write into the extension data target"
        )
    return True


def restore(
    context: OpsContext,
    identifier: str,
    *,
    target_file: str | None = None,
    target_database: str | None = None,
    target_extensions: str | None = None,
    target_attachments: str | None = None,
    replace_live: bool = False,
    confirm: str | None = None,
) -> dict[str, Any]:
    """Restore one verified backup into a new target, or the live one with consent.

    The core database, the extension data files and the attachment blobs are
    restored independently: ``--target-file``/``--target-database`` select the
    database target, ``--target-extensions`` the extension data path and
    ``--target-attachments`` the attachment storage root.
    """
    store.prepare_root(context.backup_root)
    artifact = store.load_artifact(context.backup_root, identifier)
    target = context.target()
    if target.engine == "postgresql":
        refusal = engines.postgres_restore_refusal(
            artifact.manifest.version_info.get("clientMajor"),
            artifact.manifest.version_info.get("serverMajor"),
            engines.version_major(_tool_version(("pg_restore", "--version"))),
        )
        if refusal is not None:
            raise RestoreRefused(f"backup {identifier} cannot be restored: {refusal}")
    verification = _verify_artifact(context, artifact)
    # Artifact integrity gates recovery; a missing key ring is reported by the
    # restore payload instead of blocking a disaster recovery.
    if not verification["integrityVerified"]:
        raise OpsError(f"backup {identifier} failed verification: {verification['error']}")
    if target_extensions is not None:
        extension_destination = Path(target_extensions).expanduser().absolute()
        _extension_target(
            extension_destination, artifact, replace_live=replace_live, confirm=confirm
        )
        extensions.preflight_restore(
            artifact.directory, artifact.manifest.extensions, destination=extension_destination
        )
    payload: dict[str, Any] = {}
    core_requested = target_file is not None or target_database is not None
    if core_requested:
        if target.engine == "sqlite":
            payload = _restore_sqlite(
                context,
                artifact,
                target_file=target_file,
                target_database=target_database,
                replace_live=replace_live,
                confirm=confirm,
            )
        else:
            payload = _restore_external(
                context,
                artifact,
                target,
                target_file=target_file,
                target_database=target_database,
                replace_live=replace_live,
                confirm=confirm,
            )
    if replace_live and core_requested:
        # A consented live restore is the documented recovery step for a database
        # a failed upgrade left behind; the partial marker must not survive it.
        store.clear_upgrade_attempt(context.backup_root)
    if target_attachments is not None:
        destination = Path(target_attachments).expanduser()
        if not destination.is_absolute():
            destination = Path.cwd() / destination
        replace = _attachment_target(
            destination, artifact, replace_live=replace_live, confirm=confirm
        )
        payload["attachments"] = attachments.restore(
            artifact.directory,
            artifact.manifest.attachments,
            destination=destination,
            replace=replace,
        )
        payload.setdefault("status", "ok")
        payload.setdefault("backupId", artifact.manifest.id)
        payload.setdefault("engine", target.engine)
    if target_extensions is not None:
        destination = Path(target_extensions).expanduser()
        if not destination.is_absolute():
            destination = Path.cwd() / destination
        replace = _extension_target(
            destination, artifact, replace_live=replace_live, confirm=confirm
        )
        payload["extensions"] = extensions.restore(
            artifact.directory,
            artifact.manifest.extensions,
            destination=destination,
            replace=replace,
        )
        payload.setdefault("status", "ok")
        payload.setdefault("backupId", artifact.manifest.id)
        payload.setdefault("engine", target.engine)
    elif not core_requested and target_attachments is None:
        if target.engine == "sqlite":
            raise UsageError("sqlite restores require --target-file")
        raise UsageError(f"{target.engine} restores require --target-database")
    return _attach_credential_report(context, artifact, payload)


# --------------------------------------------------------------------------- #
# Retention and status
# --------------------------------------------------------------------------- #


def _age_days(artifact: store.BackupArtifact, now: datetime) -> float:
    try:
        created = datetime.fromisoformat(artifact.manifest.created_at)
    except ValueError:
        return float("inf")
    return (now - created.astimezone(UTC)).total_seconds() / 86400.0


def prune(
    context: OpsContext,
    *,
    keep: int | None = None,
    max_age_days: int | None = None,
    dry_run: bool = False,
    partials_older_than: int | None = None,
) -> dict[str, Any]:
    """Delete artifacts outside the retention policy, never the newest verified one."""
    if keep is None and max_age_days is None and partials_older_than is None:
        raise UsageError(
            "a retention rule is required: pass --keep, --max-age-days and/or --partials-older-than"
        )
    if keep is not None and keep < 1:
        raise UsageError("--keep must be at least 1")
    if max_age_days is not None and max_age_days < 0:
        raise UsageError("--max-age-days must not be negative")
    if partials_older_than is not None and partials_older_than < 0:
        raise UsageError("--partials-older-than must not be negative")
    root = context.backup_root
    store.prepare_root(root)
    artifacts = store.list_artifacts(root)
    reclaimed: list[str] = []
    if partials_older_than is not None:
        for item in store.partial_artifacts(root):
            age = item["ageDays"]
            if age is None or age <= partials_older_than:
                continue
            if not dry_run:
                shutil.rmtree(root / item["name"], ignore_errors=True)
            reclaimed.append(item["name"])
    if not artifacts:
        return {
            "status": "ok",
            "kept": [],
            "deleted": [],
            "protected": [],
            "reclaimedPartials": reclaimed,
            "partials": store.partial_artifacts(root),
            "dryRun": dry_run,
        }
    newest = artifacts[0]
    newest_verified = next(
        (artifact for artifact in artifacts if artifact.manifest.verified is True), None
    )
    protected = [newest.manifest.id]
    if newest_verified is not None and newest_verified.manifest.id != newest.manifest.id:
        protected.append(newest_verified.manifest.id)
    now = datetime.now(UTC)
    kept: list[str] = []
    deleted: list[str] = []
    for index, artifact in enumerate(artifacts):
        if artifact.manifest.id in protected:
            kept.append(artifact.manifest.id)
            continue
        beyond_count = keep is not None and index >= keep
        too_old = max_age_days is not None and _age_days(artifact, now) > max_age_days
        if not (beyond_count or too_old):
            kept.append(artifact.manifest.id)
            continue
        if not dry_run:
            shutil.rmtree(artifact.directory)
        deleted.append(artifact.manifest.id)
    return {
        "status": "ok",
        "kept": kept,
        "deleted": deleted,
        "protected": protected,
        "reclaimedPartials": reclaimed,
        "partials": store.partial_artifacts(root),
        "dryRun": dry_run,
    }


def _last_backup_payload(
    artifacts: list[store.BackupArtifact],
) -> dict[str, Any] | None:
    """Describe the newest artifact, re-reading its dump instead of trusting metadata."""
    if not artifacts:
        return None
    last = artifacts[0]
    try:
        checksum_ok = (
            last.dump_path.is_file()
            and store.digest_file(last.dump_path)[0] == last.manifest.sha256
        )
    except OSError:
        checksum_ok = False
    return {
        "id": last.manifest.id,
        "createdAt": last.manifest.created_at,
        "size": last.manifest.size,
        "engine": last.manifest.engine,
        "sha256": last.manifest.sha256,
        "verified": last.manifest.verified if checksum_ok else False,
        "checksum": checksum_ok,
        "alembicRevision": last.manifest.alembic_revision,
        "path": str(last.directory),
    }


def status(context: OpsContext) -> dict[str, Any]:
    """Report the latest artifact, failures and last upgrade result."""
    root = context.backup_root
    try:
        target: DatabaseTarget | None = context.target()
    except OpsError:
        target = None
    artifacts = store.list_artifacts(root)
    stored = store.read_status(root)
    return {
        "status": "ok",
        "engine": None if target is None else target.engine,
        "database": None if target is None else target.describe(),
        "backupRoot": str(root),
        "backupCount": len(artifacts),
        "extensions": extensions.footprint(context.settings.extension_data_path),
        "attachments": attachments.footprint(context.settings.attachment_storage_path),
        "lastBackup": _last_backup_payload(artifacts),
        "failures": stored.get("failures", []),
        "lastUpgrade": stored.get("lastUpgrade"),
        "credentialKeys": _credential_key_report(context, artifacts[0]) if artifacts else None,
        "partials": store.partial_artifacts(root),
        "upgradeAttempt": _upgrade_attempt_payload(root),
        "updatedAt": stored.get("updatedAt"),
    }


def _upgrade_attempt_payload(root: Path) -> dict[str, Any] | None:
    """Report an unfinished or partial upgrade so automation can see it."""
    attempt = store.read_upgrade_attempt(root)
    if attempt is None:
        return None
    return {
        key: attempt.get(key)
        for key in (
            "fromRevision",
            "headRevision",
            "observedRevision",
            "schemaStatus",
            "startedAt",
            "backupId",
            "restoreCommand",
        )
        if key in attempt
    }


def _publication_state(last_backup: Mapping[str, Any] | None) -> str | None:
    """Operational health of the newest artifact as published to the browser."""
    if last_backup is None:
        return None
    if last_backup.get("checksum") is False or last_backup.get("verified") is False:
        return "failed"
    return "ok" if last_backup.get("verified") is True else "unverified"


def publish_status(context: OpsContext) -> dict[str, Any]:
    """Publish the sanitized operational summary the read-only API serves.

    Failure and upgrade history in the private status record is preserved and
    sanitized at the source; the external copy (when configured) carries the same
    allow-listed summary and no private locators.
    """
    root = context.backup_root
    try:
        target: DatabaseTarget | None = context.target()
    except OpsError:
        target = None
    secrets = () if target is None else _secrets(target)
    artifacts = store.list_artifacts(root)
    stored = store.read_status(root)
    last_backup = _last_backup_payload(artifacts)
    payload: dict[str, Any] = {
        "status": _publication_state(last_backup),
        "engine": None if target is None else target.engine,
        "backupCount": len(artifacts),
        "lastBackup": last_backup,
        "failures": stored.get("failures", []),
        "lastUpgrade": stored.get("lastUpgrade"),
    }
    return store.publish_summary(root, payload, secrets=secrets, external_path=context.status_path)
