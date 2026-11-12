"""Pure command construction for the four supported database engines.

Every helper here is a pure function of a parsed database target and an artifact
path, so the command line can be verified without the vendor tool being present
and without opening a connection. Credentials are modeled as environment values
or a private option file; they are never placed in an argv list, in a rendered
command line or in a public description.

This module owns the only place where a URL password is read for the ops tool.
It does not import ``itsm.release_mode`` and does not open a connection.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

REDACTED = "[redacted]"

ENGINE_FAMILIES = ("sqlite", "postgresql", "mysql", "mssql")

DUMP_FILENAMES = {
    "sqlite": "database.db",
    "postgresql": "database.dump",
    "mysql": "database.sql",
    "mssql": "database.bak",
}

MYSQL_DUMP_TOOLS = ("mariadb-dump", "mysqldump")
MYSQL_CLIENT_TOOLS = ("mariadb", "mysql")


class OpsError(RuntimeError):
    """Raised when an ops request cannot be satisfied safely."""


@dataclass(frozen=True)
class OptionFile:
    """A private credential file written with mode 0600 before the tool runs."""

    path: Path
    content: str = field(repr=False)


@dataclass(frozen=True)
class ToolCommand:
    """One external tool invocation; argv never carries a credential."""

    argv: tuple[str, ...]
    env: dict[str, str] = field(default_factory=dict)
    option_file: OptionFile | None = None
    stdin: Path | None = None

    def describe(self) -> str:
        """Render the command line for output; never includes environment values."""
        return render_command(self.argv)


@dataclass(frozen=True)
class DatabaseTarget:
    """Parsed connection coordinates; the password is never rendered."""

    engine: str
    database: str
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = field(default=None, repr=False)

    def describe(self) -> str:
        """Return an operator-facing locator with credentials omitted."""
        if self.engine == "sqlite":
            return f"sqlite:///{self.database}"
        authority = self.username or ""
        if authority:
            authority += "@"
        port = f":{self.port}" if self.port else ""
        return f"{self.engine}://{authority}{self.host or ''}{port}/{self.database}"


def detect_engine(raw_url: str) -> str:
    """Map a SQLAlchemy URL to one of the supported engine families."""
    try:
        drivername = make_url(raw_url).drivername
    except ArgumentError as exc:
        raise OpsError("database url is not a valid SQLAlchemy URL") from exc
    family = drivername.split("+", 1)[0]
    if family in {"mariadb", "mysql"}:
        return "mysql"
    if family in ENGINE_FAMILIES:
        return family
    raise OpsError(f"no backup mechanism for engine '{family}'")


def database_target(raw_url: str) -> DatabaseTarget:
    """Parse a database URL into a target that keeps credentials private."""
    try:
        url = make_url(raw_url)
    except ArgumentError as exc:
        raise OpsError("database url is not a valid SQLAlchemy URL") from exc
    engine = detect_engine(raw_url)
    database = url.database or ""
    if engine == "sqlite":
        if not database:
            raise OpsError("sqlite database url must include a file path")
        return DatabaseTarget(engine=engine, database=database)
    if not database:
        raise OpsError("database url must include a database name")
    return DatabaseTarget(
        engine=engine,
        database=database,
        host=url.host,
        port=url.port,
        username=url.username,
        password=url.password,
    )


def redact_url(raw_url: str) -> str:
    """Return the operator-facing locator for a URL, without credentials."""
    try:
        return database_target(raw_url).describe()
    except OpsError:
        return "<unparsable database url>"


def render_command(argv: tuple[str, ...], secrets: tuple[str, ...] = ()) -> str:
    """Render an argv list for display, masking known secret values."""
    rendered = shlex.join(argv)
    for secret in sorted({value for value in secrets if value}, key=len, reverse=True):
        rendered = rendered.replace(secret, REDACTED)
    return rendered


def dump_filename(engine: str) -> str:
    """Return the artifact file name for one engine."""
    try:
        return DUMP_FILENAMES[engine]
    except KeyError as exc:
        raise OpsError(f"no backup artifact format for engine '{engine}'") from exc


def _require(target: DatabaseTarget, engine: str) -> None:
    if target.engine != engine:
        raise OpsError(f"{engine} command builders cannot handle a {target.engine} target")


def _connection_args(target: DatabaseTarget) -> tuple[str, ...]:
    arguments: list[str] = []
    if target.host:
        arguments += ["--host", target.host]
    if target.port:
        arguments += ["--port", str(target.port)]
    if target.username:
        arguments += ["--username", target.username]
    return tuple(arguments)


def postgres_backup_command(target: DatabaseTarget, dump_path: Path) -> ToolCommand:
    """Build ``pg_dump -Fc``; the password travels only in ``PGPASSWORD``."""
    _require(target, "postgresql")
    argv = (
        "pg_dump",
        "--format=custom",
        "--no-password",
        *_connection_args(target),
        "--file",
        str(dump_path),
        "--dbname",
        target.database,
    )
    env = {"PGPASSWORD": target.password} if target.password else {}
    return ToolCommand(argv=argv, env=env)


def postgres_restore_command(
    target: DatabaseTarget,
    dump_path: Path,
    target_database: str,
    *,
    replace_live: bool = False,
) -> ToolCommand:
    """Build ``pg_restore`` into a new database, or the live one with consent."""
    _require(target, "postgresql")
    if not target_database.strip():
        raise OpsError("restore target database must not be blank")
    if target_database == target.database and not replace_live:
        raise OpsError("restore target must be a new database, not the source database")
    cleanup = ("--clean", "--if-exists") if replace_live else ()
    argv = (
        "pg_restore",
        "--no-password",
        "--exit-on-error",
        "--no-owner",
        "--no-privileges",
        *cleanup,
        *_connection_args(target),
        "--dbname",
        target_database,
        str(dump_path),
    )
    env = {"PGPASSWORD": target.password} if target.password else {}
    return ToolCommand(argv=argv, env=env)


def postgres_list_command(dump_path: Path) -> ToolCommand:
    """Read the custom-format archive table of contents without a connection."""
    return ToolCommand(argv=("pg_restore", "--list", str(dump_path)))


_VERSION_DIGITS = re.compile(r"(\d+)(?:\.\d+)?")


def version_major(version_text: str | None) -> int | None:
    """Extract the leading major number from a tool or server version string.

    ``pg_dump (PostgreSQL) 18.6``, ``pg_restore (PostgreSQL) 16.13 (Ubuntu ...)``
    and a bare ``16.13`` all yield their major. ``None``, empty text and
    ``unavailable`` yield ``None`` instead of guessing one.
    """
    if not version_text:
        return None
    match = _VERSION_DIGITS.search(version_text)
    return None if match is None else int(match.group(1))


def postgres_major_mismatch(
    client_major: int | None, server_major: int | None, *, tool: str = "pg_dump"
) -> str | None:
    """Return an actionable error when the client major cannot restore the archive.

    A PostgreSQL custom-format archive is only reliably restorable by the same
    client major that wrote it, and that major must also match the server's. The
    message names the concrete remedy; it never suggests retrying blindly.
    """
    if client_major is None:
        return (
            "the backup does not record the PostgreSQL client major version, so its "
            "restorability cannot be proven; take a new backup with this release"
        )
    if server_major is None:
        return (
            "the backup does not record the PostgreSQL server major version, so its "
            "restorability cannot be proven; take a new backup with this release"
        )
    if client_major != server_major:
        return (
            f"{tool} client major {client_major} does not match PostgreSQL server major "
            f"{server_major}: a custom-format archive written by a different client major is "
            f"not restorable. Install the PostgreSQL {server_major} client tools on this host "
            f"(or take the backup with them) and retry"
        )
    return None


def postgres_restore_refusal(
    client_major: int | None,
    server_major: int | None,
    installed_client_major: int | None,
) -> str | None:
    """Refuse a restore whose recorded or installed major cannot read the archive.

    An artifact that predates version recording is not refused here: the caller
    still runs the real tool, which fails loudly instead of being blocked on
    metadata it never had.
    """
    if client_major is not None and server_major is not None and client_major != server_major:
        return (
            f"this artifact was written by pg_dump client major {client_major} against "
            f"PostgreSQL server major {server_major}; a custom-format archive from another "
            "client major is not restorable. Take the backup with client tools that match "
            f"the server major ({server_major}) and restore that artifact"
        )
    if (
        server_major is not None
        and installed_client_major is not None
        and installed_client_major != server_major
    ):
        return (
            f"the installed pg_restore major {installed_client_major} cannot restore an "
            f"archive from PostgreSQL server major {server_major}; install the PostgreSQL "
            f"{server_major} client tools and retry"
        )
    return None


def _escape_option_value(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def mysql_option_file(target: DatabaseTarget, path: Path) -> OptionFile:
    """Build a 0600 client option file so no credential reaches argv."""
    _require(target, "mysql")
    lines = ["[client]"]
    if target.host:
        lines.append(f"host={target.host}")
    if target.port:
        lines.append(f"port={target.port}")
    if target.username:
        lines.append(f"user={_escape_option_value(target.username)}")
    if target.password:
        lines.append(f"password={_escape_option_value(target.password)}")
    return OptionFile(path=path, content="\n".join(lines) + "\n")


def mysql_backup_command(
    target: DatabaseTarget,
    dump_path: Path,
    *,
    option_file: Path,
    tool: str = "mysqldump",
) -> ToolCommand:
    """Build a consistent single-transaction logical dump."""
    _require(target, "mysql")
    if tool not in MYSQL_DUMP_TOOLS:
        raise OpsError(f"unsupported mysql dump tool '{tool}'")
    argv = (
        tool,
        f"--defaults-extra-file={option_file}",
        "--single-transaction",
        "--quick",
        "--skip-lock-tables",
        "--routines",
        "--events",
        "--result-file",
        str(dump_path),
        target.database,
    )
    return ToolCommand(argv=argv, option_file=mysql_option_file(target, option_file))


def mysql_restore_command(
    target: DatabaseTarget,
    dump_path: Path,
    target_database: str,
    *,
    option_file: Path,
    tool: str = "mysql",
) -> ToolCommand:
    """Build a client restore that feeds the dump on stdin."""
    _require(target, "mysql")
    if target_database == target.database:
        raise OpsError("restore target must be a new database, not the source database")
    if not target_database.strip():
        raise OpsError("restore target database must not be blank")
    if tool not in MYSQL_CLIENT_TOOLS:
        raise OpsError(f"unsupported mysql client tool '{tool}'")
    argv = (tool, f"--defaults-extra-file={option_file}", target_database)
    return ToolCommand(
        argv=argv,
        option_file=mysql_option_file(target, option_file),
        stdin=dump_path,
    )


def _sql_server_endpoint(target: DatabaseTarget) -> str:
    host = target.host or "localhost"
    return f"tcp:{host},{target.port}" if target.port else f"tcp:{host}"


def _sql_literal(value: str) -> str:
    return value.replace("'", "''")


def _sqlcmd_command(target: DatabaseTarget, statement: str) -> ToolCommand:
    argv = (
        "sqlcmd",
        "-S",
        _sql_server_endpoint(target),
        "-U",
        target.username or "sa",
        "-d",
        "master",
        "-b",
        "-r",
        "1",
        "-Q",
        statement,
    )
    env = {"SQLCMDPASSWORD": target.password} if target.password else {}
    return ToolCommand(argv=argv, env=env)


def mssql_backup_command(target: DatabaseTarget, dump_path: Path) -> ToolCommand:
    """Build a full ``BACKUP DATABASE ... TO DISK`` with checksum."""
    _require(target, "mssql")
    statement = (
        f"BACKUP DATABASE [{target.database.replace(']', ']]')}] "
        f"TO DISK = N'{_sql_literal(str(dump_path))}' "
        "WITH INIT, COMPRESSION, CHECKSUM, STATS = 10;"
    )
    return _sqlcmd_command(target, statement)


def mssql_verify_command(target: DatabaseTarget, dump_path: Path) -> ToolCommand:
    """Build ``RESTORE VERIFYONLY`` for an existing backup file."""
    _require(target, "mssql")
    statement = f"RESTORE VERIFYONLY FROM DISK = N'{_sql_literal(str(dump_path))}' WITH CHECKSUM;"
    return _sqlcmd_command(target, statement)


def mssql_restore_command(
    target: DatabaseTarget,
    dump_path: Path,
    target_database: str,
    moves: tuple[tuple[str, str], ...] = (),
) -> ToolCommand:
    """Build ``RESTORE DATABASE`` into a different database name.

    ``moves`` holds ``(logical_name, physical_path)`` pairs read from
    ``RESTORE FILELISTONLY``. A restore that renames the database needs them;
    the ops tool never guesses a path. This path is not verified live on this
    host because no SQL Server instance or ODBC driver is available.
    """
    _require(target, "mssql")
    if target_database == target.database:
        raise OpsError("restore target must be a new database, not the source database")
    if not target_database.strip():
        raise OpsError("restore target database must not be blank")
    clauses = ["REPLACE", "RECOVERY", "STATS = 10"]
    clauses += [
        f"MOVE N'{_sql_literal(logical)}' TO N'{_sql_literal(physical)}'"
        for logical, physical in moves
    ]
    statement = (
        f"RESTORE DATABASE [{target_database.replace(']', ']]')}] "
        f"FROM DISK = N'{_sql_literal(str(dump_path))}' "
        f"WITH {', '.join(clauses)};"
    )
    return _sqlcmd_command(target, statement)
