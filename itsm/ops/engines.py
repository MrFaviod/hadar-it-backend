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
        f"BACKUP DATABASE [{target.database}] TO DISK = N'{_sql_literal(str(dump_path))}' "
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
        f"RESTORE DATABASE [{target_database}] FROM DISK = N'{_sql_literal(str(dump_path))}' "
        f"WITH {', '.join(clauses)};"
    )
    return _sqlcmd_command(target, statement)
