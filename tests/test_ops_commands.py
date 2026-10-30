"""Pure engine command builders and redaction for the ops tool.

External database tools are absent from most verification hosts, so the command
construction is a pure function of a target and an artifact path. These checks
assert the security invariant that matters most: a password never reaches an
argv list, a rendered command line or a public description.
"""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest
from itsm.ops import engines

PASSWORD = "sup3r-s3cret-pass"


def postgres_target() -> engines.DatabaseTarget:
    return engines.database_target(
        f"postgresql+psycopg://itsm:{PASSWORD}@db.internal:5433/itsm_prod"
    )


def mysql_target() -> engines.DatabaseTarget:
    return engines.database_target(f"mysql+pymysql://itsm:{PASSWORD}@db.internal:3307/itsm_prod")


def mssql_target() -> engines.DatabaseTarget:
    return engines.database_target(
        f"mssql+pyodbc://sa:{PASSWORD}@db.internal:1433/itsm_prod?driver=ODBC+Driver+18"
    )


def sqlite_target(tmp_path: Path) -> engines.DatabaseTarget:
    return engines.database_target(f"sqlite:///{tmp_path / 'app.db'}")


@pytest.mark.parametrize(
    "url,expected",
    [
        ("sqlite:////tmp/app.db", "sqlite"),
        ("sqlite+pysqlite:////tmp/app.db", "sqlite"),
        ("postgresql+psycopg://itsm@localhost:5432/itsm", "postgresql"),
        ("postgresql://itsm@localhost:5432/itsm", "postgresql"),
        ("mysql+pymysql://itsm@localhost:3306/itsm", "mysql"),
        ("mariadb+pymysql://itsm@localhost:3306/itsm", "mysql"),
        ("mssql+pyodbc://sa@localhost:1433/itsm", "mssql"),
    ],
)
def test_detects_the_engine_family_for_every_supported_driver(url: str, expected: str) -> None:
    assert engines.detect_engine(url) == expected


def test_rejects_an_engine_without_a_backup_mechanism() -> None:
    with pytest.raises(engines.OpsError):
        engines.detect_engine("oracle+cx_oracle://user@localhost/orcl")


def test_database_target_reports_the_engine_without_the_password() -> None:
    target = postgres_target()

    assert target.engine == "postgresql"
    assert target.database == "itsm_prod"
    assert target.host == "db.internal"
    assert target.port == 5433
    assert target.username == "itsm"
    assert PASSWORD in target.password
    assert PASSWORD not in target.describe()
    assert PASSWORD not in repr(target)
    assert target.describe() == "postgresql://itsm@db.internal:5433/itsm_prod"


def test_sqlite_target_uses_the_file_path_as_the_database(tmp_path: Path) -> None:
    target = sqlite_target(tmp_path)

    assert target.engine == "sqlite"
    assert target.database == str(tmp_path / "app.db")
    assert target.username is None
    assert target.password is None


def test_postgres_backup_keeps_the_password_out_of_argv(tmp_path: Path) -> None:
    command = engines.postgres_backup_command(postgres_target(), tmp_path / "db.dump")

    assert command.argv[0] == "pg_dump"
    assert "--format=custom" in command.argv
    assert command.argv[-2:] == ("--dbname", "itsm_prod")
    assert ("--file", str(tmp_path / "db.dump")) == (
        command.argv[command.argv.index("--file")],
        command.argv[command.argv.index("--file") + 1],
    )
    assert PASSWORD not in shlex.join(command.argv)
    assert command.env == {"PGPASSWORD": PASSWORD}
    assert command.option_file is None


def test_postgres_restore_targets_a_new_database_and_never_the_source(tmp_path: Path) -> None:
    command = engines.postgres_restore_command(
        postgres_target(), tmp_path / "db.dump", "itsm_restore_20260101"
    )

    assert command.argv[0] == "pg_restore"
    assert "--dbname" in command.argv
    assert "itsm_restore_20260101" in command.argv
    assert "itsm_prod" not in command.argv
    assert "--exit-on-error" in command.argv
    assert PASSWORD not in shlex.join(command.argv)
    assert command.env == {"PGPASSWORD": PASSWORD}

    with pytest.raises(engines.OpsError):
        engines.postgres_restore_command(postgres_target(), tmp_path / "db.dump", "itsm_prod")


def test_postgres_verify_only_reads_the_archive(tmp_path: Path) -> None:
    command = engines.postgres_list_command(tmp_path / "db.dump")

    assert command.argv == ("pg_restore", "--list", str(tmp_path / "db.dump"))
    assert command.env == {}


def test_mysql_backup_uses_a_private_option_file_instead_of_argv(tmp_path: Path) -> None:
    option_file = tmp_path / "client.cnf"

    command = engines.mysql_backup_command(
        mysql_target(), tmp_path / "db.sql", option_file=option_file
    )

    assert command.argv[0] == "mysqldump"
    assert command.argv[1] == f"--defaults-extra-file={option_file}"
    assert "--single-transaction" in command.argv
    assert command.argv[-1] == "itsm_prod"
    assert PASSWORD not in shlex.join(command.argv)
    assert command.env == {}
    assert command.option_file is not None
    assert command.option_file.path == option_file
    assert PASSWORD in command.option_file.content
    assert "db.internal" in command.option_file.content
    assert command.option_file.content.startswith("[client]\n")
    assert PASSWORD not in command.describe()


def test_mysql_option_file_quotes_values_that_would_break_the_file(tmp_path: Path) -> None:
    target = engines.database_target('mysql+pymysql://itsm:pa"ss\\word@db.internal/itsm_prod')

    command = engines.mysql_backup_command(
        target, tmp_path / "db.sql", option_file=tmp_path / "client.cnf"
    )

    assert command.option_file is not None
    password_line = next(
        line for line in command.option_file.content.splitlines() if line.startswith("password=")
    )
    assert password_line == 'password="pa\\"ss\\\\word"'


def test_mysql_restore_feeds_the_dump_on_stdin(tmp_path: Path) -> None:
    command = engines.mysql_restore_command(
        mysql_target(),
        tmp_path / "db.sql",
        "itsm_restore_20260101",
        option_file=tmp_path / "client.cnf",
    )

    assert command.argv[0] == "mysql"
    assert command.argv[-1] == "itsm_restore_20260101"
    assert str(tmp_path / "db.sql") not in command.argv
    assert PASSWORD not in shlex.join(command.argv)
    assert command.stdin == tmp_path / "db.sql"

    with pytest.raises(engines.OpsError):
        engines.mysql_restore_command(
            mysql_target(),
            tmp_path / "db.sql",
            "itsm_prod",
            option_file=tmp_path / "client.cnf",
        )


def test_mssql_uses_sqlcmdpassword_and_scripts_backup_to_disk(tmp_path: Path) -> None:
    command = engines.mssql_backup_command(mssql_target(), tmp_path / "db.bak")

    assert command.argv[0] == "sqlcmd"
    assert "-S" in command.argv
    assert "tcp:db.internal,1433" in command.argv
    assert command.env == {"SQLCMDPASSWORD": PASSWORD}
    statement = command.argv[command.argv.index("-Q") + 1]
    assert statement.startswith("BACKUP DATABASE [itsm_prod] TO DISK = N'")
    assert "CHECKSUM" in statement
    assert PASSWORD not in shlex.join(command.argv)
    assert PASSWORD not in statement


def test_mssql_verify_and_restore_are_constructed_but_not_live_validated(tmp_path: Path) -> None:
    verify = engines.mssql_verify_command(mssql_target(), tmp_path / "db.bak")
    restore = engines.mssql_restore_command(
        mssql_target(), tmp_path / "db.bak", "itsm_restore_20260101"
    )

    assert "RESTORE VERIFYONLY FROM DISK" in verify.argv[verify.argv.index("-Q") + 1]
    statement = restore.argv[restore.argv.index("-Q") + 1]
    assert statement.startswith("RESTORE DATABASE [itsm_restore_20260101] FROM DISK = N'")
    assert PASSWORD not in shlex.join(restore.argv)

    with pytest.raises(engines.OpsError):
        engines.mssql_restore_command(mssql_target(), tmp_path / "db.bak", "itsm_prod")


def test_sqlite_dump_paths_are_never_engine_commands(tmp_path: Path) -> None:
    with pytest.raises(engines.OpsError):
        engines.postgres_backup_command(sqlite_target(tmp_path), tmp_path / "db.dump")


def test_render_command_redacts_known_secret_values() -> None:
    rendered = engines.render_command(
        ("psql", f"postgresql://itsm:{PASSWORD}@db.internal/itsm_prod"), secrets=(PASSWORD,)
    )

    assert PASSWORD not in rendered
    assert "[redacted]" in rendered


def test_artifact_format_is_reported_per_engine(tmp_path: Path) -> None:
    assert engines.dump_filename("sqlite") == "database.db"
    assert engines.dump_filename("postgresql") == "database.dump"
    assert engines.dump_filename("mysql") == "database.sql"
    assert engines.dump_filename("mssql") == "database.bak"
    with pytest.raises(engines.OpsError):
        engines.dump_filename("oracle")


def test_postgres_replace_live_restore_cleans_the_target_first(tmp_path: Path) -> None:
    command = engines.postgres_restore_command(
        postgres_target(), tmp_path / "db.dump", "itsm_prod", replace_live=True
    )

    assert "--clean" in command.argv
    assert "--if-exists" in command.argv
    assert PASSWORD not in shlex.join(command.argv)
