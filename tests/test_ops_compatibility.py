"""PostgreSQL client/server major compatibility for archives (R4-F1).

A ``pg_dump --format=custom`` archive is not a portable interchange format across
client majors. On this host ``pg_dump`` 18 writes an archive whose header a
``pg_restore`` 16 refuses (``unsupported version (1.16) in file header``), and a
``pg_restore`` 18 fails while restoring a 16 archive because it issues a session
GUC the 16 server does not know (``unrecognized configuration parameter
"transaction_timeout"``). Verification used to run only ``pg_restore --list``,
which succeeds without a server and therefore certified an unrestorable backup.

These checks are pure: the recorded majors travel in the artifact manifest and a
mismatch is refused before any tool runs or any connection is opened.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from itsm.config import Settings, settings_for
from itsm.ops import engines, service
from itsm.ops.service import OpsContext, RestoreRefused
from tests.test_ops_sqlite import payload, run_ops

PG_URL = "postgresql+psycopg://itsm:ops-secret@127.0.0.1:1/itsm"
ARTIFACT_ID = "postgresql-20261031T120000000000Z-abc123"


def postgres_context(tmp_path: Path) -> OpsContext:
    settings: Settings = settings_for(database_url=PG_URL)
    return OpsContext(settings=settings, backup_root=tmp_path / "backups")


def write_postgres_artifact(
    backup_root: Path,
    *,
    client_major: int | None,
    server_major: int | None,
    dump: bytes = b"PGDMP not a real archive",
) -> str:
    """Write an artifact whose manifest records the majors, without any server."""
    directory = backup_root / ARTIFACT_ID
    directory.mkdir(parents=True)
    dump_path = directory / "database.dump"
    dump_path.write_bytes(dump)
    dump_path.chmod(0o600)
    version_info: dict[str, object] = {
        "client": f"pg_dump (PostgreSQL) {client_major}.0" if client_major else None,
        "clientMajor": client_major,
        "server": f"{server_major}.13" if server_major else None,
        "serverMajor": server_major,
    }
    manifest = {
        "id": ARTIFACT_ID,
        "engine": "postgresql",
        "createdAt": "2026-10-31T12:00:00+00:00",
        "database": "postgresql://itsm@127.0.0.1:1/itsm",
        "alembicRevision": "0036_entity_change_events",
        "appVersion": "0.1.0",
        "sha256": hashlib.sha256(dump).hexdigest(),
        "size": len(dump),
        "format": "postgresql",
        "dumpFile": "database.dump",
        "toolVersions": {"pg_dump": version_info["client"] or "unavailable"},
        "versionInfo": version_info,
        "extensions": [],
        "attachments": [],
    }
    (directory / "manifest.json").write_text(json.dumps(manifest))
    return ARTIFACT_ID


def installed_pg_restore_major() -> int | None:
    version = service._tool_version(("pg_restore", "--version"))
    return engines.version_major(version)


def test_version_major_reads_tool_and_server_text() -> None:
    assert engines.version_major("pg_dump (PostgreSQL) 18.6") == 18
    assert engines.version_major("pg_restore (PostgreSQL) 16.13 (Ubuntu 16.13-1)") == 16
    assert engines.version_major("16.13") == 16
    assert engines.version_major("unavailable") is None
    assert engines.version_major(None) is None


def test_compatibility_requires_equal_client_and_server_majors() -> None:
    mismatch = engines.postgres_major_mismatch(18, 16)

    assert mismatch is not None
    assert "18" in mismatch
    assert "16" in mismatch
    assert "client" in mismatch
    assert engines.postgres_major_mismatch(16, 16) is None


def test_compatibility_reports_an_unknown_major_as_actionable() -> None:
    unknown_server = engines.postgres_major_mismatch(16, None)
    unknown_client = engines.postgres_major_mismatch(None, 16)

    assert unknown_server is not None and "server major" in unknown_server
    assert unknown_client is not None and "client major" in unknown_client
    assert "backup" in unknown_server


def test_verify_refuses_an_archive_from_a_mismatched_client_major(tmp_path: Path) -> None:
    context = postgres_context(tmp_path)
    identifier = write_postgres_artifact(context.backup_root, client_major=18, server_major=16)

    result = service.verify(context, identifier)

    assert result["verified"] is False
    assert result["checks"]["integrity"] == "incompatible"
    assert result["compatibility"]["clientMajor"] == 18
    assert result["compatibility"]["serverMajor"] == 16
    assert "client major 18" in result["error"]
    assert "server major 16" in result["error"]
    assert "pg_restore" not in result["error"] or "install" in result["error"]


def test_verify_refuses_an_archive_the_installed_client_major_cannot_restore(
    tmp_path: Path,
) -> None:
    installed = installed_pg_restore_major()
    other_major = 17 if installed != 17 else 18
    context = postgres_context(tmp_path)
    identifier = write_postgres_artifact(
        context.backup_root, client_major=other_major, server_major=other_major
    )

    result = service.verify(context, identifier)

    assert result["verified"] is False
    assert result["checks"]["integrity"] == "incompatible"
    assert "install" in result["error"].lower()
    assert str(other_major) in result["error"]


def test_verify_refuses_when_a_trial_restore_cannot_run(tmp_path: Path) -> None:
    installed = installed_pg_restore_major()
    if installed is None:  # pragma: no cover - depends on the host
        pytest.skip("pg_restore is not installed: trial-restore refusal already covered")
    context = postgres_context(tmp_path)
    identifier = write_postgres_artifact(
        context.backup_root, client_major=installed, server_major=installed
    )

    result = service.verify(context, identifier)

    assert result["verified"] is False
    assert result["checks"]["integrity"] == "unavailable"
    assert result["trialRestore"]["status"] == "unavailable"
    assert "trial restore" in result["error"]
    assert "cannot prove" in result["error"] or "not reachable" in result["error"]


def test_restore_refuses_a_mismatched_archive_with_an_actionable_message(
    tmp_path: Path,
) -> None:
    context = postgres_context(tmp_path)
    identifier = write_postgres_artifact(context.backup_root, client_major=18, server_major=16)
    settings: Settings = settings_for(database_url=PG_URL)

    refused = run_ops(
        ["restore", identifier, "--target-database", "itsm_restore"], settings, context.backup_root
    )

    assert refused.returncode == 3, refused.stdout + refused.stderr
    error = payload(refused)["error"]
    assert "client major 18" in error
    assert "server major 16" in error


def test_restore_refusal_happens_before_the_tool_runs(tmp_path: Path) -> None:
    context = postgres_context(tmp_path)
    identifier = write_postgres_artifact(context.backup_root, client_major=18, server_major=16)
    calls: list[tuple[str, ...]] = []

    def fake_run(command, target, *, timeout=0):
        calls.append(tuple(command.argv))
        raise AssertionError(f"no tool may run for a refused restore: {command.argv}")

    original = service._run_tool
    service._run_tool = fake_run  # type: ignore[assignment]
    try:
        with pytest.raises(RestoreRefused):
            service.restore(context, identifier, target_database="itsm_restore")
    finally:
        service._run_tool = original  # type: ignore[assignment]

    assert calls == []
