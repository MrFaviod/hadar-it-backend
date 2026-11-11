"""v2 per-module SQLite storage, snapshots, uninstall and legacy relocation.

Every assertion goes through the public host/CLI surface and inspects only the
module data file, the core schema fingerprint or the recorded HTTP contract.
"""

# ruff: noqa: F811 - the `env` fixture is imported and also named in signatures.

from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
import sys
from datetime import UTC
from datetime import datetime as dt
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from itsm.extensions.host import (
    ExtensionHandlerFailed,
    ExtensionHostService,
    ExtensionMigrationFailed,
    ExtensionNotFound,
    ExtensionRequiresUpgrade,
    ExtensionRollbackIncompatible,
    ExtensionStale,
    ExtensionStoreConflict,
    ExtensionStoreValidation,
    ExtensionValidationFailed,
)
from itsm.identity.service import IdentityService
from sqlalchemy import text
from tests.conftest import BACKEND_ROOT
from tests.inventory_support import asset_values
from tests.test_extension_runtime_support import (  # noqa: F401 - fixtures
    DECLARATIVE_ID,
    MODULE_ID,
    PROBE_BACKEND,
    build_package,
    core_fingerprint,
    declarative_manifest,
    digest,
    env,
    insert_legacy_rows,
    legacy_rows,
    probe_manifest,
    sqlite_master_fingerprint,
    v1_package,
)

MIGRATION_HANDLERS = """
def normalize(context):
    for item in context.store.list("records", 200, 0, None)["items"]:
        value = dict(item["data"])
        value["status"] = "active"
        context.store.put("records", item["id"], value, item["version"])


def broken(context):
    context.store.put("records", "half-migrated", {"label": "half"})
    raise ValueError("migration exploded")
"""


def migration_backend(handler: str = "normalize") -> str:
    source = PROBE_BACKEND + MIGRATION_HANDLERS
    return source.replace(
        '    sdk.operation("echo", echo)',
        f'    sdk.migration("{handler}", {handler})\n    sdk.operation("echo", echo)',
    )


def module_sqlite(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def module_rows(path: Path) -> list[sqlite3.Row]:
    connection = module_sqlite(path)
    try:
        return list(
            connection.execute(
                "SELECT collection, record_id, version, data FROM _itsm_records ORDER BY record_id"
            )
        )
    finally:
        connection.close()


def user_version(path: Path) -> int:
    connection = module_sqlite(path)
    try:
        return int(connection.execute("PRAGMA user_version").fetchone()[0])
    finally:
        connection.close()


def stored_schema_version(env: Any, extension_id: str = MODULE_ID) -> int:
    with env.factory() as session:
        row = session.execute(
            text("SELECT data_schema_version FROM extension_modules WHERE id = :id"),
            {"id": extension_id},
        ).one_or_none()
    assert row is not None
    return int(row[0])


def test_install_prepares_private_module_storage(env) -> None:
    env.install(build_package(probe_manifest()))
    storage = env.storage()
    database = env.database()
    assert storage.is_dir() and database.is_file()
    assert stat.S_IMODE(storage.stat().st_mode) == 0o700
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    connection = module_sqlite(database)
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "_itsm_records" in tables
    finally:
        connection.close()
    assert user_version(database) == 1
    assert stored_schema_version(env) == 1
    assert legacy_rows(env.settings) == []
    status = env.host.status(env.owner, MODULE_ID)
    assert status["status"] == "ready"
    assert status["schemaVersion"] == 1
    assert status["dataSizeBytes"] >= 0
    assert status["snapshots"] == []
    assert status["sandbox"]["available"] is True


def test_store_semantics_stay_identical_on_the_module_file(env) -> None:
    fingerprint = core_fingerprint(env.settings)
    master = sqlite_master_fingerprint(env.settings)
    env.install(build_package(probe_manifest()))
    created = env.invoke("put_record", {"record_id": "one", "label": "Uno"})
    assert created == {"id": "one", "version": 1, "data": {"label": "Uno"}}
    env.invoke("put_record", {"record_id": "two", "label": "Uno"})
    env.invoke("put_record", {"record_id": "three", "label": "Otro"})
    listed = env.invoke("list_records", {"limit": 2, "offset": 0})
    assert [item["id"] for item in listed["items"]] == ["one", "three"] or [
        item["id"] for item in listed["items"]
    ] == ["one", "two"]
    assert listed["total"] == 3
    filtered = env.invoke("list_records", {"filters": {"label": "Uno"}})
    assert {item["id"] for item in filtered["items"]} == {"one", "two"}
    assert env.invoke("get_record", {"record_id": "missing"}) is None
    with pytest.raises(ExtensionStoreConflict):
        env.invoke("put_record", {"record_id": "one", "label": "Wrong", "expected_version": 9})
    with pytest.raises(ExtensionStoreValidation):
        env.invoke("put_record", {"record_id": "x" * 65, "label": "Too long id"})
    assert env.invoke("delete_record", {"record_id": "one", "expected_version": 1}) == {
        "deleted": True
    }
    assert [row["record_id"] for row in module_rows(env.database())] == ["three", "two"]
    assert legacy_rows(env.settings) == []
    assert core_fingerprint(env.settings) == fingerprint
    assert sqlite_master_fingerprint(env.settings) == master


def test_failed_handler_rolls_back_module_transaction(env) -> None:
    env.install(build_package(probe_manifest()))
    env.invoke("put_record", {"record_id": "kept", "label": "Keep"})
    with pytest.raises(ExtensionHandlerFailed, match=r"^extension operation failed$"):
        env.invoke("fail_after_write")
    assert [row["record_id"] for row in module_rows(env.database())] == ["kept"]
    with pytest.raises(ExtensionStoreValidation, match="read-only"):
        env.invoke("read_only_write")
    assert [row["record_id"] for row in module_rows(env.database())] == ["kept"]


def test_upgrade_snapshots_data_and_mirrors_the_schema_version(env) -> None:
    first = build_package(probe_manifest("1.0.0", schema=1))
    env.install(first)
    env.invoke("put_record", {"record_id": "one", "label": "Uno"})
    assert env.host.discovery(env.owner)["items"][0]["revision"] == 1

    second_declaration = probe_manifest("1.1.0", schema=2)
    second_declaration["migrations"] = [{"from": 1, "to": 2, "handler": "normalize"}]
    second = build_package(second_declaration, backend=migration_backend())
    env.install(second)

    snapshot = env.storage() / "snapshots" / "1.sqlite3"
    assert snapshot.is_file()
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600
    assert stat.S_IMODE(snapshot.parent.stat().st_mode) == 0o700
    snapshot_rows = module_rows(snapshot)
    assert [(row["record_id"], row["version"]) for row in snapshot_rows] == [("one", 1)]
    assert json.loads(snapshot_rows[0]["data"]) == {"label": "Uno"}
    assert user_version(env.database()) == 2
    assert stored_schema_version(env) == 2
    migrated = module_rows(env.database())
    assert json.loads(migrated[0]["data"]) == {"label": "Uno", "status": "active"}


def test_failed_migration_restores_the_snapshot_and_previous_version(env) -> None:
    env.install(build_package(probe_manifest("1.0.0", schema=1)))
    env.invoke("put_record", {"record_id": "one", "label": "Uno"})
    second_declaration = probe_manifest("1.1.0", schema=2)
    second_declaration["migrations"] = [{"from": 1, "to": 2, "handler": "normalize"}]
    env.install(build_package(second_declaration, backend=migration_backend()))
    after_upgrade = module_rows(env.database())
    revision = env.host.discovery(env.owner)["items"][0]["revision"]

    broken_declaration = probe_manifest("1.2.0", schema=3)
    broken_declaration["compatibleSchemaVersions"] = [2, 3]
    broken_declaration["migrations"] = [{"from": 2, "to": 3, "handler": "broken"}]
    with pytest.raises(ExtensionMigrationFailed):
        env.install(build_package(broken_declaration, backend=migration_backend("broken")))

    assert [dict(row) for row in module_rows(env.database())] == [
        dict(row) for row in after_upgrade
    ]
    assert user_version(env.database()) == 2
    assert stored_schema_version(env) == 2
    item = env.host.discovery(env.owner)["items"][0]
    assert item["version"] == "1.1.0" and item["revision"] == revision
    status = env.host.status(env.owner, MODULE_ID)
    assert status["status"] == "ready" and status["schemaVersion"] == 2


def test_rollback_with_incompatible_schema_requires_confirmed_data_restore(env) -> None:
    first_declaration = probe_manifest("1.0.0", schema=1)
    first = build_package(first_declaration)
    env.install(first)
    env.invoke("put_record", {"record_id": "one", "label": "Uno"})
    second_declaration = probe_manifest("1.1.0", schema=2)
    second_declaration["migrations"] = [{"from": 1, "to": 2, "handler": "normalize"}]
    env.install(build_package(second_declaration, backend=migration_backend()))
    revision = env.host.discovery(env.owner)["items"][0]["revision"]

    with pytest.raises(ExtensionRollbackIncompatible):
        env.host.rollback(
            env.owner,
            MODULE_ID,
            version="1.0.0",
            digest=digest(first),
            expected_version=revision,
        )
    with pytest.raises(ExtensionValidationFailed):
        env.host.rollback(
            env.owner,
            MODULE_ID,
            version="1.0.0",
            digest=digest(first),
            expected_version=revision,
            restore_data=True,
        )
    with pytest.raises(ExtensionValidationFailed):
        env.host.rollback(
            env.owner,
            MODULE_ID,
            version="1.0.0",
            digest=digest(first),
            expected_version=revision,
            restore_data=True,
            confirm="other-module",
        )

    rolled = env.host.rollback(
        env.owner,
        MODULE_ID,
        version="1.0.0",
        digest=digest(first),
        expected_version=revision,
        restore_data=True,
        confirm=MODULE_ID,
    )
    assert rolled["version"] == "1.0.0"
    assert user_version(env.database()) == 1
    assert stored_schema_version(env) == 1
    assert json.loads(module_rows(env.database())[0]["data"]) == {"label": "Uno"}


def test_uninstall_keeps_module_data_and_revokes_extension_grants(env) -> None:
    fingerprint = core_fingerprint(env.settings)
    env.install(build_package(probe_manifest()))
    env.invoke("put_record", {"record_id": "keep", "label": "Keep"})
    with env.factory() as session:
        assert "ext_probe.read" in IdentityService(session, env.settings).effective_permissions(
            env.owner
        )
    with pytest.raises(ExtensionStale):
        env.host.uninstall(env.owner, MODULE_ID, expected_version=99)

    result = env.host.uninstall(env.owner, MODULE_ID, expected_version=1)
    assert result["uninstalled"] is True
    assert result["dataRetained"] is True
    assert Path(result["dataPath"]) == env.storage()
    assert env.database().is_file()
    assert module_rows(env.database())[0]["record_id"] == "keep"
    with env.factory() as session:
        assert "ext_probe.read" not in IdentityService(session, env.settings).effective_permissions(
            env.owner
        )
        remaining = session.execute(
            text("SELECT COUNT(*) FROM extension_permissions WHERE extension_id = :id"),
            {"id": MODULE_ID},
        ).scalar_one()
        assert remaining == 0
    assert env.host.discovery(env.owner)["items"] == []
    with pytest.raises(ExtensionNotFound):
        env.host.invoke(env.owner, MODULE_ID, "echo", {"value": "after uninstall"})
    assert core_fingerprint(env.settings) == fingerprint


def test_declarative_module_runs_host_side_without_module_code(env, tmp_path: Path) -> None:
    env.install(build_package(declarative_manifest(), backend=None))
    assert not (env.storage(DECLARATIVE_ID) / "backend.py").exists()
    created = env.invoke(
        "put_note",
        {"data": {"label": "Primera"}},
        extension_id=DECLARATIVE_ID,
    )
    assert created["version"] == 1 and created["data"] == {"label": "Primera"}
    assert UUID(created["id"]).version == 4
    with pytest.raises(ExtensionStoreValidation):
        env.invoke(
            "put_note",
            {"data": {"label": "Sin estado válido", "status": "unknown"}},
            extension_id=DECLARATIVE_ID,
        )
    with pytest.raises(ExtensionStoreValidation):
        env.invoke("put_note", {"data": {"status": "active"}}, extension_id=DECLARATIVE_ID)
    with pytest.raises(ExtensionStoreValidation):
        env.invoke(
            "put_note",
            {"data": {"label": "Extra", "unexpected": True}},
            extension_id=DECLARATIVE_ID,
        )
    updated = env.invoke(
        "put_note",
        {"record_id": created["id"], "data": {"label": "Segunda"}, "expected_version": 1},
        extension_id=DECLARATIVE_ID,
    )
    assert updated["version"] == 2
    with pytest.raises(ExtensionStoreConflict):
        env.invoke(
            "put_note",
            {"record_id": created["id"], "data": {"label": "Tercera"}, "expected_version": 1},
            extension_id=DECLARATIVE_ID,
        )
    listed = env.invoke(
        "list_notes", {"filters": {"label": "Segunda"}}, extension_id=DECLARATIVE_ID
    )
    assert listed["total"] == 1 and listed["items"][0]["id"] == created["id"]
    with pytest.raises(ExtensionStoreValidation):
        env.invoke("list_notes", {"filters": {"unknown": "x"}}, extension_id=DECLARATIVE_ID)
    assert (
        env.invoke("get_note", {"record_id": created["id"]}, extension_id=DECLARATIVE_ID) == updated
    )
    assert env.invoke(
        "delete_note",
        {"record_id": created["id"], "expected_version": 2},
        extension_id=DECLARATIVE_ID,
    ) == {"deleted": True}
    assert env.invoke("list_notes", {}, extension_id=DECLARATIVE_ID)["total"] == 0


def seed_installed_v1_module(env, marker: Path) -> None:
    """Reproduce the rows a v1 installation left behind, without running v1 code."""
    package = v1_package(marker=marker)
    manifest = json.loads(
        __import__("zipfile").ZipFile(__import__("io").BytesIO(package)).read("extension.json")
    )
    from itsm.extensions.manifest import digest_bytes

    package_digest = digest_bytes(package)
    with env.factory() as session:
        session.execute(
            text(
                "INSERT INTO extension_modules "
                "(id, name, description, enabled, active_version, data_schema_version, revision, "
                "created_at, updated_at) "
                "VALUES (:id, :name, :description, 1, '0.9.0', 1, 1, :now, :now)"
            ),
            {
                "id": "legacy-book",
                "name": manifest["name"],
                "description": manifest["description"],
                "now": "2026-10-01T00:00:00+00:00",
            },
        )
        session.execute(
            text(
                "INSERT INTO extension_versions "
                "(extension_id, version, digest, manifest_json, package_bytes, schema_version, "
                "installed_by, installed_at) "
                "VALUES (:id, '0.9.0', :digest, :manifest, :bytes, 1, :actor, :now)"
            ),
            {
                "id": "legacy-book",
                "digest": package_digest,
                "manifest": json.dumps(manifest),
                "bytes": package,
                "actor": env.owner.actor_id,
                "now": "2026-10-01T00:00:00+00:00",
            },
        )
        session.execute(
            text(
                "INSERT INTO extension_permissions "
                "(extension_id, code, label, description, created_at) "
                "VALUES ('legacy-book', 'ext_legacy_book.read', 'Consultar', 'Consulta', :now)"
            ),
            {"now": "2026-10-01T00:00:00+00:00"},
        )
        session.commit()


def cli_environment(env) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    environment.update(
        {
            "PYTHONPATH": str(BACKEND_ROOT),
            "PYTHONUNBUFFERED": "1",
            "ITSM_DATABASE_URL": env.settings.database_url,
            "ITSM_EXTENSION_DATA_PATH": str(env.settings.extension_data_path),
            "ITSM_ENVIRONMENT": "test",
        }
    )
    return environment


def run_relocate(env, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "itsm.extensions", "relocate-legacy", *arguments],
        capture_output=True,
        text=True,
        cwd=BACKEND_ROOT,
        env=cli_environment(env),
        timeout=120,
        check=False,
    )


def test_installed_v1_module_requires_upgrade_and_never_executes(env, tmp_path: Path) -> None:
    marker = tmp_path / "legacy-executed"
    seed_installed_v1_module(env, marker)
    items = env.host.discovery(env.owner)["items"]
    assert [item["id"] for item in items] == ["legacy-book"]
    assert items[0]["status"] == "requires_upgrade"
    with pytest.raises(ExtensionRequiresUpgrade, match="relocate-legacy"):
        env.host.invoke(env.owner, "legacy-book", "read_records", {})
    assert not marker.exists()
    assert list(env.host.list_schedules()) == []
    status = env.host.status(env.owner, "legacy-book")
    assert status["status"] == "requires_upgrade"


def test_relocate_legacy_copies_rows_idempotently_and_keeps_legacy_rows(
    env, tmp_path: Path
) -> None:
    marker = tmp_path / "legacy-executed"
    seed_installed_v1_module(env, marker)
    insert_legacy_rows(
        env.settings,
        [
            ("legacy-book", "records", "alpha", 1, {"label": "Alfa"}),
            ("legacy-book", "records", "beta", 3, {"label": "Beta"}),
            ("legacy-book", "records", "conflict", 2, {"label": "Legacy"}),
        ],
    )
    legacy_before = legacy_rows(env.settings)

    dry = run_relocate(env)
    assert dry.returncode == 0, dry.stdout + dry.stderr
    plan = json.loads(dry.stdout)
    assert plan["apply"] is False
    assert plan["extensions"][0]["extensionId"] == "legacy-book"
    assert plan["extensions"][0]["copied"] == 3
    assert not env.database("legacy-book").exists()
    assert legacy_rows(env.settings) == legacy_before

    # A pre-existing module row with different data must never be overwritten.
    env.storage("legacy-book").mkdir(parents=True)
    connection = module_sqlite(env.database("legacy-book"))
    try:
        connection.execute(
            "CREATE TABLE _itsm_records (collection TEXT NOT NULL, record_id TEXT NOT NULL, "
            "version INTEGER NOT NULL, data TEXT NOT NULL, created_at TEXT NOT NULL, "
            "updated_at TEXT NOT NULL, PRIMARY KEY (collection, record_id))"
        )
        connection.execute(
            "INSERT INTO _itsm_records VALUES ('records', 'conflict', 5, :data, :now, :now)",
            {"data": json.dumps({"label": "Module"}), "now": dt.now(UTC).isoformat()},
        )
        connection.commit()
    finally:
        connection.close()

    applied = run_relocate(env, "--apply")
    assert applied.returncode == 0, applied.stdout + applied.stderr
    report = json.loads(applied.stdout)
    assert report["apply"] is True
    summary = report["extensions"][0]
    assert summary["copied"] == 2
    assert summary["conflicts"] == 1
    rows = {row["record_id"]: row for row in module_rows(env.database("legacy-book"))}
    assert rows["alpha"]["version"] == 1
    assert json.loads(rows["alpha"]["data"]) == {"label": "Alfa"}
    assert rows["beta"]["version"] == 3
    assert json.loads(rows["conflict"]["data"]) == {"label": "Module"}
    assert legacy_rows(env.settings) == legacy_before
    assert not marker.exists()

    second = run_relocate(env, "--apply")
    assert second.returncode == 0
    assert json.loads(second.stdout)["extensions"][0]["unchanged"] == 2
    assert len(module_rows(env.database("legacy-book"))) == 3
    assert legacy_rows(env.settings) == legacy_before


def test_new_v1_candidate_is_rejected_with_an_actionable_error(env) -> None:
    marker = Path("/nonexistent/legacy")
    with pytest.raises(ExtensionValidationFailed) as failure:
        env.candidate(v1_package(marker=marker))
    message = str(failure.value).lower()
    assert "sdkversion" in message and "2" in message
    assert "relocate-legacy" in message
    assert env.host.list_candidates(env.owner)["items"] == []


def test_status_reports_storage_and_restarts_see_the_same_data(env) -> None:
    env.install(build_package(probe_manifest()))
    env.invoke("put_record", {"record_id": "one", "label": "Uno"})
    restarted = ExtensionHostService(env.settings, env.factory)
    assert restarted.invoke(env.owner, MODULE_ID, "get_record", {"record_id": "one"}) == {
        "id": "one",
        "version": 1,
        "data": {"label": "Uno"},
    }
    status = restarted.status(env.owner, MODULE_ID)
    assert status["storagePath"] == str(env.storage())
    assert status["dataSizeBytes"] > 0
    assert status["eventCursor"] == 0
    assert status["events"]["cursor"] == 0 and status["events"]["stalled"] is False
    assert status["stalled"] is False


def test_asset_capability_writes_reach_the_canonical_service(env) -> None:
    declaration = probe_manifest(capabilities=["assets.write"])
    env.install(build_package(declaration))
    values = asset_values(quick_code="EXT-CAP-001", serial="EXT-CAP-001")
    first = env.invoke(
        "probe_asset_create",
        {"values": values, "idempotency_key": "create-1"},
    )
    assert first["quickCode"] == "EXT-CAP-001"
