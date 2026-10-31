"""Real sandboxed execution: escape probes, capability allowlist and idempotency.

Every probe is executed by the production runner in a separate process; the
assertions read only observable results plus the untouched core database and
source tree.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest
from itsm.extensions.host import (
    ExtensionHandlerFailed,
    ExtensionHostService,
    ExtensionIdempotencyConflict,
    ExtensionSandboxUnavailable,
    ExtensionStoreValidation,
    ExtensionValidationFailed,
)
from itsm.inventory.service import InventoryService
from sqlalchemy import text
from tests.conftest import BACKEND_ROOT
from tests.inventory_support import asset_values
from tests.test_extension_runtime_support import (  # noqa: F401 - fixtures
    env,
    MODULE_ID,
    build_package,
    core_fingerprint,
    probe_manifest,
    sqlite_master_fingerprint,
)

SOURCE_FILE = BACKEND_ROOT / "itsm" / "extensions" / "sandbox_escape_probe.txt"


def sandbox_host(env, **overrides: Any) -> ExtensionHostService:
    from itsm.extensions.sandbox import SandboxLimits

    limits = SandboxLimits(**overrides) if overrides else SandboxLimits()
    return ExtensionHostService(env.settings, env.factory, sandbox_limits=limits)


def core_database_path(env) -> Path:
    return Path(env.settings.database_url.split("sqlite:///", 1)[-1])


def core_counts(env) -> dict[str, int]:
    connection = sqlite3.connect(core_database_path(env))
    try:
        return {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("extension_collection_records", "extension_core_calls")
        }
    finally:
        connection.close()


def test_sandbox_denies_filesystem_escapes(env, tmp_path: Path) -> None:
    fingerprint = core_fingerprint(env.settings)
    master = sqlite_master_fingerprint(env.settings)
    env.install(build_package(probe_manifest()))
    secret = tmp_path / "secret.txt"
    secret.write_text("core secret value", encoding="utf-8")

    read_secret = env.invoke("probe_read", {"path": str(secret)})
    assert read_secret["allowed"] is False
    assert read_secret["errno"] in {1, 13}
    read_core = env.invoke("probe_read", {"path": str(core_database_path(env))})
    assert read_core["allowed"] is False
    write_source = env.invoke("probe_write", {"path": str(SOURCE_FILE)})
    assert write_source["allowed"] is False
    assert not SOURCE_FILE.exists()
    write_core = env.invoke("probe_write", {"path": str(core_database_path(env))})
    assert write_core["allowed"] is False
    assert secret.read_text(encoding="utf-8") == "core secret value"
    assert core_fingerprint(env.settings) == fingerprint
    assert sqlite_master_fingerprint(env.settings) == master


def test_sandbox_denies_network_processes_and_the_core_environment(env) -> None:
    env.install(build_package(probe_manifest()))
    network = env.invoke("probe_tcp", {"host": "127.0.0.1", "port": 9})
    assert network["allowed"] is False
    subprocess_probe = env.invoke("probe_subprocess", {})
    assert subprocess_probe["allowed"] is False
    system_probe = env.invoke("probe_system", {})
    assert system_probe["allowed"] is False
    environment = env.invoke("probe_environment", {})
    assert environment["itsm"] == []
    assert all(not name.startswith("ITSM_") for name in environment["names"])
    assert "ITSM_DATABASE_URL" not in environment["names"]
    assert len(environment["names"]) <= 4


def test_sandbox_enforces_memory_and_reports_closed_failures(env) -> None:
    env.install(build_package(probe_manifest()))
    memory = env.invoke("probe_memory", {})
    assert memory["allowed"] is False and memory["error"] == "MemoryError"


def test_sandbox_enforces_wall_timeout_and_kills_the_process(env) -> None:
    env.install(build_package(probe_manifest()))
    host = sandbox_host(env, wall_timeout_seconds=2.0, cpu_seconds=30)
    started = time.monotonic()
    with pytest.raises(ExtensionHandlerFailed):
        host.invoke(env.owner, MODULE_ID, "probe_spin", {})
    assert time.monotonic() - started < 20
    # The module store still works after a killed runaway process.
    assert host.invoke(env.owner, MODULE_ID, "echo", {"value": "after"})["value"] == "after"


def test_sandbox_enforces_capability_call_and_output_caps(env) -> None:
    env.install(build_package(probe_manifest()))
    with pytest.raises(ExtensionHandlerFailed):
        env.invoke("probe_many_calls", {})
    with pytest.raises(ExtensionHandlerFailed):
        env.invoke("probe_big_result", {})
    assert env.invoke("echo", {"value": "still alive"})["value"] == "still alive"


def test_capability_allowlist_is_enforced_per_manifest(env) -> None:
    env.install(build_package(probe_manifest(capabilities=["assets.read"])))
    with env.factory() as session:
        asset = InventoryService(session, env.settings).create(
            env.owner, asset_values(quick_code="EXT-READ-001", serial="EXT-READ-001")
        )
    granted = env.invoke("probe_asset_get", {"asset_id": asset.id})
    assert granted.get("denied") is not True, "declared assets.read must reach the service"
    assert granted["quickCode"] == "EXT-READ-001"
    notify = env.invoke("probe_notify_denied", {"recipient_ids": ["nobody"]})
    assert notify["denied"] is True
    assert "notify" in notify["error"]

    env.host.uninstall(env.owner, MODULE_ID, expected_version=1)
    env.install(build_package(probe_manifest(capabilities=[])))
    undeclared = env.invoke("probe_asset_get", {"asset_id": "00000000-0000-4000-8000-000000000000"})
    assert undeclared["denied"] is True
    assert "assets.read" in undeclared["error"]


def test_mutation_capabilities_require_idempotency_keys(env) -> None:
    env.install(build_package(probe_manifest(capabilities=["assets.write"])))
    values = asset_values(quick_code="EXT-IDEM-001", serial="EXT-IDEM-001")
    # A malformed idempotency key is a capability-contract violation, not a
    # generic handler crash: the closed capability error is surfaced verbatim.
    with pytest.raises(ExtensionValidationFailed, match="idempotencyKey"):
        env.invoke("probe_asset_create", {"values": values, "idempotency_key": ""})
    with pytest.raises(ExtensionValidationFailed, match="idempotencyKey"):
        env.invoke("probe_asset_create", {"values": values, "idempotency_key": "k" * 200})

    first = env.invoke("probe_asset_create", {"values": values, "idempotency_key": "create-1"})
    replay = env.invoke("probe_asset_create", {"values": values, "idempotency_key": "create-1"})
    assert first["id"] == replay["id"]
    changed = asset_values(quick_code="EXT-IDEM-002", serial="EXT-IDEM-002")
    with pytest.raises(ExtensionIdempotencyConflict):
        env.invoke("probe_asset_create", {"values": changed, "idempotency_key": "create-1"})
    with env.factory() as session:
        rows = session.execute(
            text("SELECT COUNT(*) FROM extension_core_calls WHERE extension_id = :id"),
            {"id": MODULE_ID},
        ).scalar_one()
        assets = session.execute(
            text("SELECT COUNT(*) FROM assets WHERE quick_code LIKE 'EXT-IDEM%'")
        ).scalar_one()
        stored = session.execute(
            text(
                "SELECT capability, request_hash, response_json FROM extension_core_calls "
                "WHERE extension_id = :id AND call_key = 'create-1'"
            ),
            {"id": MODULE_ID},
        ).one()
    assert rows == 1
    assert assets == 1
    assert stored[0] == "assets.create"
    assert json.loads(stored[2])["id"] == first["id"]
    assert len(stored[1]) == 64


def test_store_mutations_are_refused_from_read_only_operations(env) -> None:
    env.install(build_package(probe_manifest()))
    # Same closed error as a host-side store write: read-only operations cannot
    # mutate the module store, and the module sees the refusal verbatim.
    with pytest.raises(ExtensionStoreValidation, match="read-only"):
        env.invoke("read_only_write", {})


def test_context_db_is_the_module_file_only(env) -> None:
    env.install(build_package(probe_manifest()))
    result = env.invoke("probe_db_write", {"value": "own"})
    assert result["rows"] == 1
    connection = sqlite3.connect(env.database())
    try:
        assert connection.execute("SELECT value FROM own_table").fetchone()[0] == "own"
    finally:
        connection.close()
    core = sqlite3.connect(core_database_path(env))
    try:
        tables = {
            row[0] for row in core.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    finally:
        core.close()
    assert "own_table" not in tables
    assert core_counts(env)["extension_collection_records"] == 0


def test_sandbox_unavailable_fails_closed(env, monkeypatch) -> None:
    env.install(build_package(probe_manifest()))
    monkeypatch.setattr(
        "itsm.extensions.host.sandbox_availability",
        lambda: {"available": False, "landlockAbi": None, "arch": "test", "detail": "unsupported"},
    )
    with pytest.raises(ExtensionSandboxUnavailable):
        env.invoke("echo", {"value": "closed"})


def test_installed_module_package_is_never_written_by_the_sandbox(env) -> None:
    env.install(build_package(probe_manifest()))
    package_root = env.settings.extension_data_path / ".packages"
    files = sorted(path for path in package_root.rglob("*") if path.is_file())
    assert files
    for path in files:
        assert path.stat().st_mode & 0o777 in {0o400, 0o500}
    env.invoke("echo", {"value": "read only"})
    assert sorted(path for path in package_root.rglob("*") if path.is_file()) == files
