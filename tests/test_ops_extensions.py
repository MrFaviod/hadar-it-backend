"""Extension data files inside the ops artifact: backup, verify, restore.

Every check drives the real ``python -m itsm.ops`` process against an isolated
SQLite core database and an isolated extension data root, so the artifact
layout, manifest, permissions and exit codes are the ones an operator sees.

The module data file is deliberately left in WAL mode with uncheckpointed
writes: a byte copy of ``data.sqlite3`` would silently lose them, which is why
the backup path must use the SQLite online backup API (S6/D3/D8).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
from collections.abc import Callable
from pathlib import Path

from itsm.config import Settings
from tests.test_ops_sqlite import migrated, payload, run_ops

EXTENSION_ID = "software-license"


def entry(path: Path, relative: str) -> dict:
    """Manifest file entry for one file, computed from the bytes on disk."""
    return {
        "path": relative,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": path.stat().st_size,
    }


def archived_file(directory: Path, relative: str) -> Path:
    return directory / "extensions" / EXTENSION_ID / relative


def run_ext_ops(
    args: list[str],
    settings: Settings,
    *,
    backup_root: Path,
    data_root: Path,
    timeout: float = 180.0,
) -> subprocess.CompletedProcess[str]:
    return run_ops(
        args,
        settings,
        backup_root,
        extra_env={"ITSM_EXTENSION_DATA_PATH": str(data_root)},
        timeout=timeout,
    )


def create_module(data_root: Path, extension_id: str = EXTENSION_ID) -> Path:
    module = data_root / extension_id
    module.mkdir(parents=True)
    module.chmod(0o700)
    (module / "files").mkdir()
    (module / "snapshots").mkdir()
    return module


def write_licenses(path: Path, values: list[str]) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE licenses (id INTEGER PRIMARY KEY, key TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO licenses (key) VALUES (?)", [(value,) for value in values]
        )
        connection.commit()
    finally:
        connection.close()


def open_wal_module(module: Path, values: list[str]) -> sqlite3.Connection:
    """Open the module database in WAL mode and keep uncheckpointed writes alive."""
    connection = sqlite3.connect(module / "data.sqlite3")
    connection.execute("PRAGMA journal_mode=WAL").fetchone()
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE licenses (id INTEGER PRIMARY KEY, key TEXT NOT NULL)")
    connection.executemany("INSERT INTO licenses (key) VALUES (?)", [(value,) for value in values])
    connection.commit()
    return connection


def backup_artifact(
    settings: Settings, backup_root: Path, data_root: Path
) -> tuple[dict, Path, dict]:
    created = run_ext_ops(["backup"], settings, backup_root=backup_root, data_root=data_root)
    assert created.returncode == 0, created.stdout + created.stderr
    created_json = payload(created)
    directory = Path(created_json["path"])
    manifest = json.loads((directory / "manifest.json").read_text())
    return created_json, directory, manifest


def restore(
    backup_id: str,
    settings: Settings,
    *,
    backup_root: Path,
    data_root: Path,
    target: Path,
    extra: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return run_ext_ops(
        [
            "restore",
            backup_id,
            "--target-extensions",
            str(target),
            *(extra or []),
        ],
        settings,
        backup_root=backup_root,
        data_root=data_root,
    )


def test_backup_snapshots_a_wal_module_database_with_uncheckpointed_writes(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    data_root = tmp_path / "extensions"
    module = create_module(data_root)
    connection = open_wal_module(module, ["LIC-1", "LIC-2", "LIC-3"])
    try:
        assert Path(f"{module / 'data.sqlite3'}-wal").stat().st_size > 0

        created_json, directory, manifest = backup_artifact(settings, backup_root, data_root)

        copied = archived_file(directory, "data.sqlite3")
        assert manifest["extensions"] == [
            {"id": EXTENSION_ID, "files": [entry(copied, "data.sqlite3")]}
        ]
        assert created_json["backup"]["extensions"] == manifest["extensions"]
        assert (copied.stat().st_mode & 0o777) == 0o600
        assert (copied.parent.stat().st_mode & 0o777) == 0o700
        assert (copied.parent.parent.stat().st_mode & 0o777) == 0o700
        restored_connection = sqlite3.connect(copied)
        try:
            keys = [row[0] for row in restored_connection.execute("SELECT key FROM licenses")]
            assert keys == ["LIC-1", "LIC-2", "LIC-3"]
            # A consistent copy, not a WAL-sidecar dependency.
            assert restored_connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
            assert restored_connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        finally:
            restored_connection.close()
        assert not (copied.parent / "data.sqlite3-wal").exists()
    finally:
        connection.close()


def test_backup_includes_snapshots_and_module_files(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    data_root = tmp_path / "extensions"
    module = create_module(data_root)
    write_licenses(module / "data.sqlite3", ["LIC-1"])
    write_licenses(module / "snapshots" / "1.sqlite3", ["LIC-1"])
    (module / "files" / "uploads").mkdir()
    (module / "files" / "notes.txt").write_text("module-owned file\n")
    (module / "files" / "uploads" / "license.pdf").write_bytes(b"%PDF-1.4 evidence")

    _created, directory, manifest = backup_artifact(settings, backup_root, data_root)

    assert manifest["extensions"] == [
        {
            "id": EXTENSION_ID,
            "files": [
                entry(archived_file(directory, "data.sqlite3"), "data.sqlite3"),
                entry(module / "files" / "notes.txt", "files/notes.txt"),
                entry(module / "files" / "uploads" / "license.pdf", "files/uploads/license.pdf"),
                entry(archived_file(directory, "snapshots/1.sqlite3"), "snapshots/1.sqlite3"),
            ],
        }
    ]
    archived = directory / "extensions" / EXTENSION_ID
    assert (archived / "files" / "uploads").stat().st_mode & 0o777 == 0o700
    assert (archived / "files" / "notes.txt").stat().st_mode & 0o777 == 0o600


def test_backup_without_an_extension_root_reports_an_empty_list(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    data_root = tmp_path / "missing-extensions"

    created_json, directory, manifest = backup_artifact(settings, backup_root, data_root)

    assert manifest["extensions"] == []
    assert created_json["backup"]["extensions"] == []
    assert not (directory / "extensions").exists()
    verified = run_ext_ops(
        ["verify", manifest["id"]], settings, backup_root=backup_root, data_root=data_root
    )
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert payload(verified)["extensions"] == []


def test_backup_ignores_symlinks_and_unexpected_names_without_following_them(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    data_root = tmp_path / "extensions"
    module = create_module(data_root)
    write_licenses(module / "data.sqlite3", ["LIC-1"])
    (module / "files" / "notes.txt").write_text("kept\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("SECRET-OPERATOR-TOKEN\n")
    (module / "files" / "leak.txt").symlink_to(outside / "secret.txt")
    (module / "files" / "linked-dir").symlink_to(outside, target_is_directory=True)
    (data_root / "linked-module").symlink_to(outside, target_is_directory=True)
    (data_root / "Bad_Name").mkdir()
    (data_root / "Bad_Name" / "data.sqlite3").write_bytes(b"not part of the contract")
    (data_root / "stray-file.txt").write_text("not a module\n")

    created_json, directory, _manifest = backup_artifact(settings, backup_root, data_root)

    archived = directory / "extensions" / EXTENSION_ID
    assert sorted(
        str(path.relative_to(archived)) for path in archived.rglob("*") if path.is_file()
    ) == ["data.sqlite3", "files/notes.txt"]
    assert not (archived / "files" / "leak.txt").exists()
    assert not (archived / "files" / "linked-dir").exists()
    assert not (directory / "extensions" / "linked-module").exists()
    assert not (directory / "extensions" / "Bad_Name").exists()
    ignored = created_json["backup"]["ignoredExtensions"]
    assert any("linked-module" in note for note in ignored)
    assert any("Bad_Name" in note for note in ignored)
    assert any("leak.txt" in note for note in ignored)
    assert any("stray-file.txt" in note for note in ignored)
    for path in directory.rglob("*"):
        assert not path.is_symlink()
    assert b"SECRET-OPERATOR-TOKEN" not in b"".join(
        path.read_bytes() for path in directory.rglob("*") if path.is_file()
    )


def test_verify_accepts_extension_files_and_reports_per_extension_status(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    data_root = tmp_path / "extensions"
    module = create_module(data_root)
    write_licenses(module / "data.sqlite3", ["LIC-1"])
    write_licenses(module / "snapshots" / "1.sqlite3", ["LIC-1"])
    (module / "files" / "notes.txt").write_text("kept\n")
    _created, _directory, manifest = backup_artifact(settings, backup_root, data_root)

    verified = run_ext_ops(
        ["verify", manifest["id"]], settings, backup_root=backup_root, data_root=data_root
    )

    assert verified.returncode == 0, verified.stdout + verified.stderr
    checked = payload(verified)
    assert checked["verified"] is True
    assert checked["checks"] == {"checksum": True, "size": True, "integrity": "ok"}
    assert checked["extensions"] == [
        {
            "id": EXTENSION_ID,
            "status": "ok",
            "checksum": True,
            "size": True,
            "integrity": "ok",
            "files": [
                {"path": "data.sqlite3", "checksum": True, "size": True, "integrity": "ok"},
                {"path": "files/notes.txt", "checksum": True, "size": True, "integrity": "skipped"},
                {"path": "snapshots/1.sqlite3", "checksum": True, "size": True, "integrity": "ok"},
            ],
            "error": None,
        }
    ]


def test_verify_detects_a_tampered_extension_file(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    data_root = tmp_path / "extensions"
    module = create_module(data_root)
    write_licenses(module / "data.sqlite3", ["LIC-1"])
    (module / "files" / "notes.txt").write_text("kept\n")
    _created, directory, manifest = backup_artifact(settings, backup_root, data_root)
    tampered = directory / "extensions" / EXTENSION_ID / "files" / "notes.txt"
    tampered.write_text("tampered\n")

    rejected = run_ext_ops(
        ["verify", manifest["id"]], settings, backup_root=backup_root, data_root=data_root
    )

    assert rejected.returncode == 1
    checked = payload(rejected)
    assert checked["status"] == "failed"
    assert checked["verified"] is False
    assert checked["extensions"][0]["status"] == "failed"
    assert checked["extensions"][0]["checksum"] is False
    assert EXTENSION_ID in checked["error"]
    assert "notes.txt" in checked["error"]


def test_restore_reproduces_extension_data_byte_for_byte(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    data_root = tmp_path / "extensions"
    module = create_module(data_root)
    write_licenses(module / "data.sqlite3", ["LIC-1", "LIC-2"])
    write_licenses(module / "snapshots" / "1.sqlite3", ["LIC-1"])
    (module / "files" / "uploads").mkdir()
    (module / "files" / "uploads" / "license.pdf").write_bytes(b"%PDF-1.4 evidence")
    _created, _directory, manifest = backup_artifact(settings, backup_root, data_root)
    target = tmp_path / "restored-extensions"

    restored = restore(
        manifest["id"],
        settings,
        backup_root=backup_root,
        data_root=data_root,
        target=target,
    )

    assert restored.returncode == 0, restored.stdout + restored.stderr
    restored_json = payload(restored)
    assert restored_json["status"] == "ok"
    assert restored_json["extensions"]["target"] == str(target)
    assert restored_json["extensions"]["replaced"] is False
    assert [entry["id"] for entry in restored_json["extensions"]["restored"]] == [EXTENSION_ID]
    assert restored_json["extensions"]["preserved"] == []
    copied_module = target / EXTENSION_ID
    assert (copied_module / "files" / "uploads" / "license.pdf").read_bytes() == (
        b"%PDF-1.4 evidence"
    )
    assert (copied_module / "files" / "uploads" / "license.pdf").stat().st_mode & 0o777 == 0o600
    assert (copied_module / "files" / "uploads").stat().st_mode & 0o777 == 0o700
    assert (copied_module.stat().st_mode & 0o777) == 0o700
    connection = sqlite3.connect(copied_module / "data.sqlite3")
    try:
        assert [row[0] for row in connection.execute("SELECT key FROM licenses ORDER BY id")] == [
            "LIC-1",
            "LIC-2",
        ]
    finally:
        connection.close()
    assert (copied_module / "snapshots" / "1.sqlite3").is_file()


def test_restore_refuses_an_existing_extension_target_without_confirmation(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    data_root = tmp_path / "extensions"
    module = create_module(data_root)
    write_licenses(module / "data.sqlite3", ["LIC-1"])
    _created, _directory, manifest = backup_artifact(settings, backup_root, data_root)
    target = tmp_path / "existing-extensions"
    (target / "unknown-module").mkdir(parents=True)
    (target / "unknown-module" / "keep.txt").write_text("keep me\n")

    refused = restore(
        manifest["id"], settings, backup_root=backup_root, data_root=data_root, target=target
    )

    assert refused.returncode == 3
    assert payload(refused)["status"] == "refused"
    assert sorted(path.name for path in target.iterdir()) == ["unknown-module"]
    assert (target / "unknown-module" / "keep.txt").read_text() == "keep me\n"

    wrong_token = restore(
        manifest["id"],
        settings,
        backup_root=backup_root,
        data_root=data_root,
        target=target,
        extra=["--replace-live", "--confirm", "another-backup"],
    )
    assert wrong_token.returncode == 3
    assert not (target / EXTENSION_ID).exists()

    replaced = restore(
        manifest["id"],
        settings,
        backup_root=backup_root,
        data_root=data_root,
        target=target,
        extra=["--replace-live", "--confirm", manifest["id"]],
    )
    assert replaced.returncode == 0, replaced.stdout + replaced.stderr
    replaced_json = payload(replaced)
    assert replaced_json["extensions"]["replaced"] is True
    assert replaced_json["extensions"]["preserved"] == ["unknown-module"]
    assert (target / EXTENSION_ID / "data.sqlite3").is_file()
    # An unknown module directory at the target is never deleted.
    assert (target / "unknown-module" / "keep.txt").read_text() == "keep me\n"


def test_restore_refuses_a_tampered_extension_archive(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    data_root = tmp_path / "extensions"
    module = create_module(data_root)
    write_licenses(module / "data.sqlite3", ["LIC-1"])
    (module / "files" / "notes.txt").write_text("kept\n")
    _created, directory, manifest = backup_artifact(settings, backup_root, data_root)
    (directory / "extensions" / EXTENSION_ID / "files" / "notes.txt").write_text("tampered\n")
    target = tmp_path / "restored-extensions"

    rejected = restore(
        manifest["id"], settings, backup_root=backup_root, data_root=data_root, target=target
    )

    assert rejected.returncode == 1
    assert "failed verification" in payload(rejected)["error"]
    assert not target.exists()


def test_verify_accepts_an_older_manifest_without_an_extensions_key(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    data_root = tmp_path / "extensions"
    module = create_module(data_root)
    write_licenses(module / "data.sqlite3", ["LIC-1"])
    (module / "files" / "notes.txt").write_text("kept\n")
    _created, directory, manifest = backup_artifact(settings, backup_root, data_root)
    legacy_manifest = {
        key: value
        for key, value in manifest.items()
        if key not in {"extensions", "ignoredExtensions"}
    }
    (directory / "manifest.json").write_text(json.dumps(legacy_manifest))
    shutil.rmtree(directory / "extensions")

    verified = run_ext_ops(
        ["verify", manifest["id"]], settings, backup_root=backup_root, data_root=data_root
    )

    assert verified.returncode == 0, verified.stdout + verified.stderr
    checked = payload(verified)
    assert checked["verified"] is True
    assert checked["extensions"] == []


def test_status_reports_the_extension_data_footprint_read_only(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    data_root = tmp_path / "extensions"
    module = create_module(data_root)
    write_licenses(module / "data.sqlite3", ["LIC-1"])
    (module / "files" / "notes.txt").write_text("kept\n")
    expected_bytes = (module / "data.sqlite3").stat().st_size + (
        module / "files" / "notes.txt"
    ).stat().st_size
    before = sorted(path.name for path in data_root.iterdir())

    reported = run_ext_ops(["status"], settings, backup_root=backup_root, data_root=data_root)

    assert reported.returncode == 0, reported.stdout + reported.stderr
    assert payload(reported)["extensions"] == {"count": 1, "bytes": expected_bytes}
    assert sorted(path.name for path in data_root.iterdir()) == before
