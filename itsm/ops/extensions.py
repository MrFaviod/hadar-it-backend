"""Extension data files inside an ops artifact (S6, decisions D3 and D8).

The extension storage decision fixes the source layout::

    <extension_data_path>/<id>/data.sqlite3            module database (may be WAL)
    <extension_data_path>/<id>/snapshots/*.sqlite3     pre-upgrade snapshots
    <extension_data_path>/<id>/files/**                other module-owned files

A backup archives each module under ``<artifact>/extensions/<id>/`` keeping those
relative paths, so restore can write them back without guessing. Module ids are
lowercase hyphen identifiers; every other entry (symlinks, unexpected names,
non-regular files) is reported and skipped, never followed. Nothing in this
module writes to the extension data root: backup and verify only read it.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from itsm.ops import sqlite as sqlite_ops
from itsm.ops import store
from itsm.ops.engines import OpsError

DATA_ROOT_DIR = "extensions"
MODULE_DATABASE = "data.sqlite3"
SNAPSHOTS_DIR = "snapshots"
FILES_DIR = "files"
SNAPSHOT_SUFFIX = ".sqlite3"

_EXTENSION_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_CHUNK = 1024 * 1024
_DIR_MODE = 0o700
_FILE_MODE = 0o600


# --------------------------------------------------------------------------- #
# Scanning the installed data root (read-only)
# --------------------------------------------------------------------------- #


def _modules(data_root: Path) -> tuple[list[Path], list[str]]:
    """Return valid module directories and one note per ignored entry."""
    if not data_root.exists():
        return [], []
    if data_root.is_symlink() or not data_root.is_dir():
        raise OpsError(f"extension data path is not a directory: {data_root}")
    modules: list[Path] = []
    ignored: list[str] = []
    for entry in sorted(data_root.iterdir(), key=lambda item: item.name):
        if entry.is_symlink():
            ignored.append(f"{entry.name}: symlink")
        elif not entry.is_dir():
            ignored.append(f"{entry.name}: not a module directory")
        elif not _EXTENSION_ID.match(entry.name):
            ignored.append(f"{entry.name}: unexpected module name")
        else:
            modules.append(entry)
    return modules, ignored


def _walk_tree(directory: Path, prefix: str, files: dict[str, Path], anomalies: list[str]) -> None:
    """Collect regular files below ``directory``, never following a symlink."""
    for entry in sorted(directory.iterdir(), key=lambda item: item.name):
        relative = f"{prefix}/{entry.name}" if prefix else entry.name
        if entry.is_symlink():
            anomalies.append(f"{relative}: symlink")
        elif entry.is_dir():
            _walk_tree(entry, relative, files, anomalies)
        elif entry.is_file():
            files[relative] = entry
        else:
            anomalies.append(f"{relative}: not a regular file")


def _module_files(module: Path) -> tuple[dict[str, Path], list[str]]:
    files: dict[str, Path] = {}
    anomalies: list[str] = []
    _walk_tree(module, "", files, anomalies)
    return files, anomalies


def footprint(data_root: Path) -> dict[str, int]:
    """Count valid module directories and the bytes of their regular files."""
    try:
        modules, _ignored = _modules(data_root)
    except OpsError:
        return {"count": 0, "bytes": 0}
    total = 0
    for module in modules:
        files, _anomalies = _module_files(module)
        for path in files.values():
            try:
                total += path.stat().st_size
            except OSError:  # a file that vanished between listing and sizing
                continue
    return {"count": len(modules), "bytes": total}


# --------------------------------------------------------------------------- #
# Backup
# --------------------------------------------------------------------------- #


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
    os.chmod(path, _DIR_MODE)


def _copy_private(source: Path, destination: Path) -> None:
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _FILE_MODE)
    with os.fdopen(descriptor, "wb") as target, source.open("rb") as stream:
        shutil.copyfileobj(stream, target, length=_CHUNK)
        target.flush()
        os.fsync(target.fileno())
    os.chmod(destination, _FILE_MODE)


def _file_entry(relative: str, archived: Path) -> store.ExtensionFileEntry:
    digest, size = store.digest_file(archived)
    return store.ExtensionFileEntry(path=relative, sha256=digest, size=size)


def _real_directory(entry: Path, relative: str, ignored: list[str]) -> bool:
    """Accept a real directory; report (never follow) a symlink or a plain file."""
    if entry.is_symlink():
        ignored.append(f"{relative}: symlink")
        return False
    if not entry.is_dir():
        ignored.append(f"{relative}: unexpected entry")
        return False
    return True


def _archive_snapshots(
    source: Path, destination: Path, prefix: str, ignored: list[str]
) -> list[store.ExtensionFileEntry]:
    _mkdir_private(destination)
    entries: list[store.ExtensionFileEntry] = []
    for entry in sorted(source.iterdir(), key=lambda item: item.name):
        relative = f"{prefix}/{entry.name}"
        if entry.is_symlink():
            ignored.append(f"{relative}: symlink")
            continue
        if not entry.is_file() or not entry.name.endswith(SNAPSHOT_SUFFIX):
            ignored.append(f"{relative}: unexpected snapshot name")
            continue
        archived = destination / entry.name
        # Snapshots are SQLite files too; the online copy stays consistent even
        # when a snapshot was left in WAL mode.
        sqlite_ops.copy_online(entry, archived, label=f"extension snapshot {entry.name}")
        os.chmod(archived, _FILE_MODE)
        entries.append(_file_entry(relative, archived))
    return entries


def _archive_tree(
    source: Path, destination: Path, prefix: str, ignored: list[str]
) -> list[store.ExtensionFileEntry]:
    _mkdir_private(destination)
    entries: list[store.ExtensionFileEntry] = []
    for entry in sorted(source.iterdir(), key=lambda item: item.name):
        relative = f"{prefix}/{entry.name}"
        if entry.is_symlink():
            ignored.append(f"{relative}: symlink")
        elif entry.is_dir():
            entries.extend(_archive_tree(entry, destination / entry.name, relative, ignored))
        elif entry.is_file():
            archived = destination / entry.name
            _copy_private(entry, archived)
            entries.append(_file_entry(relative, archived))
        else:
            ignored.append(f"{relative}: not a regular file")
    return entries


def _archive_module(
    module: Path, destination: Path, ignored: list[str]
) -> store.ExtensionBackupEntry:
    _mkdir_private(destination)
    entries: list[store.ExtensionFileEntry] = []
    for entry in sorted(module.iterdir(), key=lambda item: item.name):
        relative = f"{module.name}/{entry.name}"
        if entry.is_symlink():
            ignored.append(f"{relative}: symlink")
        elif entry.name == MODULE_DATABASE and entry.is_file():
            archived = destination / MODULE_DATABASE
            sqlite_ops.copy_online(entry, archived, label=f"extension {module.name}")
            os.chmod(archived, _FILE_MODE)
            entries.append(_file_entry(MODULE_DATABASE, archived))
        elif entry.name == SNAPSHOTS_DIR and _real_directory(entry, relative, ignored):
            entries.extend(
                _archive_snapshots(entry, destination / SNAPSHOTS_DIR, SNAPSHOTS_DIR, ignored)
            )
        elif entry.name == FILES_DIR and _real_directory(entry, relative, ignored):
            entries.extend(_archive_tree(entry, destination / FILES_DIR, FILES_DIR, ignored))
        elif not entry.is_dir():
            ignored.append(f"{relative}: unexpected entry")
        else:
            ignored.append(f"{relative}: unexpected directory")
    return store.ExtensionBackupEntry(id=module.name, files=tuple(entries))


def archive(
    data_root: Path, destination: Path
) -> tuple[list[store.ExtensionBackupEntry], list[str]]:
    """Copy every installed module's data into ``destination``.

    Returns the manifest entries plus one note per skipped entry. A missing data
    root is an empty archive, not an error: an installation without extensions
    behaves exactly as before.
    """
    modules, ignored = _modules(data_root)
    if not modules:
        return [], ignored
    try:
        _mkdir_private(destination)
        entries = [
            _archive_module(module, destination / module.name, ignored) for module in modules
        ]
    except OSError as exc:
        raise OpsError(f"extension data could not be archived: {exc.strerror or exc}") from exc
    return entries, ignored


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


def _file_integrity(path: Path) -> str:
    return sqlite_ops.integrity(path) if path.name.endswith(SNAPSHOT_SUFFIX) else "skipped"


def _verify_module(
    module_dir: Path, entry: store.ExtensionBackupEntry
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    actual: dict[str, Path] = {}
    if module_dir.is_symlink() or not module_dir.is_dir():
        errors.append(f"extension {entry.id}: archive directory is missing")
    else:
        actual, anomalies = _module_files(module_dir)
        errors.extend(f"extension {entry.id}: {note}" for note in anomalies)
    manifest_paths = {item.path for item in entry.files}
    for unexpected in sorted(set(actual) - manifest_paths):
        errors.append(f"extension {entry.id}: unexpected archived file {unexpected}")
    files: list[dict[str, Any]] = []
    for item in entry.files:
        path = actual.get(item.path)
        if path is None:
            checksum = size = False
            integrity = "failed"
            errors.append(f"extension {entry.id}: {item.path} is missing from the artifact")
        else:
            digest, byte_size = store.digest_file(path)
            checksum = digest == item.sha256
            size = byte_size == item.size
            integrity = _file_integrity(path)
            if not (checksum and size and integrity in {"ok", "skipped"}):
                errors.append(f"extension {entry.id}: {item.path} does not match the manifest")
        files.append(
            {"path": item.path, "checksum": checksum, "size": size, "integrity": integrity}
        )
    integrity_states = {item["integrity"] for item in files}
    if "failed" in integrity_states:
        overall_integrity = "failed"
    elif "ok" in integrity_states:
        overall_integrity = "ok"
    else:
        overall_integrity = "skipped"
    report = {
        "id": entry.id,
        "status": "ok" if not errors else "failed",
        "checksum": all(item["checksum"] for item in files),
        "size": all(item["size"] for item in files),
        "integrity": overall_integrity,
        "files": files,
        "error": None if not errors else "; ".join(errors),
    }
    return report, errors


def verify(
    artifact_dir: Path, entries: Sequence[store.ExtensionBackupEntry]
) -> tuple[bool, list[dict[str, Any]], list[str]]:
    """Check every archived extension file, its size and its SQLite integrity."""
    root = artifact_dir / DATA_ROOT_DIR
    reports: list[dict[str, Any]] = []
    errors: list[str] = []
    expected = {entry.id for entry in entries}
    on_disk: set[str] = set()
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        errors.append("extension archive is not a directory")
    elif root.is_dir():
        for child in sorted(root.iterdir(), key=lambda item: item.name):
            if child.is_symlink():
                errors.append(f"extension archive: symlink {child.name}")
            elif not child.is_dir():
                errors.append(f"extension archive: unexpected entry {child.name}")
            elif not _EXTENSION_ID.match(child.name):
                errors.append(f"extension archive: unexpected directory {child.name}")
            else:
                on_disk.add(child.name)
    for missing in sorted(expected - on_disk):
        errors.append(f"extension {missing}: archive directory is missing")
    for unexpected in sorted(on_disk - expected):
        errors.append(f"extension {unexpected}: unexpected archive directory")
    for entry in entries:
        report, module_errors = _verify_module(root / entry.id, entry)
        reports.append(report)
        errors.extend(module_errors)
    ok = not errors and all(report["status"] == "ok" for report in reports)
    return ok, reports, errors


# --------------------------------------------------------------------------- #
# Restore
# --------------------------------------------------------------------------- #


def _restore_file(source: Path, destination: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent, prefix=".restore-", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as target, source.open("rb") as stream:
            shutil.copyfileobj(stream, target, length=_CHUNK)
            target.flush()
            os.fsync(target.fileno())
        os.chmod(temporary, _FILE_MODE)
        if destination.name.endswith(SNAPSHOT_SUFFIX) and sqlite_ops.integrity(temporary) != "ok":
            raise OpsError(
                f"restored extension file failed the sqlite integrity check: {destination.name}"
            )
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    os.chmod(destination, _FILE_MODE)


def restore(
    artifact_dir: Path,
    entries: Sequence[store.ExtensionBackupEntry],
    *,
    destination: Path,
    replace: bool,
) -> dict[str, Any]:
    """Write the archived files into ``destination`` and delete nothing.

    Each file is staged next to its target and renamed atomically, so an
    interrupted restore never leaves a half-written module file. Module
    directories are private (0700) and files are 0600; module directories that
    the artifact does not contain are preserved and reported.
    """
    root = artifact_dir / DATA_ROOT_DIR
    ids = {entry.id for entry in entries}
    preserved: list[str] = []
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise OpsError(f"extension restore target is not a directory: {destination}")
        preserved = sorted(child.name for child in destination.iterdir() if child.name not in ids)
    else:
        _mkdir_private(destination)
    restored: list[dict[str, Any]] = []
    for entry in entries:
        module_dir = root / entry.id
        target_module = destination / entry.id
        _mkdir_private(target_module)
        written = 0
        for item in entry.files:
            source = module_dir / item.path
            if source.is_symlink() or not source.is_file():
                raise OpsError(f"extension {entry.id}: archived file is missing: {item.path}")
            target = target_module / item.path
            _mkdir_private(target.parent)
            _restore_file(source, target)
            written += item.size
        restored.append({"id": entry.id, "files": len(entry.files), "bytes": written})
    return {
        "target": str(destination),
        "replaced": replace,
        "restored": restored,
        "preserved": preserved,
    }
