"""Attachment blobs inside an ops artifact (R4-F2).

Attachment metadata is stored in the core database but the bytes live in the
separate ``ITSM_ATTACHMENT_STORAGE_PATH`` tree, keyed by an opaque 32-hex blob
key. A backup that archives only the database is not recoverable: after a
restore every download would answer ``503 attachment storage unavailable``
while verification still reported ``verified: true``.

A backup archives each blob under ``<artifact>/attachments/<key>`` and records
its SHA-256 digest and size in the manifest. Verification recomputes both, and
restore writes the bytes back into a target storage root with staging plus an
atomic rename. Nothing in this module interprets a filesystem path supplied by a
client and nothing follows a symlink.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from itsm.ops import store
from itsm.ops.engines import OpsError

DATA_ROOT_DIR = "attachments"

_KEY = re.compile(r"^[a-f0-9]{32}$")
_CHUNK = 1024 * 1024
_DIR_MODE = 0o700
_FILE_MODE = 0o600


def _blobs(storage_root: Path) -> tuple[list[Path], list[str]]:
    """Return the blob files under ``storage_root`` and one note per ignored entry."""
    if not storage_root.exists():
        return [], []
    if storage_root.is_symlink() or not storage_root.is_dir():
        raise OpsError(f"attachment storage path is not a directory: {storage_root}")
    blobs: list[Path] = []
    ignored: list[str] = []
    for entry in sorted(storage_root.iterdir(), key=lambda item: item.name):
        if entry.is_symlink():
            ignored.append(f"{entry.name}: symlink")
        elif not entry.is_file():
            ignored.append(f"{entry.name}: not a blob file")
        elif not _KEY.match(entry.name):
            ignored.append(f"{entry.name}: unexpected blob name")
        else:
            blobs.append(entry)
    return blobs, ignored


def footprint(storage_root: Path) -> dict[str, int]:
    """Count the archived blob files and their bytes."""
    try:
        blobs, _ignored = _blobs(storage_root)
    except OpsError:
        return {"count": 0, "bytes": 0}
    total = 0
    for path in blobs:
        try:
            total += path.stat().st_size
        except OSError:  # a blob that vanished between listing and sizing
            continue
    return {"count": len(blobs), "bytes": total}


def _copy_private(source: Path, destination: Path) -> None:
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _FILE_MODE)
    with os.fdopen(descriptor, "wb") as target, source.open("rb") as stream:
        shutil.copyfileobj(stream, target, length=_CHUNK)
        target.flush()
        os.fsync(target.fileno())
    os.chmod(destination, _FILE_MODE)


def archive(
    storage_root: Path, destination: Path
) -> tuple[Sequence[store.AttachmentEntry], Sequence[str]]:
    """Archive every blob under ``destination``; return entries and skip notes."""
    blobs, ignored = _blobs(storage_root)
    if not blobs:
        return (), tuple(ignored)
    destination.mkdir(mode=_DIR_MODE, exist_ok=True)
    os.chmod(destination, _DIR_MODE)
    entries: list[store.AttachmentEntry] = []
    for blob in blobs:
        archived = destination / blob.name
        _copy_private(blob, archived)
        digest, size = store.digest_file(archived)
        entries.append(store.AttachmentEntry(key=blob.name, sha256=digest, size=size))
    return tuple(entries), tuple(ignored)


def verify(
    artifact_directory: Path, entries: Sequence[store.AttachmentEntry]
) -> tuple[bool, dict[str, Any], list[str]]:
    """Recompute every archived blob digest and report missing or unexpected files."""
    root = artifact_directory / DATA_ROOT_DIR
    errors: list[str] = []
    missing: list[str] = []
    expected = {entry.key: entry for entry in entries}
    report: dict[str, Any] = {
        "count": len(entries),
        "bytes": sum(entry.size for entry in entries),
        "verified": True,
        "missing": missing,
        "errors": errors,
    }
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        errors.append("attachment archive is not a directory")
        report["verified"] = False
        return False, report, errors
    present = set()
    if root.is_dir():
        for item in sorted(root.iterdir(), key=lambda path: path.name):
            if item.is_symlink() or not item.is_file():
                errors.append(f"attachment archive entry {item.name} is not a regular file")
                continue
            present.add(item.name)
            entry = expected.get(item.name)
            if entry is None:
                errors.append(f"attachment archive entry {item.name} is not in the manifest")
                continue
            digest, size = store.digest_file(item)
            if size != entry.size:
                errors.append(f"attachment {item.name}: size does not match the manifest")
            elif digest != entry.sha256:
                errors.append(f"attachment {item.name}: does not match the manifest")
    for key in expected:
        if key not in present:
            missing.append(key)
            errors.append(f"attachment {key}: archived blob is missing")
    report["verified"] = not errors
    return report["verified"], report, errors


def _restore_file(source: Path, destination: Path) -> int:
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
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return destination.stat().st_size


def restore(
    artifact_directory: Path,
    entries: Sequence[store.AttachmentEntry],
    *,
    destination: Path,
    replace: bool,
) -> dict[str, Any]:
    """Write the archived blobs into ``destination``, keeping unrelated files.

    ``replace`` is the operator's explicit consent for an existing target; the
    caller decides it. Files that are not part of the artifact are preserved and
    reported, never deleted.
    """
    root = artifact_directory / DATA_ROOT_DIR
    created = not destination.exists()
    if created:
        destination.mkdir(parents=True, mode=_DIR_MODE)
        os.chmod(destination, _DIR_MODE)
    elif destination.is_symlink() or not destination.is_dir():
        raise OpsError(f"attachment restore target is not a directory: {destination}")
    restored_bytes = 0
    for entry in entries:
        source = root / entry.key
        if not source.is_file():
            raise OpsError(f"attachment {entry.key}: archived blob is missing")
        restored_bytes += _restore_file(source, destination / entry.key)
    expected = {entry.key for entry in entries}
    preserved = sorted(
        item.name
        for item in destination.iterdir()
        if item.name not in expected and not item.name.startswith(".")
    )
    return {
        "target": str(destination),
        "created": created,
        "replaced": replace and not created,
        "restored": [{"count": len(entries), "bytes": restored_bytes}],
        "preserved": preserved,
    }
