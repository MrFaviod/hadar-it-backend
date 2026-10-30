"""Backup artifact layout, manifest bookkeeping, status file and upgrader lock.

An artifact is a directory per backup under the backup root. It contains the
engine dump plus ``manifest.json``. The directory is assembled under a hidden
partial name and moved into place with ``os.replace`` so an interrupted backup
never looks like a complete artifact. Files are private (0600) and the artifact
directory is 0700.

The status file is operator-facing metadata only: it never carries credentials,
only the redacted database locator.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from itsm.ops.engines import REDACTED, OpsError

MANIFEST_NAME = "manifest.json"
STATUS_NAME = "status.json"
LOCK_NAME = "upgrade.lock"

ARTIFACT_FILE_MODE = 0o600
ARTIFACT_DIR_MODE = 0o700
MAX_FAILURES = 10

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
_PARTIAL_PREFIX = ".partial-"
_MANIFEST_KEYS = (
    "id",
    "engine",
    "createdAt",
    "database",
    "alembicRevision",
    "appVersion",
    "sha256",
    "size",
    "format",
    "dumpFile",
    "toolVersions",
)


class UpgraderBusy(OpsError):
    """Raised when another upgrader already holds the exclusive lock."""


@dataclass(frozen=True)
class BackupManifest:
    """Validated metadata describing one backup artifact."""

    id: str
    engine: str
    created_at: str
    database: str
    alembic_revision: str | None
    app_version: str
    sha256: str
    size: int
    format: str
    dump_file: str
    tool_versions: dict[str, str]
    verified: bool | None = None
    verified_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "engine": self.engine,
            "createdAt": self.created_at,
            "database": self.database,
            "alembicRevision": self.alembic_revision,
            "appVersion": self.app_version,
            "sha256": self.sha256,
            "size": self.size,
            "format": self.format,
            "dumpFile": self.dump_file,
            "toolVersions": dict(self.tool_versions),
            "verified": self.verified,
            "verifiedAt": self.verified_at,
        }

    @classmethod
    def from_dict(cls, raw: object, *, expected_id: str | None = None) -> BackupManifest:
        if not isinstance(raw, dict):
            raise OpsError("invalid backup manifest: not an object")
        missing = [key for key in _MANIFEST_KEYS if key not in raw]
        if missing:
            raise OpsError(f"invalid backup manifest: missing {', '.join(missing)}")
        identifier = raw["id"]
        if not isinstance(identifier, str) or not _IDENTIFIER.match(identifier):
            raise OpsError("invalid backup manifest: unsafe id")
        if expected_id is not None and identifier != expected_id:
            raise OpsError("invalid backup manifest: id does not match its directory")
        tool_versions = raw["toolVersions"]
        if not isinstance(tool_versions, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in tool_versions.items()
        ):
            raise OpsError("invalid backup manifest: toolVersions must map text to text")
        if isinstance(raw["size"], bool) or not isinstance(raw["size"], int) or raw["size"] < 0:
            raise OpsError("invalid backup manifest: size must be a non-negative integer")
        for key in ("engine", "createdAt", "database", "appVersion", "sha256", "format"):
            if not isinstance(raw[key], str) or not raw[key]:
                raise OpsError(f"invalid backup manifest: {key} must be text")
        if not re.fullmatch(r"[0-9a-f]{64}", raw["sha256"]):
            raise OpsError("invalid backup manifest: sha256 must be a hex digest")
        dump_file = raw["dumpFile"]
        if (
            not isinstance(dump_file, str)
            or not dump_file
            or "/" in dump_file
            or "\\" in dump_file
            or dump_file in {".", ".."}
        ):
            raise OpsError("invalid backup manifest: dumpFile must be a plain file name")
        revision = raw["alembicRevision"]
        if revision is not None and not isinstance(revision, str):
            raise OpsError("invalid backup manifest: alembicRevision must be text or null")
        verified = raw.get("verified")
        if verified is not None and not isinstance(verified, bool):
            raise OpsError("invalid backup manifest: verified must be true, false or null")
        verified_at = raw.get("verifiedAt")
        if verified_at is not None and not isinstance(verified_at, str):
            raise OpsError("invalid backup manifest: verifiedAt must be text or null")
        return cls(
            id=identifier,
            engine=raw["engine"],
            created_at=raw["createdAt"],
            database=raw["database"],
            alembic_revision=revision,
            app_version=raw["appVersion"],
            sha256=raw["sha256"],
            size=raw["size"],
            format=raw["format"],
            dump_file=dump_file,
            tool_versions=dict(tool_versions),
            verified=verified,
            verified_at=verified_at,
        )


@dataclass(frozen=True)
class BackupArtifact:
    """A complete artifact directory and its manifest."""

    directory: Path
    manifest: BackupManifest

    @property
    def dump_path(self) -> Path:
        return self.directory / self.manifest.dump_file


def utc_now() -> datetime:
    return datetime.now(UTC)


def isoformat(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat()


def artifact_identifier(engine: str, created_at: datetime, token: str | None = None) -> str:
    """Return a sortable, path-safe artifact identifier."""
    stamp = created_at.astimezone(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{engine}-{stamp}-{token or uuid.uuid4().hex[:6]}"


def prepare_root(root: Path) -> None:
    if root.exists() and not root.is_dir():
        raise OpsError(f"backup root is not a directory: {root}")
    try:
        root.mkdir(parents=True, exist_ok=True, mode=ARTIFACT_DIR_MODE)
    except OSError as exc:
        raise OpsError(f"backup root is not writable: {root}") from exc


def digest_file(path: Path) -> tuple[str, int]:
    """Return the SHA-256 hex digest and byte size of a file."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, ARTIFACT_FILE_MODE)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        raise
    os.chmod(path, ARTIFACT_FILE_MODE)


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:  # pragma: no cover - platform dependent
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_artifact(
    root: Path,
    *,
    engine: str,
    database: str,
    alembic_revision: str | None,
    app_version: str,
    dump_file: str,
    tool_versions: Mapping[str, str],
    write_dump: Callable[[Path], None],
    now: datetime | None = None,
) -> BackupArtifact:
    """Assemble one artifact atomically; a failure leaves no visible artifact."""
    prepare_root(root)
    created_at = now or utc_now()
    identifier = artifact_identifier(engine, created_at)
    partial = root / f"{_PARTIAL_PREFIX}{identifier}"
    try:
        partial.mkdir(mode=ARTIFACT_DIR_MODE)
    except FileExistsError as exc:  # pragma: no cover - random token collision
        raise OpsError("backup artifact identifier collision") from exc
    try:
        dump_path = partial / dump_file
        write_dump(dump_path)
        os.chmod(dump_path, ARTIFACT_FILE_MODE)
        digest, size = digest_file(dump_path)
        manifest = BackupManifest(
            id=identifier,
            engine=engine,
            created_at=isoformat(created_at),
            database=database,
            alembic_revision=alembic_revision,
            app_version=app_version,
            sha256=digest,
            size=size,
            format=engine,
            dump_file=dump_file,
            tool_versions=dict(tool_versions),
        )
        _write_private(partial / MANIFEST_NAME, json.dumps(manifest.as_dict()).encode())
        _fsync_directory(partial)
        final = root / identifier
        if final.exists():  # pragma: no cover - defensive
            raise OpsError(f"backup artifact already exists: {identifier}")
        os.replace(partial, final)
        os.chmod(final, ARTIFACT_DIR_MODE)
        _fsync_directory(root)
        return BackupArtifact(directory=final, manifest=manifest)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise


def load_artifact(root: Path, identifier: str) -> BackupArtifact:
    """Load one artifact by id, rejecting traversal and unknown ids."""
    if not _IDENTIFIER.match(identifier or ""):
        raise OpsError(f"backup id is not valid: {identifier}")
    directory = root / identifier
    manifest_path = directory / MANIFEST_NAME
    if not directory.is_dir() or not manifest_path.is_file():
        raise OpsError(f"backup {identifier} not found under {root}")
    try:
        raw = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise OpsError(f"backup {identifier} has an unreadable manifest") from exc
    return BackupArtifact(
        directory=directory, manifest=BackupManifest.from_dict(raw, expected_id=identifier)
    )


def list_artifacts(root: Path) -> list[BackupArtifact]:
    """Return complete artifacts newest first; partial or broken ones are ignored."""
    if not root.is_dir():
        return []
    artifacts: list[BackupArtifact] = []
    for entry in root.iterdir():
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        try:
            artifacts.append(load_artifact(root, entry.name))
        except OpsError:
            continue
    return sorted(
        artifacts,
        key=lambda artifact: (artifact.manifest.created_at, artifact.manifest.id),
        reverse=True,
    )


def update_verification(
    artifact: BackupArtifact, *, verified: bool, now: datetime | None = None
) -> BackupArtifact:
    """Persist the latest verification result in the manifest."""
    manifest = replace(
        artifact.manifest,
        verified=verified,
        verified_at=isoformat(now or utc_now()),
    )
    manifest_path = artifact.directory / MANIFEST_NAME
    temporary = artifact.directory / f".manifest-{uuid.uuid4().hex[:8]}.tmp"
    _write_private(temporary, json.dumps(manifest.as_dict()).encode())
    os.replace(temporary, manifest_path)
    return BackupArtifact(directory=artifact.directory, manifest=manifest)


def sanitize(text: str, secrets: tuple[str, ...] = ()) -> str:
    """Mask known credential values inside operator-facing text."""
    sanitized = text
    for secret in sorted({value for value in secrets if value}, key=len, reverse=True):
        sanitized = sanitized.replace(secret, REDACTED)
    return sanitized


def read_status(root: Path) -> dict[str, Any]:
    path = root / STATUS_NAME
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text())
    except OSError, json.JSONDecodeError:
        return {}
    return raw if isinstance(raw, dict) else {}


def write_status(root: Path, data: dict[str, Any]) -> None:
    prepare_root(root)
    temporary = root / f".status-{uuid.uuid4().hex[:8]}.tmp"
    _write_private(temporary, json.dumps(data, indent=2, sort_keys=True).encode())
    os.replace(temporary, root / STATUS_NAME)
    _fsync_directory(root)


def record_failure(
    root: Path,
    *,
    operation: str,
    reason: str,
    engine: str,
    database: str,
    secrets: tuple[str, ...] = (),
) -> None:
    """Append one bounded failure entry; stored text never contains a credential."""
    status = read_status(root)
    existing = [item for item in status.get("failures", []) if isinstance(item, dict)]
    failures = existing[-(MAX_FAILURES - 1) :]
    failures.append(
        {
            "at": isoformat(utc_now()),
            "operation": operation,
            "reason": sanitize(reason, secrets)[:500],
        }
    )
    status.update(
        engine=engine,
        database=database,
        updatedAt=isoformat(utc_now()),
        failures=failures,
    )
    write_status(root, status)


def record_upgrade(root: Path, payload: dict[str, Any], *, engine: str, database: str) -> None:
    status = read_status(root)
    status["lastUpgrade"] = payload
    status.update(engine=engine, database=database, updatedAt=isoformat(utc_now()))
    write_status(root, status)


@dataclass(frozen=True)
class UpgradeLock:
    """Exclusive lock file held for the duration of one upgrade attempt."""

    path: Path
    token: str


def _process_alive(pid: object) -> bool:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _lock_holder(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text())
    except OSError, json.JSONDecodeError:
        return {}
    return raw if isinstance(raw, dict) else {}


def acquire_lock(root: Path, *, now: datetime | None = None) -> UpgradeLock:
    """Take the exclusive upgrader lock, reclaiming only a dead holder's file."""
    prepare_root(root)
    path = root / LOCK_NAME
    for _ in range(2):
        token = uuid.uuid4().hex
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, ARTIFACT_FILE_MODE)
        except FileExistsError:
            holder = _lock_holder(path)
            pid = holder.get("pid")
            if _process_alive(pid):
                raise UpgraderBusy(
                    f"another upgrader holds the lock: pid {pid} since "
                    f"{holder.get('startedAt', 'unknown')}"
                ) from None
            with contextlib.suppress(FileNotFoundError):  # a releaser may win the race
                path.unlink()
            continue
        payload = json.dumps(
            {"pid": os.getpid(), "token": token, "startedAt": isoformat(now or utc_now())}
        ).encode()
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return UpgradeLock(path=path, token=token)
    raise UpgraderBusy("another upgrader holds the lock")  # pragma: no cover - defensive


def release_lock(lock: UpgradeLock) -> None:
    """Release the lock only when this process still owns it."""
    holder = _lock_holder(lock.path)
    if holder.get("token") != lock.token:
        return
    try:
        lock.path.unlink()
    except FileNotFoundError:  # pragma: no cover - defensive
        return
