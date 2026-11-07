"""Deterministic extension ZIPs plus strict package containment.

The archive is the only model the validator sees. Builds are byte-for-byte
repeatable, every digest is the SHA-256 of the actual archive bytes, and no
path, link, duplicate, case collision, binary or size overrun is accepted.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import zipfile
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .contract import ManifestError, validate_manifest

MAX_ARCHIVE_BYTES = 4 * 1024 * 1024
MAX_EXPANDED_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 200
MAX_FILE_BYTES = 1024 * 1024

EXACT_FILES = frozenset({"extension.json", "backend.py", "frontend.js"})
SKILL_PATTERN = re.compile(r"^skills/([a-z][a-z0-9]*(?:-[a-z0-9]+)*)/SKILL\.md$")
TEST_PATTERN = re.compile(r"^tests/[A-Za-z_][A-Za-z0-9_]*\.py$")


class PackageError(ValueError):
    """The package violates the bounded v1 file or archive contract."""


@dataclass(frozen=True)
class ArchiveLimits:
    max_archive_bytes: int = MAX_ARCHIVE_BYTES
    max_expanded_bytes: int = MAX_EXPANDED_BYTES
    max_entries: int = MAX_ENTRIES
    max_file_bytes: int = MAX_FILE_BYTES


DEFAULT_LIMITS = ArchiveLimits()


@dataclass(frozen=True)
class BuiltPackage:
    data: bytes
    digest: str
    files: Mapping[str, str]
    manifest: Mapping[str, Any]


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def allowed_path(path: str) -> bool:
    return (
        path in EXACT_FILES
        or SKILL_PATTERN.fullmatch(path) is not None
        or TEST_PATTERN.fullmatch(path) is not None
    )


def _safe_name(name: str) -> None:
    if not name or "\x00" in name or "\\" in name or any(ord(char) < 32 for char in name):
        raise PackageError(f"unsafe package path: {name!r}")
    if name.startswith("/") or name.endswith("/"):
        raise PackageError(f"unsafe package path: {name!r}")
    pure = PurePosixPath(name)
    if str(pure) != name or any(part in (".", "..") for part in pure.parts):
        raise PackageError(f"unsafe package path: {name!r}")


def _decode_json_object(text: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate manifest key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=pairs)
    except (TypeError, ValueError) as exc:
        raise PackageError(f"extension.json is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise PackageError("extension.json must contain an object")
    return value


def _read_text(name: str, data: bytes, limits: ArchiveLimits) -> str:
    if len(data) > limits.max_file_bytes:
        raise PackageError(f"file exceeds {limits.max_file_bytes} bytes: {name}")
    if b"\x00" in data:
        raise PackageError(f"binary or NUL content is not allowed: {name}")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackageError(f"file must be UTF-8 text: {name}") from exc


def read_zip(data: bytes, limits: ArchiveLimits = DEFAULT_LIMITS) -> dict[str, str]:
    """Read a bounded archive into text files, rejecting every unsafe shape."""
    if not isinstance(data, bytes):
        raise PackageError("package must be bytes")
    if len(data) > limits.max_archive_bytes:
        raise PackageError(f"archive exceeds {limits.max_archive_bytes} bytes")
    files: dict[str, str] = {}
    seen: set[str] = set()
    folded: set[str] = set()
    expanded = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise PackageError("package is not a valid ZIP archive") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > limits.max_entries:
            raise PackageError(f"archive exceeds {limits.max_entries} entries")
        for info in infos:
            name = info.filename
            _safe_name(name)
            if name in seen:
                raise PackageError(f"duplicate archive path: {name}")
            seen.add(name)
            key = name.casefold()
            if key in folded:
                raise PackageError(f"case-colliding archive path: {name}")
            folded.add(key)
            if info.flag_bits & 0x1:
                raise PackageError(f"encrypted archive entry is not allowed: {name}")
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise PackageError(f"unsupported compression for {name}")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise PackageError(f"symlink is not allowed in package: {name}")
            if info.is_dir():
                continue
            if mode not in (0, stat.S_IFREG):
                raise PackageError(f"special file is not allowed in package: {name}")
            if not allowed_path(name):
                raise PackageError(f"unsupported package path: {name}")
            if info.file_size > limits.max_file_bytes:
                raise PackageError(f"file exceeds {limits.max_file_bytes} bytes: {name}")
            expanded += info.file_size
            if expanded > limits.max_expanded_bytes:
                raise PackageError(f"archive exceeds {limits.max_expanded_bytes} expanded bytes")
            with archive.open(info) as handle:
                content = handle.read(limits.max_file_bytes + 1)
            if len(content) > limits.max_file_bytes:
                raise PackageError(f"file exceeds {limits.max_file_bytes} bytes: {name}")
            files[name] = _read_text(name, content, limits)
    if not files:
        raise PackageError("package is empty")
    return files


def load_manifest(files: Mapping[str, str]) -> dict[str, Any]:
    text = files.get("extension.json")
    if text is None:
        raise PackageError("extension.json is required at package root")
    return _decode_json_object(text)


def validate_layout(files: Mapping[str, str], manifest: Mapping[str, Any]) -> None:
    """Require exactly the declared package files and at least one Python test."""
    missing = sorted(EXACT_FILES - set(files))
    if missing:
        raise PackageError(f"missing required package files: {', '.join(missing)}")
    declared_skills = {str(item["path"]) for item in manifest.get("skills", [])}
    for path in declared_skills:
        if path not in files:
            raise PackageError(f"declared skill file is missing: {path}")
    extra = sorted(set(files) - EXACT_FILES - declared_skills)
    for path in extra:
        if SKILL_PATTERN.fullmatch(path):
            raise PackageError(f"skill file is not declared in the manifest: {path}")
        if TEST_PATTERN.fullmatch(path) is None:
            raise PackageError(f"unsupported package path: {path}")
    if not any(TEST_PATTERN.fullmatch(path) for path in files):
        raise PackageError("package must contain at least one tests/*.py file")


def build_package(
    files: Mapping[str, str],
    *,
    known_core_permissions: Collection[str],
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> BuiltPackage:
    """Build the canonical, immutable archive for a workspace file mapping."""
    if not isinstance(files, Mapping):
        raise PackageError("package files must be a mapping")
    normalized: dict[str, str] = {}
    for name, content in files.items():
        if not isinstance(name, str) or not isinstance(content, str):
            raise PackageError("package paths and contents must be text")
        _safe_name(name)
        if not allowed_path(name):
            raise PackageError(f"unsupported package path: {name}")
        if "\x00" in content:
            raise PackageError(f"binary or NUL content is not allowed: {name}")
        normalized[name] = content
    manifest = load_manifest(normalized)
    try:
        manifest = validate_manifest(
            manifest, known_core_permissions=known_core_permissions
        )
    except ManifestError as exc:
        raise PackageError("manifest invalid: " + "; ".join(exc.errors)) from exc
    validate_layout(normalized, manifest)

    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name in sorted(normalized):
            info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, normalized[name].encode("utf-8"))
    data = buffer.getvalue()
    if len(data) > limits.max_archive_bytes:
        raise PackageError(f"archive exceeds {limits.max_archive_bytes} bytes")
    return BuiltPackage(
        data=data,
        digest=digest_bytes(data),
        files=normalized,
        manifest=manifest,
    )


def parse_package(
    data: bytes,
    *,
    known_core_permissions: Collection[str],
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> BuiltPackage:
    files = read_zip(data, limits)
    manifest = load_manifest(files)
    try:
        manifest = validate_manifest(
            manifest, known_core_permissions=known_core_permissions
        )
    except ManifestError as exc:
        raise PackageError("manifest invalid: " + "; ".join(exc.errors)) from exc
    validate_layout(files, manifest)
    return BuiltPackage(
        data=data,
        digest=digest_bytes(data),
        files=files,
        manifest=manifest,
    )


def _workspace_error(path: Path, message: str) -> PackageError:
    return PackageError(f"{message}: {path.name}")


def read_workspace(
    root: Path,
    *,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> dict[str, str]:
    """Read a workspace without following links, hidden state or unsupported files."""
    root = Path(root)
    if root.is_symlink():
        raise PackageError("workspace root must not be a symlink")
    if not root.is_dir():
        raise PackageError("workspace is missing")
    files: dict[str, str] = {}
    expanded = 0
    for current, directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            candidate = current_path / directory
            if candidate.is_symlink():
                raise _workspace_error(candidate, "symlink is not allowed in workspace")
        for name in names:
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            if candidate.is_symlink():
                raise _workspace_error(candidate, "symlink is not allowed in workspace")
            try:
                _safe_name(relative)
            except PackageError as exc:
                raise PackageError(str(exc)) from exc
            if not allowed_path(relative):
                raise PackageError(f"unsupported workspace path: {relative}")
            if not candidate.is_file():
                raise PackageError(f"unsupported workspace entry: {relative}")
            size = candidate.stat().st_size
            if size > limits.max_file_bytes:
                raise PackageError(f"file exceeds {limits.max_file_bytes} bytes: {relative}")
            expanded += size
            if expanded > limits.max_expanded_bytes:
                raise PackageError(
                    f"workspace exceeds {limits.max_expanded_bytes} bytes"
                )
            try:
                data = candidate.read_bytes()
            except OSError as exc:
                raise PackageError(f"cannot read workspace file: {relative}") from exc
            files[relative] = _read_text(relative, data, limits)
            if len(files) > limits.max_entries:
                raise PackageError(f"workspace exceeds {limits.max_entries} files")
    return files
