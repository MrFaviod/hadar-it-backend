"""Bounded, import-free inspection of native extension packages.

The canonical manifest shape and cross-field semantics live in the SDK
contract resource (``itsm/extensions/sdk``).  This module owns only the host
side of admission: archive containment, immutable byte identity, required
package members, and the stdlib-only backend allowlist.  Candidate Python is
never imported or executed here.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import io
import json
import stat
import sys
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Collection, Mapping

from itsm.identity.permissions import PERMISSION_CODES

SDK_VERSION = 1
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024
MAX_EXPANDED_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 200
MAX_MEMBER_BYTES = 1024 * 1024
MAX_SKILLS = 64
MAX_TESTS = 64

REQUIRED_ROOT_FILES = ("extension.json", "backend.py", "frontend.js")
_ALLOWED_SUFFIXES = frozenset({".json", ".py", ".js", ".md", ".txt"})
_ALLOWED_COMPRESSION = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
_FORBIDDEN_PARTS = frozenset(
    {
        "__pycache__",
        ".git",
        ".hg",
        ".svn",
        ".github",
        ".pytest_cache",
        ".mypy_cache",
        "node_modules",
        "site-packages",
        "dist",
        "build",
        "venv",
        ".venv",
    }
)
_FORBIDDEN_FILENAMES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pipfile",
        "pipfile.lock",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "dockerfile",
        "makefile",
    }
)
_FORBIDDEN_SUFFIXES = (
    ".whl",
    ".egg",
    ".so",
    ".dll",
    ".dylib",
    ".exe",
    ".pyc",
    ".pyo",
    ".pth",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".jar",
    ".bin",
)


class PackageError(ValueError):
    """The package cannot be admitted for review."""


class ManifestValidationError(PackageError):
    """The canonical manifest contract rejected the declaration."""

    def __init__(self, errors: Collection[str]) -> None:
        self.errors = tuple(dict.fromkeys(str(error) for error in errors))[:40]
        super().__init__("; ".join(self.errors))


class ArgumentValidationError(PackageError):
    """Invocation arguments do not match the declared operation schema."""


@dataclass(frozen=True)
class PackageContents:
    """Validated, immutable package bytes plus the members the host needs."""

    digest: str
    package_bytes: bytes
    manifest: Mapping[str, Any]
    backend_source: str
    frontend_bytes: bytes
    frontend_source: str
    skill_sources: Mapping[str, str]
    test_files: tuple[str, ...]
    file_names: tuple[str, ...]


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def validate_manifest_dict(
    data: Any,
    *,
    known_core_permissions: Collection[str] = PERMISSION_CODES,
) -> dict[str, Any]:
    """Validate with the single T3-owned schema/semantic contract."""
    try:
        from itsm.extensions.sdk.contract import ManifestError, validate_manifest
    except ImportError as exc:  # pragma: no cover - packaging defect, not user input
        raise PackageError("the canonical extension contract is unavailable") from exc
    try:
        manifest = validate_manifest(data, known_core_permissions=known_core_permissions)
    except ManifestError as exc:
        raise ManifestValidationError(exc.errors) from None
    if not isinstance(manifest, dict):
        raise PackageError("the canonical extension contract returned an invalid manifest")
    return manifest


def validate_arguments(parameters: Mapping[str, Any], arguments: Mapping[str, Any]) -> None:
    """Validate invocation arguments with the same SDK contract as the package."""
    try:
        from itsm.extensions.sdk.contract import ArgumentError, validate_arguments as check
    except ImportError as exc:  # pragma: no cover
        raise PackageError("the canonical extension contract is unavailable") from exc
    try:
        check(parameters, arguments)
    except ArgumentError as exc:
        raise ArgumentValidationError(str(exc)) from None


def permission_codes(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(item["code"] for item in manifest["permissions"])


def version_key(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    if len(parts) != 3:
        raise PackageError("version must be strict X.Y.Z")
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        raise PackageError("version must be strict X.Y.Z") from None


def migration_plan(
    manifest: Mapping[str, Any],
    from_schema: int,
    to_schema: int,
) -> tuple[Mapping[str, Any], ...] | None:
    """Plan revisions for existing data; a new namespace starts empty."""
    if from_schema == 0 or from_schema == to_schema:
        return ()
    if from_schema > to_schema:
        return None
    by_from = {item["from"]: item for item in manifest["migrations"]}
    steps: list[Mapping[str, Any]] = []
    current = from_schema
    while current != to_schema:
        step = by_from.get(current)
        if step is None or len(steps) >= 64:
            return None
        steps.append(step)
        current = step["to"]
        if current > to_schema:
            return None
    return tuple(steps)


def _clean_name(name: str) -> str:
    if not isinstance(name, str) or not name:
        raise PackageError("package member name is empty")
    if "\x00" in name or "\\" in name or name.startswith("/"):
        raise PackageError(f"package member path is not relative: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise PackageError(f"package member path escapes the package: {name!r}")
    if path.as_posix() != name:
        raise PackageError(f"package member path is not canonical: {name!r}")
    lowered = {part.casefold() for part in path.parts}
    if lowered & _FORBIDDEN_PARTS:
        raise PackageError(f"package member path uses a forbidden directory: {name}")
    filename = path.name.casefold()
    if filename in _FORBIDDEN_FILENAMES:
        raise PackageError(f"package contains a forbidden dependency file: {name}")
    if filename.startswith("requirements") and filename.endswith(".txt"):
        raise PackageError(f"package contains a forbidden dependency file: {name}")
    if filename.endswith(_FORBIDDEN_SUFFIXES):
        raise PackageError(f"package contains a native or archive dependency: {name}")
    if path.suffix.casefold() not in _ALLOWED_SUFFIXES:
        raise PackageError(f"package member type is not supported: {name}")
    if filename.startswith(".") and name != ".gitignore":
        raise PackageError(f"package contains a hidden file: {name}")
    return name


def _member_bytes(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    if info.flag_bits & 0x1:
        raise PackageError(f"encrypted package member is not allowed: {info.filename}")
    mode = (info.external_attr >> 16) & 0xFFFF
    if mode and stat.S_IFMT(mode) not in (stat.S_IFREG, 0):
        raise PackageError(f"package member is not a regular file: {info.filename}")
    if info.is_dir() or info.filename.endswith("/"):
        raise PackageError(f"package directories are not allowed: {info.filename}")
    if info.compress_type not in _ALLOWED_COMPRESSION:
        raise PackageError(f"package member compression is not supported: {info.filename}")
    if info.file_size < 0 or info.file_size > MAX_MEMBER_BYTES:
        raise PackageError(f"package member is too large: {info.filename}")
    with archive.open(info) as handle:
        value = handle.read(MAX_MEMBER_BYTES + 1)
    if len(value) != info.file_size:
        raise PackageError(f"package member size is inconsistent: {info.filename}")
    if len(value) > MAX_MEMBER_BYTES:
        raise PackageError(f"package member is too large: {info.filename}")
    return value


def _decode(name: str, value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        raise PackageError(f"package member is not UTF-8 text: {name}") from None


def _check_backend_imports(source: str) -> None:
    try:
        tree = ast.parse(source, filename="backend.py")
    except SyntaxError as exc:
        raise PackageError(f"backend.py does not parse: {exc.msg}") from None
    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root not in stdlib:
                    raise PackageError(f"backend.py may import only the standard library: {root}")
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise PackageError("backend.py may not use relative imports")
            root = (node.module or "").split(".", 1)[0]
            if root not in stdlib:
                raise PackageError(f"backend.py may import only the standard library: {root}")


def _declared_skills(manifest: Mapping[str, Any]) -> dict[str, str]:
    skills = manifest["skills"]
    if len(skills) > MAX_SKILLS:
        raise PackageError("package declares too many skills")
    return {item["path"]: item["name"] for item in skills}


def inspect_package(
    package_bytes: bytes,
    *,
    expected_digest: str | None = None,
    known_core_permissions: Collection[str] = PERMISSION_CODES,
) -> PackageContents:
    """Validate a bounded ZIP and return immutable, import-free contents."""
    if not isinstance(package_bytes, (bytes, bytearray)):
        raise PackageError("package must be raw bytes")
    data = bytes(package_bytes)
    if not data:
        raise PackageError("package is empty")
    if len(data) > MAX_ARCHIVE_BYTES:
        raise PackageError("package archive is too large")
    digest = digest_bytes(data)
    if expected_digest is not None:
        if (
            not isinstance(expected_digest, str)
            or len(expected_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in expected_digest.lower())
        ):
            raise PackageError("expected digest must be a lowercase SHA-256 hex value")
        if not hmac.compare_digest(digest, expected_digest.lower()):
            raise PackageError("package digest does not match the submitted digest")

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise PackageError("package is not a valid ZIP archive") from None
    try:
        infos = archive.infolist()
        if len(infos) > MAX_ENTRIES:
            raise PackageError("package contains too many members")
        names: list[str] = []
        seen: set[str] = set()
        expanded = 0
        members: dict[str, bytes] = {}
        for info in infos:
            name = _clean_name(info.filename)
            folded = name.casefold()
            if folded in seen:
                raise PackageError(f"package contains a duplicate path: {name}")
            seen.add(folded)
            expanded += max(info.file_size, 0)
            if expanded > MAX_EXPANDED_BYTES:
                raise PackageError("package expands beyond the size limit")
            value = _member_bytes(archive, info)
            members[name] = value
            names.append(name)
    except zipfile.BadZipFile:
        raise PackageError("package is not a valid ZIP archive") from None
    finally:
        archive.close()

    for required in REQUIRED_ROOT_FILES:
        if required not in members:
            raise PackageError(f"package is missing required root file: {required}")

    manifest_source = _decode("extension.json", members["extension.json"])
    try:
        raw_manifest = json.loads(manifest_source)
    except json.JSONDecodeError as exc:
        raise PackageError(f"extension.json is not valid JSON: {exc.msg}") from None
    manifest = validate_manifest_dict(
        raw_manifest, known_core_permissions=known_core_permissions
    )

    skill_paths = _declared_skills(manifest)
    for path in skill_paths:
        if path not in members:
            raise PackageError(f"package is missing declared skill: {path}")
        if not _decode(path, members[path]).strip():
            raise PackageError(f"declared skill is empty: {path}")

    frontend_bytes = members["frontend.js"]
    if not frontend_bytes.strip():
        raise PackageError("frontend.js is empty")
    frontend_source = _decode("frontend.js", frontend_bytes)
    backend_source = _decode("backend.py", members["backend.py"])
    if not backend_source.strip():
        raise PackageError("backend.py is empty")
    _check_backend_imports(backend_source)

    test_files = tuple(
        name for name in names if name.startswith("tests/") and name.endswith(".py")
    )
    if not test_files:
        raise PackageError("package must include at least one tests/*.py file")
    if len(test_files) > MAX_TESTS:
        raise PackageError("package declares too many test files")
    for name in test_files:
        _decode(name, members[name])

    return PackageContents(
        digest=digest,
        package_bytes=data,
        manifest=manifest,
        backend_source=backend_source,
        frontend_bytes=frontend_bytes,
        frontend_source=frontend_source,
        skill_sources={path: _decode(path, members[path]) for path in skill_paths},
        test_files=test_files,
        file_names=tuple(names),
    )
