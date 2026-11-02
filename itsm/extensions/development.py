"""Actor-owned extension workspaces and the shared chat/MCP method dispatcher.

The API never exposes a shell, HTTP, SQL or arbitrary-filesystem tool. All
writes happen after a live canonical authorization check inside the requested
operation. The constructor is lazy: it does not create the server-owned root
or any workspace during application startup.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Any

from babel import Locale
from babel.core import UnknownLocaleError
from sqlalchemy import select
from sqlalchemy.orm import Session

from itsm import __version__ as CORE_VERSION
from itsm.extensions import storage
from itsm.extensions.sdk.contract import SDK_VERSION, ManifestError
from itsm.extensions.sdk.generator import generate_package, write_package
from itsm.extensions.sdk.package import (
    DEFAULT_LIMITS,
    PackageError,
    build_package,
    read_workspace,
)
from itsm.i18n import packs, registry
from itsm.i18n.catalog import CATALOG_DIR
from itsm.i18n.messages import plural_categories
from itsm.i18n.models import I18nProvider
from itsm.i18n.packs import CatalogError
from itsm.identity.service import IdentityError, PermissionDenied

WORKSPACE_ID = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
TEST_FILE = re.compile(r"^tests/[a-z0-9_]{1,64}\.py$")
I18N_FILE = re.compile(r"^i18n/[A-Za-z0-9][A-Za-z0-9._-]*\.json$")
I18N_DEFAULT_PAGE = 50
I18N_MAX_PAGE = 200
I18N_NAMESPACES = frozenset({"api", "ui", "ext"})
I18N_PACK_PRIORITY = 10
I18N_PACK_VERSION = "1.0.0"
SAFE_ACTOR = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
MAX_REFERENCE_BYTES = 24_384
MAX_DESCRIPTION = 1024
DEFAULT_WORKSPACE_FILES = 2 * 1024 * 1024
DEFAULT_FILE_BYTES = 512 * 1024
VALIDATION_FILE = "_validation.json"

REFERENCE_INDEX: tuple[tuple[str, str, str], ...] = (
    ("quickstart", "Quickstart", "Generate, edit, validate and submit a package."),
    ("lifecycle", "Lifecycle", "Workspace, candidate, approval, install and rollback."),
    ("manifest", "Manifest", "Exact extension.json fields and constraints."),
    ("backend", "Backend", "register(sdk), handler context and store contract."),
    (
        "frontend",
        "Frontend",
        "Declarative host-rendered views; isolated iframe components only.",
    ),
    ("collections", "Collections", "Namespaced durable data and optimistic versions."),
    (
        "events",
        "Events and reconcile",
        "Core change subscriptions, declarative references and repair paths.",
    ),
    ("migrations", "Migrations", "Ordered explicit data migrations and rollback."),
    ("security", "Security", "Trusted native code, permissions and package safety."),
    ("validation", "Validation", "Fixed offline container checks and report."),
    (
        "i18n",
        "Languages and language packs",
        "Discover keys, validate translations and package a draft language pack.",
    ),
    (
        "workspace-tools",
        "Workspace tools",
        "Shared chat/MCP methods, ownership and bounded paths.",
    ),
)
REFERENCE_ROOT = Path(__file__).resolve().parent / "sdk" / "references"
SCHEMA_RESOURCE = "schema/extension.schema.json"


class DevelopmentError(IdentityError):
    """Base error with a safe HTTP status for the parent dispatcher wrapper."""

    code = "extension_development_error"
    http_status = 400


class InvalidArguments(DevelopmentError):
    code = "invalid_arguments"
    http_status = 422


class WorkspaceNotFound(DevelopmentError):
    code = "workspace_not_found"
    http_status = 404


class WorkspaceConflict(DevelopmentError):
    code = "workspace_conflict"
    http_status = 409


class WorkspacePathRejected(DevelopmentError):
    code = "workspace_path_rejected"
    http_status = 422


class WorkspaceLimitExceeded(DevelopmentError):
    code = "workspace_limit_exceeded"
    http_status = 413


class ValidationRequired(DevelopmentError):
    code = "validation_required"
    http_status = 409


class DevelopmentUnavailable(DevelopmentError):
    code = "extension_development_unavailable"
    http_status = 503


@dataclass(frozen=True)
class _Workspace:
    workspace_id: str
    root: Path
    name: str
    description: str


def _text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise InvalidArguments(f"{field} must be text")
    cleaned = value.strip()
    if not cleaned:
        raise InvalidArguments(f"{field} is required")
    if len(cleaned) > maximum:
        raise InvalidArguments(f"{field} must be at most {maximum} characters")
    if any(ord(character) < 32 for character in cleaned):
        raise InvalidArguments(f"{field} must not contain control characters")
    return cleaned


def _arguments(value: Any, allowed: set[str], required: set[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise InvalidArguments("arguments must be an object")
    unknown = set(value) - allowed
    if unknown:
        raise InvalidArguments("unknown arguments: " + ", ".join(sorted(unknown)))
    missing = required - set(value)
    if missing:
        raise InvalidArguments("missing arguments: " + ", ".join(sorted(missing)))
    return dict(value)


def _atomic_text(path: Path, content: str, mode: int = 0o600) -> None:
    """Write a server-owned metadata/source file without following links."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".itsm-sdk-", dir=path.parent, text=False)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content.encode("utf-8"))
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _failure(digest: str, error: str) -> dict[str, Any]:
    return {
        "status": "failed",
        "digest": digest if re.fullmatch(r"[0-9a-f]{64}", digest or "") else "",
        "sdkVersion": SDK_VERSION,
        "checks": [{"name": "development", "status": "failed", "detail": error[:1000]}],
        "errors": [error[:1000]],
        "container": {
            "image": "not-run",
            "runtime": "development",
            "network": "none",
            "readOnly": True,
            "nonRoot": True,
            "capabilities": "dropped",
            "engine": "unavailable",
            "limits": (
                f"archive={DEFAULT_LIMITS.max_archive_bytes}; "
                f"expanded={DEFAULT_LIMITS.max_expanded_bytes}; "
                f"entries={DEFAULT_LIMITS.max_entries}; "
                f"file={DEFAULT_LIMITS.max_file_bytes}"
            ),
        },
        "completedAt": datetime.now(UTC).isoformat(),
    }


def _report_is_passed(report: Any, digest: str) -> bool:
    return (
        isinstance(report, dict)
        and report.get("status") == "passed"
        and report.get("digest") == digest
        and report.get("sdkVersion") == SDK_VERSION
        and isinstance(report.get("checks"), list)
        and isinstance(report.get("errors"), list)
        and not report["errors"]
    )


class DevelopmentService:
    """Bounded extension development plus the shared eight-method dispatcher."""

    def __init__(
        self,
        root: Path | str,
        *,
        session_factory: Callable[..., Any],
        identity_factory: Callable[[Any], Any],
        validator: Any,
        host: Any | None = None,
        submitter: Callable[..., Mapping[str, Any]] | None = None,
        permission: str = "system.modules",
        known_core_permissions: Collection[str] | None = None,
        file_bytes_limit: int = DEFAULT_FILE_BYTES,
        workspace_bytes_limit: int = DEFAULT_WORKSPACE_FILES,
        max_workspaces: int = 25,
    ) -> None:
        if (
            not isinstance(file_bytes_limit, int)
            or isinstance(file_bytes_limit, bool)
            or not 1024 <= file_bytes_limit <= 4 * 1024 * 1024
        ):
            raise ValueError("file_bytes_limit must be between 1 KiB and 4 MiB")
        if (
            not isinstance(workspace_bytes_limit, int)
            or isinstance(workspace_bytes_limit, bool)
            or workspace_bytes_limit < file_bytes_limit
            or workspace_bytes_limit > 32 * 1024 * 1024
        ):
            raise ValueError("workspace_bytes_limit must be bounded and >= file limit")
        if not isinstance(max_workspaces, int) or isinstance(max_workspaces, bool):
            raise ValueError("max_workspaces must be an integer")
        if not 1 <= max_workspaces <= 200:
            raise ValueError("max_workspaces must be between 1 and 200")
        if not isinstance(permission, str) or not permission:
            raise ValueError("permission must be a non-empty code")
        self._root = Path(root).expanduser()
        self._session_factory = session_factory
        self._identity_factory = identity_factory
        self._validator = validator
        self._host = host
        self._submitter = submitter
        self._permission = permission
        self._known_core = sorted(set(known_core_permissions or ()))
        self.file_bytes_limit = file_bytes_limit
        self.workspace_bytes_limit = workspace_bytes_limit
        self.max_workspaces = max_workspaces

    # ------------------------------------------------------------------ public

    def dispatch(self, method: str, arguments: Any, principal: Any) -> dict[str, Any]:
        """Authorize the trusted principal, then execute one bounded method."""
        if not isinstance(method, str) or method not in _METHODS:
            raise InvalidArguments("unknown extension development method")
        self._authorize(principal)
        data = arguments if isinstance(arguments, Mapping) else {}
        handler = _METHODS[method]
        result = handler(self, data, principal)
        if not isinstance(result, dict):
            raise DevelopmentError("extension development method returned no object")
        return result

    def workspace_root(self, principal: Any, workspace_id: str) -> Path:
        """Return one actor-owned workspace root after live authorization."""
        self._authorize(principal)
        workspace = self._workspace(principal, workspace_id)
        return workspace.root

    # ------------------------------------------------------------- SDK refs

    def _sdk_index(self, arguments: Any, principal: Any) -> dict[str, Any]:
        _arguments(arguments, set(), set())
        return {
            "sdkVersion": SDK_VERSION,
            "schema": SCHEMA_RESOURCE,
            "trust": "trusted-native",
            "notice": (
                "Approved extensions are trusted native code in the host process, "
                "not hostile-code isolation. Human approval is required."
            ),
            "references": [
                {"name": name, "title": title, "summary": summary}
                for name, title, summary in REFERENCE_INDEX
            ],
            "limits": {
                "archiveBytes": DEFAULT_LIMITS.max_archive_bytes,
                "expandedBytes": DEFAULT_LIMITS.max_expanded_bytes,
                "entries": DEFAULT_LIMITS.max_entries,
                "fileBytes": DEFAULT_LIMITS.max_file_bytes,
                "hint": "references/validation.md",
            },
        }

    def _sdk_reference(self, arguments: Any, principal: Any) -> dict[str, Any]:
        data = _arguments(arguments, {"name"}, {"name"})
        name = data["name"]
        entry = next(
            (item for item in REFERENCE_INDEX if item[0] == name),
            None,
        )
        if entry is None or not isinstance(name, str):
            raise InvalidArguments("unknown SDK reference")
        path = REFERENCE_ROOT / f"{name}.md"
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(REFERENCE_ROOT.resolve())
            content = resolved.read_text(encoding="utf-8")
        except (OSError, ValueError) as exc:
            raise DevelopmentUnavailable("SDK reference is unavailable") from exc
        if len(content.encode("utf-8")) > MAX_REFERENCE_BYTES:
            raise DevelopmentUnavailable("SDK reference exceeds the bounded size")
        return {
            "sdkVersion": SDK_VERSION,
            "name": entry[0],
            "title": entry[1],
            "summary": entry[2],
            "content": content,
        }

    # ------------------------------------------------------------ workspaces

    def _workspace_create(self, arguments: Any, principal: Any) -> dict[str, Any]:
        data = _arguments(arguments, {"id", "name", "description"}, {"id", "name"})
        workspace_id = data["id"]
        if not isinstance(workspace_id, str) or not WORKSPACE_ID.fullmatch(workspace_id):
            raise InvalidArguments("workspace id is invalid")
        if len(workspace_id) < 2 or len(workspace_id) > 48:
            raise InvalidArguments("workspace id must be between 2 and 48 characters")
        name = _text(data["name"], "name", 120)
        description = _text(
            data.get("description", "Registros internos de ejemplo."),
            "description",
            MAX_DESCRIPTION,
        )
        actor_root = self._actor_root(principal, create=True)
        workspaces = actor_root / "workspaces"
        self._assert_directory_safe(actor_root)
        self._assert_directory_safe(workspaces, create=True)
        if self._workspace_count(actor_root) >= self.max_workspaces:
            raise WorkspaceLimitExceeded("workspace limit reached")
        target = workspaces / workspace_id
        if target.exists() or target.is_symlink():
            raise WorkspaceConflict("workspace already exists")
        package = generate_package(
            extension_id=workspace_id,
            name=name,
            description=description,
            known_core_permissions=self._known_core,
        )
        write_package(target, package)
        metadata = {
            "id": workspace_id,
            "name": name,
            "description": description,
            "createdAt": self._now(),
        }
        _atomic_text(
            actor_root / "meta" / f"{workspace_id}.json",
            json.dumps(metadata, ensure_ascii=False),
        )
        return {
            "id": workspace_id,
            "name": name,
            "description": description,
            "files": sorted(package.files),
            "validation": None,
        }

    def _workspace_files(self, arguments: Any, principal: Any) -> dict[str, Any]:
        data = _arguments(arguments, {"workspace_id"}, set())
        if "workspace_id" not in data:
            actor_root = self._actor_root(principal)
            return {"workspaces": self._list_workspaces(actor_root)}
        workspace = self._workspace(principal, data["workspace_id"])
        return self._listing(workspace)

    def _workspace_read(self, arguments: Any, principal: Any) -> dict[str, Any]:
        data = _arguments(arguments, {"workspace_id", "path"}, {"workspace_id", "path"})
        workspace = self._workspace(principal, data["workspace_id"])
        path = self._package_path(workspace.workspace_id, data["path"])
        files = self._package_files(workspace)
        if path not in files:
            raise WorkspaceNotFound("workspace file not found")
        return {
            "workspace": self._workspace_payload(workspace),
            "path": path,
            "content": files[path],
        }

    def _workspace_write(self, arguments: Any, principal: Any) -> dict[str, Any]:
        data = _arguments(
            arguments, {"workspace_id", "path", "content"}, {"workspace_id", "path", "content"}
        )
        workspace = self._workspace(principal, data["workspace_id"])
        path = self._package_path(workspace.workspace_id, data["path"])
        content = data["content"]
        if not isinstance(content, str):
            raise InvalidArguments("content must be text")
        encoded = content.encode("utf-8")
        if len(encoded) > self.file_bytes_limit:
            raise WorkspaceLimitExceeded("file exceeds the workspace file limit")
        if "\x00" in content:
            raise WorkspacePathRejected("binary content is not allowed")
        files = self._package_files(workspace)
        projected = sum(
            len(value.encode("utf-8")) for name, value in files.items() if name != path
        ) + len(encoded)
        if projected > self.workspace_bytes_limit:
            raise WorkspaceLimitExceeded("workspace byte limit exceeded")
        destination = workspace.root / path
        self._assert_file_parent_safe(workspace.root, destination)
        _atomic_text(destination, content)
        self._clear_validation(workspace)
        return {
            "workspace": self._workspace_payload(workspace),
            "path": path,
            "bytes": len(encoded),
            "validation": "invalidated",
        }

    def _workspace_validate(self, arguments: Any, principal: Any) -> dict[str, Any]:
        data = _arguments(arguments, {"workspace_id"}, {"workspace_id"})
        workspace = self._workspace(principal, data["workspace_id"])
        try:
            files = self._package_files(workspace)
            built = build_package(files, known_core_permissions=self._known_core)
        except (PackageError, ManifestError, WorkspacePathRejected, OSError) as exc:
            report = _failure("", f"package preflight failed: {exc}")
            self._persist_validation(workspace, report)
            return report

        try:
            report = self._validator.validate(built.data, digest=built.digest)
        except Exception as exc:
            if _is_unavailable(exc):
                raise
            report = _failure(built.digest, f"validator failed: {type(exc).__name__}")

        if not isinstance(report, dict) or report.get("digest") != built.digest:
            report = _failure(built.digest, "validation digest does not match the package bytes")
        elif report.get("status") not in ("passed", "failed"):
            report = _failure(built.digest, "validation status is invalid")
        elif report.get("status") == "failed" and not report.get("errors"):
            report = dict(report)
            report["errors"] = ["validation failed without a reported error"]
        self._persist_validation(workspace, report)
        return report

    def _workspace_submit(self, arguments: Any, principal: Any) -> dict[str, Any]:
        data = _arguments(arguments, {"workspace_id"}, {"workspace_id"})
        workspace = self._workspace(principal, data["workspace_id"])
        stored = self._validation_state(workspace)
        if not stored or stored.get("status") != "passed":
            raise ValidationRequired("validate the workspace before submitting")
        try:
            files = self._package_files(workspace)
            built = build_package(files, known_core_permissions=self._known_core)
        except (PackageError, ManifestError, WorkspacePathRejected, OSError) as exc:
            self._clear_validation(workspace)
            raise ValidationRequired(f"workspace changed: {exc}") from exc
        if stored.get("digest") != built.digest:
            self._clear_validation(workspace)
            raise ValidationRequired("workspace source changed since validation")
        report = stored.get("report")
        if not _report_is_passed(report, built.digest):
            raise ValidationRequired("the stored validation report is not passed")
        if self._host is None and self._submitter is None:
            raise DevelopmentUnavailable("extension host is unavailable")

        try:
            if self._submitter is not None:
                detail = self._submitter(principal, built.data, built.digest)
                if not isinstance(detail, Mapping):
                    raise DevelopmentUnavailable("extension host returned no candidate")
                candidate_id = detail.get("id")
                revision = detail.get("revision")
                if not candidate_id:
                    raise DevelopmentUnavailable("extension host returned no candidate id")
                record = getattr(self._host, "record_validation_report", None)
                if record is None:
                    raise DevelopmentUnavailable("extension host cannot record validation evidence")
                record(candidate_id, report, expected_version=revision)
            else:
                submit = getattr(self._host, "submit_candidate", None)
                if submit is None:
                    raise DevelopmentUnavailable("extension host cannot accept candidates")
                detail = submit(principal, built.data, expected_digest=built.digest)
                if not isinstance(detail, Mapping):
                    raise DevelopmentUnavailable("extension host returned no candidate")
                candidate_id = detail.get("id")
                revision = detail.get("revision")
                if not candidate_id:
                    raise DevelopmentUnavailable("extension host returned no candidate id")
                record = getattr(self._host, "record_validation_report", None)
                if record is None:
                    raise DevelopmentUnavailable("extension host cannot record validation evidence")
                record(candidate_id, report, expected_version=revision)
        except DevelopmentError:
            raise
        except Exception as exc:
            if _is_unavailable(exc):
                raise DevelopmentUnavailable(str(exc)) from exc
            raise DevelopmentError("extension host rejected the candidate") from exc
        return dict(detail)

    # --------------------------------------------------------------- helpers

    def _authorize(self, principal: Any) -> None:
        if principal is None or not getattr(principal, "actor_id", None):
            raise PermissionDenied(
                "permission denied", key="api.extensions.permission_denied", params={}
            )
        with self._session_factory() as session:
            identity = self._identity_factory(session)
            identity.authorize(principal, self._permission, resource="extensions:development")

    def _actor_root(self, principal: Any, *, create: bool = False) -> Path:
        actor = getattr(principal, "actor_id", None)
        if not isinstance(actor, str) or not actor:
            raise PermissionDenied(
                "permission denied", key="api.extensions.permission_denied", params={}
            )
        key = hashlib.sha256(actor.encode("utf-8")).hexdigest()[:32]
        root = self._root / key
        if create:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                os.chmod(root, 0o700)
            except OSError:
                pass
        return root

    def _workspace(self, principal: Any, workspace_id: Any) -> _Workspace:
        if not isinstance(workspace_id, str) or not WORKSPACE_ID.fullmatch(workspace_id):
            raise InvalidArguments("workspace id is invalid")
        actor_root = self._actor_root(principal)
        root = actor_root / "workspaces" / workspace_id
        try:
            root.relative_to(actor_root)
        except ValueError as exc:
            raise WorkspacePathRejected("workspace escapes its actor root") from exc
        if root.is_symlink() or not root.is_dir():
            raise WorkspaceNotFound("workspace not found")
        metadata = self._metadata(actor_root, workspace_id)
        return _Workspace(
            workspace_id=workspace_id,
            root=root,
            name=metadata.get("name", workspace_id),
            description=metadata.get("description", ""),
        )

    def _metadata(self, actor_root: Path, workspace_id: str) -> dict[str, Any]:
        path = actor_root / "meta" / f"{workspace_id}.json"
        try:
            content = json.loads(path.read_text(encoding="utf-8"))
        except OSError, json.JSONDecodeError, UnicodeDecodeError:
            return {"id": workspace_id}
        return content if isinstance(content, dict) else {"id": workspace_id}

    def _workspace_count(self, actor_root: Path) -> int:
        directory = actor_root / "workspaces"
        if not directory.is_dir() or directory.is_symlink():
            return 0
        return sum(1 for item in directory.iterdir() if item.is_dir() and not item.is_symlink())

    def _list_workspaces(self, actor_root: Path) -> list[dict[str, Any]]:
        directory = actor_root / "workspaces"
        if not directory.is_dir() or directory.is_symlink():
            return []
        workspaces = []
        for item in sorted(directory.iterdir(), key=lambda path: path.name):
            if not item.is_dir() or item.is_symlink():
                continue
            if not WORKSPACE_ID.fullmatch(item.name):
                continue
            metadata = self._metadata(actor_root, item.name)
            stored = self._read_validation(actor_root, item.name)
            workspaces.append(
                {
                    "id": item.name,
                    "name": metadata.get("name", item.name),
                    "description": metadata.get("description", ""),
                    "validation": (
                        {"status": stored.get("status"), "digest": stored.get("digest")}
                        if stored
                        else None
                    ),
                }
            )
        return workspaces

    def _listing(self, workspace: _Workspace) -> dict[str, Any]:
        files = self._package_files(workspace)
        return {
            "workspace": self._workspace_payload(workspace),
            "files": [
                {"path": name, "bytes": len(value.encode("utf-8"))}
                for name, value in sorted(files.items())
            ],
        }

    def _workspace_payload(self, workspace: _Workspace) -> dict[str, Any]:
        stored = self._validation_state(workspace)
        validation = None
        if stored:
            validation = {
                "status": stored.get("status"),
                "digest": stored.get("digest"),
                "updatedAt": stored.get("updatedAt"),
            }
        return {
            "id": workspace.workspace_id,
            "name": workspace.name,
            "description": workspace.description,
            "validation": validation,
        }

    def _package_files(self, workspace: _Workspace) -> dict[str, str]:
        try:
            files = read_workspace(workspace.root)
        except PackageError as exc:
            raise WorkspacePathRejected(str(exc)) from exc
        return files

    def _package_path(self, workspace_id: str, path: Any) -> str:
        if not isinstance(path, str) or not path:
            raise InvalidArguments("path must be text")
        if (
            path in ("extension.json", "backend.py", "frontend.js")
            or path == f"skills/{workspace_id}/SKILL.md"
            or TEST_FILE.fullmatch(path) is not None
            or I18N_FILE.fullmatch(path) is not None
        ):
            pure = PurePosixPath(path)
            if pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
                raise WorkspacePathRejected("path escapes the workspace")
            return path
        raise WorkspacePathRejected("unsupported workspace path")

    def _assert_directory_safe(self, path: Path, *, create: bool = False) -> None:
        if create:
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink() or not path.is_dir():
            raise WorkspacePathRejected("workspace directory is not safe")

    def _assert_file_parent_safe(self, root: Path, destination: Path) -> None:
        try:
            destination.relative_to(root)
        except ValueError as exc:
            raise WorkspacePathRejected("path escapes the workspace") from exc
        current = root
        for part in destination.relative_to(root).parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise WorkspacePathRejected("path contains a symlink")
            if current.exists() and not current.is_dir():
                raise WorkspacePathRejected("path component is not a directory")
        if destination.is_symlink():
            raise WorkspacePathRejected("destination is a symlink")

    def _validation_path(self, actor_root: Path, workspace_id: str) -> Path:
        return actor_root / "validation" / f"{workspace_id}.json"

    def _validation_state(self, workspace: _Workspace) -> dict[str, Any] | None:
        actor_root = workspace.root.parent.parent
        return self._read_validation(actor_root, workspace.workspace_id)

    def _read_validation(self, actor_root: Path, workspace_id: str) -> dict[str, Any] | None:
        path = self._validation_path(actor_root, workspace_id)
        try:
            stored = json.loads(path.read_text(encoding="utf-8"))
        except OSError, json.JSONDecodeError, UnicodeDecodeError:
            return None
        if not isinstance(stored, dict):
            return None
        report = stored.get("report")
        if not isinstance(report, dict):
            return None
        return stored

    def _persist_validation(self, workspace: _Workspace, report: dict[str, Any]) -> None:
        actor_root = workspace.root.parent.parent
        directory = actor_root / "validation"
        if directory.is_symlink():
            raise WorkspacePathRejected("validation directory is not safe")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        stored = {
            "status": report.get("status"),
            "digest": report.get("digest"),
            "updatedAt": self._now(),
            "report": report,
        }
        _atomic_text(
            self._validation_path(actor_root, workspace.workspace_id),
            json.dumps(stored, ensure_ascii=False),
        )

    def _clear_validation(self, workspace: _Workspace) -> None:
        actor_root = workspace.root.parent.parent
        path = self._validation_path(actor_root, workspace.workspace_id)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise WorkspaceConflict("validation state could not be invalidated") from exc

    def _contract_gap(self, arguments: Mapping[str, Any], principal: Any) -> dict[str, Any]:
        """Record a missing public contract instead of editing private structures."""
        self._authorize(principal)
        extension_id = arguments.get("extensionId") or "sdk"
        if not isinstance(extension_id, str) or not WORKSPACE_ID.fullmatch(extension_id):
            raise InvalidArguments("extensionId must be a valid extension id")
        capability = _gap_text(arguments.get("capability"), "capability", 200)
        reason = _gap_text(arguments.get("reason"), "reason", 1024)
        example = _gap_text(arguments.get("example"), "example", 1024)
        with self._session_factory() as session:
            storage.record_event(
                session,
                extension_id=extension_id,
                action="extension.contract_gap",
                actor_id=principal.actor_id,
                detail={"capability": capability, "reason": reason, "example": example},
            )
            session.commit()
        return {
            "recorded": True,
            "extensionId": extension_id,
            "capability": capability,
        }

    # --------------------------------------------------------- language packs

    def _i18n_keys(self, arguments: Any, principal: Any) -> dict[str, Any]:
        """Every source key with its translator context, bounded and filterable.

        The source of truth is the core ``es`` catalog plus the source catalogs
        of installed modules; pack contributions never change what is translated.
        """
        data = _arguments(arguments, {"namespace", "prefix", "limit", "offset"}, set())
        include, prefix = _i18n_filter(data)
        limit, offset = _i18n_page(data)
        with self._session_factory() as session:
            sources = _i18n_sources(session)
        context = _translator_context()
        keys = [key for key in sorted(sources.messages) if _i18n_selected(key, include, prefix)]
        page = keys[offset : offset + limit]
        return {
            "total": len(keys),
            "limit": limit,
            "offset": offset,
            "keys": [
                {
                    "key": key,
                    "namespace": packs.key_namespace(key) or "",
                    "source": sources.owners.get(key, "core"),
                    "context": context.get(key),
                    "message": sources.messages[key],
                }
                for key in page
            ],
        }

    def _i18n_missing(self, arguments: Any, principal: Any) -> dict[str, Any]:
        """Source keys the target locale still lacks, fallback chain included."""
        data = _arguments(
            arguments, {"locale", "namespace", "prefix", "limit", "offset"}, {"locale"}
        )
        tag, display = _i18n_pack_tag(data["locale"])
        include, prefix = _i18n_filter(data)
        limit, offset = _i18n_page(data)
        with self._session_factory() as session:
            sources = _i18n_sources(session)
            snapshot = registry.snapshot(session)
        chain = tuple(
            candidate for candidate in registry.tag_chain(tag) if candidate in snapshot.locale_views
        )
        covered: set[str] = set()
        for installed in chain:
            view = snapshot.locale_views.get(installed)
            if view is not None:
                covered.update(view.messages)
        missing = [
            key
            for key in sorted(sources.messages)
            if key not in covered and _i18n_selected(key, include, prefix)
        ]
        page = missing[offset : offset + limit]
        return {
            "locale": display,
            "sourceLocale": "es",
            "chain": list(chain),
            "total": len(missing),
            "limit": limit,
            "offset": offset,
            "missing": [
                {
                    "key": key,
                    "namespace": packs.key_namespace(key) or "",
                    "source": sources.owners.get(key, "core"),
                }
                for key in page
            ],
        }

    def _i18n_validate(self, arguments: Any, principal: Any) -> dict[str, Any]:
        """Check a draft catalog with the same rules the host applies on install."""
        data = _arguments(arguments, {"locale", "catalog", "overrides"}, {"locale", "catalog"})
        tag, display = _i18n_pack_tag(data["locale"])
        overrides = _i18n_overrides(data.get("overrides"))
        errors: list[str] = []
        catalog: dict[str, str] = {}
        value = data["catalog"]
        try:
            if isinstance(value, str):
                catalog = packs.parse_catalog(value, name=tag)
            elif isinstance(value, Mapping):
                catalog = _i18n_catalog_object(value)
            else:
                raise InvalidArguments("catalog must be an object or JSON text")
        except CatalogError as exc:
            errors.append(str(exc))
        except InvalidArguments as exc:
            errors.append(str(exc))
        with self._session_factory() as session:
            sources = _i18n_sources(session)
            owners = registry.owner_catalogs(session).get(registry.canonical_tag(tag) or tag, {})
        categories = plural_categories(tag)
        source_categories = plural_categories("es")
        for key in sorted(catalog):
            message = catalog[key]
            errors.extend(packs.key_errors(key))
            source = sources.messages.get(key)
            if source is None:
                errors.append(f"{key}: no source message defines this key")
            else:
                errors.extend(packs.validate_translation(key, tag, message, source, "es"))
                if len(packs.plural_forms(source)) > 1 and categories != source_categories:
                    forms = len(packs.plural_forms(message))
                    if forms != len(categories):
                        errors.append(
                            f"{tag} {key}: the locale selects by {len(categories)} plural"
                            f" categories ({', '.join(categories)}), found {forms}"
                        )
            if key in owners and key not in overrides:
                owner = sources.owners.get(key, "its owner")
                errors.append(
                    f"{key}: already defined by {owner}; "
                    "list it in overrides to replace it explicitly"
                )
        return {"locale": display, "valid": not errors, "keys": len(catalog), "errors": errors}

    def _i18n_package(self, arguments: Any, principal: Any) -> dict[str, Any]:
        """Scaffold a draft language-pack workspace; a human still publishes it."""
        data = _arguments(
            arguments,
            {"workspace_id", "locale", "name", "native_name", "overrides"},
            {"workspace_id", "locale"},
        )
        workspace_id = data["workspace_id"]
        if not isinstance(workspace_id, str) or not WORKSPACE_ID.fullmatch(workspace_id):
            raise InvalidArguments("workspace id is invalid")
        if not 2 <= len(workspace_id) <= 48:
            raise InvalidArguments("workspace id must be between 2 and 48 characters")
        _, display = _i18n_pack_tag(data["locale"])
        name = _i18n_pack_name(data.get("name"), display)
        native_name = _i18n_pack_native(data.get("native_name"), display, name)
        overrides = _i18n_overrides(data.get("overrides"))
        actor_root = self._actor_root(principal, create=True)
        workspaces = actor_root / "workspaces"
        self._assert_directory_safe(actor_root)
        self._assert_directory_safe(workspaces, create=True)
        if self._workspace_count(actor_root) >= self.max_workspaces:
            raise WorkspaceLimitExceeded("workspace limit reached")
        target = workspaces / workspace_id
        if target.exists() or target.is_symlink():
            raise WorkspaceConflict("workspace already exists")
        with self._session_factory() as session:
            sources = _i18n_sources(session)
        compatibility = {
            "core": f"^{CORE_VERSION}",
            "extensions": {
                provider_id: f"^{version}"
                for provider_id, version in sorted(sources.extension_versions.items())
            },
        }
        manifest = {
            "sdkVersion": 2,
            "id": workspace_id,
            "name": name,
            "version": "1.0.0",
            "kind": "language-pack",
            "locales": [{"tag": display, "name": name, "nativeName": native_name}],
            "compatibility": compatibility,
            "catalogs": {display: f"i18n/{display}.json"},
            "overrides": overrides,
            "priority": I18N_PACK_PRIORITY,
            "review": {"status": "draft"},
        }
        catalog = {key: sources.messages[key] for key in sorted(sources.messages)}
        try:
            problems = packs.pack_manifest_errors(manifest)
        except CatalogError as exc:  # pragma: no cover - defensive parity with the host
            raise DevelopmentError(str(exc)) from exc
        if problems:
            raise DevelopmentError("language pack manifest is invalid: " + "; ".join(problems))
        self._assert_directory_safe(workspaces, create=True)
        target.mkdir(mode=0o700)
        _atomic_text(
            target / "extension.json",
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        _atomic_text(
            target / "i18n" / f"{display}.json",
            json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        description = f"Language pack for {display}."
        _atomic_text(
            actor_root / "meta" / f"{workspace_id}.json",
            json.dumps(
                {
                    "id": workspace_id,
                    "name": name,
                    "description": description,
                    "createdAt": self._now(),
                },
                ensure_ascii=False,
            ),
        )
        workspace = self._workspace(principal, workspace_id)
        with self._session_factory() as session:
            from itsm.i18n.catalog import DEFAULT_LOCALE, resolve_installed_locale
            from itsm.i18n.messages import message_for, render
            from itsm.i18n.settings import read_installation_settings

            installation = read_installation_settings(session)
            locale = resolve_installed_locale(installation.default_locale) or DEFAULT_LOCALE
            template, _tag = message_for("api.i18n.pack_created", locale)
        message = None
        if template:
            message = {
                "key": "api.i18n.pack_created",
                "params": {"tag": display, "workspace": workspace_id},
                "locale": locale,
                "text": render(template, locale, {"tag": display, "workspace": workspace_id}),
            }
        return {
            "workspace": self._workspace_payload(workspace),
            "id": workspace_id,
            "tag": display,
            "kind": "language-pack",
            "review": "draft",
            "compatibility": compatibility,
            "keys": len(catalog),
            "manifest": manifest,
            "files": [
                {"path": "extension.json", "bytes": (target / "extension.json").stat().st_size},
                {
                    "path": f"i18n/{display}.json",
                    "bytes": (target / "i18n" / f"{display}.json").stat().st_size,
                },
            ],
            "message": message,
            "next": "extension_workspace_validate",
        }

    @staticmethod
    def _now() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())


def _gap_text(value: Any, label: str, limit: int) -> str:
    if not isinstance(value, str):
        raise InvalidArguments(f"{label} must be a string")
    text = value.strip()
    if not text or len(text) > limit:
        raise InvalidArguments(f"{label} must be 1-{limit} characters")
    return text


@dataclass(frozen=True)
class _I18nSources:
    """Owner catalogs a translation is checked against, plus installed modules."""

    messages: dict[str, str]
    owners: dict[str, str]
    extension_versions: dict[str, str]


def _i18n_sources(session: Session) -> _I18nSources:
    """Core ``es`` text plus each installed module's own catalogs.

    Packs and custom translations are deliberately absent: they are what a new
    pack fills, never the source that defines a key.
    """
    catalogs = registry.owner_catalogs(session)
    ordered = ["es", "en", *(sorted(set(catalogs) - {"es", "en"}))]
    messages: dict[str, str] = {}
    for locale in ordered:
        for key, value in catalogs.get(locale, {}).items():
            messages.setdefault(key, value)
    owners: dict[str, str] = {}
    for key in messages:
        namespace = packs.key_namespace(key) or ""
        if namespace in {"api", "ui"}:
            owners[key] = "core"
        elif namespace.startswith("ext."):
            owners[key] = namespace.split(".", 1)[1]
    versions = {
        provider.id: provider.version
        for provider in session.scalars(
            select(I18nProvider)
            .where(I18nProvider.kind == registry.EXTENSION)
            .order_by(I18nProvider.id)
        )
    }
    return _I18nSources(messages=messages, owners=owners, extension_versions=versions)


@cache
def _translator_context() -> dict[str, str]:
    """Where each core key is used, so a translation keeps the right meaning."""
    try:
        stored = json.loads((Path(CATALOG_DIR) / "context.json").read_text(encoding="utf-8"))
    except OSError, json.JSONDecodeError, UnicodeDecodeError:
        return {}
    if not isinstance(stored, dict):
        return {}
    return {str(key): str(value) for key, value in stored.items() if isinstance(value, str)}


def _i18n_page(data: Mapping[str, Any]) -> tuple[int, int]:
    limit = data.get("limit", I18N_DEFAULT_PAGE)
    offset = data.get("offset", 0)
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise InvalidArguments("limit must be an integer")
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise InvalidArguments("offset must be an integer")
    if not 1 <= limit <= I18N_MAX_PAGE:
        raise InvalidArguments(f"limit must be between 1 and {I18N_MAX_PAGE}")
    if offset < 0:
        raise InvalidArguments("offset must not be negative")
    return limit, offset


def _i18n_filter(data: Mapping[str, Any]) -> tuple[str | None, str]:
    namespace = data.get("namespace")
    prefix = data.get("prefix", "")
    if not isinstance(prefix, str) or len(prefix) > packs.MAX_KEY_LENGTH:
        raise InvalidArguments("prefix must be text")
    if namespace is None:
        return None, prefix
    if not isinstance(namespace, str) or not namespace:
        raise InvalidArguments("namespace must be text")
    if namespace in I18N_NAMESPACES:
        return namespace, prefix
    if namespace.startswith("ext.") and packs.key_namespace(f"{namespace}.x") == namespace:
        return namespace, prefix
    raise InvalidArguments("unknown i18n namespace")


def _i18n_selected(key: str, namespace: str | None, prefix: str) -> bool:
    if prefix and not key.startswith(prefix):
        return False
    if namespace is None:
        return True
    own = packs.key_namespace(key) or ""
    if namespace == "ext":
        return own.startswith("ext.")
    return own == namespace


def _i18n_tag(value: Any) -> str:
    canonical = registry.canonical_tag(value) if isinstance(value, str) else None
    if canonical is None:
        raise InvalidArguments("locale must be a valid language tag")
    return canonical


def _i18n_pack_tag(value: Any) -> tuple[str, str]:
    canonical = _i18n_tag(value)
    parts = canonical.split("-")
    display = "-".join(
        [parts[0]] + [part.upper() if len(part) == 2 else part for part in parts[1:]]
    )
    return canonical, display


def _i18n_babel_name(tag: str, language: str) -> str | None:
    try:
        return Locale.parse(tag.replace("-", "_")).get_display_name(language)
    except UnknownLocaleError, ValueError:
        return None


def _i18n_pack_name(value: Any, display: str) -> str:
    if value is not None:
        return _text(value, "name", 120)
    return _i18n_babel_name(display, "en") or display


def _i18n_pack_native(value: Any, display: str, fallback: str) -> str:
    if value is not None:
        return _text(value, "native_name", 120)
    return _i18n_babel_name(display, display.replace("-", "_")) or fallback


def _i18n_overrides(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Collection):
        raise InvalidArguments("overrides must be a list of keys")
    selected: list[str] = []
    for item in value:
        if not isinstance(item, str) or packs.key_errors(item):
            raise InvalidArguments("overrides must list valid translation keys")
        if item not in selected:
            selected.append(item)
    return selected


def _i18n_catalog_object(value: Mapping[Any, Any]) -> dict[str, str]:
    catalog: dict[str, str] = {}
    for key, message in value.items():
        if not isinstance(key, str):
            raise InvalidArguments("catalog keys must be text")
        if not isinstance(message, str):
            raise InvalidArguments("catalog values must be text")
        catalog[key] = message
    return catalog


_METHODS: dict[str, Callable[[DevelopmentService, Any, Any], dict[str, Any]]] = {
    "extension_contract_gap": DevelopmentService._contract_gap,
    "extension_sdk_index": DevelopmentService._sdk_index,
    "extension_sdk_reference": DevelopmentService._sdk_reference,
    "extension_workspace_create": DevelopmentService._workspace_create,
    "extension_workspace_files": DevelopmentService._workspace_files,
    "extension_workspace_read": DevelopmentService._workspace_read,
    "extension_workspace_write": DevelopmentService._workspace_write,
    "extension_workspace_validate": DevelopmentService._workspace_validate,
    "extension_workspace_submit": DevelopmentService._workspace_submit,
    "i18n_keys": DevelopmentService._i18n_keys,
    "i18n_missing": DevelopmentService._i18n_missing,
    "i18n_validate": DevelopmentService._i18n_validate,
    "i18n_package": DevelopmentService._i18n_package,
}
METHODS = tuple(sorted(_METHODS))


def _is_unavailable(exc: BaseException) -> bool:
    names = {cls.__name__ for cls in type(exc).__mro__}
    return bool(
        names
        & {
            "ValidatorUnavailable",
            "ContainerUnavailable",
            "DevelopmentUnavailable",
            "ExtensionUnavailable",
            "ExtensionHostUnavailable",
        }
    )
