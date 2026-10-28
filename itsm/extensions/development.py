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
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from itsm.extensions.sdk.contract import ManifestError
from itsm.extensions.sdk.generator import generate_package, write_package
from itsm.extensions.sdk.package import (
    DEFAULT_LIMITS,
    PackageError,
    build_package,
    read_workspace,
)
from itsm.identity.service import IdentityError, PermissionDenied

WORKSPACE_ID = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
TEST_FILE = re.compile(r"^tests/[a-z0-9_]{1,64}\.py$")
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
    ("frontend", "Frontend", "Native Vue registration and host components."),
    ("collections", "Collections", "Namespaced durable data and optimistic versions."),
    ("migrations", "Migrations", "Ordered explicit data migrations and rollback."),
    ("security", "Security", "Trusted native code, permissions and package safety."),
    ("validation", "Validation", "Fixed offline container checks and report."),
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
    descriptor, temporary = tempfile.mkstemp(
        prefix=".itsm-sdk-", dir=path.parent, text=False
    )
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
        "sdkVersion": 1,
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
        "completedAt": datetime.now(timezone.utc).isoformat(),
    }


def _report_is_passed(report: Any, digest: str) -> bool:
    return (
        isinstance(report, dict)
        and report.get("status") == "passed"
        and report.get("digest") == digest
        and report.get("sdkVersion") == 1
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

    def dispatch(
        self, method: str, arguments: Any, principal: Any
    ) -> dict[str, Any]:
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
            "sdkVersion": 1,
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
            "sdkVersion": 1,
            "name": entry[0],
            "title": entry[1],
            "summary": entry[2],
            "content": content,
        }

    # ------------------------------------------------------------ workspaces

    def _workspace_create(self, arguments: Any, principal: Any) -> dict[str, Any]:
        data = _arguments(
            arguments, {"id", "name", "description"}, {"id", "name"}
        )
        workspace_id = data["id"]
        if not isinstance(workspace_id, str) or not WORKSPACE_ID.fullmatch(workspace_id):
            raise InvalidArguments("workspace id is invalid")
        if len(workspace_id) < 2 or len(workspace_id) > 48:
            raise InvalidArguments("workspace id must be between 2 and 48 characters")
        name = _text(data["name"], "name", 120)
        description = _text(data.get("description", "Registros internos de ejemplo."), "description", MAX_DESCRIPTION)
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
            report = _failure(
                built.digest, "validation digest does not match the package bytes"
            )
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
                    raise DevelopmentUnavailable(
                        "extension host cannot record validation evidence"
                    )
                record(candidate_id, report, expected_version=revision)
            else:
                submit = getattr(self._host, "submit_candidate", None)
                if submit is None:
                    raise DevelopmentUnavailable("extension host cannot accept candidates")
                detail = submit(
                    principal, built.data, expected_digest=built.digest
                )
                if not isinstance(detail, Mapping):
                    raise DevelopmentUnavailable("extension host returned no candidate")
                candidate_id = detail.get("id")
                revision = detail.get("revision")
                if not candidate_id:
                    raise DevelopmentUnavailable("extension host returned no candidate id")
                record = getattr(self._host, "record_validation_report", None)
                if record is None:
                    raise DevelopmentUnavailable(
                        "extension host cannot record validation evidence"
                    )
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
            raise PermissionDenied("permission denied")
        with self._session_factory() as session:
            identity = self._identity_factory(session)
            identity.authorize(
                principal, self._permission, resource="extensions:development"
            )

    def _actor_root(self, principal: Any, *, create: bool = False) -> Path:
        actor = getattr(principal, "actor_id", None)
        if not isinstance(actor, str) or not actor:
            raise PermissionDenied("permission denied")
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
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return {"id": workspace_id}
        return content if isinstance(content, dict) else {"id": workspace_id}

    def _workspace_count(self, actor_root: Path) -> int:
        directory = actor_root / "workspaces"
        if not directory.is_dir() or directory.is_symlink():
            return 0
        return sum(
            1
            for item in directory.iterdir()
            if item.is_dir() and not item.is_symlink()
        )

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
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
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

    @staticmethod
    def _now() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())


_METHODS: dict[str, Callable[[DevelopmentService, Any, Any], dict[str, Any]]] = {
    "extension_sdk_index": DevelopmentService._sdk_index,
    "extension_sdk_reference": DevelopmentService._sdk_reference,
    "extension_workspace_create": DevelopmentService._workspace_create,
    "extension_workspace_files": DevelopmentService._workspace_files,
    "extension_workspace_read": DevelopmentService._workspace_read,
    "extension_workspace_write": DevelopmentService._workspace_write,
    "extension_workspace_validate": DevelopmentService._workspace_validate,
    "extension_workspace_submit": DevelopmentService._workspace_submit,
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
