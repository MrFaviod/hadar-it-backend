"""In-container validation of one bounded extension package.

This fixed parent reads and validates one framed archive without importing it.
Candidate Python and package tests run in a bounded child process. Only
normal-completion per-check diagnostics are merged; candidate stdout is never
a report. The offline container, not same-UID processes, is the security
boundary. Execution diagnostics are not hostile-code security attestations.
"""

from __future__ import annotations

import ast
import contextlib
import copy
import importlib.metadata
import importlib.util
import inspect
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from ..contract import ManifestError, validate_manifest  # noqa: F401
    from ..package import (
        DEFAULT_LIMITS,
        ArchiveLimits,
        PackageError,  # noqa: F401
        load_manifest,
        read_zip,
        validate_layout,
    )
    from ..validator.protocol import (
        MAX_FRAME_BYTES,
        MAX_OUTPUT_BYTES,
        ProtocolError,
        parse_frame,
    )
except ImportError:  # pragma: no cover - only the fixed image layout
    from itsm.extensions.sdk.contract import (  # type: ignore[no-redef]
        validate_manifest,
    )
    from itsm.extensions.sdk.package import (  # type: ignore[no-redef]
        DEFAULT_LIMITS,
        ArchiveLimits,
        load_manifest,
        read_zip,
        validate_layout,
    )
    from itsm.extensions.sdk.validator.protocol import (  # type: ignore[no-redef]
        MAX_FRAME_BYTES,
        MAX_OUTPUT_BYTES,
        ProtocolError,
        parse_frame,
    )

REPORT_KEYS = frozenset(
    {
        "status",
        "digest",
        "sdkVersion",
        "checks",
        "errors",
        "container",
        "completedAt",
    }
)
CHECK_NAMES = (
    "protocol",
    "archive",
    "manifest",
    "layout",
    "backend",
    "registration",
    "operations",
    "migrations",
    "schedules",
    "tests",
    "frontend",
)
MAX_CHECKS = 200
MAX_DETAIL = 1000
MAX_ERRORS = 40
MAX_OPERATION_BYTES = 128 * 1024
MAX_PACKAGE_TESTS = 20
PACKAGE_TEST_TIMEOUT = 20.0
EXECUTION_TIMEOUT = 50.0
EXECUTION_CHECK_NAMES = ("registration", "operations", "migrations", "schedules", "tests")
JS_TIMEOUT = 10.0
_ENGINE_NAMES = ("node", "bun")
_HANDLER_NAME = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_JS_ENGINE: tuple[str, str] | None = None


class ValidationFailure(RuntimeError):
    """One check failed with an actionable, bounded detail."""


def _detail(value: Any, limit: int = MAX_DETAIL) -> str:
    text = str(value)
    text = "".join(
        character if character.isprintable() or character in "\n\t" else " " for character in text
    )
    return text[:limit]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _python_version() -> str:
    return sys.version.split()[0]


def _jsonschema_version() -> str:
    try:
        return importlib.metadata.version("jsonschema")
    except importlib.metadata.PackageNotFoundError:
        return "unavailable"


def _js_engine() -> tuple[str, str]:
    """Return (name, version) once per process; fail when neither is present."""
    global _JS_ENGINE
    if _JS_ENGINE is not None:
        return _JS_ENGINE
    for name in _ENGINE_NAMES:
        executable = shutil.which(name)
        if not executable:
            continue
        try:
            completed = subprocess.run(
                [executable, "--version"],
                capture_output=True,
                text=True,
                timeout=JS_TIMEOUT,
                check=False,
                env={"PATH": os.environ.get("PATH", ""), "HOME": "/tmp"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValidationFailure(f"{name} could not start: {exc}") from exc
        if completed.returncode != 0:
            raise ValidationFailure(f"{name} --version failed")
        output = (completed.stdout or completed.stderr or name).strip()
        version = output.split()[-1] if output else "unknown"
        _JS_ENGINE = (name, version)
        return _JS_ENGINE
    raise ValidationFailure("no JavaScript engine is available; frontend syntax cannot be claimed")


def _container(engine: str) -> dict[str, Any]:
    return {
        "image": "itsm-extension-validator:1",
        "runtime": "docker",
        "network": "none",
        "readOnly": True,
        "nonRoot": True,
        "capabilities": "dropped",
        "engine": (f"python {_python_version()}; jsonschema {_jsonschema_version()}; js {engine}"),
        "limits": (
            f"archive={DEFAULT_LIMITS.max_archive_bytes}; "
            f"expanded={DEFAULT_LIMITS.max_expanded_bytes}; "
            f"entries={DEFAULT_LIMITS.max_entries}; "
            f"file={DEFAULT_LIMITS.max_file_bytes}"
        ),
    }


def _failed_report(digest: str, errors: list[str], engine: str) -> dict[str, Any]:
    return {
        "status": "failed",
        "digest": digest if re.fullmatch(r"[0-9a-f]{64}", digest or "") else "",
        "sdkVersion": 1,
        "checks": [{"name": "protocol", "status": "failed", "detail": errors[0][:MAX_DETAIL]}],
        "errors": [item[:MAX_DETAIL] for item in errors[:MAX_ERRORS]],
        "container": _container(engine),
        "completedAt": _now(),
    }


class MemoryStore:
    """Store contract fixture: shapes match the host exactly."""

    def __init__(self, collections: set[str]):
        self._collections = collections
        self._data: dict[str, dict[str, dict[str, Any]]] = {name: {} for name in collections}

    def _collection(self, name: str) -> dict[str, dict[str, Any]]:
        if name not in self._collections:
            raise RuntimeError(f"collection {name!r} is not declared")
        return self._data[name]

    def list(
        self,
        collection: str,
        limit: int = 20,
        offset: int = 0,
        filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
            raise RuntimeError("limit must be between 1 and 200")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise RuntimeError("offset must be a non-negative integer")
        if filters is not None and not isinstance(filters, dict):
            raise RuntimeError("filters must be an object")
        rows = [
            {"id": name, **copy.deepcopy(value)}
            for name, value in self._collection(collection).items()
            if not filters or all(value["data"].get(key) == item for key, item in filters.items())
        ]
        rows.sort(key=lambda row: row["id"])
        return {"items": rows[offset : offset + limit], "total": len(rows)}

    def get(self, collection: str, record_id: str) -> dict[str, Any] | None:
        value = self._collection(collection).get(record_id)
        return {"id": record_id, **copy.deepcopy(value)} if value else None

    def put(
        self,
        collection: str,
        record_id: str,
        data: dict[str, Any],
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        if not isinstance(record_id, str) or not record_id or len(record_id) > 128:
            raise RuntimeError("record id must be bounded text")
        if not isinstance(data, dict):
            raise RuntimeError("record data must be a JSON object")
        if expected_version is not None and (
            not isinstance(expected_version, int)
            or isinstance(expected_version, bool)
            or expected_version < 0
        ):
            raise RuntimeError("expected_version must be a non-negative integer")
        rows = self._collection(collection)
        current = rows.get(record_id)
        if expected_version == 0 and current is not None:
            raise RuntimeError("record already exists")
        if expected_version not in (None, 0) and (
            current is None or current["version"] != expected_version
        ):
            raise RuntimeError("record version conflict")
        version = (current["version"] + 1) if current else 1
        rows[record_id] = {"version": version, "data": copy.deepcopy(data)}
        return {"id": record_id, **copy.deepcopy(rows[record_id])}

    def delete(self, collection: str, record_id: str, expected_version: int | None = None) -> bool:
        if expected_version is not None and (
            type(expected_version) is not int or expected_version < 0
        ):
            raise RuntimeError("expected_version must be a non-negative integer")
        rows = self._collection(collection)
        current = rows.get(record_id)
        if expected_version is not None and (
            (current is None and expected_version != 0)
            or (current is not None and current["version"] != expected_version)
        ):
            raise RuntimeError("record version conflict")
        return rows.pop(record_id, None) is not None


# The runner hands modules the invoking principal as a plain dict, so the
# offline harness must use the same shape or a module would pass here and fail
# in the sandbox.
HARNESS_PRINCIPAL: dict[str, Any] = {
    "actor_id": "extension-validator",
    "kind": "human",
    "username": "extension-validator",
    "display_name": "Extension validator",
    "role_id": "superadmin",
    "delegated_by": None,
    "scopes": [],
    "execution_id": None,
    "authorization_ref": None,
    "session_id": None,
}


class NotFound(Exception):
    """Missing asset in the validator's deliberately empty inventory fixture."""


class Assets:
    def __init__(self, context: Any):
        self._context = context

    def get(self, asset_id: str) -> dict[str, Any]:
        self._context.authorize("assets.view")
        raise NotFound(f"asset {asset_id!r} not found")

    def search(
        self,
        *,
        query: str | None = None,
        category: str | None = None,
        site: str | None = None,
        status: str | None = None,
        quick_code: str | None = None,
        asset_id: str | None = None,
        site_id: str | None = None,
        location_id: str | None = None,
        responsible_person_id: str | None = None,
        archived: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        self._context.authorize("assets.view")
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        if type(offset) is not int or offset < 0:
            raise ValueError("offset must be a non-negative integer")
        return {"items": [], "total": 0, "limit": limit, "offset": offset}


class Context:
    """Native context contract with empty assets and in-memory transactions.

    This fixture does not claim to validate real inventory policy, recipient
    policy or queue delivery. Those belong to the installed host integration.
    """

    def __init__(self, permissions: set[str], collections: set[str], extension_id: str):
        self.principal = dict(HARNESS_PRINCIPAL)
        self._permissions = permissions
        self._extension_id = extension_id
        self.authorized: list[str] = []
        self.store = MemoryStore(collections)
        self.notices: list[dict[str, Any]] = []
        self.assets = Assets(self)

    def authorize(self, permission: Any) -> None:
        if not isinstance(permission, str) or permission not in self._permissions:
            raise PermissionError(f"permission {permission!r} is not granted")
        self.authorized.append(permission)

    def notify(
        self,
        *,
        recipient_ids: list[str] | tuple[str, ...],
        key: str,
        title: str,
        body: str,
        permission: str,
        asset_id: str | None = None,
        url: str | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        # ``idempotency_key`` is a host requirement for mutating capabilities;
        # the offline harness only records that the module supplied one.
        if idempotency_key is not None and (
            not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 128
        ):
            raise ValueError("idempotency_key must be bounded text")
        if not isinstance(recipient_ids, (list, tuple)) or not 1 <= len(recipient_ids) <= 100:
            raise ValueError("recipient_ids must contain 1..100 actors")
        if any(not isinstance(item, str) or not 1 <= len(item) <= 64 for item in recipient_ids):
            raise ValueError("recipient ids must be bounded text")
        if not isinstance(key, str) or re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", key) is None:
            raise ValueError("notice key is invalid")
        if not isinstance(title, str) or not 1 <= len(title) <= 200:
            raise ValueError("notice title must contain 1..200 characters")
        if not isinstance(body, str) or not 1 <= len(body) <= 4000:
            raise ValueError("notice body must contain 1..4000 characters")
        if not isinstance(permission, str) or not permission.startswith(
            "ext_" + self._extension_id.replace("-", "_") + "."
        ):
            raise PermissionError("notice permission must belong to this extension")
        self.authorize(permission)
        if asset_id is not None:
            if not isinstance(asset_id, str) or len(asset_id) > 64:
                raise ValueError("notice asset id is invalid")
            self.assets.get(asset_id)
        if url is not None and (
            not isinstance(url, str)
            or len(url) > 500
            or not url.startswith(f"#/extensiones/{self._extension_id}/")
        ):
            raise ValueError("notice URL must belong to this extension")
        recipients = list(dict.fromkeys(recipient_ids))
        if self.principal["actor_id"] in recipients:
            self.notices.append(
                {
                    "recipient_ids": [self.principal["actor_id"]],
                    "key": key,
                    "title": title,
                    "body": body,
                    "permission": permission,
                    "asset_id": asset_id,
                    "url": url,
                }
            )

    @contextlib.contextmanager
    def transaction(self):
        data = copy.deepcopy(self.store._data)
        notices = copy.deepcopy(self.notices)
        try:
            yield self
        except BaseException:
            self.store._data = data
            self.notices[:] = notices
            raise


class _Binder:
    def __init__(self, manifest: dict[str, Any]):
        self.operations = {item["name"]: item for item in manifest["operations"]}
        self.migrations = {item["handler"]: item for item in manifest["migrations"]}
        self.schedules = {item["name"]: item for item in manifest["schedules"]}
        self.bound_operations: dict[str, Any] = {}
        self.bound_migrations: dict[str, Any] = {}
        self.bound_schedules: dict[str, Any] = {}

    def operation(self, name: str, handler: Any) -> None:
        self._bind(name, handler, self.operations, self.bound_operations, "operation")

    def migration(self, name: str, handler: Any) -> None:
        self._bind(name, handler, self.migrations, self.bound_migrations, "migration")

    def schedule(self, name: str, handler: Any) -> None:
        self._bind(name, handler, self.schedules, self.bound_schedules, "schedule")

    @staticmethod
    def _bind(
        name: str,
        handler: Any,
        declared: dict[str, Any],
        target: dict[str, Any],
        kind: str,
    ) -> None:
        if not isinstance(name, str) or name not in declared:
            raise RuntimeError(f"{kind} {name!r} is not declared by the manifest")
        if name in target:
            raise RuntimeError(f"{kind} {name!r} is registered twice")
        if not callable(handler):
            raise RuntimeError(f"{kind} {name!r} handler is not callable")
        target[name] = handler


def _check_signature(handler: Any, operation: dict[str, Any]) -> None:
    try:
        signature = inspect.signature(handler)
    except (TypeError, ValueError) as exc:
        raise ValidationFailure(f"handler signature is not inspectable: {exc}") from exc
    parameters = list(signature.parameters.values())
    if not parameters:
        raise ValidationFailure("handler must accept the context as its first argument")
    if parameters[0].kind not in (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    ):
        raise ValidationFailure("handler context must be positional")
    if any(parameter.kind is inspect.Parameter.VAR_POSITIONAL for parameter in parameters):
        raise ValidationFailure("handler must not accept *args")
    properties = operation["parameters"]["properties"]
    required = operation["parameters"].get("required", [])
    for names in (required, properties):
        try:
            signature.bind(object(), **dict.fromkeys(names))
        except TypeError as exc:
            raise ValidationFailure(f"handler does not accept declared arguments: {exc}") from exc


def _json_bound(value: Any, label: str) -> None:
    try:
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValidationFailure(f"{label} result is not JSON: {exc}") from exc
    if len(encoded.encode("utf-8")) > MAX_OPERATION_BYTES:
        raise ValidationFailure(f"{label} result exceeds {MAX_OPERATION_BYTES} bytes")


def _frontend_checks(frontend: Path, manifest: dict[str, Any]) -> tuple[str, str, str]:
    engine, version = _js_engine()
    engine_label = f"{engine} {version}"
    harness_dir = Path(__file__).resolve().parent / "js"
    parse = harness_dir / "parse.js"
    registration = harness_dir / "register.js"
    if not parse.is_file() or not registration.is_file():
        raise ValidationFailure("fixed JavaScript harness is missing from the image")
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "NO_COLOR": "1",
    }
    try:
        syntax = subprocess.run(
            [engine, str(parse), str(frontend)],
            capture_output=True,
            text=True,
            timeout=JS_TIMEOUT,
            check=False,
            env=environment,
            cwd="/tmp",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationFailure(f"frontend syntax check failed to run: {exc}") from exc
    if syntax.returncode != 0:
        message = (syntax.stderr or syntax.stdout or "syntax error").strip()
        raise ValidationFailure(f"frontend syntax is invalid: {message[:MAX_DETAIL]}")

    components: list[str] = []
    frontend_manifest = manifest["frontend"]
    contributions = (
        frontend_manifest["pages"]
        + frontend_manifest["assetPanels"]
        + frontend_manifest.get("contributions", [])
    )
    for item in contributions:
        component = item.get("component")
        if component is not None and component not in components:
            components.append(component)
    try:
        registered = subprocess.run(
            [
                engine,
                str(registration),
                str(frontend),
                json.dumps(components),
            ],
            capture_output=True,
            text=True,
            timeout=JS_TIMEOUT,
            check=False,
            env=environment,
            cwd="/tmp",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationFailure(f"frontend registration failed to run: {exc}") from exc
    if registered.returncode != 0:
        message = (registered.stderr or registered.stdout or "registration failed").strip()
        raise ValidationFailure(
            f"frontend did not register the declared components: {message[:MAX_DETAIL]}"
        )
    try:
        payload = json.loads(registered.stdout)
    except json.JSONDecodeError as exc:
        raise ValidationFailure("frontend registration output was not JSON") from exc
    if payload.get("id") != manifest["id"]:
        raise ValidationFailure("frontend registered a different extension id")
    bound = set(payload.get("components") or [])
    missing = [name for name in components if name not in bound]
    if missing:
        raise ValidationFailure("frontend did not provide components: " + ", ".join(missing))
    return (
        "syntax and registration passed with " + engine_label,
        "registered " + ", ".join(sorted(bound)) + f" with {engine_label}",
        engine_label,
    )


@contextlib.contextmanager
def _package_on_path(root: Path):
    added = str(root) not in sys.path
    if added:
        sys.path.insert(0, str(root))
    try:
        yield
    finally:
        if added:
            try:
                sys.path.remove(str(root))
            except ValueError:
                pass


def _run_package_tests(root: Path) -> str:
    test_files = sorted(
        path.name
        for path in (root / "tests").glob("*.py")
        if path.is_file() and not path.is_symlink()
    )
    if not test_files:
        raise ValidationFailure("package must ship at least one tests/*.py file")
    if len(test_files) > MAX_PACKAGE_TESTS:
        raise ValidationFailure("package ships too many test files")
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "PYTHONPATH": str(root),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "NO_COLOR": "1",
    }
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
                "-t",
                "tests",
                "-v",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=PACKAGE_TEST_TIMEOUT,
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValidationFailure("package tests exceeded the 20 second limit") from exc
    output = ((completed.stdout or "") + "\n" + (completed.stderr or "")).strip()
    output = output.replace(str(root), "<package>")
    if completed.returncode != 0:
        raise ValidationFailure("package tests failed: " + _detail(output[-1500:], 1500))
    if "Ran 0 tests" in output:
        raise ValidationFailure(
            "package tests discovered no test functions; name files tests/test*.py"
        )
    return "package tests passed: " + _detail(output.splitlines()[-1] if output else "", 200)


def _backend_syntax(source: str) -> str:
    tree = ast.parse(source, filename="backend.py")
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise ValidationFailure("backend.py must not use relative imports")
            if node.module:
                roots.add(node.module.split(".", 1)[0])
    allowed = set(sys.stdlib_module_names) | {"__future__"}
    forbidden = sorted(name for name in roots if name not in allowed or name == "sdk_runtime")
    if forbidden:
        raise ValidationFailure("backend.py imports non-stdlib modules: " + ", ".join(forbidden))
    register = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "register"
        ),
        None,
    )
    if register is None:
        raise ValidationFailure("backend.py must define register(sdk)")
    if not register.args.args:
        raise ValidationFailure("register must accept the sdk binder")
    return "backend.py syntax and standard-library imports checked"


def _exercise_candidate(root: Path, manifest: dict[str, Any]) -> list[dict[str, str]]:
    """Collect child diagnostics, never a digest/status/container report."""
    checks: list[dict[str, str]] = []

    def record(name: str, function: Any) -> bool:
        try:
            detail = function()
        except Exception as exc:
            text = _detail(f"{type(exc).__name__}: {exc}").replace(str(root), "<package>")
            checks.append({"name": name, "status": "failed", "detail": text})
            return False
        checks.append({"name": name, "status": "passed", "detail": _detail(detail)})
        return True

    binder = _Binder(manifest)

    def registration_check() -> str:
        with _package_on_path(root):
            spec = importlib.util.spec_from_file_location(
                "itsm_extension_candidate", root / "backend.py"
            )
            if spec is None or spec.loader is None:
                raise ValidationFailure("backend.py could not be loaded")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        register = getattr(module, "register", None)
        if not callable(register):
            raise ValidationFailure("backend.py does not export register(sdk)")
        register(binder)
        for label, expected, bound in (
            ("operations", binder.operations, binder.bound_operations),
            ("migrations", binder.migrations, binder.bound_migrations),
            ("schedules", binder.schedules, binder.bound_schedules),
        ):
            if set(bound) != set(expected):
                raise ValidationFailure(
                    label + " not registered: " + ", ".join(sorted(set(expected) - set(bound)))
                )
        return (
            f"backend imported; {len(binder.operations)} operations; "
            f"{len(binder.migrations)} migrations; {len(binder.schedules)} schedules"
        )

    if not record("registration", registration_check):
        return checks

    def context() -> Context:
        permissions = {item["code"] for item in manifest["permissions"]}
        permissions.update(manifest["corePermissions"])
        return Context(
            permissions, {item["name"] for item in manifest["collections"]}, manifest["id"]
        )

    def operations_check() -> str:
        names = []
        for operation in manifest["operations"]:
            handler = binder.bound_operations[operation["name"]]
            _check_signature(handler, operation)
            names.append(operation["name"])
        return (
            f"{len(names)} operations: "
            + ", ".join(names)
            + "; signatures checked; domain execution belongs to package tests"
        )

    record("operations", operations_check)

    def migrations_check() -> str:
        current = context()
        names: list[str] = []
        for migration in manifest["migrations"]:
            handler = binder.bound_migrations[migration["handler"]]
            signature = inspect.signature(handler)
            parameters = list(signature.parameters.values())
            if not parameters or parameters[0].kind not in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            ):
                raise ValidationFailure(f"migration {migration['handler']} must accept context")
            if any(
                item.default is inspect.Parameter.empty
                and item.kind
                in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                )
                for item in parameters[1:]
            ):
                raise ValidationFailure(
                    f"migration {migration['handler']} requires unexpected arguments"
                )
            _json_bound(handler(current), migration["handler"])
            names.append(f"{migration['from']}->{migration['to']}:{migration['handler']}")
        return "migrations executed: " + ", ".join(names) if names else "no migrations declared"

    record("migrations", migrations_check)

    def schedules_check() -> str:
        current = context()
        names: list[str] = []
        for schedule in manifest["schedules"]:
            current.authorize(schedule["permission"])
            _json_bound(binder.bound_schedules[schedule["name"]](current), schedule["name"])
            names.append(schedule["name"])
        return "schedules executed: " + ", ".join(names) if names else "no schedules declared"

    record("schedules", schedules_check)
    record("tests", lambda: _run_package_tests(root))
    return checks


def execution_main(root: Path, result_fd: int) -> int:
    """Fixed child entry; stdout/stderr are candidate logs, not report framing."""
    manifest = load_manifest(
        {"extension.json": (root / "extension.json").read_text(encoding="utf-8")}
    )
    checks = _exercise_candidate(root, manifest)
    encoded = json.dumps({"completed": True, "checks": checks}, separators=(",", ":")).encode(
        "utf-8"
    )
    with os.fdopen(result_fd, "wb") as output:
        output.write(encoded)
    return 0


def _execution_evidence(payload: bytes) -> list[dict[str, str]]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationFailure(
            "candidate subprocess did not complete its execution checks"
        ) from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"completed", "checks"}
        or value["completed"] is not True
    ):
        raise ValidationFailure("candidate subprocess returned invalid completion evidence")
    checks = value["checks"]
    if not isinstance(checks, list) or len(checks) not in (1, len(EXECUTION_CHECK_NAMES)):
        raise ValidationFailure("candidate subprocess returned incomplete execution checks")
    for index, check in enumerate(checks):
        if (
            not isinstance(check, dict)
            or set(check) != {"name", "status", "detail"}
            or check["name"] != EXECUTION_CHECK_NAMES[index]
            or check["status"] not in ("passed", "failed")
            or not isinstance(check["detail"], str)
            or len(check["detail"]) > MAX_DETAIL
        ):
            raise ValidationFailure("candidate subprocess returned invalid execution checks")
    if len(checks) == 1 and checks[0]["status"] != "failed":
        raise ValidationFailure("candidate subprocess did not complete all execution checks")
    return checks


def _run_execution(root: Path, max_output: int) -> list[dict[str, str]]:
    """Bound all child channels; the inherited result pipe accepts checks only."""
    read_fd, write_fd = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    evidence = bytearray()
    received = 0
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "NO_COLOR": "1",
    }
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                str(Path(__file__).with_name("run.py")),
                "--exercise",
                str(root),
                str(write_fd),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=root,
            env=environment,
            close_fds=True,
            pass_fds=(write_fd,),
            start_new_session=True,
        )
        os.close(write_fd)
        write_fd = -1
        assert process.stdout is not None and process.stderr is not None
        deadline = time.monotonic() + EXECUTION_TIMEOUT
        with selectors.DefaultSelector() as selector:
            for stream, kind in (
                (read_fd, "evidence"),
                (process.stdout, "log"),
                (process.stderr, "log"),
            ):
                os.set_blocking(stream if isinstance(stream, int) else stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, kind)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValidationFailure("validator candidate execution exceeded its time limit")
                for key, _event in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    received += len(chunk)
                    if received > max_output:
                        raise ValidationFailure("validator output exceeded its limit")
                    if key.data == "evidence":
                        evidence.extend(chunk)
            try:
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise ValidationFailure(
                    "validator candidate execution exceeded its time limit"
                ) from exc
        if process.returncode != 0:
            raise ValidationFailure(f"candidate subprocess exited with {process.returncode}")
        return _execution_evidence(bytes(evidence))
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        os.close(read_fd)
        if write_fd != -1:
            os.close(write_fd)


def _declarative_evidence(root: Path, manifest: dict[str, Any]) -> list[dict[str, str]]:
    """Checks for a module that ships no executable code at all."""
    checks: list[dict[str, str]] = []
    kinds = ", ".join(f"{item['name']}:{contract_kind(item)}" for item in manifest["operations"])
    checks.append(
        {
            "name": "registration",
            "status": "passed",
            "detail": "declarative runtime: no handlers to register",
        }
    )
    checks.append(
        {
            "name": "operations",
            "status": "passed",
            "detail": f"{len(manifest['operations'])} declarative operations executed by the host: {kinds}",
        }
    )
    checks.append(
        {
            "name": "migrations",
            "status": "passed",
            "detail": "no migrations declared",
        }
    )
    checks.append({"name": "schedules", "status": "passed", "detail": "no schedules declared"})
    try:
        checks.append({"name": "tests", "status": "passed", "detail": _run_package_tests(root)})
    except Exception as exc:
        checks.append(
            {
                "name": "tests",
                "status": "failed",
                "detail": _detail(f"{type(exc).__name__}: {exc}").replace(str(root), "<package>"),
            }
        )
    return checks


def contract_kind(operation: dict[str, Any]) -> str:
    return str(operation.get("kind") or "handler")


def _declarative_view_detail(manifest: dict[str, Any]) -> str:
    frontend = manifest["frontend"]
    declared = {item["name"] for item in manifest["operations"]}
    problems: list[str] = []
    views = 0
    for section in ("pages", "assetPanels", "widgets"):
        for item in frontend.get(section) or []:
            view = item.get("view") or {}
            views += 1
            for kind in ("table", "form"):
                body = view.get(kind)
                if not body:
                    continue
                operation = body.get("operation")
                if operation not in declared:
                    problems.append(
                        f"{section} {item['id']} references unknown operation {operation!r}"
                    )
    if problems:
        raise ValidationFailure("; ".join(problems))
    return f"{views} declarative view(s) rendered by the host; no module JavaScript"


def _isolated_frontend_check(
    frontend: Path, manifest: dict[str, Any], engine: str, version: str
) -> tuple[str, str, str]:
    """Syntax plus registration check for isolated (iframe) module code only."""
    engine_label = f"{engine} {version}"
    harness_dir = Path(__file__).resolve().parent / "js"
    parse = harness_dir / "parse.js"
    if not parse.is_file():
        raise ValidationFailure("fixed JavaScript harness is missing from the image")
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "NO_COLOR": "1",
    }
    try:
        syntax = subprocess.run(
            [engine, str(parse), str(frontend)],
            capture_output=True,
            text=True,
            timeout=JS_TIMEOUT,
            check=False,
            env=environment,
            cwd="/tmp",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationFailure(f"frontend syntax check failed to run: {exc}") from exc
    if syntax.returncode != 0:
        message = (syntax.stderr or syntax.stdout or "syntax error").strip()
        raise ValidationFailure(f"frontend syntax is invalid: {message[:MAX_DETAIL]}")
    source = frontend.read_text(encoding="utf-8", errors="replace")
    if "ITSMExtension.register" not in source:
        raise ValidationFailure(
            "isolated frontend code must call window.ITSMExtension.register({components})"
        )
    components: list[str] = []
    for section in ("pages", "assetPanels", "widgets"):
        for item in manifest["frontend"].get(section) or []:
            for component in (
                item.get("component"),
                (item.get("view") or {}).get("isolated", {}).get("component"),
            ):
                if component and component not in components:
                    components.append(component)
    for contribution in manifest["frontend"].get("contributions") or []:
        component = contribution.get("component")
        if component and component not in components:
            components.append(component)
    missing = [name for name in components if name not in source]
    if missing:
        raise ValidationFailure(
            "isolated frontend does not define components: " + ", ".join(missing)
        )
    registration = harness_dir / "register.js"
    if not registration.is_file():
        raise ValidationFailure("fixed JavaScript harness is missing from the image")
    try:
        registered = subprocess.run(
            [engine, str(registration), str(frontend), json.dumps(components)],
            capture_output=True,
            text=True,
            timeout=JS_TIMEOUT,
            check=False,
            env=environment,
            cwd="/tmp",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationFailure(f"frontend registration failed to run: {exc}") from exc
    if registered.returncode != 0:
        message = (registered.stderr or registered.stdout or "registration error").strip()
        raise ValidationFailure(
            f"isolated frontend registration is invalid: {message[:MAX_DETAIL]}"
        )
    return (
        "syntax passed and registration present with " + engine_label,
        "isolated components: " + ", ".join(components),
        engine_label,
    )


def _raiser(error: BaseException) -> Callable[[], str]:
    """Turn an already captured failure back into a failing check."""

    def raise_error() -> str:
        raise error

    return raise_error


def validate_payload(payload: bytes) -> dict[str, Any]:
    """Own digest, static checks and the final report outside candidate Python."""
    checks: list[dict[str, str]] = []
    errors: list[str] = []

    def record(name: str, function: Any) -> Any:
        try:
            detail = function()
        except Exception as exc:
            message = _detail(f"{type(exc).__name__}: {exc}")
            checks.append({"name": name, "status": "failed", "detail": message})
            errors.append(f"{name}: {message}")
            return None
        if name == "archive":
            text = _detail(
                f"{len(detail)} files; "
                f"{sum(len(value.encode('utf-8')) for value in detail.values())} expanded bytes; "
                + ", ".join(sorted(detail))
            )
        elif name == "execution":
            text = "candidate subprocess completed; bounded diagnostic checks received"
        elif name == "frontend":
            # Isolated code reports (summary, components); declarative views
            # report a single summary string.
            text = (
                _detail(detail[0] + "; " + detail[1])
                if isinstance(detail, tuple)
                else _detail(detail)
            )
        else:
            text = _detail(detail or "passed")
        checks.append({"name": name, "status": "passed", "detail": text})
        return detail

    try:
        frame = parse_frame(payload)
    except ProtocolError as exc:
        return _failed_report("", [f"protocol: {_detail(exc)}"], "unavailable")
    engine = "unavailable"
    try:
        engine = f"{_js_engine()[0]} {_js_engine()[1]}"
    except ValidationFailure:
        pass
    checks.append(
        {
            "name": "protocol",
            "status": "passed",
            "detail": f"protocolVersion=1 bytes={len(frame.archive)}",
        }
    )
    limits = ArchiveLimits(
        max_archive_bytes=frame.limits["archiveBytes"],
        max_expanded_bytes=frame.limits["expandedBytes"],
        max_entries=frame.limits["entries"],
        max_file_bytes=frame.limits["fileBytes"],
    )
    files = record("archive", lambda: read_zip(frame.archive, limits))
    if files is None:
        return _finish(frame.digest, checks, errors, engine)
    manifest: dict[str, Any] = {}

    def manifest_check() -> str:
        manifest.update(
            validate_manifest(
                load_manifest(files), known_core_permissions=frame.known_core_permissions
            )
        )
        return f"{manifest['id']} {manifest['version']} schema={manifest['schemaVersion']}"

    if record("manifest", manifest_check) is None:
        return _finish(frame.digest, checks, errors, engine)

    def layout_check() -> str:
        validate_layout(files, manifest)
        return f"{len(files)} files; {len(manifest['skills'])} skill(s); tests/ present"

    if record("layout", layout_check) is None:
        return _finish(frame.digest, checks, errors, engine)
    runtime = manifest["runtime"]
    if runtime == "sandboxed":
        if record("backend", lambda: _backend_syntax(files["backend.py"])) is None:
            return _finish(frame.digest, checks, errors, engine)
    else:
        record(
            "backend",
            lambda: "declarative runtime ships no executable backend",
        )
    with tempfile.TemporaryDirectory(prefix="itsm-sdk-package-") as directory:
        root = Path(directory)
        for relative, content in files.items():
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
        if runtime == "sandboxed":
            evidence = record(
                "execution", lambda: _run_execution(root, frame.limits["outputBytes"])
            )
        else:
            # Declarative modules ship no code: the host-side evidence list is
            # appended once by the shared block below.
            evidence = _declarative_evidence(root, manifest)
        if evidence is not None:
            checks.extend(evidence)
            errors.extend(
                f"{item['name']}: {item['detail']}"
                for item in evidence
                if item["status"] == "failed"
            )
        entry = (manifest["frontend"] or {}).get("entry")
        if entry:
            try:
                engine_name, engine_version = _js_engine()
            except ValidationFailure as failure:
                record("frontend", _raiser(failure))
            else:
                frontend = record(
                    "frontend",
                    lambda: _isolated_frontend_check(
                        root / entry, manifest, engine_name, engine_version
                    ),
                )
                if frontend is not None:
                    engine = frontend[2]
        else:
            record("frontend", lambda: _declarative_view_detail(manifest))
    return _finish(frame.digest, checks, errors, engine)


def _finish(
    digest: str, checks: list[dict[str, str]], errors: list[str], engine: str
) -> dict[str, Any]:
    failed = any(item["status"] == "failed" for item in checks)
    return {
        "status": "failed" if failed else "passed",
        "digest": digest,
        "sdkVersion": 2,
        "checks": checks[:MAX_CHECKS],
        "errors": errors[:MAX_ERRORS],
        "container": _container(engine),
        "completedAt": _now(),
    }


def main() -> int:
    try:
        payload = sys.stdin.buffer.read(MAX_FRAME_BYTES + 1)
        report = validate_payload(payload)
    except Exception as exc:  # never print a traceback or accept a partial pass
        report = _failed_report(
            "",
            [f"validator failed: {_detail(f'{type(exc).__name__}: {exc}')}"],
            "unavailable",
        )
    encoded = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_OUTPUT_BYTES:
        report = _failed_report(
            report.get("digest", ""),
            ["validator output exceeded the 256 KiB limit"],
            "unavailable",
        )
        encoded = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write(encoded + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
