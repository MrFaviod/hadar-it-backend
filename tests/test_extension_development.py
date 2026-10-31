"""Extension SDK development surface: generation, packaging, workspace, validation.

These checks use the public CLI, SDK resources, filesystem effects and report
contracts. Candidate package bytes are the only model used by the validator;
no core checkout is copied into it.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import http.client
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path
from typing import Any

import pytest
from itsm.extensions.development import (
    DevelopmentService,
    DevelopmentUnavailable,
    InvalidArguments,
    ValidationRequired,
    WorkspaceConflict,
    WorkspaceLimitExceeded,
    WorkspaceNotFound,
    WorkspacePathRejected,
)
from itsm.extensions.sdk.contract import ManifestError, load_schema, validate_manifest
from itsm.extensions.sdk.generator import generate_package, write_package
from itsm.extensions.sdk.package import (
    ArchiveLimits,
    PackageError,
    build_package,
    parse_package,
)
from itsm.extensions.sdk.validator.protocol import build_frame
from itsm.extensions.validator import ContainerValidator, ValidatorUnavailable
from itsm.identity.service import PermissionDenied
from tests.conftest import BACKEND_ROOT
from tests.inventory_support import READER, prepare

REPORT_KEYS = {
    "status",
    "digest",
    "sdkVersion",
    "checks",
    "errors",
    "container",
    "completedAt",
}
REQUIRED_CHECKS = {
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
}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest_from_package(data: bytes) -> dict[str, Any]:
    return parse_package(data, known_core_permissions=()).manifest


def _report_for(
    package_bytes: bytes,
    *,
    status: str = "passed",
    digest: str | None = None,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    manifest = _manifest_from_package(package_bytes)
    actual = digest or _digest(package_bytes)
    failed = status != "passed"
    return {
        "status": status,
        "digest": actual,
        "sdkVersion": 2,
        "checks": [
            {
                "name": "archive",
                "status": "failed" if failed else "passed",
                "detail": f"fixture for {manifest['id']}",
            }
        ],
        "errors": list(errors or (["fixture failure"] if failed else [])),
        "container": {
            "image": "itsm-extension-validator:1",
            "runtime": "fixture",
            "network": "none",
            "readOnly": True,
            "nonRoot": True,
            "capabilities": "dropped",
            "engine": "python 3.14.8; jsonschema 4.26.0; js fixture",
            "limits": "archive=4MiB; expanded=8MiB; entries=200; file=1MiB",
        },
        "completedAt": "2026-10-28T10:00:01+00:00",
    }


class FakeValidator:
    """Test double at the validator boundary; generated package bytes stay real."""

    def __init__(
        self,
        *,
        status: str = "passed",
        digest_override: str | None = None,
        unavailable: bool = False,
    ) -> None:
        self.status = status
        self.digest_override = digest_override
        self.unavailable = unavailable
        self.calls: list[tuple[bytes, str]] = []

    def validate(self, package_bytes: bytes, *, digest: str) -> dict[str, Any]:
        if self.unavailable:
            raise ValidatorUnavailable("validator image is not built")
        self.calls.append((package_bytes, digest))
        return _report_for(
            package_bytes,
            status=self.status,
            digest=self.digest_override,
        )


class FakeHost:
    """Trusted host double: candidate submission plus internal report binding."""

    def __init__(self) -> None:
        self.submissions: list[tuple[str, bytes, str | None]] = []
        self.reports: list[tuple[str, dict[str, Any], int | None]] = []

    def submit_candidate(
        self,
        principal: Any,
        package_bytes: bytes,
        expected_digest: str | None = None,
    ) -> dict[str, Any]:
        self.submissions.append((principal.actor_id, package_bytes, expected_digest))
        return {
            "id": "candidate-1",
            "extensionId": "record-registry",
            "digest": _digest(package_bytes),
            "state": "pending",
            "revision": 7,
        }

    def record_validation_report(
        self,
        candidate_id: str,
        report: dict[str, Any],
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        self.reports.append((candidate_id, report, expected_version))
        return {"id": candidate_id}


@pytest.fixture()
def catalog(settings_factory):
    database = prepare(settings_factory)
    try:
        yield database
    finally:
        database.engine.dispose()


@pytest.fixture()
def admin(catalog):
    return catalog.admin()


@pytest.fixture()
def reader(catalog):
    return catalog.add_user(*READER)


def _service(
    catalog,
    root: Path,
    *,
    validator=None,
    host=None,
    **kwargs,
) -> DevelopmentService:
    return DevelopmentService(
        root,
        session_factory=catalog.factory(),
        identity_factory=lambda session: catalog.service(session),
        validator=validator or FakeValidator(),
        host=host,
        **kwargs,
    )


def _create(service: DevelopmentService, admin, *, workspace_id: str = "record-registry"):
    return service.dispatch(
        "extension_workspace_create",
        {
            "id": workspace_id,
            "name": "Registro de registros",
            "description": "Registros internos de ejemplo para el SDK.",
        },
        admin,
    )


def _validate(service: DevelopmentService, admin, workspace_id: str = "record-registry"):
    return service.dispatch(
        "extension_workspace_validate",
        {"workspace_id": workspace_id},
        admin,
    )


def test_generate_writes_complete_working_record_registry(tmp_path: Path) -> None:
    generated = generate_package(
        extension_id="record-registry",
        name="Registro de registros",
        description="Registros internos de ejemplo para el SDK.",
    )
    assert set(generated.files) == {
        "extension.json",
        "backend.py",
        "skills/record-registry/SKILL.md",
        "tests/test_backend.py",
    }
    manifest = validate_manifest(generated.manifest, known_core_permissions=())
    assert manifest["id"] == "record-registry"
    assert manifest["sdkVersion"] == 2
    assert manifest["runtime"] == "sandboxed"
    assert manifest["storage"] == {"engine": "sqlite"}
    assert {item["kind"] for item in manifest["operations"]} == {"handler"}
    assert manifest["frontend"]["pages"][0]["view"]["table"]["operation"] == "list_records"
    assert "entry" not in manifest["frontend"]
    assert manifest["version"] == "1.0.0"
    assert manifest["schemaVersion"] == 2
    assert manifest["compatibleSchemaVersions"] == [1, 2]
    assert [item["handler"] for item in manifest["migrations"]] == ["normalize_status"]
    assert {item["name"] for item in manifest["collections"]} == {"records"}
    assert {item["name"] for item in manifest["operations"]} == {
        "list_records",
        "create_record",
    }
    assert all(
        operation["permission"].startswith("ext_record_registry.")
        for operation in manifest["operations"]
    )
    assert "license" not in json.dumps(manifest).lower()

    target = tmp_path / "generated"
    written = write_package(target, generated)
    assert sorted(written) == sorted(generated.files)
    for relative, content in generated.files.items():
        assert (target / relative).read_text(encoding="utf-8") == content
    with pytest.raises(PackageError):
        write_package(target, generated)

    declarative = generate_package(
        extension_id="notes-board",
        name="Tablero de notas",
        description="Notas declarativas sin código de módulo.",
        runtime="declarative",
    )
    assert set(declarative.files) == {
        "extension.json",
        "skills/notes-board/SKILL.md",
        "tests/test_module.py",
    }
    declarative_manifest = validate_manifest(declarative.manifest, known_core_permissions=())
    assert declarative_manifest["runtime"] == "declarative"
    assert "backend.py" not in declarative.files
    assert {item["kind"] for item in declarative_manifest["operations"]} == {
        "list",
        "get",
        "put",
        "delete",
    }
    assert declarative_manifest["migrations"] == []
    assert (
        declarative_manifest["frontend"]["pages"][0]["view"]["table"]["operation"] == "list_notes"
    )
    with pytest.raises(ValueError, match="runtime"):
        generate_package(
            extension_id="notes-board",
            name="Tablero de notas",
            description="Runtime desconocido.",
            runtime="native",
        )


def test_package_bytes_are_deterministic_and_digest_is_actual_bytes() -> None:
    generated = generate_package(
        extension_id="record-registry",
        name="Registro de registros",
        description="Registros internos de ejemplo para el SDK.",
    )
    first = build_package(generated.files, known_core_permissions=())
    second = build_package(generated.files, known_core_permissions=())
    assert first.data == second.data
    assert first.digest == second.digest == _digest(first.data)
    assert parse_package(first.data, known_core_permissions=()).digest == first.digest

    with zipfile.ZipFile(io.BytesIO(first.data)) as archive:
        infos = archive.infolist()
        assert [item.filename for item in infos] == sorted(item.filename for item in infos)
        assert {item.date_time for item in infos} == {(1980, 1, 1, 0, 0, 0)}

    edited = dict(generated.files)
    edited["backend.py"] += "\n# source edit\n"
    changed = build_package(edited, known_core_permissions=())
    assert changed.digest != first.digest
    assert changed.data != first.data


def test_real_harness_validates_generated_package_operations_and_migrations(
    tmp_path: Path,
) -> None:
    if not (shutil.which("node") or shutil.which("bun")):
        pytest.skip("no JavaScript engine on the host for the local harness")
    generated = generate_package(
        extension_id="record-registry",
        name="Registro de registros",
        description="Registros internos de ejemplo para el SDK.",
    )
    built = build_package(generated.files, known_core_permissions=())
    payload = build_frame(built.data, digest=built.digest, known_core_permissions=())
    run_py = BACKEND_ROOT / "itsm" / "extensions" / "sdk" / "validator" / "run.py"
    completed = subprocess.run(
        [sys.executable, "-I", str(run_py)],
        input=payload,
        capture_output=True,
        timeout=90,
        cwd=tmp_path,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    report = json.loads(completed.stdout)
    assert set(report) == REPORT_KEYS
    assert report["status"] == "passed", report["errors"]
    assert report["digest"] == built.digest
    assert report["container"]["network"] == "none"
    assert report["container"]["readOnly"] is True
    engine = report["container"]["engine"]
    assert engine.startswith("python ")
    assert " js " in engine and engine.split(" js ", 1)[1].startswith(("node ", "bun "))
    checks = {item["name"]: item for item in report["checks"]}
    assert set(checks) >= REQUIRED_CHECKS
    assert all(item["status"] == "passed" for item in checks.values())
    assert checks["archive"]["detail"].startswith("4 files;")
    assert "expanded bytes" in checks["archive"]["detail"]
    assert "backend.py" in checks["archive"]["detail"]
    assert "def register" not in checks["archive"]["detail"]
    assert checks["backend"]["detail"] == "backend.py syntax and standard-library imports checked"
    assert checks["execution"]["status"] == "passed"
    assert checks["operations"]["detail"].startswith("2 operations")
    assert "normalize_status" in checks["migrations"]["detail"]
    assert "1->2" in checks["migrations"]["detail"]
    assert "declarative view" in checks["frontend"]["detail"]


@pytest.mark.parametrize("failure", [None, "signature", "business"])
def test_validator_uses_package_fixtures_for_domain_operations(
    tmp_path: Path,
    failure: str | None,
) -> None:
    generated = generate_package(
        extension_id="asset-records",
        name="Registros de equipos",
        description="Validación con activos y fechas reales de prueba.",
    )
    files = dict(generated.files)
    manifest = copy.deepcopy(generated.manifest)
    operation = manifest["operations"][1]
    manifest["corePermissions"] = ["assets.view"]
    manifest["operations"] = [
        {
            **operation,
            "name": "record_asset",
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "asset_id": {"type": "string"},
                    "expires_on": {"type": "string"},
                    "notes": {"type": "string"},
                },
                "required": ["asset_id", "expires_on"],
            },
        }
    ]
    manifest["schemaVersion"] = 1
    manifest["compatibleSchemaVersions"] = [1]
    manifest["migrations"] = []
    manifest["frontend"] = {"pages": [], "assetPanels": [], "contributions": []}
    files["extension.json"] = json.dumps(manifest)
    files["backend.py"] = """
from datetime import date

def record_asset(context, asset_id, expires_on, notes=""):
    asset = context.assets.get(asset_id)
    return {"asset_id": asset["id"],
            "expires_on": date.fromisoformat(expires_on).isoformat(), "notes": notes}

def register(sdk):
    sdk.operation("record_asset", record_asset)
"""
    files["tests/test_backend.py"] = """
import unittest
from types import SimpleNamespace
from backend import record_asset

class Assets:
    def get(self, asset_id):
        if asset_id != "test-computer":
            raise LookupError(asset_id)
        return {"id": "test-computer"}

class DomainTests(unittest.TestCase):
    def test_required_asset_and_expiration(self):
        context = SimpleNamespace(assets=Assets())
        self.assertEqual(record_asset(context, "test-computer", "2030-01-02", "Office"),
                         {"asset_id": "test-computer", "expires_on": "2030-01-02",
                          "notes": "Office"})
        with self.assertRaises(LookupError):
            record_asset(context, "missing", "2030-01-02")
        with self.assertRaises(ValueError):
            record_asset(context, "test-computer", "not-a-date")
"""
    if failure == "signature":
        files["backend.py"] += """
def register(sdk):
    sdk.operation("record_asset", lambda context, asset_id, expires_on: {})
"""
    elif failure == "business":
        files["backend.py"] = files["backend.py"].replace(
            "date.fromisoformat(expires_on).isoformat()",
            '"incorrect-expiration"',
        )
    built = build_package(files, known_core_permissions=("assets.view",))
    completed = subprocess.run(
        [sys.executable, "-I", str(BACKEND_ROOT / "itsm/extensions/sdk/validator/run.py")],
        input=build_frame(built.data, digest=built.digest, known_core_permissions=("assets.view",)),
        capture_output=True,
        timeout=90,
        cwd=tmp_path,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    report = json.loads(completed.stdout)
    checks = {item["name"]: item for item in report["checks"]}
    if failure is None:
        assert report["status"] == "passed", report["errors"]
    else:
        assert report["status"] == "failed"
        assert checks["operations" if failure == "signature" else "tests"]["status"] == "failed"


def test_manifest_contract_rejects_unknown_fields_and_unsafe_shapes() -> None:
    generated = generate_package(
        extension_id="record-registry",
        name="Registro de registros",
        description="Registros internos de ejemplo para el SDK.",
    )
    base = copy.deepcopy(generated.manifest)

    def rejected(change) -> ManifestError:
        candidate = copy.deepcopy(base)
        change(candidate)
        with pytest.raises(ManifestError) as caught:
            validate_manifest(candidate, known_core_permissions=())
        return caught.value

    def unknown_field(candidate):
        candidate["unexpected"] = True

    def bad_permission(candidate):
        candidate["operations"][0]["permission"] = "assets.view"

    def undeclared_core(candidate):
        candidate["corePermissions"] = ["not.a.permission"]

    def duplicate_operation(candidate):
        candidate["operations"].append(copy.deepcopy(candidate["operations"][0]))

    def broken_migration(candidate):
        candidate["migrations"][0]["to"] = 3

    def wrong_skill_path(candidate):
        candidate["skills"][0]["path"] = "skills/other/SKILL.md"

    def bad_version(candidate):
        candidate["version"] = "1.0"

    def unknown_field_error(exc: ManifestError) -> bool:
        return any("unknown" in error for error in exc.errors)

    assert unknown_field_error(rejected(unknown_field))
    assert any("permission" in error for error in rejected(bad_permission).errors)
    assert any("core permission" in error for error in rejected(undeclared_core).errors)
    assert any("duplicate" in error for error in rejected(duplicate_operation).errors)
    assert any("migration" in error for error in rejected(broken_migration).errors)
    assert any("skill" in error for error in rejected(wrong_skill_path).errors)
    assert any("version" in error for error in rejected(bad_version).errors)
    schema = load_schema()
    assert schema["properties"]["sdkVersion"]["const"] == 2
    assert schema["additionalProperties"] is False


def _composition_manifest(mode="replace", target="page.inventory"):
    manifest = generate_package(
        extension_id="record-registry",
        name="Records",
        description="SDK composition test.",
    ).manifest
    item = {
        "id": "inventory-summary",
        "label": "Inventory summary",
        "target": target,
        "mode": mode,
        "permission": "ext_record_registry.records_read",
        "order": 10,
    }
    if mode != "hide":
        item["component"] = "RecordList"
    manifest["frontend"]["contributions"] = [item]
    # SDK v2 renders module components only inside the isolated iframe, so a
    # component contribution requires the module's own entry bundle.
    manifest["frontend"]["entry"] = "frontend.js"
    return manifest


COMPOSITION_FRONTEND = """
window.ITSMExtension.register({components: {RecordList: {template: "<div>records</div>"}}});
"""


@pytest.mark.parametrize("mode", ["add", "hide", "replace"])
def test_business_ui_composition_roundtrips_package_and_keeps_old_pages(mode):
    manifest = _composition_manifest(mode)
    validated = validate_manifest(manifest, known_core_permissions=())
    assert validated["sdkVersion"] == 2
    assert validated["frontend"]["contributions"][0]["mode"] == mode
    generated = generate_package(
        extension_id="record-registry",
        name="Records",
        description="SDK composition test.",
    )
    files = dict(generated.files)
    files["extension.json"] = json.dumps(manifest)
    files["frontend.js"] = COMPOSITION_FRONTEND
    packed = build_package(files, known_core_permissions=())
    decoded = parse_package(packed.data, known_core_permissions=()).manifest
    assert decoded == manifest
    assert decoded["frontend"]["pages"] == generated.manifest["frontend"]["pages"]
    assert decoded["frontend"]["assetPanels"] == generated.manifest["frontend"]["assetPanels"]
    legacy = copy.deepcopy(manifest)
    del legacy["frontend"]["contributions"]
    assert validate_manifest(legacy, known_core_permissions=()) == legacy


@pytest.mark.parametrize(
    "target",
    [
        "nav.reports",
        "page.inventory",
        "widget.activity",
        "asset.panel.warranty",
        "asset.action.assign",
        "config.apariencia",
    ],
)
def test_business_ui_catalogue_accepts_each_surface(target):
    manifest = _composition_manifest(target=target)
    assert validate_manifest(manifest, known_core_permissions=()) == manifest


@pytest.mark.parametrize(
    "change",
    [
        {"target": "page.login"},
        {"target": "nav.users"},
        {"target": "nav.config"},
        {"target": "config.seguridad"},
        {"target": "config.extensiones"},
        {"target": "config.sistema"},
        {"target": "#app .sidebar"},
        {"target": "widget.unknown"},
        {"mode": "remove"},
        {"order": True},
        {"permission": "assets.view"},
        {"component": "<script>"},
        {"id": "records"},
        {"mode": "hide", "component": "RecordList"},
        {"target": "nav.extensions", "mode": "replace"},
    ],
)
def test_business_ui_composition_rejects_invalid_declarations_without_mutating(change):
    manifest = _composition_manifest()
    manifest["frontend"]["contributions"][0].update(change)
    before = copy.deepcopy(manifest)
    with pytest.raises(ManifestError):
        validate_manifest(manifest, known_core_permissions=())
    assert manifest == before


@pytest.mark.parametrize("mode", ["add", "replace"])
def test_business_ui_composition_requires_a_component(mode):
    manifest = _composition_manifest(mode)
    del manifest["frontend"]["contributions"][0]["component"]
    with pytest.raises(ManifestError):
        validate_manifest(manifest, known_core_permissions=())


@pytest.mark.parametrize("registered", [False, True])
def test_real_harness_requires_new_composition_components(tmp_path, registered):
    if not (shutil.which("node") or shutil.which("bun")):
        pytest.skip("no JavaScript engine on the host for the local harness")
    generated = generate_package(
        extension_id="record-registry",
        name="Records",
        description="SDK composition test.",
    )
    manifest = _composition_manifest()
    component = "RecordList" if registered else "MissingBusinessWidget"
    manifest["frontend"]["contributions"][0]["component"] = component
    files = dict(generated.files)
    files["extension.json"] = json.dumps(manifest)
    files["frontend.js"] = COMPOSITION_FRONTEND
    built = build_package(files, known_core_permissions=())
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(BACKEND_ROOT / "itsm/extensions/sdk/validator/run.py"),
        ],
        input=build_frame(built.data, digest=built.digest, known_core_permissions=()),
        capture_output=True,
        timeout=90,
        cwd=tmp_path,
        check=False,
    )
    report = json.loads(completed.stdout)
    # The framed validator process completed; rejection lives in the report.
    assert completed.returncode == 0, completed.stderr.decode()
    assert report["status"] == ("passed" if registered else "failed"), report
    if registered:
        assert report["errors"] == []
    else:
        assert "MissingBusinessWidget" in json.dumps(report["errors"])


def test_manifest_allows_forward_compatible_rollback_without_down_migration() -> None:
    generated = generate_package(
        extension_id="record-registry",
        name="Registro de registros",
        description="Registros internos de ejemplo para el SDK.",
    )
    manifest = copy.deepcopy(generated.manifest)
    manifest["schemaVersion"] = 1
    manifest["compatibleSchemaVersions"] = [1, 2]
    manifest["migrations"] = []
    validated = validate_manifest(manifest, known_core_permissions=())
    assert validated["schemaVersion"] == 1
    assert validated["compatibleSchemaVersions"] == [1, 2]
    assert validated["migrations"] == []


def test_archive_containment_rejects_traversal_links_duplicates_and_size() -> None:
    generated = generate_package(
        extension_id="record-registry",
        name="Registro de registros",
        description="Registros internos de ejemplo para el SDK.",
    )
    built = build_package(generated.files, known_core_permissions=())

    def archive_with(extra: list[tuple[str, bytes, int]]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in generated.files.items():
                archive.writestr(name, content)
            for name, content, mode in extra:
                info = zipfile.ZipInfo(name)
                info.external_attr = mode << 16
                archive.writestr(info, content)
        return buffer.getvalue()

    traversal = archive_with([("../escape.py", b"print('x')", stat.S_IFREG | 0o644)])
    with pytest.raises(PackageError):
        parse_package(traversal, known_core_permissions=())

    link = archive_with([("tests/test_link.py", b"target", stat.S_IFLNK | 0o777)])
    with pytest.raises(PackageError):
        parse_package(link, known_core_permissions=())

    duplicate = io.BytesIO()
    with zipfile.ZipFile(duplicate, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in generated.files.items():
            archive.writestr(name, content)
        archive.writestr("backend.py", "duplicate")
    with pytest.raises(PackageError):
        parse_package(duplicate.getvalue(), known_core_permissions=())

    with pytest.raises(PackageError):
        parse_package(
            built.data,
            known_core_permissions=(),
            limits=ArchiveLimits(max_archive_bytes=64),
        )

    binary = dict(generated.files)
    binary["tests/test_binary.py"] = "print('x')\x00"
    with pytest.raises(PackageError):
        build_package(binary, known_core_permissions=())


def test_workspace_create_list_read_write_is_actor_owned(
    tmp_path: Path, catalog, admin, reader
) -> None:
    service = _service(catalog, tmp_path / "development")
    created = _create(service, admin)
    assert created["id"] == "record-registry"
    assert created["validation"] is None
    assert set(created["files"]) == {
        "extension.json",
        "backend.py",
        "skills/record-registry/SKILL.md",
        "tests/test_backend.py",
    }

    listing = service.dispatch(
        "extension_workspace_files",
        {"workspace_id": "record-registry"},
        admin,
    )
    assert {item["path"] for item in listing["files"]} == set(created["files"])
    assert listing["workspace"]["id"] == "record-registry"

    read = service.dispatch(
        "extension_workspace_read",
        {"workspace_id": "record-registry", "path": "backend.py"},
        admin,
    )
    assert "def register(sdk)" in read["content"]

    written = service.dispatch(
        "extension_workspace_write",
        {
            "workspace_id": "record-registry",
            "path": "skills/record-registry/SKILL.md",
            "content": "---\nname: record-registry\ndescription: changed\n---\n# Registry\n",
        },
        admin,
    )
    assert written["validation"] == "invalidated"
    assert service.dispatch(
        "extension_workspace_read",
        {"workspace_id": "record-registry", "path": "skills/record-registry/SKILL.md"},
        admin,
    )["content"].startswith("---")

    with pytest.raises(PermissionDenied):
        service.dispatch(
            "extension_workspace_files",
            {"workspace_id": "record-registry"},
            reader,
        )
    with pytest.raises(PermissionDenied):
        _create(service, reader, workspace_id="reader-records")
    with pytest.raises(WorkspaceConflict):
        _create(service, admin)
    with pytest.raises(WorkspaceNotFound):
        service.dispatch(
            "extension_workspace_files",
            {"workspace_id": "missing-workspace"},
            admin,
        )
    with pytest.raises(InvalidArguments):
        service.dispatch("extension_workspace_read", {"workspace_id": "record-registry"}, admin)


def test_forbidden_paths_links_and_sizes_preserve_workspace_and_validation(
    tmp_path: Path, catalog, admin, reader
) -> None:
    service = _service(catalog, tmp_path / "development")
    _create(service, admin)
    first = _validate(service, admin)
    assert first["status"] == "passed"
    before = service.dispatch(
        "extension_workspace_files",
        {"workspace_id": "record-registry"},
        admin,
    )

    for path in ("../escape.py", "/etc/passwd", "skills/../../escape.py", "notes.md"):
        with pytest.raises(WorkspacePathRejected):
            service.dispatch(
                "extension_workspace_write",
                {"workspace_id": "record-registry", "path": path, "content": "x"},
                admin,
            )
    with pytest.raises(WorkspaceLimitExceeded):
        service.dispatch(
            "extension_workspace_write",
            {
                "workspace_id": "record-registry",
                "path": "backend.py",
                "content": "x" * (service.file_bytes_limit + 1),
            },
            admin,
        )
    with pytest.raises(PermissionDenied):
        service.dispatch(
            "extension_workspace_write",
            {
                "workspace_id": "record-registry",
                "path": "backend.py",
                "content": "tampered",
            },
            reader,
        )

    root = service.workspace_root(admin, "record-registry")
    (root / "tests" / "test_link.py").symlink_to(root / "backend.py")
    with pytest.raises(WorkspacePathRejected):
        service.dispatch(
            "extension_workspace_files",
            {"workspace_id": "record-registry"},
            admin,
        )
    failed = _validate(service, admin)
    assert failed["status"] == "failed"
    assert any("symlink" in error.lower() for error in failed["errors"])
    (root / "tests" / "test_link.py").unlink()

    after = service.dispatch(
        "extension_workspace_files",
        {"workspace_id": "record-registry"},
        admin,
    )
    assert {item["path"] for item in after["files"]} == {item["path"] for item in before["files"]}
    assert after["workspace"]["validation"]["status"] == "failed"


def test_source_edit_invalidates_validation_and_stale_submit_is_denied(
    tmp_path: Path, catalog, admin
) -> None:
    host = FakeHost()
    service = _service(catalog, tmp_path / "development", host=host)
    _create(service, admin)
    report = _validate(service, admin)
    assert report["status"] == "passed"

    service.dispatch(
        "extension_workspace_write",
        {
            "workspace_id": "record-registry",
            "path": "backend.py",
            "content": service.dispatch(
                "extension_workspace_read",
                {"workspace_id": "record-registry", "path": "backend.py"},
                admin,
            )["content"]
            + "\n# another candidate\n",
        },
        admin,
    )
    with pytest.raises(ValidationRequired):
        service.dispatch(
            "extension_workspace_submit",
            {"workspace_id": "record-registry"},
            admin,
        )
    assert host.submissions == []
    listing = service.dispatch(
        "extension_workspace_files",
        {"workspace_id": "record-registry"},
        admin,
    )
    assert listing["workspace"]["validation"] is None


def test_submit_uses_immutable_bytes_and_records_bound_report(
    tmp_path: Path, catalog, admin
) -> None:
    host = FakeHost()
    service = _service(catalog, tmp_path / "development", host=host)
    _create(service, admin)
    _validate(service, admin)
    detail = service.dispatch(
        "extension_workspace_submit",
        {"workspace_id": "record-registry"},
        admin,
    )
    assert detail["state"] == "pending"
    assert len(host.submissions) == 1
    actor_id, package_bytes, expected_digest = host.submissions[0]
    assert actor_id == admin.actor_id
    assert expected_digest == _digest(package_bytes)
    assert _manifest_from_package(package_bytes)["id"] == "record-registry"
    assert len(host.reports) == 1
    candidate_id, report, expected_version = host.reports[0]
    assert candidate_id == "candidate-1"
    assert expected_version == 7
    assert report["digest"] == expected_digest
    assert report["status"] == "passed"
    assert set(report) == REPORT_KEYS


def test_submit_without_host_and_unavailable_validator_are_explicit(
    tmp_path: Path, catalog, admin
) -> None:
    service = _service(
        catalog,
        tmp_path / "no-host",
        validator=FakeValidator(unavailable=True),
    )
    _create(service, admin)
    with pytest.raises(ValidatorUnavailable):
        _validate(service, admin)
    listing = service.dispatch(
        "extension_workspace_files",
        {"workspace_id": "record-registry"},
        admin,
    )
    assert listing["workspace"]["validation"] is None

    service = _service(catalog, tmp_path / "no-submit")
    _create(service, admin)
    _validate(service, admin)
    with pytest.raises(DevelopmentUnavailable):
        service.dispatch(
            "extension_workspace_submit",
            {"workspace_id": "record-registry"},
            admin,
        )


def test_failed_or_digest_mismatched_report_is_never_submittable(
    tmp_path: Path, catalog, admin
) -> None:
    failed = FakeValidator(status="failed")
    service = _service(catalog, tmp_path / "failed", validator=failed)
    _create(service, admin)
    report = _validate(service, admin)
    assert report["status"] == "failed"
    with pytest.raises(ValidationRequired):
        service.dispatch(
            "extension_workspace_submit",
            {"workspace_id": "record-registry"},
            admin,
        )

    mismatch = FakeValidator(digest_override="0" * 64)
    service = _service(catalog, tmp_path / "mismatch", validator=mismatch)
    _create(service, admin)
    report = _validate(service, admin)
    assert report["status"] == "failed"
    assert any("digest" in error for error in report["errors"])
    with pytest.raises(ValidationRequired):
        service.dispatch(
            "extension_workspace_submit",
            {"workspace_id": "record-registry"},
            admin,
        )


def test_bad_manifest_in_workspace_fails_closed_before_the_container(
    tmp_path: Path, catalog, admin
) -> None:
    validator = FakeValidator()
    service = _service(catalog, tmp_path / "bad-manifest", validator=validator)
    _create(service, admin)
    manifest = json.loads(
        service.dispatch(
            "extension_workspace_read",
            {"workspace_id": "record-registry", "path": "extension.json"},
            admin,
        )["content"]
    )
    manifest["unexpected"] = "not allowed"
    service.dispatch(
        "extension_workspace_write",
        {
            "workspace_id": "record-registry",
            "path": "extension.json",
            "content": json.dumps(manifest),
        },
        admin,
    )
    report = _validate(service, admin)
    assert report["status"] == "failed"
    assert report["digest"] == ""
    assert validator.calls == []
    with pytest.raises(ValidationRequired):
        service.dispatch(
            "extension_workspace_submit",
            {"workspace_id": "record-registry"},
            admin,
        )


def test_sdk_reference_is_bounded_and_searchable(tmp_path: Path, catalog, admin) -> None:
    service = _service(catalog, tmp_path / "references")
    index = service.dispatch("extension_sdk_index", {}, admin)
    assert index["sdkVersion"] == 2
    assert index["schema"] == "schema/extension.schema.json"
    names = {item["name"] for item in index["references"]}
    assert {
        "quickstart",
        "lifecycle",
        "manifest",
        "backend",
        "frontend",
        "collections",
        "migrations",
        "security",
        "validation",
        "workspace-tools",
    } <= names
    for item in index["references"]:
        reference = service.dispatch("extension_sdk_reference", {"name": item["name"]}, admin)
        assert reference["sdkVersion"] == 2
        assert reference["content"]
        assert len(reference["content"]) <= 24_384
    with pytest.raises(InvalidArguments):
        service.dispatch("extension_sdk_reference", {"name": "../secret"}, admin)


def test_container_command_is_fixed_isolated_and_uniquely_named() -> None:
    validator = ContainerValidator(core_permissions=("assets.view",))
    first = validator._command("itsm-ext-val-one")
    second = validator._command("itsm-ext-val-two")
    assert first[0] == "docker"
    assert "run" in first
    assert "--pull=never" in first
    assert "--network" in first and first[first.index("--network") + 1] == "none"
    assert "--read-only" in first
    assert first[first.index("--cap-drop") + 1] == "ALL"
    assert first[first.index("--security-opt") + 1] == "no-new-privileges"
    assert "--user" in first and first[first.index("--user") + 1] == "10001:10001"
    assert "--tmpfs" in first
    assert first[first.index("--name") + 1] == "itsm-ext-val-one"
    assert first != second
    for forbidden in ("-v", "--mount", "--volume", "--privileged", "--env-file"):
        assert forbidden not in first
    assert validator._container_name() != validator._container_name()
    with pytest.raises(ValueError):
        ContainerValidator(image="--rm")


def test_cli_generate_pack_inspect_offline_roundtrip(tmp_path: Path) -> None:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    target = tmp_path / "cli-package"
    generated = subprocess.run(
        [
            sys.executable,
            "-m",
            "itsm.extensions",
            "generate",
            str(target),
            "--id",
            "cli-records",
            "--name",
            "CLI Records",
            "--description",
            "Paquete generado desde la CLI.",
        ],
        cwd=BACKEND_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr
    generated_payload = json.loads(generated.stdout)
    assert generated_payload["id"] == "cli-records"
    assert (target / "backend.py").is_file()

    archive = tmp_path / "cli-records.zip"
    packed = subprocess.run(
        [
            sys.executable,
            "-m",
            "itsm.extensions",
            "pack",
            str(target),
            "--output",
            str(archive),
        ],
        cwd=BACKEND_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert packed.returncode == 0, packed.stderr
    packed_payload = json.loads(packed.stdout)
    assert packed_payload["digest"] == _digest(archive.read_bytes())

    inspected = subprocess.run(
        [
            sys.executable,
            "-m",
            "itsm.extensions",
            "inspect",
            str(archive),
        ],
        cwd=BACKEND_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert inspected.returncode == 0, inspected.stderr
    inspected_payload = json.loads(inspected.stdout)
    assert inspected_payload["digest"] == packed_payload["digest"]
    assert inspected_payload["manifest"]["id"] == "cli-records"
    assert set(inspected_payload["files"]) == set(generated_payload["files"])

    bad = subprocess.run(
        [
            sys.executable,
            "-m",
            "itsm.extensions",
            "generate",
            str(target),
            "--id",
            "other-id",
            "--name",
            "Other",
            "--description",
            "No debe sobrescribir.",
        ],
        cwd=BACKEND_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert bad.returncode != 0
    assert "exists" in bad.stderr.lower()


def test_container_validator_smoke_is_prerequisite_gated(tmp_path: Path) -> None:
    validator = ContainerValidator(
        core_permissions=(),
        image=os.environ.get("ITSM_TEST_EXTENSION_VALIDATOR_IMAGE", "itsm-extension-validator:1"),
    )
    if not validator.available():
        pytest.skip("validator image is not built; parent runs the actual container smoke")
    generated = generate_package(
        extension_id="record-registry",
        name="Registro de registros",
        description="Registros internos de ejemplo para el SDK.",
    )
    built = build_package(generated.files, known_core_permissions=())
    report = validator.validate(built.data, digest=built.digest)
    assert set(report) == REPORT_KEYS
    assert report["status"] == "passed", report["errors"]
    assert report["digest"] == built.digest
    assert all(item["status"] == "passed" for item in report["checks"])


@pytest.mark.parametrize(
    "backend",
    [
        "def register(sdk):\n    while True:\n        print('x' * 8192, flush=True)\n",
        "def register(sdk):\n    while True:\n        pass\n",
    ],
)
def test_real_container_bounds_candidate_output_and_time(backend) -> None:
    validator = ContainerValidator(core_permissions=(), timeout=5, max_output=4096)
    if not validator.available():
        pytest.skip("fixed local validator image is not available")
    generated = generate_package(
        extension_id="bounded-records",
        name="Registros acotados",
        description="Prueba de límites del validador.",
    )
    files = dict(generated.files)
    files["backend.py"] = backend
    built = build_package(files, known_core_permissions=())
    started = time.monotonic()
    report = validator.validate(built.data, digest=built.digest)
    assert time.monotonic() - started < 20
    assert report["status"] == "failed"
    assert report["digest"] == built.digest
    assert len(json.dumps(report).encode()) < 8192
    assert report["container"]["network"] == "none"


@contextlib.contextmanager
def _running_validator_broker():
    from itsm.extensions.validator import create_validator_server

    validator = ContainerValidator(
        core_permissions=(),
        image=os.environ.get("ITSM_TEST_EXTENSION_VALIDATOR_IMAGE", "itsm-extension-validator:1"),
    )
    if not validator.available():
        pytest.skip("fixed local validator image is not available")
    token = "fixed-broker-test-token-with-32-characters"
    server = create_validator_server(
        validator=validator,
        token=token,
        host="127.0.0.1",
        port=0,
        read_timeout=2,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", token
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_remote_validator_uses_authenticated_fixed_http_path_without_proxy(monkeypatch) -> None:
    from itsm.extensions.validator import RemoteContainerValidator

    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    generated = generate_package(
        extension_id="remote-records",
        name="Registros remotos",
        description="Prueba de protocolo fijo del validador.",
    )
    built = build_package(generated.files, known_core_permissions=())
    with _running_validator_broker() as (url, token):
        validator = RemoteContainerValidator(url, token=token)
        report = validator.validate(built.data, digest=built.digest)
        assert set(report) == REPORT_KEYS
        assert report["status"] == "passed", report["errors"]
        assert report["digest"] == built.digest
        assert "bun 1.4.2" in report["container"]["engine"]
        assert all(item["status"] == "passed" for item in report["checks"])
        denied = RemoteContainerValidator(url, token="wrong-token-that-is-at-least-32-characters")
        with pytest.raises(ValidatorUnavailable, match="authorization"):
            denied.validate(built.data, digest=built.digest)


def test_validator_broker_rejects_auth_paths_oversize_and_digest_before_execution() -> None:
    with _running_validator_broker() as (url, token):
        port = int(url.rsplit(":", 1)[1])

        def request(path, headers, body=None):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
            try:
                connection.putrequest("POST", path)
                for name, value in headers.items():
                    connection.putheader(name, value)
                connection.endheaders(body)
                response = connection.getresponse()
                return response.status, json.loads(response.read())
            finally:
                connection.close()

        auth = {"Authorization": "Bearer " + token, "Content-Type": "application/zip"}
        status, body = request("/validate", {"Content-Length": "4194304"})
        assert status == 401
        assert body == {"error": "validator authorization required"}
        assert request("/other", {**auth, "Content-Length": "0"})[0] == 404
        assert request("/validate?image=other", {**auth, "Content-Length": "0"})[0] == 404
        assert request("/validate", {**auth, "Content-Length": "4194305"})[0] == 413
        assert (
            request(
                "/validate",
                {**auth, "Content-Length": "1", "X-ITSM-Extension-Digest": "0" * 64},
                b"x",
            )[0]
            == 422
        )
        assert request("/validate", {**auth, "Transfer-Encoding": "chunked"})[0] == 411


@pytest.mark.parametrize(
    "url",
    [
        "ftp://localhost",
        "http://user:password@localhost",
        "http://localhost/validate",
        "http://localhost?image=other",
        "http://localhost#fragment",
        "http://localhost:0",
    ],
)
def test_remote_validator_rejects_non_fixed_server_urls(url) -> None:
    from itsm.extensions.validator import RemoteContainerValidator

    with pytest.raises(ValueError):
        RemoteContainerValidator(url, token="fixed-broker-test-token-with-32-characters")


def test_harness_context_matches_native_store_assets_and_notice_contract(tmp_path: Path) -> None:
    generated = generate_package(
        extension_id="context-records",
        name="Contrato nativo",
        description="Prueba del contexto publicado por el SDK.",
    )
    files = dict(generated.files)
    manifest = dict(generated.manifest)
    manifest["corePermissions"] = ["assets.view"]
    files["extension.json"] = json.dumps(manifest)
    files["backend.py"] += """

_create_record = create_record

def create_record(context, title, status="open", notes="", asset_id=None):
    # The sandboxed runner hands modules a plain dict projection, not a dataclass.
    assert context.principal["actor_id"]
    assert context.principal["kind"] == "human"
    page = context.assets.search(query="registry", limit=2, offset=0)
    assert page == {"items": [], "total": 0, "limit": 2, "offset": 0}
    try:
        context.assets.get("missing")
    except Exception as exc:
        assert type(exc).__name__ == "NotFound"
    else:
        raise AssertionError("missing assets must not return None")
    result = _create_record(context, title, status, notes, asset_id)
    record = result["record"]
    try:
        with context.transaction() as active:
            assert active is context
            context.store.delete("records", record["id"], expected_version=record["version"])
            raise ValueError("rollback fixture")
    except ValueError:
        pass
    assert context.store.get("records", record["id"]) is not None
    try:
        context.store.delete("records", record["id"], expected_version=0)
    except Exception:
        pass
    else:
        raise AssertionError("delete must reject a stale expected version")
    assert context.store.get("records", record["id"]) is not None
    context.notify(
        recipient_ids=[context.principal["actor_id"]], key="record-created",
        title="Registro creado", body="Se ha creado el registro.",
        permission=WRITE_PERMISSION, url="#/extensiones/context-records/records",
    )
    return result

_normalize_status = normalize_status

def normalize_status(context):
    create_record(context, "Explicit context fixture")
    return _normalize_status(context)
"""
    files["tests/test_backend.py"] = """
import unittest
import backend

class RegistrationTest(unittest.TestCase):
    def test_register_binds_public_handlers(self):
        class Binder:
            def __init__(self):
                self.operations = {}
                self.migrations = {}
            def operation(self, name, handler):
                self.operations[name] = handler
            def migration(self, name, handler):
                self.migrations[name] = handler
        binder = Binder()
        backend.register(binder)
        self.assertEqual(set(binder.operations), {"list_records", "create_record"})
        self.assertEqual(set(binder.migrations), {"normalize_status"})
"""
    built = build_package(files, known_core_permissions=("assets.view",))
    payload = build_frame(built.data, digest=built.digest, known_core_permissions=("assets.view",))
    completed = subprocess.run(
        [sys.executable, "-I", str(BACKEND_ROOT / "itsm/extensions/sdk/validator/run.py")],
        input=payload,
        capture_output=True,
        timeout=90,
        cwd=tmp_path,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    report = json.loads(completed.stdout)
    assert report["status"] == "passed", report["errors"]
    assert all(check["status"] == "passed" for check in report["checks"])


@contextlib.contextmanager
def _protocol_report_server(status: int, payload: dict[str, Any]):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Location", "http://127.0.0.1:1/untrusted")
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    "change", ["unknown", "digest", "sdk", "failed-check", "empty-checks", "redirect"]
)
def test_remote_validator_rejects_malformed_success_and_redirects(change) -> None:
    from itsm.extensions.validator import RemoteContainerValidator

    generated = generate_package(
        extension_id="report-records", name="Informe", description="Informe acotado."
    )
    built = build_package(generated.files, known_core_permissions=())
    report = _report_for(built.data)
    status = 200
    if change == "unknown":
        report["extra"] = True
    elif change == "digest":
        report["digest"] = "0" * 64
    elif change == "sdk":
        report["sdkVersion"] = True
    elif change == "failed-check":
        report["checks"][0]["status"] = "failed"
    elif change == "empty-checks":
        report["checks"] = []
    else:
        status = 302
    with _protocol_report_server(status, report) as url:
        validator = RemoteContainerValidator(
            url, token="fixed-broker-test-token-with-32-characters"
        )
        with pytest.raises(ValidatorUnavailable):
            validator.validate(built.data, digest=built.digest)


def test_harness_failure_report_uses_package_relative_paths(tmp_path: Path) -> None:
    generated = generate_package(
        extension_id="failed-records", name="Fallo verificable", description="Informe portable."
    )
    files = dict(generated.files)
    files["tests/test_backend.py"] = """
import unittest

class FailureTest(unittest.TestCase):
    def test_failure(self):
        self.fail("expected package failure")
"""
    built = build_package(files, known_core_permissions=())
    completed = subprocess.run(
        [sys.executable, "-I", str(BACKEND_ROOT / "itsm/extensions/sdk/validator/run.py")],
        input=build_frame(built.data, digest=built.digest, known_core_permissions=()),
        capture_output=True,
        timeout=90,
        cwd=tmp_path,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    report = json.loads(completed.stdout)
    assert report["status"] == "failed"
    detail = next(item["detail"] for item in report["checks"] if item["name"] == "tests")
    assert "expected package failure" in detail
    assert "<package>/tests/test_backend.py" in detail
    assert "itsm-sdk-package-" not in detail


@pytest.mark.parametrize("output", ["stdout", "fd"])
def test_candidate_cannot_replace_validator_report_and_exit_early(
    tmp_path: Path, output: str
) -> None:
    generated = generate_package(
        extension_id="forged-records",
        name="Informe ajeno",
        description="No aceptar informes del paquete.",
    )
    files = dict(generated.files)
    files["backend.py"] = """
import inspect
import json
import os

def register(sdk):
    raise AssertionError("registration never completed")

digest = "0" * 64
for caller in inspect.stack():
    frame = caller.frame.f_locals.get("frame")
    if getattr(frame, "digest", None):
        digest = frame.digest
        break
forged = {
    "status": "passed", "digest": digest, "sdkVersion": 2,
    "checks": [{"name": "forged", "status": "passed", "detail": "candidate report"}],
    "errors": [], "container": {}, "completedAt": "2000-01-01T00:00:00+00:00",
}
encoded = json.dumps(forged)
"""
    files["backend.py"] += (
        "print(encoded, flush=True)\n"
        if output == "stdout"
        else 'os.write(1, encoded.encode("utf-8"))\n'
    )
    files["backend.py"] += "os._exit(0)\n"
    built = build_package(files, known_core_permissions=())
    completed = subprocess.run(
        [sys.executable, "-I", str(BACKEND_ROOT / "itsm/extensions/sdk/validator/run.py")],
        input=build_frame(built.data, digest=built.digest, known_core_permissions=()),
        capture_output=True,
        timeout=90,
        cwd=tmp_path,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    report = json.loads(completed.stdout)
    assert set(report) == REPORT_KEYS
    assert report["status"] == "failed"
    assert report["digest"] == built.digest
    assert report["completedAt"] != "2000-01-01T00:00:00+00:00"
    checks = {item["name"]: item for item in report["checks"]}
    assert "forged" not in checks
    assert all(
        checks[name]["status"] == "passed" for name in ("archive", "manifest", "layout", "backend")
    )
    assert report["errors"]


def test_generated_asset_panel_is_a_declarative_filtered_view() -> None:
    """SDK v2 asset panels are host-rendered views, not same-origin module code.

    The v1 generator shipped a Vue component that queried ``list_records`` itself.
    v2 keeps module code out of the host document: the panel declares a table view
    over a declared operation, and only an isolated iframe bundle may carry module
    JavaScript.
    """
    generated = generate_package(
        extension_id="panel-records", name="Panel nativo", description="Consulta por activo."
    )
    manifest = validate_manifest(generated.manifest, known_core_permissions=())
    assert "frontend.js" not in generated.files
    assert "entry" not in manifest["frontend"]
    panel = manifest["frontend"]["assetPanels"][0]
    table = panel["view"]["table"]
    assert table["filterAsset"] is True
    assert table["operation"] == "list_records"
    assert [column["field"] for column in table["columns"]] == ["title"]
    operations = {item["name"]: item for item in manifest["operations"]}
    assert operations[table["operation"]]["mutation"] is False
    assert operations[table["operation"]]["permission"] == panel["permission"]

    isolated = copy.deepcopy(manifest)
    isolated["frontend"]["entry"] = "frontend.js"
    isolated["frontend"]["assetPanels"][0]["view"] = {
        "isolated": {"component": "RecordSummary", "height": 320}
    }
    files = dict(generated.files)
    files["extension.json"] = json.dumps(isolated)
    files["frontend.js"] = (
        'window.ITSMExtension.register({components: {RecordSummary: {template: "<div/>"}}});'
    )
    packed = build_package(files, known_core_permissions=())
    decoded = parse_package(packed.data, known_core_permissions=()).manifest
    assert decoded["frontend"]["entry"] == "frontend.js"
    assert decoded["frontend"]["assetPanels"][0]["view"]["isolated"]["component"] == (
        "RecordSummary"
    )
