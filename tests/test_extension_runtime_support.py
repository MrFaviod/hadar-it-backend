"""Shared public-interface fixtures for the v2 extension isolation suites.

Everything here drives the same entry points production code uses: package
admission, the host service, the SQLite module file and the HTTP router.  No
test helper imports host internals or reaches into the sandbox process.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import zipfile
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.extensions.host import ExtensionHostService
from itsm.identity.service import IdentityService, Principal
from sqlalchemy import inspect
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, run_migrations

MODULE_ID = "probe"
DECLARATIVE_ID = "declarative-notes"
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
README = "Use only the declared operations and capabilities.\n"

PROBE_BACKEND = r"""
import os


def echo(context, value):
    return {"value": value, "extensionId": context.extension_id, "version": context.version}


def put_record(context, record_id, label, expected_version=None):
    return context.store.put("records", record_id, {"label": label}, expected_version)


def get_record(context, record_id):
    return context.store.get("records", record_id)


def list_records(context, limit=20, offset=0, filters=None):
    return context.store.list("records", limit, offset, filters)


def delete_record(context, record_id, expected_version=None):
    return {"deleted": context.store.delete("records", record_id, expected_version)}


def fail_after_write(context):
    context.store.put("records", "rolled-back", {"label": "never committed"})
    raise ValueError("private handler detail must never escape")


def read_only_write(context):
    return context.store.put("records", "denied", {"label": "read only"})


def probe_read(context, path):
    try:
        with open(path, "rb") as handle:
            return {"allowed": True, "content": handle.read(64).decode("utf-8", "replace")}
    except OSError as exc:
        return {"allowed": False, "errno": exc.errno, "error": type(exc).__name__}


def probe_write(context, path):
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("written by a sandboxed module")
        return {"allowed": True}
    except OSError as exc:
        return {"allowed": False, "errno": exc.errno, "error": type(exc).__name__}


def probe_tcp(context, host, port):
    socket = __import__("socket")

    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connection.settimeout(1)
            connection.connect((host, port))
        finally:
            connection.close()
        return {"allowed": True}
    except OSError as exc:
        return {"allowed": False, "errno": exc.errno, "error": type(exc).__name__}


def probe_subprocess(context):
    subprocess = __import__("subprocess")

    try:
        completed = subprocess.run(
            ["/bin/true"], capture_output=True, timeout=5, check=False
        )
        return {"allowed": completed.returncode == 0}
    except Exception as exc:
        return {"allowed": False, "error": type(exc).__name__}


def probe_system(context):
    try:
        status = getattr(os, "system")("true")
    except Exception as exc:
        return {"allowed": False, "error": type(exc).__name__}
    return {"allowed": status == 0, "status": status}


def probe_environment(context):
    return {
        "names": sorted(os.environ),
        "itsm": sorted(name for name in os.environ if name.startswith("ITSM_")),
    }


def probe_memory(context):
    try:
        block = bytearray(512 * 1024 * 1024)
    except MemoryError:
        return {"allowed": False, "error": "MemoryError"}
    return {"allowed": len(block) > 0}


def probe_spin(context):
    while True:
        pass


def probe_many_calls(context):
    for _ in range(400):
        context.authorize("ext_probe.read")
    return {"done": True}


def probe_big_result(context):
    return {"value": "x" * (2 * 1024 * 1024)}


def probe_asset_get(context, asset_id):
    try:
        return context.assets.get(asset_id)
    except Exception as exc:
        return {"denied": True, "error": str(exc)}


def probe_notify_denied(context, recipient_ids):
    try:
        context.notify(
            recipient_ids=recipient_ids,
            key="probe:notice",
            title="Probe",
            body="Probe notice",
            permission="ext_probe.write",
        )
    except Exception as exc:
        return {"denied": True, "error": str(exc)}
    return {"denied": False}


def probe_asset_create(context, values, idempotency_key):
    return context.assets.create(values, idempotencyKey=idempotency_key)


def probe_notify(context, recipient_ids):
    context.notify(
        recipient_ids=recipient_ids,
        key="probe:notice",
        title="Probe",
        body="Probe notice",
        permission="ext_probe.write",
    )
    return {"notified": True}


def probe_db_write(context, value):
    context.db.execute("CREATE TABLE IF NOT EXISTS own_table (value TEXT)")
    context.db.execute("INSERT INTO own_table (value) VALUES (?)", (value,))
    context.db.commit()
    row = context.db.execute("SELECT COUNT(*) FROM own_table").fetchone()
    return {"rows": row[0]}


def register(sdk):
    sdk.operation("echo", echo)
    sdk.operation("put_record", put_record)
    sdk.operation("get_record", get_record)
    sdk.operation("list_records", list_records)
    sdk.operation("delete_record", delete_record)
    sdk.operation("fail_after_write", fail_after_write)
    sdk.operation("read_only_write", read_only_write)
    sdk.operation("probe_read", probe_read)
    sdk.operation("probe_write", probe_write)
    sdk.operation("probe_tcp", probe_tcp)
    sdk.operation("probe_subprocess", probe_subprocess)
    sdk.operation("probe_system", probe_system)
    sdk.operation("probe_environment", probe_environment)
    sdk.operation("probe_memory", probe_memory)
    sdk.operation("probe_spin", probe_spin)
    sdk.operation("probe_many_calls", probe_many_calls)
    sdk.operation("probe_big_result", probe_big_result)
    sdk.operation("probe_asset_get", probe_asset_get)
    sdk.operation("probe_asset_create", probe_asset_create)
    sdk.operation("probe_notify", probe_notify)
    sdk.operation("probe_notify_denied", probe_notify_denied)
    sdk.operation("probe_db_write", probe_db_write)
"""

PROBE_OPERATIONS = (
    ("echo", False, {"value": "string"}, ["value"]),
    (
        "put_record",
        True,
        {"record_id": "string", "label": "string", "expected_version": "integer"},
        ["record_id", "label"],
    ),
    ("get_record", False, {"record_id": "string"}, ["record_id"]),
    (
        "list_records",
        False,
        {"limit": "integer", "offset": "integer", "filters": "object"},
        [],
    ),
    (
        "delete_record",
        True,
        {"record_id": "string", "expected_version": "integer"},
        ["record_id"],
    ),
    ("fail_after_write", True, {}, []),
    ("read_only_write", False, {}, []),
    ("probe_read", False, {"path": "string"}, ["path"]),
    ("probe_write", False, {"path": "string"}, ["path"]),
    (
        "probe_tcp",
        False,
        {"host": "string", "port": "integer"},
        ["host", "port"],
    ),
    ("probe_subprocess", False, {}, []),
    ("probe_system", False, {}, []),
    ("probe_environment", False, {}, []),
    ("probe_memory", False, {}, []),
    ("probe_spin", False, {}, []),
    ("probe_many_calls", False, {}, []),
    ("probe_big_result", False, {}, []),
    ("probe_asset_get", False, {"asset_id": "string"}, ["asset_id"]),
    (
        "probe_asset_create",
        True,
        {"values": "object", "idempotency_key": "string"},
        ["values", "idempotency_key"],
    ),
    ("probe_notify", True, {"recipient_ids": "array"}, ["recipient_ids"]),
    ("probe_notify_denied", True, {"recipient_ids": "array"}, ["recipient_ids"]),
    ("probe_db_write", True, {"value": "string"}, ["value"]),
)


def parameters(properties: Mapping[str, str], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {name: {"type": kind} for name, kind in properties.items()},
        "required": required,
        "additionalProperties": False,
    }


READ = "ext_probe.read"
WRITE = "ext_probe.write"


def probe_manifest(
    version: str = "1.0.0",
    *,
    schema: int = 1,
    capabilities: list[str] | None = None,
    runtime: str = "sandboxed",
    declarative: bool = False,
    extra_permissions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    permissions = [
        {"code": READ, "label": "Consultar", "description": "Consulta los registros"},
        {"code": WRITE, "label": "Editar", "description": "Edita los registros"},
        *(extra_permissions or []),
    ]
    declaration: dict[str, Any] = {
        "sdkVersion": 2,
        "id": MODULE_ID,
        "name": "Módulo de pruebas",
        "description": "Módulo de pruebas de aislamiento",
        "version": version,
        "runtime": runtime,
        "storage": {"engine": "sqlite"},
        "capabilities": list(capabilities or []),
        "permissions": permissions,
        "corePermissions": [],
        "operations": [],
        "collections": [
            {
                "name": "records",
                "description": "Registros del módulo",
                "schema": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string", "maxLength": 120},
                        "status": {"type": "string", "enum": ["active", "archived"]},
                    },
                    "required": ["label"],
                    "additionalProperties": False,
                },
            }
        ],
        "schemaVersion": schema,
        "compatibleSchemaVersions": [1] if schema == 1 else [1, schema],
        "migrations": [],
        "schedules": [],
        "skills": [
            {
                "name": "probe-guide",
                "description": "Uso autorizado",
                "path": "skills/probe-guide/SKILL.md",
            }
        ],
        "frontend": {"pages": [], "assetPanels": [], "contributions": []},
    }
    if not declarative:
        declaration["operations"] = [
            {
                "name": name,
                "description": "Operación de prueba con efecto observable",
                "permission": READ if not mutation else WRITE,
                "mutation": mutation,
                "kind": "handler",
                "parameters": parameters(properties, required),
            }
            for name, mutation, properties, required in PROBE_OPERATIONS
        ]
    return declaration


def declarative_manifest(version: str = "1.0.0", *, schema: int = 1) -> dict[str, Any]:
    declaration = probe_manifest(version, schema=schema, runtime="declarative", declarative=True)
    declaration["id"] = DECLARATIVE_ID
    declaration["name"] = "Notas declarativas"
    declaration["description"] = "Colección declarativa sin código de módulo"
    declaration["permissions"] = [
        {
            "code": f"ext_{DECLARATIVE_ID.replace('-', '_')}.read",
            "label": "Consultar",
            "description": "Consulta notas",
        },
        {
            "code": f"ext_{DECLARATIVE_ID.replace('-', '_')}.write",
            "label": "Editar",
            "description": "Edita notas",
        },
    ]
    prefix = f"ext_{DECLARATIVE_ID.replace('-', '_')}."
    declaration["operations"] = [
        {
            "name": "list_notes",
            "description": "Lista las notas declarativas",
            "permission": prefix + "read",
            "mutation": False,
            "kind": "list",
            "collection": "records",
            "parameters": parameters(
                {"limit": "integer", "offset": "integer", "filters": "object"}, []
            ),
        },
        {
            "name": "get_note",
            "description": "Obtiene una nota declarativa",
            "permission": prefix + "read",
            "mutation": False,
            "kind": "get",
            "collection": "records",
            "parameters": parameters({"record_id": "string"}, ["record_id"]),
        },
        {
            "name": "put_note",
            "description": "Crea o actualiza una nota declarativa",
            "permission": prefix + "write",
            "mutation": True,
            "kind": "put",
            "collection": "records",
            "parameters": parameters(
                {"record_id": "string", "data": "object", "expected_version": "integer"},
                ["data"],
            ),
        },
        {
            "name": "delete_note",
            "description": "Elimina una nota declarativa",
            "permission": prefix + "write",
            "mutation": True,
            "kind": "delete",
            "collection": "records",
            "parameters": parameters(
                {"record_id": "string", "expected_version": "integer"}, ["record_id"]
            ),
        },
    ]
    declaration["frontend"] = {
        "pages": [
            {
                "id": "notes",
                "label": "Notas",
                "permission": prefix + "read",
                "view": {
                    "table": {
                        "operation": "list_notes",
                        "columns": [{"field": "label", "label": "Etiqueta"}],
                    }
                },
            }
        ],
        "assetPanels": [],
        "contributions": [],
    }
    declaration["skills"] = [
        {
            "name": "notes-guide",
            "description": "Uso autorizado",
            "path": "skills/notes-guide/SKILL.md",
        }
    ]
    return declaration


def build_package(
    declaration: dict[str, Any],
    *,
    backend: str | None = PROBE_BACKEND,
    frontend: str | None = None,
    extra: Mapping[str, bytes] | None = None,
) -> bytes:
    members: dict[str, bytes] = {"extension.json": json.dumps(declaration).encode()}
    if backend is not None:
        members["backend.py"] = backend.encode()
    if frontend is not None:
        members["frontend.js"] = frontend.encode()
    skill = declaration["skills"][0]["path"]
    members[skill] = b"# Guide\nUse only authorized operations.\n"
    members["tests/test_module.py"] = b"def test_names():\n    assert 'read' != 'write'\n"
    members.update(extra or {})
    output = BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in members.items():
            archive.writestr(name, value)
    return output.getvalue()


def v1_package(*, marker: Path) -> bytes:
    """A legacy SDK v1 package whose backend would create a marker if executed."""
    declaration = {
        "sdkVersion": 1,
        "id": "legacy-book",
        "name": "Legado",
        "description": "Módulo v1 instalado antes de la migración",
        "version": "0.9.0",
        "permissions": [
            {"code": "ext_legacy_book.read", "label": "Consultar", "description": "Consulta"}
        ],
        "corePermissions": [],
        "operations": [
            {
                "name": "read_records",
                "description": "Operación heredada",
                "permission": "ext_legacy_book.read",
                "mutation": False,
                "parameters": parameters({}, []),
            }
        ],
        "collections": [{"name": "records", "description": "Registros heredados"}],
        "schemaVersion": 1,
        "compatibleSchemaVersions": [1],
        "migrations": [],
        "frontend": {
            "entry": "frontend.js",
            "pages": [
                {
                    "id": "legacy",
                    "label": "Legado",
                    "component": "Legacy",
                    "permission": "ext_legacy_book.read",
                }
            ],
            "assetPanels": [],
        },
        "schedules": [],
        "skills": [],
    }
    backend = (
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
        "def read_records(context):\n    return {'items': []}\n"
        "def register(sdk):\n    sdk.operation('read_records', read_records)\n"
    )
    output = BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("extension.json", json.dumps(declaration).encode())
        archive.writestr("backend.py", backend.encode())
        archive.writestr("frontend.js", b"window.ITSMExtensions.register('legacy-book', {});")
        archive.writestr("tests/test_legacy.py", b"def test_ok():\n    assert True\n")
    return output.getvalue()


def trusted_unit_report(digest: str, *, status: str = "passed") -> dict[str, Any]:
    """Unit fixture at the host ingestion boundary; not container proof."""
    return {
        "status": status,
        "digest": digest,
        "sdkVersion": 2,
        "checks": [
            {
                "name": "unit-boundary-fixture",
                "status": status,
                "detail": "No validator/container execution claimed",
            }
        ],
        "errors": [] if status == "passed" else ["unit validation failure"],
        "container": {"source": "trusted-internal-unit-fixture", "notExecutionEvidence": True},
        "completedAt": NOW.isoformat(),
    }


def core_fingerprint(settings: Any) -> dict[str, Any]:
    """Structure fingerprint of the core SQLite schema (tables/columns/indexes)."""
    engine = create_engine_from_settings(settings)
    try:
        inspector = inspect(engine)
        tables: dict[str, Any] = {}
        for name in sorted(inspector.get_table_names()):
            tables[name] = {
                "columns": [
                    (column["name"], str(column["type"]), bool(column["nullable"]))
                    for column in inspector.get_columns(name)
                ],
                "indexes": sorted(
                    (index["name"], tuple(index["column_names"]))
                    for index in inspector.get_indexes(name)
                ),
                "pk": tuple(inspector.get_pk_constraint(name)["constrained_columns"]),
            }
        return tables
    finally:
        engine.dispose()


def sqlite_master_fingerprint(settings: Any) -> list[tuple[str, str, str]]:
    """Triggers and views are invisible to some inspectors; read sqlite_master."""
    path = settings.database_url.split("sqlite:///", 1)[-1]
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute(
            "SELECT type, name, COALESCE(sql, '') FROM sqlite_master "
            "WHERE type IN ('trigger', 'view') ORDER BY type, name"
        ).fetchall()
        return [tuple(row) for row in rows]
    finally:
        connection.close()


def legacy_rows(settings: Any) -> list[tuple[str, str, str, int, str]]:
    path = settings.database_url.split("sqlite:///", 1)[-1]
    connection = sqlite3.connect(path)
    try:
        return [
            tuple(row)
            for row in connection.execute(
                "SELECT extension_id, collection, record_id, version, data_json "
                "FROM extension_collection_records ORDER BY extension_id, collection, record_id"
            ).fetchall()
        ]
    finally:
        connection.close()


def insert_legacy_rows(settings: Any, rows: list[tuple[str, str, str, int, Any]]) -> None:
    path = settings.database_url.split("sqlite:///", 1)[-1]
    connection = sqlite3.connect(path)
    try:
        for extension_id, collection, record_id, version, data in rows:
            connection.execute(
                "INSERT INTO extension_collection_records "
                "(extension_id, collection, record_id, version, data_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    extension_id,
                    collection,
                    record_id,
                    version,
                    json.dumps(data, sort_keys=True, separators=(",", ":")),
                    NOW.isoformat(),
                    NOW.isoformat(),
                ),
            )
        connection.commit()
    finally:
        connection.close()


@dataclass
class Environment:
    settings: Any
    factory: Any
    host: ExtensionHostService
    owner: Principal
    data_root: Path
    now: list[datetime] = field(default_factory=lambda: [NOW])

    def candidate(self, data: bytes) -> dict[str, Any]:
        return self.host.submit_candidate(self.owner, data)

    def validated(self, data: bytes) -> dict[str, Any]:
        candidate = self.candidate(data)
        return self.host.record_validation_report(
            candidate["id"],
            trusted_unit_report(candidate["digest"]),
            expected_version=candidate["revision"],
        )

    def install(self, data: bytes) -> dict[str, Any]:
        candidate = self.validated(data)
        return self.host.approve_candidate(
            self.owner,
            candidate["id"],
            digest=candidate["digest"],
            expected_version=candidate["currentRevision"],
        )

    def storage(self, extension_id: str = MODULE_ID) -> Path:
        return self.data_root / extension_id

    def database(self, extension_id: str = MODULE_ID) -> Path:
        return self.data_root / extension_id / "data.sqlite3"

    def invoke(
        self,
        operation: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        extension_id: str = MODULE_ID,
        actor: Principal | None = None,
    ) -> Any:
        return self.host.invoke(actor or self.owner, extension_id, operation, dict(arguments or {}))


@pytest.fixture
def env(settings_factory: Callable[..., Any], tmp_path: Path) -> Iterator[Environment]:
    data_root = tmp_path / "extensions-data"
    settings = settings_factory(extension_data_path=data_root)
    migration = run_migrations(settings)
    assert migration.returncode == 0, migration.stdout + migration.stderr
    engine = create_engine_from_settings(settings)
    factory = create_session_factory(engine)
    with factory() as session:
        identity = IdentityService(session, settings)
        user = identity.bootstrap_superadmin(ADMIN_USERNAME, "Ana Admin", ADMIN_PASSWORD)
        owner = identity.resolve_actor(user.id)
    now = [NOW]
    host = ExtensionHostService(settings, factory, now=lambda: now[0])
    yield Environment(settings, factory, host, owner, data_root, now)
    engine.dispose()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


__all__ = [
    "DECLARATIVE_ID",
    "MODULE_ID",
    "PROBE_BACKEND",
    "READ",
    "WRITE",
    "Environment",
    "build_package",
    "core_fingerprint",
    "declarative_manifest",
    "digest",
    "env",
    "insert_legacy_rows",
    "legacy_rows",
    "probe_manifest",
    "sqlite_master_fingerprint",
    "trusted_unit_report",
    "v1_package",
]
