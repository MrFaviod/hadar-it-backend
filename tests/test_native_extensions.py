"""Public host/API boundaries on isolated SQLite.

The seven-key report fixture exercises the trusted *internal ingestion* boundary;
it is deliberately not evidence that a container validator ran successfully.
"""

from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from io import BytesIO
from typing import Any, Callable, Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from conftest import ADMIN_PASSWORD, ADMIN_USERNAME, run_migrations
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.extensions.api import create_extension_router, install_extension_error_handlers
from itsm.extensions.host import (
    ExtensionConflict,
    ExtensionDigestMismatch,
    ExtensionDisabled,
    ExtensionHandlerFailed,
    ExtensionHostService,
    ExtensionMigrationFailed,
    ExtensionRollbackIncompatible,
    ExtensionStale,
    ExtensionStoreConflict,
    ExtensionStoreValidation,
    ExtensionValidationFailed,
)
from itsm.extensions.manifest import MAX_MEMBER_BYTES, PackageError, inspect_package
from itsm.identity.api import create_identity_router, install_error_handlers
from itsm.identity.permissions import PERMISSION_CATALOG, is_known_permission
from itsm.identity.service import IdentityService, PermissionDenied, Principal
from itsm.inventory.service import InventoryService
from tests.inventory_support import asset_values

MODULE_ID = "record-book"
READ = "ext_record_book.read"
WRITE = "ext_record_book.write"
NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)

BACKEND = '''
def read_records(context):
    context.authorize("ext_record_book.read")
    return context.store.list("records", limit=200)

def get_record(context, record_id):
    return context.store.get("records", record_id)

def put_record(context, record_id, label, expected_version=None):
    return context.store.put("records", record_id, {"label": label}, expected_version)

def delete_record(context, record_id, expected_version=None):
    return {"deleted": context.store.delete("records", record_id, expected_version)}

def fail_write(context):
    context.store.put("records", "transient", {"label": "must roll back"})
    raise ValueError("private handler detail must never escape")

def readonly_write(context):
    return context.store.put("records", "readonly", {"label": "not permitted"})

def notify_record(context, recipient_ids, url=None):
    context.store.put("records", "notice-write", {"label": "transactional"})
    context.notify(recipient_ids=recipient_ids, key="expiry:one", title="Vence pronto",
                   body="Revisa tu registro", permission="ext_record_book.read", url=url)
    return {"notified": True}

def canonical_asset(context, asset_id):
    return context.assets.get(asset_id)

def write_then_authorize(context, permission):
    record = context.store.put("records", "pending-authority", {"label": "transactional"})
    context.authorize(permission)
    return record

def write_then_asset(context, mode, asset_id):
    context.store.put("records", "pending-asset", {"label": "transactional"})
    if mode == "get":
        return context.assets.get(asset_id)
    return context.assets.search(limit=1)

def migrate_records(context):
    for record in context.store.list("records", limit=200)["items"]:
        value = dict(record["data"])
        value["status"] = "active"
        context.store.put("records", record["id"], value, record["version"])
    __MIGRATION_FAILURE__

def tick(context):
    previous = context.store.get("records", "ticks")
    count = 0 if previous is None else previous["data"]["count"]
    context.store.put("records", "ticks", {"count": count + 1},
                      0 if previous is None else previous["version"])
    __SCHEDULE_FAILURE__
    return {"count": count + 1}

def register(sdk):
    sdk.operation("read_records", read_records)
    sdk.operation("get_record", get_record)
    sdk.operation("put_record", put_record)
    sdk.operation("delete_record", delete_record)
    sdk.operation("fail_write", fail_write)
    sdk.operation("readonly_write", readonly_write)
    sdk.operation("notify_record", notify_record)
    sdk.operation("canonical_asset", canonical_asset)
    sdk.operation("write_then_authorize", write_then_authorize)
    sdk.operation("write_then_asset", write_then_asset)
    __MIGRATION_BINDING__
    __SCHEDULE_BINDING__
'''


def parameters(properties: dict[str, str], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {name: {"type": kind} for name, kind in properties.items()},
        "required": required,
        "additionalProperties": False,
    }


def manifest(
    version: str = "1.0.0",
    *,
    schema: int = 1,
    compatible: list[int] | None = None,
    schedules: bool = False,
) -> dict[str, Any]:
    declarations = [
        ("read_records", READ, False, {}, []),
        ("get_record", READ, False, {"record_id": "string"}, ["record_id"]),
        (
            "put_record", WRITE, True,
            {"record_id": "string", "label": "string", "expected_version": "integer"},
            ["record_id", "label"],
        ),
        (
            "delete_record", WRITE, True,
            {"record_id": "string", "expected_version": "integer"}, ["record_id"],
        ),
        ("fail_write", WRITE, True, {}, []),
        ("readonly_write", READ, False, {}, []),
        ("notify_record", WRITE, True, {"recipient_ids": "array", "url": "string"}, ["recipient_ids"]),
        ("canonical_asset", READ, False, {"asset_id": "string"}, ["asset_id"]),
        ("write_then_authorize", WRITE, True, {"permission": "string"}, ["permission"]),
        (
            "write_then_asset", WRITE, True,
            {"mode": "string", "asset_id": "string"}, ["mode", "asset_id"],
        ),
    ]
    return {
        "sdkVersion": 1,
        "id": MODULE_ID,
        "name": "Registro nativo",
        "description": "Registros persistidos con autorización nativa",
        "version": version,
        "permissions": [
            {"code": READ, "label": "Consultar", "description": "Consulta los registros"},
            {"code": WRITE, "label": "Editar", "description": "Edita los registros"},
        ],
        "corePermissions": ["assets.view"],
        "operations": [
            {
                "name": name,
                "description": "Operación de prueba con efecto observable",
                "permission": permission,
                "mutation": mutation,
                "parameters": parameters(properties, required),
            }
            for name, permission, mutation, properties, required in declarations
        ],
        "collections": [{"name": "records", "description": "Registros del módulo"}],
        "schemaVersion": schema,
        "compatibleSchemaVersions": compatible or ([1, 2] if schema == 2 else [1]),
        "migrations": (
            [{"from": 1, "to": 2, "handler": "migrate_records"}] if schema == 2 else []
        ),
        "frontend": {
            "entry": "frontend.js",
            "pages": [{"id": "records", "label": "Registros", "component": "Records", "permission": READ}],
            "assetPanels": [],
        },
        "schedules": (
            [{"name": "expiry", "handler": "run_expiry", "intervalSeconds": 60, "permission": WRITE}]
            if schedules else []
        ),
        "skills": [{"name": "record-guide", "description": "Uso autorizado", "path": "skills/record-guide/SKILL.md"}],
    }


def package(
    declaration: dict[str, Any] | None = None,
    *,
    fail_migration: bool = False,
    fail_schedule: bool = False,
    backend_prefix: str = "",
    extra: dict[str, bytes] | None = None,
) -> bytes:
    declaration = declaration or manifest()
    source = BACKEND.replace(
        "__MIGRATION_FAILURE__", "raise ValueError('migration secret')" if fail_migration else "pass"
    ).replace(
        "__SCHEDULE_FAILURE__", "raise ValueError('schedule secret')" if fail_schedule else "pass"
    ).replace(
        "__MIGRATION_BINDING__",
        'sdk.migration("migrate_records", migrate_records)' if declaration["migrations"] else "pass",
    ).replace(
        "__SCHEDULE_BINDING__", 'sdk.schedule("expiry", tick)' if declaration["schedules"] else "pass"
    )
    members: dict[str, bytes] = {
        "extension.json": json.dumps(declaration).encode(),
        "backend.py": (backend_prefix + source).encode(),
        "frontend.js": b'window.ITSMExtensions.register("record-book", {components: {Records: {template: "<p>Registros</p>"}}});',
        "skills/record-guide/SKILL.md": b"# Record guide\nUse only authorized operations.\n",
        "tests/test_package.py": b"def test_operation_names():\n    assert 'read_records' != 'put_record'\n",
    }
    members.update(extra or {})
    output = BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in members.items():
            archive.writestr(name, value)
    return output.getvalue()


def trusted_unit_report(digest: str, *, status: str = "passed") -> dict[str, Any]:
    """Unit fixture at the host-only boundary, never container-validation proof."""
    return {
        "status": status,
        "digest": digest,
        "sdkVersion": 1,
        "checks": [{"name": "unit-boundary-fixture", "status": status, "detail": "No validator/container execution claimed"}],
        "errors": [] if status == "passed" else ["unit validation failure"],
        "container": {"source": "trusted-internal-unit-fixture", "notExecutionEvidence": True},
        "completedAt": NOW.isoformat(),
    }


@dataclass
class Environment:
    settings: Any
    factory: Any
    host: ExtensionHostService
    owner: Principal
    now: list[datetime]

    def candidate(self, data: bytes | None = None) -> dict[str, Any]:
        return self.host.submit_candidate(self.owner, data or package())

    def validated(self, data: bytes | None = None) -> dict[str, Any]:
        candidate = self.candidate(data)
        return self.host.record_validation_report(
            candidate["id"], trusted_unit_report(candidate["digest"]), expected_version=candidate["revision"]
        )

    def install(self, data: bytes | None = None) -> dict[str, Any]:
        candidate = self.validated(data)
        return self.host.approve_candidate(
            self.owner, candidate["id"], digest=candidate["digest"], expected_version=candidate["currentRevision"]
        )

    def invoke(self, operation: str, arguments: dict[str, Any] | None = None, actor: Principal | None = None) -> Any:
        return self.host.invoke(actor or self.owner, MODULE_ID, operation, arguments or {})

    def records(self) -> list[dict[str, Any]]:
        return self.invoke("read_records")["items"]

    def human(self, name: str, permissions: list[str]) -> tuple[Principal, str]:
        with self.factory() as session:
            identity = IdentityService(session, self.settings)
            role = identity.create_role(self.owner, name="role " + name, permissions=permissions)
            user = identity.create_user(
                self.owner, username=name, name=name.title(), role_id=role.id, password=ADMIN_PASSWORD
            )
            return identity.resolve_actor(user.id), role.id


@pytest.fixture
def env(settings_factory: Callable[..., Any]) -> Iterator[Environment]:
    settings = settings_factory()
    migration = run_migrations(settings)
    assert migration.returncode == 0, migration.stdout + migration.stderr
    engine = create_engine_from_settings(settings)
    factory = create_session_factory(engine)
    with factory() as session:
        identity = IdentityService(session, settings)
        user = identity.bootstrap_superadmin(ADMIN_USERNAME, "Ana Admin", ADMIN_PASSWORD)
        owner = identity.resolve_actor(user.id)
    now = [NOW]
    yield Environment(settings, factory, ExtensionHostService(settings, factory, now=lambda: now[0]), owner, now)
    engine.dispose()


def test_inspection_has_no_candidate_import_and_rejects_unsafe_members(tmp_path):
    marker = tmp_path / "candidate-imported"
    payload = package(backend_prefix=f"from pathlib import Path\nPath({str(marker)!r}).write_text('imported')\n")
    inspected = inspect_package(payload)
    assert inspected.digest == hashlib.sha256(payload).hexdigest()
    assert not marker.exists()
    with pytest.raises(PackageError, match="digest"):
        inspect_package(payload, expected_digest="0" * 64)
    for unsafe in ("../escape.py", "/absolute.py", "tests/../escape.py", "backend\\evil.py", "requirements.txt", "node_modules/code.js", "library.so"):
        with pytest.raises(PackageError):
            inspect_package(package(extra={unsafe: b"bad"}))
    with pytest.raises(PackageError, match="large|limit|size"):
        inspect_package(package(extra={"tests/huge.py": b"x" * (MAX_MEMBER_BYTES + 1)}))
    duplicate = BytesIO(payload)
    with zipfile.ZipFile(duplicate, "a") as archive:
        archive.writestr("backend.py", b"raise AssertionError('never imported')")
    with pytest.raises(PackageError, match="duplicate"):
        inspect_package(duplicate.getvalue())
    symlink = BytesIO(payload)
    with zipfile.ZipFile(symlink, "a") as archive:
        member = zipfile.ZipInfo("tests/link.py")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, b"../../outside")
    with pytest.raises(PackageError, match="link"):
        inspect_package(symlink.getvalue())
    bad = manifest()
    bad["unknown"] = True
    with pytest.raises(PackageError):
        inspect_package(package(bad))
    with pytest.raises(PackageError, match="dependenc|import|stdlib"):
        inspect_package(package(backend_prefix="import requests\n"))


def test_candidate_review_digest_and_validation_are_immutable(env):
    candidate = env.candidate()
    assert candidate["currentRevision"] is None
    assert candidate["validation"] is None
    assert candidate["manifest"] == manifest()
    assert candidate["manifest"]["corePermissions"] == ["assets.view"]
    assert candidate["trust"]["sandboxed"] is False
    assert candidate["permissionDelta"]["added"][0]["code"] == READ
    assert env.host.discovery(env.owner)["items"] == []
    with pytest.raises(ExtensionValidationFailed, match="trusted validation"):
        env.host.approve_candidate(env.owner, candidate["id"], digest=candidate["digest"], expected_version=None)
    with pytest.raises(ExtensionValidationFailed):
        env.host.record_validation_report(candidate["id"], {"passed": True}, expected_version=1)
    with pytest.raises(ExtensionDigestMismatch):
        env.host.record_validation_report(candidate["id"], trusted_unit_report("0" * 64), expected_version=1)
    assert env.host.candidate_detail(env.owner, candidate["id"])["revision"] == 1
    validated = env.host.record_validation_report(candidate["id"], trusted_unit_report(candidate["digest"]), expected_version=1)
    assert validated["revision"] == 2
    with pytest.raises(ExtensionDigestMismatch):
        env.host.approve_candidate(env.owner, candidate["id"], digest="0" * 64, expected_version=None)
    assert env.host.discovery(env.owner)["items"] == []
    replacement = env.candidate(package(backend_prefix="# edited bytes invalidate review\n"))
    assert replacement["digest"] != candidate["digest"]
    old = env.host.candidate_detail(env.owner, candidate["id"])
    assert old["state"] == "superseded"
    with pytest.raises(ExtensionConflict):
        env.host.approve_candidate(env.owner, candidate["id"], digest=candidate["digest"], expected_version=None)
    assert env.host.discovery(env.owner)["items"] == []


def test_install_store_optimistic_versions_restart_and_disable(env):
    installed = env.install()
    assert installed["state"] == "installed"
    item = env.host.discovery(env.owner)["items"][0]
    assert item["revision"] == 1 and item["version"] == "1.0.0" and item["enabled"]
    record = env.invoke("put_record", {"record_id": "old", "label": "Before", "expected_version": 0})
    assert record == {"id": "old", "version": 1, "data": {"label": "Before"}}
    with pytest.raises(ExtensionStoreConflict):
        env.invoke("put_record", {"record_id": "old", "label": "Wrong", "expected_version": 0})
    assert env.records() == [record]
    updated = env.invoke("put_record", {"record_id": "old", "label": "After", "expected_version": 1})
    assert updated["version"] == 2
    with pytest.raises(ExtensionStoreConflict):
        env.invoke("delete_record", {"record_id": "old", "expected_version": 1})
    restarted = ExtensionHostService(env.settings, env.factory)
    assert restarted.invoke(env.owner, MODULE_ID, "get_record", {"record_id": "old"}) == updated
    disabled = env.host.set_enabled(env.owner, MODULE_ID, enabled=False, expected_version=1)
    assert disabled["revision"] == 2 and not disabled["enabled"] and disabled["frontendUrl"] is None
    assert restarted.discovery(env.owner)["items"][0]["enabled"] is False
    with pytest.raises(ExtensionDisabled):
        restarted.invoke(env.owner, MODULE_ID, "read_records", {})
    with pytest.raises(ExtensionDisabled):
        restarted.skill(env.owner, MODULE_ID, "record-guide")
    with pytest.raises(ExtensionStale):
        env.host.set_enabled(env.owner, MODULE_ID, enabled=True, expected_version=1)
    env.host.set_enabled(env.owner, MODULE_ID, enabled=True, expected_version=2)
    assert env.records() == [updated]
    assert env.invoke("delete_record", {"record_id": "old", "expected_version": 2}) == {"deleted": True}
    assert env.records() == []


def test_handler_and_readonly_failures_leave_all_records_unchanged(env):
    env.install()
    env.invoke("put_record", {"record_id": "kept", "label": "Keep"})
    before = env.records()
    with pytest.raises(ExtensionHandlerFailed, match="^extension operation failed$"):
        env.invoke("fail_write")
    assert env.records() == before
    with pytest.raises(ExtensionStoreValidation, match="read-only"):
        env.invoke("readonly_write")
    assert env.records() == before
    with pytest.raises(ExtensionValidationFailed):
        env.invoke("put_record", {"record_id": "bad", "label": "Bad", "unexpected": True})
    assert env.records() == before


@pytest.mark.parametrize("boundary", ["authorize", "notify", "asset_get", "asset_search"])
def test_write_then_denial_rolls_back_without_secondary_writer(env, boundary):
    env.install()
    actor, _ = env.human("writer.only", [WRITE])
    callbacks = []
    env.host._notify = lambda **values: callbacks.append(values)
    with env.factory() as session:
        asset = InventoryService(session, env.settings).create(
            env.owner, asset_values(responsible=None)
        )
    env.invoke("put_record", {"record_id": "kept", "label": "Keep"})
    before = env.records()
    if boundary == "authorize":
        operation, arguments = "write_then_authorize", {"permission": READ}
    elif boundary == "notify":
        operation, arguments = "notify_record", {"recipient_ids": [env.owner.actor_id]}
    else:
        operation, arguments = "write_then_asset", {
            "mode": "get" if boundary == "asset_get" else "search", "asset_id": asset.id,
        }
    with pytest.raises(PermissionDenied, match="^permission denied$"):
        env.invoke(operation, arguments, actor=actor)
    assert env.records() == before
    assert callbacks == []
    assert env.invoke("canonical_asset", {"asset_id": asset.id})["id"] == asset.id


def test_write_then_sensitive_machine_authority_keeps_reference_and_scope_ceiling(env):
    env.install()
    with env.factory() as session:
        identity = IdentityService(session, env.settings)
        role = identity.create_role(
            env.owner, name="Extension remote operator",
            permissions=[WRITE, READ, "assets.view", "assets.remote"],
        )
        machine = identity.create_user(
            env.owner, username="remote.extension.agent", name="Remote Extension Agent",
            role_id=role.id, actor_kind="internal_agent", delegated_by_id=env.owner.actor_id,
        )
        actor = identity.resolve_actor(machine.id)
    before = env.records()
    arguments = {"permission": "assets.remote"}
    with pytest.raises(PermissionDenied, match="^permission denied$"):
        env.invoke("write_then_authorize", arguments, actor=actor)
    assert env.records() == before
    approved = replace(actor, authorization_ref="human-approved-remote-operation")
    assert env.invoke("write_then_authorize", arguments, actor=approved) == {
        "id": "pending-authority", "version": 1, "data": {"label": "transactional"},
    }
    before = env.records()
    scoped = replace(approved, scopes=frozenset({WRITE}))
    with pytest.raises(PermissionDenied, match="^permission denied$"):
        env.invoke("write_then_authorize", arguments, actor=scoped)
    assert env.records() == before


def test_live_permissions_catalog_ceiling_no_global_leak_and_forged_claims(env, settings_factory):
    env.install()
    actor, role_id = env.human("reader.person", [READ, "assets.view"])
    assert env.invoke("read_records", actor=actor) == {"items": [], "total": 0}
    with pytest.raises(PermissionDenied):
        env.invoke("put_record", {"record_id": "no", "label": "Denied"}, actor=actor)
    forged = replace(actor, kind="human", role_id="superadmin", username=ADMIN_USERNAME)
    candidate = env.validated(package(manifest("1.1.0")))
    with pytest.raises(PermissionDenied):
        env.host.approve_candidate(forged, candidate["id"], digest=candidate["digest"], expected_version=1)
    with env.factory() as session:
        identity = IdentityService(session, env.settings)
        assert READ in identity.catalog(env.owner).permissions
        assert is_known_permission(READ, session)
        assert not is_known_permission(READ)
        identity.update_role(env.owner, role_id, name="reader revoked", permissions=["assets.view"])
    with pytest.raises(PermissionDenied):
        env.invoke("read_records", actor=actor)
    assert env.host.discovery(actor)["items"] == []
    assert env.records() == []
    # A second app/session never inherits a process-global permission registration.
    second_settings = settings_factory(database_url=env.settings.database_url + ".other")
    migration = run_migrations(second_settings)
    assert migration.returncode == 0, migration.stderr
    second_engine = create_engine_from_settings(second_settings)
    try:
        with create_session_factory(second_engine)() as session:
            identity = IdentityService(session, second_settings)
            user = identity.bootstrap_superadmin("second.owner", "Second Owner", ADMIN_PASSWORD)
            other = identity.resolve_actor(user.id)
            assert identity.catalog(other).permissions == PERMISSION_CATALOG
            assert not is_known_permission(READ, session)
    finally:
        second_engine.dispose()


def test_machine_delegated_developer_cannot_approve_install(env):
    env.install()
    with env.factory() as session:
        identity = IdentityService(session, env.settings)
        role = identity.create_role(env.owner, name="Extension developer", permissions=["system.modules"])
        machine = identity.create_user(
            env.owner, username="extension.agent", name="Extension Agent", role_id=role.id,
            actor_kind="internal_agent", delegated_by_id=env.owner.actor_id,
        )
        actor = identity.resolve_actor(machine.id)
    candidate = env.host.submit_candidate(actor, package(manifest("1.1.0")))
    env.host.record_validation_report(candidate["id"], trusted_unit_report(candidate["digest"]), expected_version=1)
    before = env.host.discovery(env.owner)["items"][0]
    with pytest.raises(PermissionDenied, match="human Superadmin"):
        env.host.approve_candidate(actor, candidate["id"], digest=candidate["digest"], expected_version=1)
    with pytest.raises(PermissionDenied, match="human Superadmin"):
        env.host.set_enabled(actor, MODULE_ID, enabled=False, expected_version=1)
    assert env.host.discovery(env.owner)["items"][0] == before
    assert env.records() == []


def test_revision_cas_rejects_candidate_after_toggle_aba(env):
    env.install()
    env.invoke("put_record", {"record_id": "kept", "label": "Before"})
    candidate = env.validated(package(manifest("1.1.0")))
    env.host.set_enabled(env.owner, MODULE_ID, enabled=False, expected_version=1)
    env.host.set_enabled(env.owner, MODULE_ID, enabled=True, expected_version=2)
    with pytest.raises(ExtensionStale, match="revision"):
        env.host.approve_candidate(env.owner, candidate["id"], digest=candidate["digest"], expected_version=1)
    with pytest.raises(ExtensionStale, match="baseline"):
        env.host.approve_candidate(env.owner, candidate["id"], digest=candidate["digest"], expected_version=3)
    assert env.host.discovery(env.owner)["items"][0]["version"] == "1.0.0"
    assert env.records()[0]["data"] == {"label": "Before"}


def test_failed_migration_keeps_old_active_data_candidate_and_permissions(env):
    env.install()
    env.invoke("put_record", {"record_id": "kept", "label": "Before"})
    before = env.records()
    candidate = env.validated(package(manifest("2.0.0", schema=2), fail_migration=True))
    with pytest.raises(ExtensionMigrationFailed):
        env.host.approve_candidate(env.owner, candidate["id"], digest=candidate["digest"], expected_version=1)
    assert env.records() == before
    assert env.host.discovery(env.owner)["items"][0]["version"] == "1.0.0"
    detail = env.host.candidate_detail(env.owner, candidate["id"])
    assert detail["state"] == "pending" and detail["approvedAt"] is None
    assert detail["currentRevision"] == 1


def test_upgrade_and_compatible_rollback_preserve_before_and_after_records(env):
    first = env.install(package(manifest(compatible=[1, 2])))
    env.invoke("put_record", {"record_id": "before", "label": "Old"})
    upgraded = env.install(package(manifest("2.0.0", schema=2)))
    assert upgraded["currentVersion"] == "2.0.0"
    env.invoke("put_record", {"record_id": "after", "label": "New"})
    before_rollback = env.records()
    assert next(item for item in before_rollback if item["id"] == "before")["data"]["status"] == "active"
    rolled = env.host.rollback(env.owner, MODULE_ID, version="1.0.0", digest=first["digest"], expected_version=2)
    assert rolled["version"] == "1.0.0" and rolled["schemaVersion"] == 2 and rolled["revision"] == 3
    assert env.records() == before_rollback
    restarted = ExtensionHostService(env.settings, env.factory)
    assert restarted.discovery(env.owner)["items"][0]["version"] == "1.0.0"
    assert restarted.invoke(env.owner, MODULE_ID, "read_records", {})["items"] == before_rollback
    history = env.host.history(env.owner, MODULE_ID)["items"]
    assert any(item["action"] == "extension.rolled_back" and item["detail"]["digest"] == first["digest"] for item in history)


def test_incompatible_rollback_and_stale_digest_leave_business_state_unchanged(env):
    first = env.install()
    env.invoke("put_record", {"record_id": "kept", "label": "Keep"})
    env.install(package(manifest("2.0.0", schema=2)))
    before = env.records()
    with pytest.raises(ExtensionRollbackIncompatible):
        env.host.rollback(env.owner, MODULE_ID, version="1.0.0", digest=first["digest"], expected_version=2)
    with pytest.raises(ExtensionDigestMismatch):
        env.host.rollback(env.owner, MODULE_ID, version="1.0.0", digest="0" * 64, expected_version=2)
    with pytest.raises(ExtensionStale):
        env.host.rollback(env.owner, MODULE_ID, version="1.0.0", digest=first["digest"], expected_version=1)
    assert env.records() == before
    assert env.host.discovery(env.owner)["items"][0]["revision"] == 2


def test_notification_callback_failure_rolls_back_notice_and_business_data(env):
    env.install()
    env.invoke("put_record", {"record_id": "kept", "label": "Keep"})
    before = env.records()
    # Callback writes an independently observable SQL effect in the caller's
    # transaction, then fails.  This proves no callback-owned commit boundary.
    def failing_notify(*, session, **values):
        session.execute(text("UPDATE identity_identities SET name=:name WHERE id=:id"), {"name": "must rollback", "id": env.owner.actor_id})
        raise RuntimeError("native inbox unavailable")
    host = ExtensionHostService(env.settings, env.factory, notify=failing_notify)
    with pytest.raises(ExtensionHandlerFailed):
        host.invoke(env.owner, MODULE_ID, "notify_record", {"recipient_ids": [env.owner.actor_id]})
    assert env.records() == before
    with env.factory() as session:
        assert IdentityService(session, env.settings).resolve_actor(env.owner.actor_id).display_name == "Ana Admin"



def test_notification_native_hash_route_and_recipient_authority(env):
    env.install()
    reader, _ = env.human("notice.reader", [READ, "assets.view"])
    without_core, _ = env.human("notice.no.core", [READ])
    without_module, _ = env.human("notice.no.module", ["assets.view"])
    notices = []
    host = ExtensionHostService(env.settings, env.factory, notify=lambda **values: notices.append(values))
    route = "#/extensiones/record-book/records"
    recipients = [reader.actor_id, without_core.actor_id, without_module.actor_id, "absent"]
    assert host.invoke(env.owner, MODULE_ID, "notify_record", {"recipient_ids": recipients, "url": route}) == {"notified": True}
    assert len(notices) == 1
    assert notices[0]["recipient_ids"] == (reader.actor_id,)
    assert notices[0]["url"] == route
    before = env.records()
    for invalid in ("https://example.com/", "/arbitrary", "#/extensiones/other/records", "#/extensiones/record-book-evil/records", route + "x" * 500):
        with pytest.raises(ExtensionValidationFailed, match="native extension page"):
            host.invoke(env.owner, MODULE_ID, "notify_record", {"recipient_ids": recipients, "url": invalid})
        assert env.records() == before
    assert len(notices) == 1

def test_schedules_persist_owner_due_claim_disable_revoke_and_failure_atomicity(env):
    env.install(package(manifest(schedules=True)))
    schedule = env.host.list_schedules()[0]
    assert schedule.owner_id == env.owner.actor_id
    assert schedule.next_due_at.replace(tzinfo=UTC) == NOW + timedelta(seconds=60)
    assert env.host.run_due_schedules(NOW)["claimed"] == 0
    due = NOW + timedelta(seconds=61)
    # Separate service instances share SQL claims, not a process-local timer.
    other = ExtensionHostService(env.settings, env.factory)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda host: host.run_due_schedules(due), (env.host, other)))
    assert sum(item["succeeded"] for item in outcomes) == 1
    assert env.invoke("get_record", {"record_id": "ticks"})["data"] == {"count": 1}
    env.host.set_enabled(env.owner, MODULE_ID, enabled=False, expected_version=1)
    assert env.host.run_due_schedules(due + timedelta(minutes=2))["claimed"] == 0
    env.host.set_enabled(env.owner, MODULE_ID, enabled=True, expected_version=2)
    # Live owner revocation prevents execution although the persisted schedule remains.
    with env.factory() as session:
        session.execute(text("DELETE FROM identity_role_policies WHERE role_id='superadmin' AND resource='ext_record_book' AND operation='write'"))
        session.commit()
    assert env.host.run_due_schedules(due + timedelta(minutes=2))["succeeded"] == 0
    assert env.invoke("get_record", {"record_id": "ticks"})["data"] == {"count": 1}


def test_failed_schedule_rolls_back_records_and_has_bounded_retry(env):
    env.install(package(manifest(schedules=True), fail_schedule=True))
    result = env.host.run_due_schedules(NOW + timedelta(seconds=61))
    assert result["failed"] == 1 and result["succeeded"] == 0
    assert env.invoke("get_record", {"record_id": "ticks"}) is None
    state = env.host.list_schedules()[0]
    assert state.last_error and len(state.last_error) <= 500
    assert state.next_due_at.replace(tzinfo=UTC) > NOW + timedelta(seconds=61)


def test_http_auth_csrf_review_install_history_frontend_skill_and_invoke(env):
    app = FastAPI()
    app.state.settings = env.settings
    app.state.session_factory = env.factory
    app.state.extensions = env.host
    app.include_router(create_identity_router(), prefix=env.settings.api_prefix)
    app.include_router(create_extension_router(), prefix=env.settings.api_prefix)
    install_error_handlers(app)
    install_extension_error_handlers(app)
    prefix = env.settings.api_prefix + "/extensions"
    with TestClient(app) as client:
        assert client.get(prefix).status_code == 401
        login = client.post(env.settings.api_prefix + "/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}, headers={"Origin": env.settings.auth_origin})
        assert login.status_code == 200, login.text
        headers = {"Origin": env.settings.auth_origin, "X-CSRF-Token": login.json()["csrfToken"]}
        rejected = client.post(prefix + "/candidates", content=iter([b"x" * MAX_MEMBER_BYTES] * 5), headers={**headers, "Content-Type": "application/zip"})
        assert rejected.status_code == 413 and rejected.json()["error"]["code"] == "package_too_large"
        assert env.host.list_candidates(env.owner)["items"] == []
        upload = client.post(prefix + "/candidates", content=package(), headers={**headers, "Content-Type": "application/zip"})
        assert upload.status_code == 201, upload.text
        candidate = upload.json()
        assert candidate["manifest"] == manifest()
        detail = client.get(prefix + "/candidates/" + candidate["id"])
        assert detail.status_code == 200
        assert detail.json()["manifest"] == manifest()
        assert detail.json()["manifest"]["corePermissions"] == ["assets.view"]
        env.host.record_validation_report(candidate["id"], trusted_unit_report(candidate["digest"]), expected_version=1)
        approval = {"digest": candidate["digest"], "expectedVersion": None}
        assert client.post(prefix + "/candidates/" + candidate["id"] + "/approve", json=approval).status_code == 403
        approved = client.post(prefix + "/candidates/" + candidate["id"] + "/approve", json=approval, headers=headers)
        assert approved.status_code == 200, approved.text
        assert approved.json()["manifest"]["id"] == MODULE_ID
        discovery = client.get(prefix).json()["items"][0]
        assert isinstance(discovery["revision"], int)
        frontend = client.get(discovery["frontendUrl"])
        assert frontend.status_code == 200 and "ITSMExtensions.register" in frontend.text
        assert frontend.headers["cache-control"] == "no-store"
        assert frontend.headers["x-content-type-options"] == "nosniff"
        assert client.get(prefix + "/" + MODULE_ID + "/frontend.js?digest=" + "0" * 64).json()["error"]["code"] == "digest_mismatch"
        skill = client.get(prefix + "/" + MODULE_ID + "/skills/record-guide")
        assert skill.status_code == 200 and skill.json()["content"].startswith("# Record guide")
        assert client.get(prefix + "/" + MODULE_ID + "/history").json()["items"]
        invoke = client.post(prefix + "/" + MODULE_ID + "/invoke/put_record", json={"record_id": "http", "label": "Native"}, headers=headers)
        assert invoke.status_code == 200, invoke.text
        assert invoke.json()["data"] == {"label": "Native"}
        stale = client.post(prefix + "/" + MODULE_ID + "/enabled", json={"enabled": False, "expectedVersion": 0}, headers=headers)
        assert stale.status_code == 409 and stale.json()["error"]["code"] == "stale"
        assert env.records()[0]["id"] == "http"
