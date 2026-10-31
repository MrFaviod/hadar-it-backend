"""Automatic SDK acceptance for the software-license reference extension.

The suite proves the promise that matters to the human: a module can be
installed, used, upgraded and disabled without touching the core code or the
core schema. It drives the public host service and HTTP API, validates the
package with the local offline harness, dispatches real core events, and
asserts the same core schema fingerprint, core source hash and empty legacy
collection table before the first step and after every single step.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from itsm.config import BACKEND_ROOT
from itsm.extensions.errors import (
    ExtensionDisabled,
    ExtensionNotFound,
    ExtensionValidationFailed,
)
from itsm.extensions.sdk.package import build_package as build_sdk_package
from itsm.extensions.sdk.validator.harness import validate_payload
from itsm.extensions.sdk.validator.protocol import build_frame
from itsm.identity.service import IdentityService, PermissionDenied
from itsm.inventory.service import InventoryService
from sqlalchemy import text
from tests.inventory_support import asset_values, serve
from tests.test_extension_isolation_http import _client, _headers
from tests.test_extension_runtime_support import (
    Environment,
    core_fingerprint,
    sqlite_master_fingerprint,
)
from tests.test_extension_runtime_support import env as env

MODULE = "software-licenses"
READ = "ext_software_licenses.read"
WRITE = "ext_software_licenses.write"
EXAMPLES = BACKEND_ROOT / "itsm" / "extensions" / "sdk" / "examples" / "software-licenses"


def package_files(version: str) -> dict[str, str]:
    root = EXAMPLES / version
    assert root.is_dir(), f"missing reference package {root}"
    files = {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
    assert "extension.json" in files and "backend.py" in files
    return files


def validated_package(version: str) -> tuple[Any, dict[str, Any]]:
    built = build_sdk_package(package_files(version), known_core_permissions=())
    report = validate_payload(
        build_frame(built.data, digest=built.digest, known_core_permissions=())
    )
    assert report["status"] == "passed", report["errors"]
    return built, report


def install(env: Environment, version: str) -> dict[str, Any]:
    built, report = validated_package(version)
    candidate = env.candidate(built.data)
    validated = env.host.record_validation_report(
        candidate["id"], report, expected_version=candidate["revision"]
    )
    env.host.approve_candidate(
        env.owner,
        validated["id"],
        digest=built.digest,
        expected_version=validated["currentRevision"],
    )
    return env.host.status(env.owner, MODULE)


def core_schema(env: Environment) -> tuple[Any, Any]:
    return core_fingerprint(env.settings), sqlite_master_fingerprint(env.settings)


def source_hash() -> str:
    digest = hashlib.sha256()
    for base in ("itsm", "migrations"):
        root = BACKEND_ROOT / base
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            digest.update(path.relative_to(BACKEND_ROOT).as_posix().encode())
            digest.update(b"\x00")
            digest.update(path.read_bytes())
            digest.update(b"\x00")
    return digest.hexdigest()


class Boundary:
    """Core invariants that must hold before and after every acceptance step."""

    def __init__(self, env: Environment) -> None:
        self.schema = core_schema(env)
        self.source = source_hash()
        self.data_root = env.data_root

    def assert_unchanged(self, env: Environment) -> None:
        assert core_schema(env) == self.schema, "core schema changed"
        assert source_hash() == self.source, "core source tree changed"
        with env.factory() as session:
            legacy = session.execute(
                text("SELECT COUNT(*) FROM extension_collection_records")
            ).scalar_one()
        assert legacy == 0, "extension rows leaked into the legacy core table"
        if self.data_root.exists():
            roots = {
                item.relative_to(self.data_root).parts[0]
                for item in self.data_root.rglob("*")
                if item != self.data_root
            }
            # `.packages` is the host's read-only package cache (D4), not module data.
            assert roots <= {MODULE, ".packages"}, f"data escaped its folder: {roots}"
            assert not list(self.data_root.glob("*/*.sqlite3")) or {
                item.parent.name for item in self.data_root.glob("*/*.sqlite3")
            } <= {MODULE}, "a module database was stored outside its folder"


def create_asset(env: Environment) -> str:
    with env.factory() as session:
        asset = InventoryService(session, env.settings).create(env.owner, asset_values())
        session.commit()
        return asset.id


def archive_asset(env: Environment, asset_id: str) -> None:
    with env.factory() as session:
        InventoryService(session, env.settings).archive(env.owner, asset_id, reason="retired")
        session.commit()


def purge_asset(env: Environment, asset_id: str) -> None:
    with env.factory() as session:
        InventoryService(session, env.settings).purge(env.owner, asset_id, confirm=True)
        session.commit()


def dispatch(env: Environment) -> dict[str, int]:
    return env.host.dispatch_entity_events(now=env.now[0], lag=0, grace_seconds=0.0)


def assignments(env: Environment, asset_id: str) -> list[dict[str, Any]]:
    listed = env.invoke(
        "list_assignments",
        {"asset_id": asset_id},
        extension_id=MODULE,
    )
    return listed["items"]


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def machine_credential(env: Environment) -> str:
    with env.factory() as session:
        identity = IdentityService(session, env.settings)
        role = identity.create_role(env.owner, name="License MCP", permissions=[READ])
        machine = identity.create_user(
            env.owner,
            username="license.mcp",
            name="License MCP",
            role_id=role.id,
            actor_kind="internal_agent",
            delegated_by_id=env.owner.actor_id,
        )
        credential = identity.issue_machine_credential(machine.username)
        return credential.token


def test_reference_extension_keeps_the_core_untouched(env: Environment) -> None:
    boundary = Boundary(env)
    boundary.assert_unchanged(env)

    # 1. Package -> candidate -> offline validation -> human approval install.
    installed = install(env, "1.0.0")
    assert installed["version"] == "1.0.0" and installed["status"] == "ready"
    boundary.assert_unchanged(env)

    # 2. Use: create a license and assign it to an existing asset by permanent id.
    asset_id = create_asset(env)
    license = env.invoke(
        "create_license",
        {"product": "AutoCAD", "vendor": "Autodesk", "seats": 5, "expires_on": "2027-12-31"},
        extension_id=MODULE,
    )
    assignment = env.invoke(
        "assign_license",
        {"license_id": license["id"], "asset_id": asset_id},
        extension_id=MODULE,
    )
    assert assignment["data"]["assetId"] == asset_id
    assert len(assignments(env, asset_id)) == 1
    summary = env.invoke("compliance_summary", {}, extension_id=MODULE)
    assert summary == {"licenses": 1, "seats": 5, "assignments": 1, "orphaned": 0, "flagged": 0}

    # 3. HTTP invoke with the cookie session and CSRF guard.
    prefix = env.settings.api_prefix + "/extensions"
    with _client(env) as client:
        headers = _headers(env, client)
        response = client.post(
            prefix + "/" + MODULE + "/invoke/compliance_summary",
            json={},
            headers=headers,
        )
        assert response.status_code == 200, response.text
        assert response.json()["assignments"] == 1

    # 4. MCP tool call through the real bearer transport.
    credential = machine_credential(env)
    with serve(env.settings, free_port()) as base:

        async def call_tool() -> dict[str, Any]:
            transport = StreamableHttpTransport(
                base + "/api/v1/mcp", headers={"Authorization": "Bearer " + credential}
            )
            async with Client(transport) as client:
                result = await client.call_tool(
                    "extension_invoke",
                    {
                        "id": MODULE,
                        "operation": "compliance_summary",
                        "arguments": {},
                    },
                )
                return dict(result.data)

        payload = asyncio.run(call_tool())
        assert payload["result"]["assignments"] == 1
    boundary.assert_unchanged(env)

    # 5. Casbin denial for a reader that only holds the read permission.
    with env.factory() as session:
        identity = IdentityService(session, env.settings)
        reader_role = identity.create_role(env.owner, name="License reader", permissions=[READ])
        reader_user = identity.create_user(
            env.owner,
            username="license.reader",
            name="License Reader",
            role_id=reader_role.id,
            password="License-Reader-Pass-123",
        )
        reader = identity.resolve_actor(reader_user.id)
    with env.factory() as session, pytest.raises(PermissionDenied):
        IdentityService(session, env.settings).authorize(
            reader, WRITE, resource=f"extension:{MODULE}"
        )
    # A module that tries an undeclared capability is refused by the host broker.
    with pytest.raises(ExtensionValidationFailed):
        env.invoke("unauthorized_asset_write", {}, extension_id=MODULE)
    with env.factory() as session:
        assert InventoryService(session, env.settings).search(env.owner).total == 1

    # 6. Core archive event: the host policy flags, the subscription reacts.
    archive_asset(env, asset_id)
    first = dispatch(env)
    assert first["failed"] == 0
    row = assignments(env, asset_id)[0]["data"]
    assert row["_references"] == {"assetId": "archived"}
    assert row["flagged"] is True and row["orphaned"] is False
    boundary.assert_unchanged(env)

    # 7. Core purge: missing reference, assignment stays orphaned, reconcile repairs.
    purge_asset(env, asset_id)
    dispatch(env)
    row = assignments(env, asset_id)[0]["data"]
    assert row["_references"] == {"assetId": "missing"}
    assert row["orphaned"] is True
    revision = env.host.status(env.owner, MODULE)["revision"]
    repaired = env.host.reconcile(env.owner, MODULE, expected_version=revision)
    again = env.host.reconcile(env.owner, MODULE, expected_version=revision)
    assert repaired["reconcile"]["states"][asset_id] == "missing"
    assert again == repaired
    boundary.assert_unchanged(env)

    # 8. Upgrade 1.0.0 -> 1.1.0: data preserved and the migration applied.
    upgraded = install(env, "1.1.0")
    assert upgraded["version"] == "1.1.0" and upgraded["schemaVersion"] == 2
    migrated = env.invoke("get_license", {"license_id": license["id"]}, extension_id=MODULE)
    assert migrated["data"]["product"] == "AutoCAD"
    assert migrated["data"]["costCenter"] == "unassigned"
    assert len(assignments(env, asset_id)) == 1
    boundary.assert_unchanged(env)

    # 9. Rollback to 1.0.0 restores the pre-migration snapshot.
    baseline_digest = validated_package("1.0.0")[0].digest
    rolled = env.host.rollback(
        env.owner,
        MODULE,
        version="1.0.0",
        digest=baseline_digest,
        expected_version=upgraded["revision"],
        restore_data=True,
        confirm=MODULE,
    )
    assert rolled["version"] == "1.0.0" and rolled["schemaVersion"] == 1
    restored = env.invoke("get_license", {"license_id": license["id"]}, extension_id=MODULE)
    assert "costCenter" not in restored["data"]
    boundary.assert_unchanged(env)

    # 10. Disable keeps the data file, refuses work and resumes when enabled.
    status = env.host.status(env.owner, MODULE)
    env.host.set_enabled(env.owner, MODULE, enabled=False, expected_version=status["revision"])
    database = env.storage(MODULE) / "data.sqlite3"
    assert database.is_file()
    with pytest.raises(ExtensionDisabled):
        env.invoke("compliance_summary", {}, extension_id=MODULE)
    revision = env.host.status(env.owner, MODULE)["revision"]
    env.host.set_enabled(env.owner, MODULE, enabled=True, expected_version=revision)
    assert env.invoke("compliance_summary", {}, extension_id=MODULE)["licenses"] == 1
    boundary.assert_unchanged(env)

    # 11. Uninstall removes the module registry rows but never the module data.
    revision = env.host.status(env.owner, MODULE)["revision"]
    env.host.uninstall(env.owner, MODULE, expected_version=revision)
    assert database.is_file()
    with pytest.raises(ExtensionNotFound):
        env.invoke("compliance_summary", {}, extension_id=MODULE)
    boundary.assert_unchanged(env)
