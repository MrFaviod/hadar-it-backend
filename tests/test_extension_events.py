# ruff: noqa: F811 - the `env` fixture is imported and also named in signatures.
"""Event dispatch, reconciliation and contract-gap reporting for extensions.

Sandboxed modules subscribe to the core outbox; declarative modules declare
reference policies the host applies to their own SQLite file. Both paths are
at-least-once, idempotent and resumable, and every gap between the SDK and a
module's need is recorded instead of worked around.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from itsm.extensions.development import DevelopmentService
from itsm.extensions.errors import ExtensionIdempotencyConflict, ExtensionStale
from itsm.extensions.events import process_extension_events
from itsm.extensions.tools import dispatch_extension_tool
from itsm.identity.service import PermissionDenied
from itsm.inventory.service import InventoryService
from tests.inventory_support import asset_values
from tests.test_extension_runtime_support import (  # noqa: F401 - fixture
    MODULE_ID,
    PROBE_BACKEND,
    Environment,
    build_package,
    declarative_manifest,
    env,
    parameters,
    probe_manifest,
)

EVENT_BACKEND = (
    PROBE_BACKEND
    + r"""

def _fail_flag(context):
    return context.store.get("records", "fail-events")


def on_archived(context):
    if _fail_flag(context):
        raise ValueError("subscription failed on purpose")
    event = context.event
    context.store.put("records", f"archived-{event['sequence']}", {"label": event["id"]})
    return {"handled": event["id"]}


def on_deleted(context):
    event = context.event
    context.store.put("records", f"deleted-{event['sequence']}", {"label": event["id"]})
    return {"handled": event["id"]}


def reconcile(context):
    rows = context.store.list("records", 200, 0, {})["items"]
    ids = sorted(
        {
            row["data"]["label"]
            for row in rows
            if isinstance(row["data"].get("label"), str)
            and len(row["data"]["label"]) == 36
        }
    )
    resolved = context.assets.resolve("asset", ids) if ids else {"states": {}}
    states = resolved["states"]
    context.store.put("records", "reconcile-report", {"label": str(len(states))})
    return {"checked": len(ids), "states": states}


_original_register = register


def register(sdk):
    _original_register(sdk)
    sdk.subscribe("asset.archived", on_archived)
    sdk.subscribe("asset.deleted", on_deleted)
    sdk.reconcile("reconcile", reconcile)
"""
)


def sandboxed_event_manifest(*, capabilities: list[str] | None = None) -> dict[str, Any]:
    declaration = probe_manifest(capabilities=capabilities or ["assets.read"])
    declaration["subscriptions"] = [
        {"event": "asset.archived", "handler": "on_archived"},
        {"event": "asset.deleted", "handler": "on_deleted"},
    ]
    declaration["reconcile"] = {"handler": "reconcile", "intervalSeconds": 300}
    return declaration


def reference_declaration(*, extension_id: str = "declarative-refs") -> dict[str, Any]:
    declaration = declarative_manifest()
    declaration["id"] = extension_id
    prefix = f"ext_{extension_id.replace('-', '_')}."
    declaration["permissions"] = [
        {"code": prefix + "read", "label": "Consultar", "description": "Consulta referencias"},
        {"code": prefix + "write", "label": "Editar", "description": "Edita referencias"},
    ]
    declaration["collections"] = [
        {
            "name": "flagged",
            "description": "Registros con referencia marcada",
            "schema": {
                "type": "object",
                "properties": {"assetId": {"type": "string", "maxLength": 36}},
                "required": ["assetId"],
                "additionalProperties": False,
            },
            "references": [
                {"field": "assetId", "entity": "asset", "onArchive": "flag", "onDelete": "flag"}
            ],
        },
        {
            "name": "pruned",
            "description": "Registros que se eliminan con la entidad",
            "schema": {
                "type": "object",
                "properties": {"assetId": {"type": "string", "maxLength": 36}},
                "required": ["assetId"],
                "additionalProperties": False,
            },
            "references": [
                {
                    "field": "assetId",
                    "entity": "asset",
                    "onArchive": "keep",
                    "onDelete": "delete",
                }
            ],
        },
    ]
    declaration["operations"] = []
    for suffix in ("list", "get", "put", "delete"):
        for collection in ("flagged", "pruned"):
            name = f"{suffix}_{collection}"
            kind = suffix
            properties: dict[str, str] = {
                "limit": "integer",
                "offset": "integer",
                "filters": "object",
            }
            required: list[str] = []
            if suffix == "get":
                properties = {"record_id": "string"}
                required = ["record_id"]
            elif suffix == "put":
                properties = {
                    "record_id": "string",
                    "data": "object",
                    "expected_version": "integer",
                }
                required = ["data"]
            elif suffix == "delete":
                properties = {"record_id": "string", "expected_version": "integer"}
                required = ["record_id"]
            declaration["operations"].append(
                {
                    "name": name,
                    "description": f"Operación {suffix} sobre {collection}",
                    "permission": prefix + ("write" if suffix in ("put", "delete") else "read"),
                    "mutation": suffix in ("put", "delete"),
                    "kind": kind,
                    "collection": collection,
                    "parameters": parameters(properties, required),
                }
            )
    declaration["frontend"] = {"pages": [], "assetPanels": [], "contributions": []}
    return declaration


def make_asset(environment: Environment) -> str:
    with environment.factory() as session:
        created = InventoryService(session, environment.settings).create(
            environment.owner, asset_values()
        )
        session.commit()
        return created.id


def archive_asset(environment: Environment, asset_id: str) -> None:
    with environment.factory() as session:
        InventoryService(session, environment.settings).archive(environment.owner, asset_id)
        session.commit()


def restore_asset(environment: Environment, asset_id: str) -> None:
    with environment.factory() as session:
        InventoryService(session, environment.settings).restore(environment.owner, asset_id)
        session.commit()


def purge_asset(environment: Environment, asset_id: str) -> None:
    with environment.factory() as session:
        InventoryService(session, environment.settings).purge(
            environment.owner, asset_id, confirm=True
        )
        session.commit()


DECLARATIVE_ID = "declarative-refs"


def invoke(
    environment: Environment, operation: str, arguments: dict[str, Any] | None = None
) -> Any:
    return environment.invoke(operation, arguments or {}, extension_id=DECLARATIVE_ID)


def dispatch(environment: Environment) -> dict[str, Any]:
    return environment.host.dispatch_entity_events(now=environment.now[0], lag=0, grace_seconds=0.0)


def test_declarative_reference_policy_flags_and_removes_records(
    env: Environment, tmp_path: Path
) -> None:
    declaration = reference_declaration()
    env.install(build_package(declaration, backend=None))
    asset_id = make_asset(env)
    invoke(env, "put_flagged", {"record_id": "flag-1", "data": {"assetId": asset_id}})
    invoke(env, "put_pruned", {"record_id": "prune-1", "data": {"assetId": asset_id}})

    archive_asset(env, asset_id)
    first = dispatch(env)
    assert first == {"modules": 1, "delivered": 2, "failed": 0, "skipped": 0}, first
    flagged = invoke(env, "get_flagged", {"record_id": "flag-1"})
    assert flagged["data"]["_references"] == {"assetId": "archived"}
    assert invoke(env, "get_pruned", {"record_id": "prune-1"}) is not None

    before = invoke(env, "get_flagged", {"record_id": "flag-1"})["version"]
    dispatch(env)
    assert invoke(env, "get_flagged", {"record_id": "flag-1"})["version"] == before

    purge_asset(env, asset_id)
    dispatch(env)
    flagged = invoke(env, "get_flagged", {"record_id": "flag-1"})
    assert flagged["data"]["_references"] == {"assetId": "missing"}
    assert invoke(env, "get_pruned", {"record_id": "prune-1"}) is None


def test_restore_clears_the_archived_reference_flag(env: Environment) -> None:
    env.install(build_package(reference_declaration(), backend=None))
    asset_id = make_asset(env)
    invoke(env, "put_flagged", {"record_id": "flag-1", "data": {"assetId": asset_id}})
    archive_asset(env, asset_id)
    dispatch(env)
    assert invoke(env, "get_flagged", {"record_id": "flag-1"})["data"]["_references"] == {
        "assetId": "archived"
    }
    restore_asset(env, asset_id)
    dispatch(env)
    assert "_references" not in invoke(env, "get_flagged", {"record_id": "flag-1"})["data"]


def test_declarative_reconcile_repairs_a_missed_event(env: Environment) -> None:
    env.install(build_package(reference_declaration(), backend=None))
    asset_id = make_asset(env)
    invoke(env, "put_flagged", {"record_id": "flag-1", "data": {"assetId": asset_id}})
    archive_asset(env, asset_id)
    result = env.host.reconcile(env.owner, DECLARATIVE_ID, expected_version=1)
    assert result["references"] == 1
    assert invoke(env, "get_flagged", {"record_id": "flag-1"})["data"]["_references"] == {
        "assetId": "archived"
    }
    again = env.host.reconcile(env.owner, DECLARATIVE_ID, expected_version=1)
    assert again["references"] == 0


def test_sandboxed_subscriptions_are_delivered_once_and_acknowledged(
    env: Environment,
) -> None:
    env.install(build_package(sandboxed_event_manifest(), backend=EVENT_BACKEND))
    asset_id = make_asset(env)
    archive_asset(env, asset_id)
    first = dispatch(env)
    assert first["delivered"] == 2
    rows = env.invoke("list_records", {"limit": 50})["items"]
    assert len(rows) == 1
    assert rows[0]["id"].startswith("archived-")
    assert len(rows[0]["data"]["label"]) == 36
    assert env.host.event_status(MODULE_ID)["stalled"] is False
    second = dispatch(env)
    assert second["delivered"] == 0
    assert len(env.invoke("list_records", {"limit": 50})["items"]) == 1


def test_event_failure_stalls_the_consumer_until_explicit_reset(env: Environment) -> None:
    env.install(build_package(sandboxed_event_manifest(), backend=EVENT_BACKEND))
    env.invoke("put_record", {"record_id": "fail-events", "label": "flag"})
    asset_id = make_asset(env)
    archive_asset(env, asset_id)
    for _ in range(5):
        env.now[0] = env.now[0] + timedelta(hours=2)
        dispatch(env)
    status = env.host.event_status(MODULE_ID)
    assert status["stalled"] is True
    assert status["lastError"] == "handler_error"
    assert status["cursor"] == 1

    module = env.host.status(env.owner, MODULE_ID)
    assert module["events"]["stalled"] is True
    assert module["events"]["lastError"] == "handler_error"

    env.invoke("delete_record", {"record_id": "fail-events"})
    reset = env.host.reset_events(env.owner, MODULE_ID, expected_version=module["revision"])
    assert reset["events"]["stalled"] is False
    with pytest.raises(ExtensionStale):
        env.host.reset_events(env.owner, MODULE_ID, expected_version=module["revision"])
    dispatch(env)
    status = env.host.event_status(MODULE_ID)
    assert status["stalled"] is False and status["cursor"] >= 1


def test_disabled_module_keeps_its_cursor_and_resumes(env: Environment) -> None:
    env.install(build_package(sandboxed_event_manifest(), backend=EVENT_BACKEND))
    asset_id = make_asset(env)
    archive_asset(env, asset_id)
    dispatch(env)
    cursor = env.host.event_status(MODULE_ID)["cursor"]
    env.host.set_enabled(env.owner, MODULE_ID, enabled=False, expected_version=1)
    restore_asset(env, asset_id)
    archive_asset(env, asset_id)
    skipped = dispatch(env)
    assert skipped["delivered"] == 0
    assert env.host.event_status(MODULE_ID)["cursor"] == cursor
    env.host.set_enabled(env.owner, MODULE_ID, enabled=True, expected_version=2)
    resumed = dispatch(env)
    assert resumed["delivered"] >= 1
    assert env.host.event_status(MODULE_ID)["cursor"] > cursor


def test_sandboxed_reconcile_resolves_and_repairs_references(env: Environment) -> None:
    env.install(build_package(sandboxed_event_manifest(), backend=EVENT_BACKEND))
    asset_id = make_asset(env)
    env.invoke("put_record", {"record_id": "ref-1", "label": asset_id})
    result = env.host.reconcile(env.owner, MODULE_ID, expected_version=1)
    assert result["reconcile"]["checked"] == 1
    assert result["reconcile"]["states"] == {asset_id: "active"}
    archive_asset(env, asset_id)
    result = env.host.reconcile(env.owner, MODULE_ID, expected_version=1)
    assert result["reconcile"]["states"] == {asset_id: "archived"}


def test_reconcile_requires_the_module_installer_authority(env: Environment) -> None:
    env.install(build_package(sandboxed_event_manifest(), backend=EVENT_BACKEND))
    from itsm.identity.service import IdentityService

    with env.factory() as session:
        reader_role = IdentityService(session, env.settings).create_role(
            env.owner, name="Events reader", permissions=["assets.view"]
        )
        reader = IdentityService(session, env.settings).create_user(
            env.owner,
            username="events.reader",
            name="Events Reader",
            role_id=reader_role.id,
            password="Events-Reader-Pass-123",
        )
        actor = IdentityService(session, env.settings).resolve_actor(reader.id)
    with pytest.raises(PermissionDenied):
        env.host.reconcile(actor, MODULE_ID, expected_version=1)
    with pytest.raises(PermissionDenied):
        env.host.reset_events(actor, MODULE_ID, expected_version=1)


def test_worker_entry_point_dispatches_events(env: Environment) -> None:
    env.install(build_package(sandboxed_event_manifest(), backend=EVENT_BACKEND))
    asset_id = make_asset(env)
    archive_asset(env, asset_id)
    result = process_extension_events(env.settings, env.now[0], lag=0, grace_seconds=0.0)
    assert result["modules"] == 1
    assert result["delivered"] == 2


def test_contract_gap_tool_records_a_typed_gap_instead_of_bypassing(
    env: Environment, tmp_path: Path
) -> None:
    from itsm.identity.service import IdentityService

    development = DevelopmentService(
        tmp_path / "workspaces",
        session_factory=env.factory,
        identity_factory=lambda session: IdentityService(session, env.settings),
        validator=object(),
        known_core_permissions=(),
    )
    recorded = dispatch_extension_tool(
        "extension_contract_gap",
        {
            "extensionId": "software-licenses",
            "capability": "assets.relationships",
            "reason": "Necesito leer las asignaciones vigentes del activo.",
            "example": "context.assets.relationships(asset_id)",
        },
        principal=env.owner,
        host=env.host,
        development=development,
    )
    assert recorded["recorded"] is True
    listed = env.host.contract_gaps(env.owner)
    assert len(listed["items"]) == 1
    item = listed["items"][0]
    assert item["extensionId"] == "software-licenses"
    assert item["capability"] == "assets.relationships"
    assert "asignaciones" in item["reason"]
    assert item["example"] == "context.assets.relationships(asset_id)"


def test_contract_gap_listing_is_superadmin_only(env: Environment) -> None:
    from itsm.identity.service import IdentityService

    with env.factory() as session:
        role = IdentityService(session, env.settings).create_role(
            env.owner, name="Gap reader", permissions=["assets.view"]
        )
        user = IdentityService(session, env.settings).create_user(
            env.owner,
            username="gap.reader",
            name="Gap Reader",
            role_id=role.id,
            password="Gap-Reader-Pass-123",
        )
        actor = IdentityService(session, env.settings).resolve_actor(user.id)
    with pytest.raises(PermissionDenied):
        env.host.contract_gaps(actor)


def test_retrying_a_capability_mutation_with_the_same_key_is_safe(
    env: Environment,
) -> None:
    declaration = probe_manifest(capabilities=["assets.write"])
    env.install(build_package(declaration))
    values = asset_values()
    key = "license-op-1"
    first = env.invoke("probe_asset_create", {"values": values, "idempotency_key": key})
    second = env.invoke("probe_asset_create", {"values": values, "idempotency_key": key})
    assert first == second
    with env.factory() as session:
        assert InventoryService(session, env.settings).search(env.owner).total == 1
    with pytest.raises(ExtensionIdempotencyConflict):
        env.invoke(
            "probe_asset_create",
            {"values": asset_values(quick_code="SW-SN-002"), "idempotency_key": key},
        )


def test_status_exposes_consumer_state_and_http_control_routes(env) -> None:
    from tests.test_extension_isolation_http import _client, _headers

    prefix = env.settings.api_prefix + "/extensions"
    env.install(
        build_package(sandboxed_event_manifest(capabilities=["assets.read"]), backend=EVENT_BACKEND)
    )
    with _client(env) as client:
        headers = _headers(env, client)
        status = client.get(prefix + "/" + MODULE_ID + "/status").json()
        assert status["events"] == {
            "consumer": "extension:" + MODULE_ID,
            "cursor": 0,
            "stalled": False,
            "lastError": None,
            "attempts": 0,
            "retryAfter": None,
            "state": "active",
        }

        denied = client.post(
            prefix + "/" + MODULE_ID + "/events/reset", json={"expectedVersion": 1}
        )
        assert denied.status_code == 403
        stale = client.post(
            prefix + "/" + MODULE_ID + "/events/reset",
            json={"expectedVersion": 99},
            headers=headers,
        )
        assert stale.status_code == 409 and stale.json()["error"]["code"] == "stale"

        asset_id = make_asset(env)
        env.invoke("put_record", {"record_id": "ref-http", "label": asset_id})
        archive_asset(env, asset_id)
        dispatch(env)
        reconciled = client.post(
            prefix + "/" + MODULE_ID + "/reconcile",
            json={"expectedVersion": 1},
            headers=headers,
        )
        assert reconciled.status_code == 200, reconciled.text
        assert reconciled.json()["reconcile"]["states"][asset_id] == "archived"
        again = client.post(
            prefix + "/" + MODULE_ID + "/reconcile",
            json={"expectedVersion": 1},
            headers=headers,
        )
        assert again.status_code == 200

        reset = client.post(
            prefix + "/" + MODULE_ID + "/events/reset",
            json={"expectedVersion": 1},
            headers=headers,
        )
        assert reset.status_code == 200, reset.text
        assert reset.json()["events"]["stalled"] is False
