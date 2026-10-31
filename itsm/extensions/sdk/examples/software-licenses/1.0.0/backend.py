"""Software-license registry backed by the module's own SQLite file.

Assignments relate to core assets by their permanent ids only. Existence and
lifecycle state are resolved through the declared ``assets.read`` capability;
nothing here imports ITSM code or opens the core database.
"""

from __future__ import annotations

import uuid

LICENSES = "licenses"
ASSIGNMENTS = "assignments"
READ = "ext_software_licenses.read"
WRITE = "ext_software_licenses.write"


def _license(context, license_id):
    row = context.store.get(LICENSES, license_id)
    if row is None:
        raise ValueError("license not found")
    return row


def _assignments(context, asset_id=None):
    filters = {"assetId": asset_id} if asset_id else {}
    return context.store.list(ASSIGNMENTS, limit=200, offset=0, filters=filters)["items"]


def _put(context, collection, record_id, data, version=None):
    return context.store.put(collection, record_id, data, version)


def list_licenses(context, limit=50, offset=0, product=None, vendor=None):
    context.authorize(READ)
    filters = {
        key: value
        for key, value in {"product": product, "vendor": vendor}.items()
        if value is not None
    }
    return context.store.list(LICENSES, limit=limit, offset=offset, filters=filters)


def get_license(context, license_id):
    context.authorize(READ)
    return _license(context, license_id)


def create_license(context, product, vendor, seats, expires_on=None):
    context.authorize(WRITE)
    data = {"product": product, "vendor": vendor, "seats": seats}
    if expires_on is not None:
        data["expiresOn"] = expires_on
    return _put(context, LICENSES, str(uuid.uuid4()), data)


def update_license(context, license_id, data, expected_version):
    context.authorize(WRITE)
    return _put(context, LICENSES, license_id, data, expected_version)


def assign_license(context, license_id, asset_id):
    context.authorize(WRITE)
    _license(context, license_id)
    for row in _assignments(context, asset_id):
        if row["data"].get("licenseId") == license_id:
            return row
    # Existence and lifecycle come from the public capability, never from SQL.
    context.assets.get(asset_id)
    data = {
        "licenseId": license_id,
        "assetId": asset_id,
        "flagged": False,
        "orphaned": False,
        "referenceState": "active",
    }
    return _put(context, ASSIGNMENTS, str(uuid.uuid4()), data)


def unassign_license(context, assignment_id):
    context.authorize(WRITE)
    context.store.delete(ASSIGNMENTS, assignment_id)
    return {"deleted": True}


def list_assignments(context, asset_id=None, limit=50, offset=0):
    context.authorize(READ)
    filters = {"assetId": asset_id} if asset_id else {}
    return context.store.list(ASSIGNMENTS, limit=limit, offset=offset, filters=filters)


def compliance_summary(context):
    context.authorize(READ)
    licenses = context.store.list(LICENSES, limit=200, offset=0, filters={})
    rows = _assignments(context)
    return {
        "licenses": licenses["total"],
        "seats": sum(int(item["data"].get("seats") or 0) for item in licenses["items"]),
        "assignments": len(rows),
        "orphaned": sum(1 for item in rows if item["data"].get("orphaned")),
        "flagged": sum(1 for item in rows if item["data"].get("flagged")),
    }


def unauthorized_asset_write(context):
    """Deliberate boundary probe: assets.write is not declared by the manifest."""
    context.authorize(WRITE)
    return context.assets.create({"quickCode": "SW-LIC-001"}, idempotencyKey="license-denied")


def _set_state(context, asset_id, *, flagged, orphaned, state):
    if not asset_id:
        return 0
    changed = 0
    for row in _assignments(context, asset_id):
        data = dict(row["data"])
        data.update({"flagged": flagged, "orphaned": orphaned, "referenceState": state})
        if data != row["data"]:
            _put(context, ASSIGNMENTS, row["id"], data, row["version"])
            changed += 1
    return changed


def on_asset_archived(context):
    event = context.event or {}
    changed = _set_state(
        context, event.get("entityId"), flagged=True, orphaned=False, state="archived"
    )
    return {"eventId": event.get("id"), "changed": changed}


def on_asset_deleted(context):
    event = context.event or {}
    changed = _set_state(
        context, event.get("entityId"), flagged=False, orphaned=True, state="missing"
    )
    return {"eventId": event.get("id"), "changed": changed}


def on_asset_restored(context):
    event = context.event or {}
    changed = _set_state(
        context, event.get("entityId"), flagged=False, orphaned=False, state="active"
    )
    return {"eventId": event.get("id"), "changed": changed}


def reconcile_assignments(context):
    context.authorize(READ)
    rows = _assignments(context)
    ids = sorted({row["data"]["assetId"] for row in rows if row["data"].get("assetId")})
    states = context.assets.resolve("asset", ids[:200])["states"] if ids else {}
    changed = 0
    for row in rows:
        state = states.get(row["data"].get("assetId"), "missing")
        data = dict(row["data"])
        data.update(
            {
                "flagged": state == "archived",
                "orphaned": state == "missing",
                "referenceState": state,
            }
        )
        if data != row["data"]:
            _put(context, ASSIGNMENTS, row["id"], data, row["version"])
            changed += 1
    return {"checked": len(rows), "changed": changed, "states": states}


def register(sdk):
    sdk.operation("list_licenses", list_licenses)
    sdk.operation("get_license", get_license)
    sdk.operation("create_license", create_license)
    sdk.operation("update_license", update_license)
    sdk.operation("assign_license", assign_license)
    sdk.operation("unassign_license", unassign_license)
    sdk.operation("list_assignments", list_assignments)
    sdk.operation("compliance_summary", compliance_summary)
    sdk.operation("unauthorized_asset_write", unauthorized_asset_write)
    sdk.subscribe("asset.archived", on_asset_archived)
    sdk.subscribe("asset.deleted", on_asset_deleted)
    sdk.subscribe("asset.restored", on_asset_restored)
    sdk.reconcile("reconcile_assignments", reconcile_assignments)
