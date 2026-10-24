"""Fixed previews and durable per-row receipts over canonical inventory rules."""

from __future__ import annotations

import csv
import hashlib
import json
from io import StringIO
from typing import Any
from uuid import uuid4

from sqlalchemy import select

from itsm.identity.clock import utcnow
from itsm.identity.models import Identity
from itsm.identity.service import (
    Conflict,
    IdentityError,
    IdentityService,
    NotFound,
    PermissionDenied,
    ValidationFailed,
)
from itsm.inventory.codes import serialized
from itsm.inventory.models import Asset
from itsm.inventory.service import ASSET_FIELDS, InventoryService
from itsm.workflows.models import ImportProfile, Operation, OperationRow
from itsm.workflows.parsing import ALIASES, inspect_file, parse, wants_inspection

LIMIT = 5000
BUILTINS = [
    {"id": "csv-standard", "name": "CSV standard", "options": {"delimiter": ","}},
    {
        "id": "csv-spanish",
        "name": "CSV Spanish decimal",
        "options": {"delimiter": ";", "decimalSeparator": ","},
    },
    {"id": "xlsx-sites", "name": "Excel sites by sheet", "options": {"siteFromSheet": True}},
]


DEFAULT_EXPORT_FIELDS = [
    "quick_code",
    "name",
    "category",
    "status",
    "serial",
    "site",
    "location",
    "responsible",
]
EXPORT_SEPARATORS = {"comma": ",", "semicolon": ";", "tab": "\t", "pipe": "|"}
EXPORT_FLAGS = ("headerRow", "bom", "includeEmpty")
EXPORT_DEFAULTS = {"separator": ",", "headerRow": True, "bom": True, "includeEmpty": True}


def export_options(options: Any) -> dict[str, Any]:
    """Validate the incumbent export controls; unknown or malformed keys fail.

    ``separator`` is named (comma/semicolon/tab/pipe), never a raw delimiter;
    ``headerRow`` includes the header line, ``bom`` marks UTF-8 output and
    ``includeEmpty`` keeps columns with no value at all.
    """
    if options is None:
        return dict(EXPORT_DEFAULTS)
    if not isinstance(options, dict):
        raise ValidationFailed("export options must be an object")
    unknown = set(options) - set(EXPORT_DEFAULTS)
    if unknown:
        raise ValidationFailed("unsupported export options: " + ", ".join(sorted(unknown)))
    resolved = dict(EXPORT_DEFAULTS)
    if "separator" in options:
        name = options["separator"]
        if not isinstance(name, str) or name not in EXPORT_SEPARATORS:
            raise ValidationFailed("separator must be comma, semicolon, tab or pipe")
        resolved["separator"] = EXPORT_SEPARATORS[name]
    for flag in EXPORT_FLAGS:
        if flag in options:
            if type(options[flag]) is not bool:
                raise ValidationFailed(f"{flag} must be a boolean")
            resolved[flag] = options[flag]
    return resolved


def _cell(value: Any) -> str:
    """One export cell: JSON for structures, neutralized for spreadsheet formulas."""
    text = (
        json.dumps(value, ensure_ascii=False)
        if isinstance(value, (dict, list))
        else str(value)
        if value is not None
        else ""
    )
    if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        text = "'" + text
    return text


def version(asset):
    # Include all persisted business columns, not just mutable time stamps.
    content = {c.name: str(getattr(asset, c.name)) for c in Asset.__table__.columns}
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()


def compact_operation(value: Any, limit: int = 20) -> Any:
    """Bound every row-bearing workflow result for the agent/MCP transports.

    The REST adapter keeps its full page; agent and MCP tool results stay at
    ``limit`` rows while ``total`` remains the true row count and ``hasMore``
    tells the caller to page through ``get_inventory_operation``.
    """
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValidationFailed("compact limit must be 1-100")
    if not isinstance(value, dict):
        return value
    result = dict(value)
    rows = value.get("rows")
    if isinstance(rows, list):
        result["total"] = max(result.get("total") or 0, len(rows))
        if len(rows) > limit:
            result["rows"] = rows[:limit]
            result["hasMore"] = True
    sheets = value.get("sheets")
    if isinstance(sheets, list):
        result["sheets"] = [compact_operation(sheet, limit) for sheet in sheets]
        result["totalSheets"] = len(sheets)
    return result


class DeferredAudit:
    """Canonical authorization; defer only successful terminal audit commits.

    Inventory methods perform all existing validation/history. Their success
    audit is emitted after the corresponding receipt exists in this transaction.
    Denial authorization is never deferred or treated as success.
    """

    def __init__(self, identity):
        self.identity = identity
        self.events = []

    def __getattr__(self, name):
        return getattr(self.identity, name)

    def record_operation(self, principal, **event):
        self.events.append((principal, event))

    def finish(self):
        for principal, event in self.events:
            stored = self.identity._session.get(Identity, principal.actor_id)
            self.identity._audit(
                actor_id=principal.actor_id,
                actor_kind=stored.actor_kind,
                actor_username=stored.username,
                execution_id=principal.execution_id,
                delegated_by=stored.delegated_by_id,
                authorization_ref=principal.authorization_ref,
                outcome=event.pop("outcome", "success"),
                **event,
            )


class WorkflowService:
    def __init__(self, session, settings, *, identity=None, source="rest"):
        self._session = session
        self.settings = settings
        self.identity = identity or IdentityService(session, settings)
        self.source = source
        self.inventory = InventoryService(session, settings, identity=self.identity, source=source)

    def _auth(self, principal, permission="assets.edit"):
        self.identity.authorize(principal, permission, resource="inventory:operations")

    def _operation(self, principal, operation_id, permission="assets.view"):
        self._auth(principal, permission)
        row = self._session.get(Operation, operation_id)
        if row is None:
            raise NotFound("operation not found")
        # Human approval can be shared with authorized machines; UUID is a
        # locator, never authorization. All operations require current scope.
        return row

    def _rows(self, operation_id):
        return list(
            self._session.scalars(
                select(OperationRow)
                .where(OperationRow.operation_id == operation_id)
                .order_by(OperationRow.index)
            )
        )

    def get(self, principal, operation_id, *, offset=0, limit=100):
        row = self._operation(principal, operation_id)
        if (
            type(offset) is not int
            or offset < 0
            or type(limit) is not int
            or not 1 <= limit <= 5000
        ):
            raise ValidationFailed("invalid operation page")
        rows = self._rows(row.id)
        summary = {"created": 0, "modified": 0, "omitted": 0, "failed": 0}
        for item in rows:
            state = item.payload.get("result")
            if state in summary:
                summary[state] += 1
        return {
            "id": row.id,
            "state": row.state,
            "jobId": row.job_id,
            "approved": row.approver_id is not None,
            "total": len(rows),
            "processed": sum(summary.values()),
            "summary": summary,
            "rows": [dict(index=r.index, **r.payload) for r in rows[offset : offset + limit]],
            "hasMore": offset + limit < len(rows),
        }

    def _store(self, principal, rows, kind):
        row = Operation(
            id=str(uuid4()),
            owner_id=principal.actor_id,
            payload={"kind": kind},
            state="preview",
            created_at=utcnow().replace(tzinfo=None),
        )
        self._session.add(row)
        self._session.flush()
        for index, value in enumerate(rows):
            self._session.add(OperationRow(operation_id=row.id, index=index, payload=value))
        self._session.commit()
        return self.get(principal, row.id, limit=5000)

    def profiles(self, principal):
        self._auth(principal, "assets.view")
        return {
            "items": BUILTINS
            + [
                {"id": p.id, "name": p.name, "options": p.options}
                for p in self._session.scalars(
                    select(ImportProfile).order_by(ImportProfile.name).limit(100)
                )
            ]
        }

    def save_profile(self, principal, name, options, profile_id=None):
        self._auth(principal)
        if (
            not isinstance(name, str)
            or not 1 <= len(name.strip()) <= 100
            or not isinstance(options, dict)
            or len(json.dumps(options)) > 20000
        ):
            raise ValidationFailed("invalid import profile")
        row = self._session.get(ImportProfile, profile_id) if profile_id else None
        if profile_id and row is None:
            raise NotFound("profile not found")
        if row is None:
            row = ImportProfile(id=str(uuid4()), name=name.strip(), options=options)
            self._session.add(row)
        else:
            row.name, row.options = name.strip(), options
        self.identity.record_operation(
            principal, action="inventory.import_profile_saved", resource=f"import-profile:{row.id}"
        )
        return {"id": row.id, "name": row.name, "options": row.options}

    def delete_profile(self, principal, profile_id):
        self._auth(principal)
        row = self._session.get(ImportProfile, profile_id)
        if row is None:
            raise NotFound("profile not found")
        self._session.delete(row)
        self.identity.record_operation(
            principal,
            action="inventory.import_profile_deleted",
            resource=f"import-profile:{profile_id}",
        )

    def analyze(self, principal, data, filename, options=None):
        self._auth(principal)
        # JSON callers may send any decoded value; only an object is a contract.
        if options is not None and not isinstance(options, dict):
            raise ValidationFailed("import options must be an object")
        options = dict(options or {})
        if options.get("profileId"):
            profile = next(
                (p for p in self.profiles(principal)["items"] if p["id"] == options["profileId"]),
                None,
            )
            if profile is None:
                raise NotFound("profile not found")
            options = {**profile["options"], **options}
        if wants_inspection(options):
            return inspect_file(data, filename, options)
        rows = parse(data, filename, options)
        match_fields = options.get("matchFields", ["quick_code", "serial"])
        if not isinstance(match_fields, list) or any(
            f not in {"quick_code", "serial", "ip"} for f in match_fields
        ):
            raise ValidationFailed("matchFields supports quick_code, serial, ip")
        for row in rows:
            values = row["values"]
            permanent_id = values.pop("id", None)
            asset = self._session.get(Asset, permanent_id) if permanent_id else None
            candidates = []
            if permanent_id and asset is None:
                row["errors"].append("permanent id does not exist; resolve as new explicitly")
            if not permanent_id:
                for field in match_fields:
                    if values.get(field):
                        candidates.extend(
                            self._session.scalars(
                                select(Asset.id)
                                .where(getattr(Asset, field) == values[field])
                                .limit(21)
                            )
                        )
            row.update(
                {
                    "assetId": asset.id if asset else None,
                    "version": version(asset) if asset else None,
                    "classification": "error"
                    if row["errors"]
                    else "safe"
                    if asset
                    else "possible_duplicate"
                    if candidates
                    else "new",
                    "candidates": list(dict.fromkeys(candidates))[:20],
                    "action": "update" if asset else "create",
                }
            )
            unknown = set(values) - set(ASSET_FIELDS)
            if unknown:
                row["errors"].append("unsupported fields: " + ", ".join(sorted(unknown)))
                row["classification"] = "error"
            if not row["errors"] and row["classification"] != "possible_duplicate":
                try:
                    if asset:
                        self.inventory._prepare_changes(asset, values, principal=principal)
                    else:
                        # Do not allocate a quick code during analysis.
                        self.inventory._prepare_create(
                            {"quick_code": "PREVIEW", **values}, principal=principal
                        )
                except IdentityError as exc:
                    row["errors"].append(str(exc))
                    row["classification"] = "error"
        return self._store(principal, rows, "import")

    def _select(self, principal, asset_ids=None, filters=None):
        self._auth(principal, "assets.view")
        if asset_ids is not None:
            if (
                not isinstance(asset_ids, list)
                or not asset_ids
                or len(asset_ids) > LIMIT
                or any(not isinstance(i, str) for i in asset_ids)
            ):
                raise ValidationFailed("select 1-5000 permanent asset IDs")
            return list(dict.fromkeys(asset_ids))
        filters = filters or {}
        if not filters or set(filters) - {
            "all",
            "category",
            "status",
            "site_id",
            "location_id",
            "responsible_person_id",
            "archived",
        }:
            raise ValidationFailed("explicit selection or supported nonempty filters required")
        if "all" in filters and filters["all"] is not True:
            raise ValidationFailed('the "all" filter accepts only true')
        query = select(Asset.id)
        for field, value in filters.items():
            if field == "all":
                continue
            if field == "archived":
                if type(value) is not bool:
                    raise ValidationFailed("archived filter must be boolean")
                query = query.where(
                    Asset.archived_at.is_not(None) if value else Asset.archived_at.is_(None)
                )
            else:
                query = query.where(getattr(Asset, field) == value)
        ids = list(self._session.scalars(query.order_by(Asset.id).limit(LIMIT + 1)))
        if len(ids) > LIMIT:
            raise ValidationFailed("selection exceeds 5000 assets; narrow filters")
        return ids

    def preview(
        self, principal, *, asset_ids=None, filters=None, changes=None, action="update", reason=None
    ):
        self._auth(principal)
        if action not in {"update", "archive", "transfer", "assign", "return"}:
            raise ValidationFailed("unsupported bulk action")
        if not isinstance(changes, dict) or len(json.dumps(changes)) > 20000:
            raise ValidationFailed("changes must be an explicit bounded object")
        changes = {ALIASES.get(k, k): v for k, v in changes.items()}
        ids = self._select(principal, asset_ids, filters)
        rows = []
        for asset_id in ids:
            asset = self._session.get(Asset, asset_id)
            errors = []
            if asset is None:
                errors.append("asset not found")
            elif action == "update":
                try:
                    self.inventory._prepare_changes(asset, changes, principal=principal)
                except IdentityError as exc:
                    errors.append(str(exc))
            rows.append(
                {
                    "assetId": asset_id,
                    "version": version(asset) if asset else None,
                    "values": changes,
                    "action": action,
                    "reason": reason,
                    "classification": "error" if errors else "safe",
                    "errors": errors,
                }
            )
        return self._store(principal, rows, "bulk")

    @serialized
    def resolve(self, principal, operation_id, index, action, asset_id=None, values=None):
        operation = self._operation(principal, operation_id, "assets.edit")
        if operation.state not in {"preview", "approved"}:
            raise Conflict("only unapplied previews can be resolved")
        row = self._session.get(OperationRow, (operation.id, index))
        if row is None or action not in {"skip", "create", "update"}:
            raise ValidationFailed("invalid row resolution")
        payload = dict(row.payload)
        if values is not None:
            if not isinstance(values, dict) or set(values) - set(ASSET_FIELDS):
                raise ValidationFailed("unsupported row values")
            payload["values"] = values
        asset = self.inventory._asset(asset_id) if action == "update" else None
        if action != "skip":
            if asset:
                self.inventory._prepare_changes(asset, payload["values"], principal=principal)
            else:
                self.inventory._prepare_create(
                    {"quick_code": "PREVIEW", **payload["values"]}, principal=principal
                )
        payload.update(
            action=action,
            assetId=asset.id if asset else None,
            version=version(asset) if asset else None,
            classification="omitted" if action == "skip" else "safe" if asset else "new",
            errors=[],
        )
        row.payload = payload
        operation.approver_id, operation.state = None, "preview"
        self._session.commit()
        return self.get(principal, operation.id, limit=5000)

    def _row_permissions(self, principal, rows):
        for permission in self._required_permissions(rows):
            self._auth(principal, permission)

    def _required_permissions(self, rows):
        if any(
            any(
                k in row.payload.get("values", {}) for k in ("responsible", "responsible_person_id")
            )
            or row.payload.get("action") in {"assign", "return"}
            for row in rows
        ):
            return ("assets.edit", "assets.assign")
        return ("assets.edit",)

    @serialized
    def approve(self, principal, operation_id):
        operation = self._operation(principal, operation_id, "assets.edit")
        if principal.kind != "human":
            raise PermissionDenied("only an authorized human can approve a fixed preview")
        if operation.state not in {"preview", "approved"}:
            raise Conflict("operation is already applying or completed")
        rows = self._rows(operation.id)
        self._row_permissions(principal, rows)
        if any(r.payload["classification"] in {"possible_duplicate", "error"} for r in rows):
            raise Conflict("resolve or skip conflicts before approval")
        for row in rows:
            if row.payload.get("assetId") and row.payload.get("action") != "skip":
                asset = self.inventory._asset(row.payload["assetId"])
                if version(asset) != row.payload["version"]:
                    raise Conflict("preview is stale; prepare a new preview")
        operation.approver_id, operation.state = principal.actor_id, "approved"
        self.identity.record_operation(
            principal, action="inventory.operation_approved", resource=f"operation:{operation.id}"
        )
        return self.get(principal, operation.id, limit=5000)

    def _approval(self, operation, principal, permissions=None):
        if not operation.approver_id:
            raise Conflict("human approval of the exact preview is required")
        stored = self._session.get(Identity, operation.approver_id)
        if stored is None or stored.actor_kind != "human":
            raise PermissionDenied("approval is no longer valid")
        approver = self.identity._principal(stored)
        if permissions is None:
            permissions = self._required_permissions(self._rows(operation.id))
        for permission in permissions:
            self._auth(principal, permission)
            self._auth(approver, permission)

    @serialized
    def _start_execution(self, principal, operation_id):
        self._session.expire_all()
        operation = self._operation(principal, operation_id, "assets.edit")
        rows = self._rows(operation.id)
        permissions = self._required_permissions(rows)
        self._approval(operation, principal, permissions)
        indexes = [
            row.index
            for row in rows
            if row.payload.get("result") not in {"created", "modified", "omitted"}
        ]
        # Freeze the approved preview before reusing its permission projection.
        # Each row still revalidates current executor and approver authority.
        if operation.state != "complete":
            operation.state = "running"
        self._session.commit()
        return indexes, permissions

    def execute(self, principal, operation_id):
        indexes, permissions = self._start_execution(principal, operation_id)
        for index in indexes:
            try:
                self._apply_row(principal, operation_id, index, permissions)
            except PermissionDenied:
                raise
            except IdentityError as exc:
                self._fail_row(principal, operation_id, index, str(exc), permissions)
        operation = self._session.get(Operation, operation_id)
        operation.state = "complete"
        self._session.commit()
        return self.get(principal, operation_id, limit=5000)

    @serialized
    def _fail_row(self, principal, operation_id, index, message, permissions):
        self._session.expire_all()
        operation = self._session.get(Operation, operation_id)
        self._approval(operation, principal, permissions)
        row = self._session.get(OperationRow, (operation_id, index))
        if row.payload.get("result") not in {"created", "modified", "omitted"}:
            row.payload = {**row.payload, "result": "failed", "error": message}
            self._session.commit()

    @serialized
    def _apply_row(self, principal, operation_id, index, permissions):
        self._session.expire_all()
        operation = self._session.get(Operation, operation_id)
        self._approval(operation, principal, permissions)
        row = self._session.get(OperationRow, (operation_id, index))
        payload = dict(row.payload)
        if payload.get("result") in {"created", "modified", "omitted"}:
            return
        action, values = payload["action"], payload["values"]
        deferred = DeferredAudit(self.identity)
        inventory = InventoryService(
            self._session, self.settings, identity=deferred, source=self.source
        )
        if action == "skip":
            result = "omitted"
        elif action == "create":
            view = inventory.create(principal, values)
            payload["createdAssetId"] = view.id
            result = "created"
        else:
            asset = inventory._asset(payload["assetId"])
            if version(asset) != payload["version"]:
                raise Conflict("asset changed since preview; prepare a new preview")
            if action == "archive":
                inventory.archive(principal, asset.id, reason=payload.get("reason"))
            elif action == "transfer":
                inventory.transfer(principal, asset.id, reason=payload.get("reason"), **values)
            elif action == "assign":
                inventory.assign_responsible(
                    principal,
                    asset.id,
                    values.get("responsible_person_id"),
                    reason=payload.get("reason"),
                )
            elif action == "return":
                inventory.return_responsible(principal, asset.id, reason=payload.get("reason"))
            else:
                inventory.update(principal, asset.id, values)
            result = "modified"
        row.payload = {**payload, "result": result, "error": None}
        deferred.finish()
        operation.state = "running"
        self._session.commit()

    def export(self, principal, *, asset_ids=None, filters=None, fields=None, options=None):
        """Return CSV text for an authorized selection using validated controls."""
        controls = export_options(options)
        ids = self._select(principal, asset_ids, filters)
        fields = list(dict.fromkeys(["id", *(fields or DEFAULT_EXPORT_FIELDS)]))
        if any(f not in {"id", *ASSET_FIELDS} for f in fields):
            raise ValidationFailed("unsupported export field")
        table = [
            [_cell(getattr(self.inventory._asset(asset_id), field, None)) for field in fields]
            for asset_id in ids
        ]
        if not controls["includeEmpty"]:
            # A wholly empty column is dropped; the permanent ID always survives.
            kept = [
                index
                for index, field in enumerate(fields)
                if field == "id" or any(row[index] for row in table)
            ]
            fields = [fields[index] for index in kept]
            table = [[row[index] for index in kept] for row in table]
        output = StringIO(newline="")
        writer = csv.writer(output, delimiter=controls["separator"])
        if controls["headerRow"]:
            writer.writerow(fields)
        writer.writerows(table)
        return output.getvalue()
