"""Individual coverage, receipt references and persisted warning preferences."""

from __future__ import annotations

import calendar
from datetime import date, timedelta

from sqlalchemy import select

from itsm.attachments.models import Attachment
from itsm.identity.service import IdentityService, NotFound, ValidationFailed
from itsm.inventory.codes import serialized
from itsm.inventory.service import InventoryService
from itsm.workflows.models import Warranty, WarrantyPreference


class WarrantyService:
    def __init__(self, session, settings, *, identity=None, source="rest"):
        self._session = session
        self.identity = identity or IdentityService(session, settings)
        self.inventory = InventoryService(session, settings, identity=self.identity, source=source)

    def preferences(self, principal):
        self.identity.authorize(principal, "assets.view", resource="warranties:preferences")
        row = self._session.get(WarrantyPreference, "expiring")
        return {"expiringDays": row.days if row else 30}

    def set_preferences(self, principal, days):
        self.identity.authorize(principal, "config.general", resource="warranties:preferences")
        if type(days) is not int or not 1 <= days <= 365:
            raise ValidationFailed(
                "expiringDays must be 1-365", key="api.workflows.expiringdays_1_365"
            )
        row = self._session.get(WarrantyPreference, "expiring")
        if row is None:
            self._session.add(WarrantyPreference(key="expiring", days=days))
        else:
            row.days = days
        self.identity.record_operation(
            principal, action="inventory.warranty_preferences", resource="warranties:preferences"
        )
        return {"expiringDays": days}

    def _view(self, row, days):
        payload = dict(row.payload)
        expiry = date.fromisoformat(payload["expiresOn"]) if payload.get("expiresOn") else None
        today = date.today()
        payload["coverage"] = (
            "unknown"
            if expiry is None
            else "expired"
            if expiry < today
            else "expiring"
            if expiry <= today + timedelta(days=days)
            else "current"
        )
        return {"assetId": row.asset_id, **payload}

    def get(self, principal, asset_id):
        self.inventory.get(principal, asset_id)
        row = self._session.get(Warranty, asset_id)
        if row is None:
            raise NotFound("warranty not found", key="api.workflows.warranty_not_found")
        return self._view(row, self.preferences(principal)["expiringDays"])

    def list(self, principal, *, coverage=None, offset=0, limit=100):
        self.identity.authorize(principal, "assets.view", resource="warranties")
        if (
            coverage not in {None, "current", "expiring", "expired", "unknown"}
            or type(offset) is not int
            or offset < 0
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise ValidationFailed(
                "invalid warranty query", key="api.workflows.invalid_warranty_query"
            )
        days = self.preferences(principal)["expiringDays"]
        # The portable JSON payload is projected in bounded pages. Stop when
        # enough matching rows exist; never materialize all warranties.
        items, matched = [], 0
        query = select(Warranty).order_by(Warranty.asset_id).execution_options(yield_per=100)
        for row in self._session.scalars(query):
            view = self._view(row, days)
            if coverage and view["coverage"] != coverage:
                continue
            if matched >= offset:
                items.append(view)
                if len(items) > limit:
                    break
            matched += 1
        return {"items": items[:limit], "hasMore": len(items) > limit, "offset": offset}

    @serialized
    def put(self, principal, asset_id, values):
        self.identity.authorize(principal, "assets.edit", resource=f"asset:{asset_id}:warranty")
        asset = self.inventory._asset(asset_id)
        allowed = {
            "supplier",
            "purchaseDate",
            "durationMonths",
            "expiresOn",
            "status",
            "receiptId",
            "notes",
        }
        if not isinstance(values, dict) or set(values) - allowed:
            raise ValidationFailed(
                "unsupported warranty fields", key="api.workflows.unsupported_warranty_fields"
            )
        payload = dict(values)
        for key, maximum in (("supplier", 160), ("notes", 2000)):
            value = payload.get(key)
            if value is not None and (not isinstance(value, str) or len(value) > maximum):
                raise ValidationFailed(
                    f"{key} is too long or is not text",
                    key="api.workflows.key_too_long_not_text",
                    params={"key": key},
                )
        if payload.get("status", "active") not in {"active", "cancelled", "claimed", "unknown"}:
            raise ValidationFailed(
                "unsupported warranty status", key="api.workflows.unsupported_warranty_status"
            )
        payload.setdefault("status", "active")
        dates = {}
        for key in ("purchaseDate", "expiresOn"):
            value = payload.get(key)
            if value is not None:
                try:
                    if not isinstance(value, str) or len(value) != 10:
                        raise ValueError()
                    dates[key] = date.fromisoformat(value)
                except ValueError, TypeError:
                    raise ValidationFailed(
                        f"invalid {key}", key="api.workflows.invalid_key", params={"key": key}
                    ) from None
        months = payload.get("durationMonths")
        if months is not None:
            if type(months) is not int or not 1 <= months <= 1200:
                raise ValidationFailed(
                    "durationMonths must be 1-1200", key="api.workflows.durationmonths_1_1200"
                )
            if "purchaseDate" not in dates:
                raise ValidationFailed(
                    "durationMonths requires purchaseDate",
                    key="api.workflows.durationmonths_requires_purchasedate",
                )
            purchase = dates["purchaseDate"]
            total = purchase.year * 12 + purchase.month - 1 + months
            year, month = divmod(total, 12)
            month += 1
            if year > 9999:
                raise ValidationFailed(
                    "warranty expiry exceeds supported date range",
                    key="api.workflows.warranty_expiry_exceeds_supported_date_range",
                )
            calculated = date(year, month, min(purchase.day, calendar.monthrange(year, month)[1]))
            if "expiresOn" in dates and dates["expiresOn"] != calculated:
                raise ValidationFailed(
                    "duration and expiry conflict", key="api.workflows.duration_expiry_conflict"
                )
            dates["expiresOn"] = calculated
            payload["expiresOn"] = calculated.isoformat()
        if (
            dates.get("expiresOn")
            and dates.get("purchaseDate")
            and dates["expiresOn"] < dates["purchaseDate"]
        ):
            raise ValidationFailed(
                "expiry cannot precede purchase", key="api.workflows.expiry_cannot_precede_purchase"
            )
        receipt_id = payload.get("receiptId")
        if receipt_id:
            if not isinstance(receipt_id, str) or len(receipt_id) != 36:
                raise ValidationFailed("invalid receiptId", key="api.workflows.invalid_receiptid")
            receipt = self._session.get(Attachment, receipt_id)
            if receipt is None or receipt.asset_id != asset_id or receipt.deleted_at is not None:
                raise ValidationFailed(
                    "receipt must be an accessible attachment of this asset",
                    key="api.workflows.receipt_accessible_attachment_asset",
                )
        row = self._session.get(Warranty, asset_id)
        previous = row.payload if row else None
        if row is None:
            row = Warranty(asset_id=asset_id, payload=payload)
            self._session.add(row)
        else:
            row.payload = payload
        self.inventory._record_history(
            principal,
            asset,
            "warranty_updated",
            changes={"warranty": {"old": previous, "new": payload}},
            entity_type="warranty",
            entity_id=asset_id,
        )
        self.identity.record_operation(
            principal, action="inventory.warranty_updated", resource=f"asset:{asset_id}"
        )
        return self.get(principal, asset_id)

    @serialized
    def delete(self, principal, asset_id):
        self.identity.authorize(principal, "assets.edit", resource=f"asset:{asset_id}:warranty")
        asset = self.inventory._asset(asset_id)
        row = self._session.get(Warranty, asset_id)
        if row is None:
            raise NotFound("warranty not found", key="api.workflows.warranty_not_found")
        self.inventory._record_history(
            principal,
            asset,
            "warranty_deleted",
            changes={"warranty": {"old": row.payload, "new": None}},
            entity_type="warranty",
            entity_id=asset_id,
        )
        self._session.delete(row)
        self.identity.record_operation(
            principal, action="inventory.warranty_deleted", resource=f"asset:{asset_id}"
        )
