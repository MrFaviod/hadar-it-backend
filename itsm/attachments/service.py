"""Authorized asset documents over SQL metadata and independent blob storage."""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePath
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from itsm.attachments.models import Attachment
from itsm.attachments.storage import BlobStorage, LocalBlobStorage
from itsm.config import Settings
from itsm.identity.clock import utcnow
from itsm.identity.service import Conflict, IdentityService, NotFound, Principal, ValidationFailed
from itsm.inventory.codes import serialized
from itsm.inventory.media import detect_image_type
from itsm.inventory.service import InventoryService


class StorageUnavailable(Exception):
    """Blob storage is unavailable; do not expose filesystem details to callers."""


def validate_document(filename: str, category: str, data: bytes, maximum: int) -> str:
    if (
        not isinstance(filename, str)
        or not 1 <= len(filename) <= 180
        or PurePath(filename).name != filename
        or any(c in filename for c in "/\\")
        or any(ord(c) < 32 or ord(c) == 127 for c in filename)
    ):
        raise ValidationFailed("filename must be a plain display name of 1-180 characters")
    if category not in {"photo", "receipt", "manual", "document"}:
        raise ValidationFailed("category must be photo, receipt, manual or document")
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        raise ValidationFailed(f"file must contain 1-{maximum} bytes")
    suffix = PurePath(filename).suffix.lower()
    raster = detect_image_type(data)
    extensions = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
    }
    if raster and extensions.get(suffix) == raster:
        return raster
    if category == "photo":
        raise ValidationFailed("photo requires a PNG, JPEG, GIF or WebP file")
    if suffix == ".pdf" and data.startswith(b"%PDF-") and b"%%EOF" in data[-1024:]:
        return "application/pdf"
    if suffix in {".txt", ".csv"}:
        try:
            text = data.decode("utf-8-sig")
        except UnicodeError:
            raise ValidationFailed("text documents must use UTF-8") from None
        if not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", text):
            return "text/plain; charset=utf-8" if suffix == ".txt" else "text/csv; charset=utf-8"
    raise ValidationFailed("unsupported document type or file content")


class AttachmentService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        identity=None,
        source="rest",
        storage: BlobStorage | None = None,
    ):
        self._session = session
        self._settings = settings
        self._identity = identity or IdentityService(session, settings)
        self._inventory = InventoryService(
            session, settings, identity=self._identity, source=source
        )
        self._storage = storage or LocalBlobStorage(settings.attachment_storage_path)

    def _authorize(self, principal: Principal, asset_id: str, permission: str):
        self._identity.authorize(principal, permission, resource=f"asset:{asset_id}")
        return self._inventory._asset(asset_id)

    def _row(self, asset_id: str, attachment_id: str, *, deleted=False):
        row = self._session.get(Attachment, attachment_id)
        if row is None or row.asset_id != asset_id or (row.deleted_at is not None and not deleted):
            raise NotFound("attachment not found")
        return row

    def _payload(self, row: Attachment) -> dict[str, Any]:
        return {
            "id": row.id,
            "assetId": row.asset_id,
            "filename": row.filename,
            "category": row.category,
            "contentType": row.content_type,
            "size": row.size,
            "sha256": row.sha256,
            "createdBy": row.created_by,
            "createdAt": row.created_at.isoformat(),
            "downloadUrl": (
                f"{self._settings.api_prefix}/assets/{row.asset_id}/attachments/{row.id}/download"
            ),
        }

    def list(self, principal: Principal, asset_id: str, *, limit=50, offset=0):
        self._authorize(principal, asset_id, "assets.view")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
            or isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
        ):
            raise ValidationFailed("limit must be 1-100 and offset nonnegative")
        rows = self._session.scalars(
            select(Attachment)
            .where(Attachment.asset_id == asset_id, Attachment.deleted_at.is_(None))
            .order_by(Attachment.created_at, Attachment.id)
            .offset(offset)
            .limit(limit + 1)
        ).all()
        return {
            "items": [self._payload(row) for row in rows[:limit]],
            "limit": limit,
            "offset": offset,
            "hasMore": len(rows) > limit,
        }

    @serialized
    def upload(
        self, principal: Principal, asset_id: str, *, filename: str, category: str, data: bytes
    ):
        asset = self._authorize(principal, asset_id, "assets.edit")
        content_type = validate_document(
            filename, category, data, self._settings.attachment_max_bytes
        )
        row = Attachment(
            id=str(uuid4()),
            asset_id=asset.id,
            blob_key=uuid4().hex,
            filename=filename,
            category=category,
            content_type=content_type,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            created_by=principal.username,
            created_at=utcnow().replace(tzinfo=None),
        )
        try:
            self._storage.put(row.blob_key, data)
        except OSError:
            raise StorageUnavailable() from None
        try:
            self._session.add(row)
            self._inventory._record_history(
                principal,
                asset,
                "attachment_uploaded",
                changes={"attachment": {"old": None, "new": self._payload(row)}},
                entity_type="attachment",
                entity_id=row.id,
            )
            self._session.flush()
            self._identity.record_operation(
                principal,
                action="inventory.attachment_uploaded",
                resource=f"asset:{asset.id}:attachment:{row.id}",
            )
        except Exception:
            self._session.rollback()
            self._storage.delete(row.blob_key)
            raise
        return self._payload(row)

    def download(self, principal: Principal, asset_id: str, attachment_id: str):
        self._authorize(principal, asset_id, "assets.view")
        row = self._row(asset_id, attachment_id)
        try:
            data = self._storage.read(row.blob_key, self._settings.attachment_max_bytes)
        except OSError:
            raise StorageUnavailable() from None
        if len(data) != row.size or hashlib.sha256(data).hexdigest() != row.sha256:
            raise StorageUnavailable()
        return self._payload(row), data

    @serialized
    def delete(self, principal: Principal, asset_id: str, attachment_id: str):
        asset = self._authorize(principal, asset_id, "assets.edit")
        row = self._row(asset_id, attachment_id, deleted=True)
        from itsm.workflows.models import Warranty

        warranty = self._session.get(Warranty, asset_id)
        if warranty is not None and warranty.payload.get("receiptId") == row.id:
            raise Conflict("attachment is referenced by the individual warranty")
        from itsm.interventions.models import InterventionAttachment

        if self._session.scalar(
            select(InterventionAttachment.intervention_id)
            .where(InterventionAttachment.attachment_id == row.id)
            .limit(1)
        ):
            raise Conflict("attachment is referenced by a technical intervention")
        if row.deleted_at is None:
            row.deleted_at = utcnow().replace(tzinfo=None)
            self._inventory._record_history(
                principal,
                asset,
                "attachment_deleted",
                changes={"attachment": {"old": self._payload(row), "new": None}},
                entity_type="attachment",
                entity_id=row.id,
            )
            self._identity.record_operation(
                principal,
                action="inventory.attachment_deleted",
                resource=f"asset:{asset.id}:attachment:{row.id}",
            )
        # Tombstone commits first: interruption can leave hidden garbage, never a
        # live SQL row pointing at deleted bytes. Same DELETE retries cleanup.
        try:
            self._storage.delete(row.blob_key)
        except FileNotFoundError:
            pass
        except OSError:
            raise StorageUnavailable() from None
        self._session.delete(row)
        self._session.commit()
