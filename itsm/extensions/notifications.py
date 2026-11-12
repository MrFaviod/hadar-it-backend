"""Transactional native inbox delivery for trusted extension contexts.

The caller owns the transaction. Recipient authority is projected without a
failed authorize call, which would commit a denial audit in IdentityService.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Collection, Sequence
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.identity.clock import utcnow
from itsm.identity.models import Identity
from itsm.identity.service import IdentityService, PermissionDenied, Principal, ValidationFailed
from itsm.notifications.models import NotificationEvent, NotificationInbox, NotificationOutbox

_MODULE_ID = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


def enqueue_extension_notice(
    session: Session,
    settings: Settings,
    *,
    module_id: str,
    module_permissions: Collection[str],
    principal: Principal,
    recipient_ids: Sequence[str],
    key: str,
    title: str,
    body: str,
    permission: str,
    asset_id: str | None = None,
    url: str | None = None,
) -> dict[str, int]:
    """Deliver once per module/key/authorized recipient, without committing."""
    if (
        not isinstance(module_id, str)
        or not 2 <= len(module_id) <= 48
        or not _MODULE_ID.fullmatch(module_id)
        or permission not in module_permissions
    ):
        raise ValidationFailed(
            "notice permission must be declared by its module",
            key="api.extensions.notice_permission_undeclared",
            params={"permission": permission},
        )
    if (
        not isinstance(key, str)
        or not 1 <= len(key) <= 200
        or not isinstance(title, str)
        or not 1 <= len(title) <= 200
        or not isinstance(body, str)
        or not 1 <= len(body) <= 4000
    ):
        raise ValidationFailed(
            "notice key, title and body must be bounded text",
            key="api.extensions.notice_text_bounded",
            params={},
        )
    if isinstance(recipient_ids, str) or not isinstance(recipient_ids, (list, tuple)):
        raise ValidationFailed(
            "recipient_ids must be a list",
            key="api.extensions.notice_recipients_list",
            params={},
        )
    if not 1 <= len(recipient_ids) <= 100 or any(
        not isinstance(value, str) or not 1 <= len(value) <= 36 for value in recipient_ids
    ):
        raise ValidationFailed(
            "notice recipients must contain 1-100 identity ids",
            key="api.extensions.notice_recipient_count",
            params={"minimum": 1, "maximum": 100},
        )
    if url is not None and (
        not isinstance(url, str)
        or len(url) > 500
        or not url.startswith(f"#/extensiones/{module_id}/")
    ):
        raise ValidationFailed(
            "notice url must point to its native extension page",
            key="api.extensions.notice_url_native_page",
            params={},
        )
    identity_service = IdentityService(session, settings)
    granted = identity_service.effective_permissions(principal)
    if permission not in granted or (asset_id is not None and "assets.view" not in granted):
        raise PermissionDenied(
            "permission denied", key="api.extensions.permission_denied", params={}
        )
    if asset_id is not None:
        from itsm.inventory.service import InventoryService

        # Canonical reads may persist denial audits; never commit business writes.
        with Session(session.get_bind()) as asset_session:
            InventoryService(asset_session, settings).get(principal, asset_id)
    now = utcnow()
    event_key = hashlib.sha256(key.encode()).hexdigest()
    alert_id = "extension:" + hashlib.sha256(module_id.encode()).hexdigest()[:48]
    event = session.scalar(
        select(NotificationEvent).where(
            NotificationEvent.alert_id == alert_id,
            NotificationEvent.event_key == event_key,
        )
    )
    created = 0
    skipped = 0
    for recipient_id in dict.fromkeys(recipient_ids):
        recipient = session.get(Identity, recipient_id)
        if recipient is None or not recipient.active or recipient.actor_kind != "human":
            skipped += 1
            continue
        granted = identity_service.effective_permissions(
            identity_service.resolve_actor(recipient.id)
        )
        if permission not in granted or "assets.view" not in granted:
            skipped += 1
            continue
        dedupe_key = f"extension:{module_id}:{event_key}:{recipient_id}"
        existing = session.scalar(
            select(NotificationOutbox.id).where(NotificationOutbox.dedupe_key == dedupe_key)
        )
        if existing is not None:
            skipped += 1
            continue
        if event is None:
            event = NotificationEvent(
                id=str(uuid4()),
                alert_id=alert_id,
                event_key=event_key,
                event_type="extension",
                severity="warning",
                asset_id=asset_id,
                title=title,
                body=body,
                url=url,
                occurred_at=now,
                created_at=now,
            )
            session.add(event)
            session.flush()
        outbox = NotificationOutbox(
            id=str(uuid4()),
            dedupe_key=dedupe_key,
            event_id=event.id,
            alert_id=alert_id,
            recipient_id=recipient_id,
            channel_id="internal-default",
            status="delivered",
            attempts=1,
            max_attempts=1,
            severity="warning",
            asset_id=asset_id,
            title=title,
            body=body,
            url=url,
            next_attempt_at=now,
            delivered_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(outbox)
        session.flush()
        session.add(
            NotificationInbox(
                id=str(uuid4()),
                outbox_id=outbox.id,
                recipient_id=recipient_id,
                alert_id=alert_id,
                event_key=event_key,
                event_type="extension",
                severity="warning",
                asset_id=asset_id,
                title=title,
                body=body,
                url=url,
                extension_id=module_id,
                required_permission=permission,
                created_at=now,
            )
        )
        session.flush()
        created += 1
    return {"created": created, "skipped": skipped}
