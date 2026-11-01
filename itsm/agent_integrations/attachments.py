"""Owner-scoped chat attachments over the existing independent blob store.

The bytes are validated with the same content sniffing as asset documents and
stored outside the main SQL database. A row is readable only by the owner of the
session it belongs to, never by another human who happens to know its id, and it
is deleted together with the attachment or the conversation.

Limits are constants, not configuration: per file, per message and per session.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from itsm.agent_integrations.models import AgentSession, ChatAttachment
from itsm.attachments.service import (
    CHAT_FILE_KIND,
    CHAT_IMAGE_KIND,
    CHAT_TEXT_KIND,
    StorageUnavailable,
    validate_chat_attachment,
)
from itsm.attachments.storage import BlobStorage, LocalBlobStorage
from itsm.config import Settings
from itsm.identity.clock import utcnow
from itsm.identity.service import IdentityService, NotFound, Principal, ValidationFailed

#: One message may carry at most this many attachments of either origin.
MAX_MESSAGE_ATTACHMENTS = 4
#: A single stored chat attachment; the deployment maximum can only lower it.
MAX_CHAT_ATTACHMENT_BYTES = 4 * 1024 * 1024
#: Decoded bytes for all attachments of one message, chat and asset combined.
MAX_CHAT_MESSAGE_BYTES = 4 * 1024 * 1024
#: Uploading stays bounded even without sending, so rows cannot grow forever.
MAX_SESSION_ATTACHMENTS = 20

#: Conservative reservation estimate per modality, settled later by real usage.
IMAGE_TOKEN_ESTIMATE = 2048
FILE_TOKEN_ESTIMATE = 4096
TEXT_TOKEN_BYTES = 4


@dataclass(frozen=True)
class ChatAttachmentInput:
    """One validated attachment body handed to a runtime, never to a log."""

    filename: str
    media_type: str
    kind: str
    data: bytes
    identifier: str = ""
    asset_id: str | None = None

    def metadata(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.identifier,
            "filename": self.filename,
            "mediaType": self.media_type,
            "kind": self.kind,
            "size": len(self.data),
        }
        if self.asset_id is not None:
            payload["assetId"] = self.asset_id
        return payload


def estimate_attachment_tokens(items: Iterable[ChatAttachmentInput]) -> int:
    """Conservative pre-call estimate for company-funded reservations.

    An image is charged a flat 2048 tokens and a document 4096, both above the
    typical provider cost of a bounded attachment. Inlined text/CSV is charged
    one token per four bytes plus the fence. Settlement always replaces the
    estimate with the provider's measured usage, so precision rules do not move.
    """

    total = 0
    for item in items:
        if item.kind == CHAT_IMAGE_KIND:
            total += IMAGE_TOKEN_ESTIMATE
        elif item.kind == CHAT_FILE_KIND:
            total += FILE_TOKEN_ESTIMATE
        else:
            total += 8 + (len(item.data) + TEXT_TOKEN_BYTES - 1) // TEXT_TOKEN_BYTES
    return total


def encoded_size(data: bytes) -> int:
    """Standard base64 size; the unit the managed gateway lease budgets in."""

    return 4 * ((len(data) + 2) // 3)


def encoded_attachment_bytes(items: Iterable[ChatAttachmentInput]) -> int:
    """Encoded size of every bytes-bearing attachment of one message."""

    return sum(encoded_size(item.data) for item in items if item.kind != CHAT_TEXT_KIND)


def bounded_attachment_ids(value: Any) -> list[str]:
    """Validate a bounded, duplicate-free list of attachment identifiers."""

    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or len(value) > MAX_MESSAGE_ATTACHMENTS:
        raise ValidationFailed(
            f"at most {MAX_MESSAGE_ATTACHMENTS} attachments are allowed per message",
            key="api.agent_integrations.message_attachments_limit",
            params={"limit": MAX_MESSAGE_ATTACHMENTS},
        )
    seen: list[str] = []
    for item in value:
        if not isinstance(item, str) or not 1 <= len(item) <= 64:
            raise ValidationFailed(
                "attachment ids must be identifiers",
                key="api.agent_integrations.attachment_ids_invalid",
            )
        if item not in seen:
            seen.append(item)
    return seen


class ChatAttachmentService:
    """Stored chat attachments for one database session; callers own commits."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        storage: BlobStorage | None = None,
        identity: IdentityService | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._identity = identity or IdentityService(session, settings)
        self._storage = storage or LocalBlobStorage(settings.attachment_storage_path)

    @staticmethod
    def maximum_for(settings: Settings) -> int:
        """One chat attachment may never exceed the deployment document ceiling."""

        return min(settings.attachment_max_bytes, MAX_CHAT_ATTACHMENT_BYTES)

    @property
    def maximum_bytes(self) -> int:
        return self.maximum_for(self._settings)

    def _owned_session(self, principal: Principal, session_id: str) -> AgentSession:
        row = self._session.get(AgentSession, session_id)
        if row is None or row.owner_id != principal.actor_id:
            raise NotFound(
                "agent session not found",
                key="api.agent_integrations.record_not_found",
                params={"field": "agent session"},
            )
        return row

    def _row(self, principal: Principal, session_id: str, attachment_id: str) -> ChatAttachment:
        row = self._session.get(ChatAttachment, attachment_id)
        if row is None or row.session_id != session_id or row.owner_id != principal.actor_id:
            raise NotFound(
                "attachment not found",
                key="api.agent_integrations.record_not_found",
                params={"field": "attachment"},
            )
        return row

    @staticmethod
    def payload(row: ChatAttachment) -> dict[str, Any]:
        """Owner-visible metadata only: never bytes, digests or storage keys."""

        return {
            "id": row.id,
            "filename": row.filename,
            "mediaType": row.media_type,
            "kind": row.kind,
            "size": row.size,
        }

    def upload(
        self, principal: Principal, session_id: str, *, filename: str, data: bytes
    ) -> dict[str, Any]:
        self._owned_session(principal, session_id)
        media_type, kind = validate_chat_attachment(filename, data, self.maximum_bytes)
        stored = self._session.scalar(
            select(func.count(ChatAttachment.id)).where(ChatAttachment.session_id == session_id)
        )
        if int(stored or 0) >= MAX_SESSION_ATTACHMENTS:
            raise ValidationFailed(
                f"a conversation accepts at most {MAX_SESSION_ATTACHMENTS} attachments",
                key="api.agent_integrations.session_attachments_limit",
                params={"limit": MAX_SESSION_ATTACHMENTS},
            )
        row = ChatAttachment(
            id=str(uuid4()),
            session_id=session_id,
            owner_id=principal.actor_id,
            blob_key=uuid4().hex,
            filename=filename,
            media_type=media_type,
            kind=kind,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            created_at=utcnow().replace(tzinfo=None),
        )
        try:
            self._storage.put(row.blob_key, data)
        except OSError:
            raise StorageUnavailable() from None
        try:
            self._session.add(row)
            self._session.flush()
            self._identity.record_operation(
                principal,
                action="agent.chat_attachment_uploaded",
                resource=f"agent-session:{session_id}:attachment:{row.id}",
            )
        except Exception:
            self._session.rollback()
            self._storage.delete(row.blob_key)
            raise
        return self.payload(row)

    def delete(self, principal: Principal, session_id: str, attachment_id: str) -> None:
        self._owned_session(principal, session_id)
        row = self._row(principal, session_id, attachment_id)
        self._drop_row(principal, row)

    def delete_for_session(self, principal: Principal, session_id: str) -> int:
        """Remove every attachment of an owned session, bytes included."""

        self._owned_session(principal, session_id)
        rows = self._session.scalars(
            select(ChatAttachment).where(
                ChatAttachment.session_id == session_id,
                ChatAttachment.owner_id == principal.actor_id,
            )
        ).all()
        for row in rows:
            self._drop_row(principal, row)
        return len(rows)

    def _drop_row(self, principal: Principal, row: ChatAttachment) -> None:
        try:
            self._storage.delete(row.blob_key)
        except FileNotFoundError:
            pass
        except OSError:
            raise StorageUnavailable() from None
        self._session.delete(row)
        self._session.flush()
        self._identity.record_operation(
            principal,
            action="agent.chat_attachment_deleted",
            resource=f"agent-session:{row.session_id}:attachment:{row.id}",
        )

    def inputs(
        self, principal: Principal, session_id: str, attachment_ids: Iterable[str]
    ) -> list[ChatAttachmentInput]:
        """Resolve identifiers into validated bytes for this owned session only."""

        wanted = list(attachment_ids)
        if not wanted:
            return []
        rows = self._session.scalars(
            select(ChatAttachment)
            .where(
                ChatAttachment.id.in_(wanted),
                ChatAttachment.session_id == session_id,
                ChatAttachment.owner_id == principal.actor_id,
            )
            .order_by(ChatAttachment.created_at, ChatAttachment.id)
        ).all()
        if len(rows) != len(wanted):
            raise NotFound(
                "attachment not found",
                key="api.agent_integrations.record_not_found",
                params={"field": "attachment"},
            )
        return [self._read(row) for row in rows]

    def by_ids(
        self, principal: Principal, session_id: str, attachment_ids: Iterable[str]
    ) -> list[ChatAttachment]:
        """Owner-scoped rows, in the persisted order, without reading bytes."""

        wanted = list(attachment_ids)
        if not wanted:
            return []
        rows = self._session.scalars(
            select(ChatAttachment)
            .where(
                ChatAttachment.id.in_(wanted),
                ChatAttachment.session_id == session_id,
                ChatAttachment.owner_id == principal.actor_id,
            )
            .order_by(ChatAttachment.created_at, ChatAttachment.id)
        ).all()
        if len(rows) != len(wanted):
            raise NotFound(
                "attachment not found",
                key="api.agent_integrations.record_not_found",
                params={"field": "attachment"},
            )
        return list(rows)

    def _read(self, row: ChatAttachment) -> ChatAttachmentInput:
        try:
            data = self._storage.read(row.blob_key, self.maximum_bytes)
        except OSError:
            raise StorageUnavailable() from None
        if len(data) != row.size or hashlib.sha256(data).hexdigest() != row.sha256:
            raise StorageUnavailable()
        return ChatAttachmentInput(
            filename=row.filename,
            media_type=row.media_type,
            kind=row.kind,
            data=data,
            identifier=row.id,
        )


def check_message_bytes(items: Iterable[ChatAttachmentInput]) -> None:
    total = sum(len(item.data) for item in items)
    if total > MAX_CHAT_MESSAGE_BYTES:
        raise ValidationFailed(
            f"attachments must contain at most {MAX_CHAT_MESSAGE_BYTES} bytes per message",
            key="api.agent_integrations.message_bytes_limit",
            params={"limit": MAX_CHAT_MESSAGE_BYTES},
        )


__all__ = [
    "MAX_CHAT_ATTACHMENT_BYTES",
    "MAX_CHAT_MESSAGE_BYTES",
    "MAX_MESSAGE_ATTACHMENTS",
    "MAX_SESSION_ATTACHMENTS",
    "ChatAttachmentInput",
    "ChatAttachmentService",
    "bounded_attachment_ids",
    "check_message_bytes",
    "encoded_attachment_bytes",
    "encoded_size",
    "estimate_attachment_tokens",
]
