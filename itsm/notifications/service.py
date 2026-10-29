"""Notification rules, durable outbox, owned inbox and Apprise-backed delivery.

The service is synchronous SQLAlchemy, like the rest of the backend. Alert
ingestion calls :func:`record_alert_event`, which writes the event and its
outbox rows inside the caller's transaction and never commits it. The periodic
worker calls :func:`process_notifications`, which owns its session and commits.
Confirmation semantics are deliberately conservative:

* ``delivered``   - Apprise reported success or the internal inbox row exists;
* ``failed``      - a confirmed non-delivery, retried on the rule's interval;
* ``uncertain``   - a transport outcome we cannot prove either way; retained
  for operators and never resent automatically;
* ``exhausted``   - retries or configuration cannot make delivery succeed.

No credential, token-bearing URL or raw plugin exception is stored or returned.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.demo.state import is_demo
from itsm.identity.clock import as_utc, utcnow
from itsm.identity.models import Identity
from itsm.identity.permissions import HUMAN_ACTOR_KIND
from itsm.identity.policy import PolicyEngine
from itsm.identity.service import (
    Conflict,
    IdentityService,
    NotFound,
    Principal,
    ValidationFailed,
)
from itsm.logging import log_event
from itsm.monitoring.service import MonitoringService
from itsm.notifications.delivery import (
    CHANNEL_INTERNAL,
    CHANNEL_KINDS,
    SECRET_REFERENCE,
    deliver_external,
    safe_config,
    secret_value,
)
from itsm.notifications.models import (
    NotificationBase,
    NotificationChannel,
    NotificationEvent,
    NotificationInbox,
    NotificationOutbox,
    NotificationRule,
    NotificationRuntimeState,
)

logger = logging.getLogger("itsm.notifications")

DEFAULT_CHANNEL_ID = "internal-default"
DEFAULT_RULE_ID = "default-operations"
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
DELIVERY_BATCH = 200
ESCALATION_BATCH = 100
RETENTION_BATCH = 200
CLAIM_TIMEOUT_SECONDS = 300
MAX_RECIPIENTS = 100
MAX_CHANNELS_PER_RULE = 20
MAX_ATTEMPTS_LIMIT = 10
MAX_EVENT_BODY = 4000
MAX_EVENT_URL = 500
UNSET: Any = object()

SEVERITIES: tuple[str, ...] = ("info", "warning", "critical")
SEVERITY_RANK: dict[str, int] = {name: index for index, name in enumerate(SEVERITIES)}
ACK_EVENT_TYPES: frozenset[str] = frozenset({"acknowledged", "ack", "acknowledgement"})

STATUS_PENDING = "pending"
STATUS_CLAIMED = "claimed"
STATUS_DELIVERED = "delivered"
STATUS_FAILED = "failed"
STATUS_EXHAUSTED = "exhausted"
STATUS_UNCERTAIN = "uncertain"
STATUS_SUPPRESSED = "suppressed"
TERMINAL_STATUSES: frozenset[str] = frozenset(
    {STATUS_DELIVERED, STATUS_EXHAUSTED, STATUS_UNCERTAIN, STATUS_SUPPRESSED}
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_EVENT_KEY = re.compile(r"^[A-Za-z0-9_.:+-]{1,200}$")
_EVENT_TYPE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
_ENTITY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,35}$")
_TIMES = re.compile(r"^([01][0-9]|2[0-3]):([0-5][0-9])$")

_CHANNEL_KEYS = frozenset({"id", "kind", "name", "enabled", "secretRef", "config"})
_RULE_KEYS = frozenset(
    {
        "id",
        "name",
        "enabled",
        "minimumSeverity",
        "recipientIds",
        "channelIds",
        "escalationRecipientIds",
        "schedule",
        "acknowledgeAfterSeconds",
        "retryIntervalSeconds",
        "escalateAfterSeconds",
        "maxAttempts",
    }
)
_SCHEDULE_KEYS = frozenset({"timezone", "start", "end"})


def _text(value: Any, field: str, limit: int, *, required: bool = False) -> str:
    if not isinstance(value, str):
        raise ValidationFailed(f"{field} must be text")
    cleaned = value.strip()
    if required and not cleaned:
        raise ValidationFailed(f"{field} is required")
    if len(value) > limit:
        raise ValidationFailed(f"{field} is too long")
    return value if not required else cleaned


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationFailed(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ValidationFailed(f"{field} is out of range")
    return value


def _entity_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ENTITY_ID.fullmatch(value):
        raise ValidationFailed(f"{field} is invalid")
    return value


def _iso(value: datetime | None) -> str | None:
    return None if value is None else as_utc(value).isoformat()


def _timestamp(value: datetime | None) -> datetime:
    if value is None:
        return utcnow()
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _safe_url(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationFailed("url must be text")
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > MAX_EVENT_URL or any(character.isspace() for character in cleaned):
        raise ValidationFailed("url is invalid")
    if cleaned.startswith("/") and not cleaned.startswith("//"):
        return cleaned
    try:
        from urllib.parse import urlsplit

        parts = urlsplit(cleaned)
    except ValueError as exc:
        raise ValidationFailed("url is invalid") from exc
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
    ):
        raise ValidationFailed("url must be an http(s) URL or an absolute path")
    return cleaned


def _inbox_dto(item: NotificationInbox) -> dict[str, Any]:
    return {
        "id": item.id,
        "alertId": item.alert_id,
        "eventKey": item.event_key,
        "eventType": item.event_type,
        "severity": item.severity,
        "assetId": item.asset_id,
        "title": item.title,
        "body": item.body,
        "url": item.url,
        "createdAt": _iso(item.created_at),
        "readAt": _iso(item.read_at),
        "unread": item.read_at is None,
    }


def _channel_dto(channel: NotificationChannel, settings: Settings) -> dict[str, Any]:
    if channel.kind == CHANNEL_INTERNAL:
        configured = True
    else:
        configured = secret_value(settings, channel.secret_ref) is not None
    return {
        "id": channel.id,
        "kind": channel.kind,
        "name": channel.name,
        "enabled": bool(channel.enabled),
        "secretRef": channel.secret_ref,
        "configured": configured,
        "config": dict(channel.config or {}),
        "createdAt": _iso(channel.created_at),
        "updatedAt": _iso(channel.updated_at),
    }


def _rule_dto(rule: NotificationRule) -> dict[str, Any]:
    schedule = None
    if rule.schedule_timezone and rule.schedule_start and rule.schedule_end:
        schedule = {
            "timezone": rule.schedule_timezone,
            "start": rule.schedule_start,
            "end": rule.schedule_end,
        }
    return {
        "id": rule.id,
        "name": rule.name,
        "enabled": bool(rule.enabled),
        "minimumSeverity": rule.minimum_severity,
        "recipientIds": list(rule.recipient_ids or []),
        "channelIds": list(rule.channel_ids or []),
        "escalationRecipientIds": list(rule.escalation_recipient_ids or []),
        "schedule": schedule,
        "acknowledgeAfterSeconds": rule.acknowledge_after_seconds,
        "retryIntervalSeconds": rule.retry_interval_seconds,
        "escalateAfterSeconds": rule.escalate_after_seconds,
        "maxAttempts": rule.max_attempts,
        "builtIn": bool(rule.built_in),
        "createdAt": _iso(rule.created_at),
        "updatedAt": _iso(rule.updated_at),
    }


def _dedupe_key(
    event: NotificationEvent,
    rule_id: str | None,
    recipient_id: str | None,
    channel_id: str,
    bucket: int,
) -> str:
    """Stable outbox identity: alert/event/rule/recipient/channel/bucket."""
    raw = (
        f"{event.alert_id}:{event.id}:{rule_id or '-'}:{recipient_id or '-'}:{channel_id}:{bucket}"
    )
    if len(raw) <= 255:
        return raw
    # Rule/recipient ids are validated bounded values; the digest only guards
    # against future formats while keeping the unique key portable.
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"{event.alert_id[:64]}:{event.id}:{digest[:64]}:{bucket}"


def _window_start(rule: NotificationRule, moment: datetime) -> datetime:
    """Return ``moment`` when inside the rule window, else the next opening."""
    if not (rule.schedule_timezone and rule.schedule_start and rule.schedule_end):
        return moment
    try:
        zone = ZoneInfo(rule.schedule_timezone)
    except ZoneInfoNotFoundError, ValueError:
        return moment
    start_match = _TIMES.fullmatch(rule.schedule_start)
    end_match = _TIMES.fullmatch(rule.schedule_end)
    if start_match is None or end_match is None:
        return moment
    local = moment.astimezone(zone)
    start = int(start_match.group(1)) * 60 + int(start_match.group(2))
    end = int(end_match.group(1)) * 60 + int(end_match.group(2))
    minutes = local.hour * 60 + local.minute
    inside = start <= minutes < end if start < end else minutes >= start or minutes < end
    if inside:
        return moment
    next_local = local.replace(hour=start // 60, minute=start % 60, second=0, microsecond=0)
    if next_local <= local:
        next_local += timedelta(days=1)
    return next_local.astimezone(UTC)


class NotificationService:
    """Authorized notification configuration, inbox and delivery operations."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        identity: IdentityService | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._identity = identity or IdentityService(session, settings)
        self._monitoring = MonitoringService(session, settings, identity=self._identity)

    # ------------------------------------------------------------- defaults
    def _ensure_defaults(self) -> None:
        now = utcnow()
        if self._session.get(NotificationChannel, DEFAULT_CHANNEL_ID) is None:
            self._session.add(
                NotificationChannel(
                    id=DEFAULT_CHANNEL_ID,
                    kind=CHANNEL_INTERNAL,
                    name="Notificaciones internas",
                    enabled=True,
                    secret_ref=None,
                    config={},
                    created_at=now,
                    updated_at=now,
                )
            )
            self._session.flush()
        if self._session.get(NotificationRule, DEFAULT_RULE_ID) is None:
            self._session.add(
                NotificationRule(
                    id=DEFAULT_RULE_ID,
                    name="Operaciones",
                    enabled=True,
                    minimum_severity="info",
                    recipient_ids=[],
                    channel_ids=[DEFAULT_CHANNEL_ID],
                    escalation_recipient_ids=[],
                    schedule_timezone=None,
                    schedule_start=None,
                    schedule_end=None,
                    acknowledge_after_seconds=900,
                    retry_interval_seconds=60,
                    escalate_after_seconds=0,
                    max_attempts=3,
                    built_in=True,
                    created_at=now,
                    updated_at=now,
                )
            )
            self._session.flush()
        if self._session.get(NotificationRuntimeState, 1) is None:
            self._session.add(NotificationRuntimeState(id=1, last_run_at=None, updated_at=now))
            self._session.flush()

    def _lock_state(self, now: datetime) -> None:
        """Take the shared SQL write lock used by every notification worker."""
        result = self._session.execute(
            update(NotificationRuntimeState)
            .where(NotificationRuntimeState.id == 1)
            .values(updated_at=now)
        )
        if result.rowcount != 1:
            raise Conflict("notification schema is not ready; run migrations")

    # ----------------------------------------------------------- validation
    def _recipient_values(self, values: Iterable[Any], field: str) -> list[str]:
        if not isinstance(values, (list, tuple)):
            raise ValidationFailed(f"{field} must be a list")
        cleaned: list[str] = []
        for value in values:
            identity_id = _entity_id(value, field)
            if identity_id not in cleaned:
                cleaned.append(identity_id)
        if len(cleaned) > MAX_RECIPIENTS:
            raise ValidationFailed(f"{field} has too many identities")
        identities = {
            identity.id: identity
            for identity in self._session.execute(
                select(Identity).where(Identity.id.in_(cleaned))
            ).scalars()
        }
        policy = PolicyEngine.load(self._session)
        for identity_id in cleaned:
            identity = identities.get(identity_id)
            if identity is None:
                raise ValidationFailed("recipient is unknown")
            if identity.actor_kind != HUMAN_ACTOR_KIND:
                raise ValidationFailed("recipient must be a human identity")
            if not identity.active:
                raise ValidationFailed("recipient is not active")
            if "assets.view" not in policy.permissions(identity.role_id):
                raise ValidationFailed("recipient cannot view assets")
        return cleaned

    def _channel_values(self, values: Iterable[Any]) -> list[str]:
        if not isinstance(values, (list, tuple)):
            raise ValidationFailed("channelIds must be a list")
        cleaned: list[str] = []
        for value in values:
            channel_id = _entity_id(value, "channelId")
            if channel_id not in cleaned:
                cleaned.append(channel_id)
        if not cleaned:
            raise ValidationFailed("a rule needs at least one channel")
        if len(cleaned) > MAX_CHANNELS_PER_RULE:
            raise ValidationFailed("a rule has too many channels")
        for channel_id in cleaned:
            if self._session.get(NotificationChannel, channel_id) is None:
                raise ValidationFailed("channel is unknown")
        return cleaned

    def _schedule_values(self, value: Any) -> tuple[str | None, str | None, str | None]:
        if value is None:
            return None, None, None
        if not isinstance(value, Mapping):
            raise ValidationFailed("schedule must be an object or null")
        unknown = set(value) - _SCHEDULE_KEYS
        if unknown or set(value) != _SCHEDULE_KEYS:
            raise ValidationFailed("schedule must contain timezone, start and end")
        timezone = _text(value["timezone"], "schedule timezone", 64, required=True)
        start = _text(value["start"], "schedule start", 5, required=True)
        end = _text(value["end"], "schedule end", 5, required=True)
        if _TIMES.fullmatch(start) is None or _TIMES.fullmatch(end) is None:
            raise ValidationFailed("schedule times must use HH:MM")
        if start == end:
            raise ValidationFailed("schedule start and end must differ")
        try:
            ZoneInfo(timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValidationFailed("schedule timezone is unknown") from exc
        return timezone, start, end

    def _channel_row(
        self, values: Mapping[str, Any], existing: NotificationChannel | None
    ) -> NotificationChannel:
        unknown = set(values) - _CHANNEL_KEYS
        if unknown:
            raise ValidationFailed("channel contains unsupported fields")
        now = utcnow()
        kind = values.get("kind", existing.kind if existing else UNSET)
        if kind is UNSET:
            raise ValidationFailed("kind is required")
        if kind not in CHANNEL_KINDS:
            raise ValidationFailed("channel kind is invalid")
        name = values.get("name", existing.name if existing else UNSET)
        if name is UNSET:
            raise ValidationFailed("name is required")
        name = _text(name, "name", 120, required=True)
        enabled = values.get("enabled", existing.enabled if existing else True)
        if not isinstance(enabled, bool):
            raise ValidationFailed("enabled must be a boolean")
        supplied_ref = values.get("secretRef", existing.secret_ref if existing else None)
        if supplied_ref is not None and (
            not isinstance(supplied_ref, str) or not SECRET_REFERENCE.fullmatch(supplied_ref)
        ):
            raise ValidationFailed("secretRef is invalid")
        if kind == CHANNEL_INTERNAL:
            if supplied_ref is not None:
                raise ValidationFailed("internal channels do not use a secretRef")
        elif not supplied_ref:
            raise ValidationFailed("external channels need a secretRef")

        supplied_config = values.get("config", existing.config if existing else {})
        if not isinstance(supplied_config, Mapping):
            raise ValidationFailed("config must be an object")
        cleaned_config: dict[str, str] = {}
        for key, item in supplied_config.items():
            if not isinstance(key, str) or not isinstance(item, str):
                raise ValidationFailed("channel config values must be text")
            cleaned_config[key] = item
        try:
            cleaned_config = safe_config(kind, cleaned_config)
        except ValueError as exc:
            raise ValidationFailed(str(exc)) from exc

        if existing is None:
            channel_id = values.get("id")
            channel_id = str(uuid4()) if channel_id is None else _entity_id(channel_id, "id")
            if channel_id == DEFAULT_CHANNEL_ID:
                raise ValidationFailed("channel id is reserved")
            channel = NotificationChannel(
                id=channel_id,
                kind=kind,
                name=name,
                enabled=enabled,
                secret_ref=supplied_ref,
                config=cleaned_config,
                created_at=now,
                updated_at=now,
            )
            self._session.add(channel)
            return channel

        existing.kind = kind
        existing.name = name
        existing.enabled = enabled
        existing.secret_ref = supplied_ref
        existing.config = cleaned_config
        existing.updated_at = now
        return existing

    def _rule_row(
        self, values: Mapping[str, Any], existing: NotificationRule | None
    ) -> NotificationRule:
        unknown = set(values) - _RULE_KEYS
        if unknown:
            raise ValidationFailed("rule contains unsupported fields")
        now = utcnow()
        name = values.get("name", existing.name if existing else UNSET)
        if name is UNSET:
            raise ValidationFailed("name is required")
        name = _text(name, "name", 120, required=True)
        enabled = values.get("enabled", existing.enabled if existing else True)
        if not isinstance(enabled, bool):
            raise ValidationFailed("enabled must be a boolean")
        severity = values.get("minimumSeverity", existing.minimum_severity if existing else "info")
        if severity not in SEVERITIES:
            raise ValidationFailed("minimumSeverity is invalid")

        if "recipientIds" in values:
            recipients = self._recipient_values(values["recipientIds"], "recipientIds")
        else:
            recipients = list(existing.recipient_ids or []) if existing else []
        built_in = bool(existing.built_in) if existing else False
        if not recipients and not built_in:
            raise ValidationFailed("a rule needs at least one recipient")

        if "channelIds" in values:
            channels = self._channel_values(values["channelIds"])
        else:
            channels = list(existing.channel_ids or []) if existing else []
            if not channels:
                raise ValidationFailed("a rule needs at least one channel")

        if "escalationRecipientIds" in values:
            escalation = self._recipient_values(
                values["escalationRecipientIds"], "escalationRecipientIds"
            )
        else:
            escalation = list(existing.escalation_recipient_ids or []) if existing else []

        if "schedule" in values:
            schedule = self._schedule_values(values["schedule"])
        elif existing is not None:
            schedule = (
                existing.schedule_timezone,
                existing.schedule_start,
                existing.schedule_end,
            )
        else:
            schedule = (None, None, None)

        acknowledge = (
            _integer(values["acknowledgeAfterSeconds"], "acknowledgeAfterSeconds", 0, 604800)
            if "acknowledgeAfterSeconds" in values
            else (existing.acknowledge_after_seconds if existing else 900)
        )
        retry = (
            _integer(values["retryIntervalSeconds"], "retryIntervalSeconds", 0, 86400)
            if "retryIntervalSeconds" in values
            else (existing.retry_interval_seconds if existing else 60)
        )
        escalate = (
            _integer(values["escalateAfterSeconds"], "escalateAfterSeconds", 0, 604800)
            if "escalateAfterSeconds" in values
            else (existing.escalate_after_seconds if existing else 0)
        )
        attempts = (
            _integer(values["maxAttempts"], "maxAttempts", 1, MAX_ATTEMPTS_LIMIT)
            if "maxAttempts" in values
            else (existing.max_attempts if existing else 3)
        )
        if escalate > 0 and not escalation:
            raise ValidationFailed("escalation needs at least one recipient")

        if existing is None:
            rule_id = values.get("id")
            rule_id = str(uuid4()) if rule_id is None else _entity_id(rule_id, "id")
            if rule_id == DEFAULT_RULE_ID:
                raise ValidationFailed("rule id is reserved")
            rule = NotificationRule(
                id=rule_id,
                name=name,
                enabled=enabled,
                minimum_severity=severity,
                recipient_ids=recipients,
                channel_ids=channels,
                escalation_recipient_ids=escalation,
                schedule_timezone=schedule[0],
                schedule_start=schedule[1],
                schedule_end=schedule[2],
                acknowledge_after_seconds=acknowledge,
                retry_interval_seconds=retry,
                escalate_after_seconds=escalate,
                max_attempts=attempts,
                built_in=False,
                created_at=now,
                updated_at=now,
            )
            self._session.add(rule)
            return rule

        existing.name = name
        existing.enabled = enabled
        existing.minimum_severity = severity
        existing.recipient_ids = recipients
        existing.channel_ids = channels
        existing.escalation_recipient_ids = escalation
        existing.schedule_timezone = schedule[0]
        existing.schedule_start = schedule[1]
        existing.schedule_end = schedule[2]
        existing.acknowledge_after_seconds = acknowledge
        existing.retry_interval_seconds = retry
        existing.escalate_after_seconds = escalate
        existing.max_attempts = attempts
        existing.updated_at = now
        return existing

    # ------------------------------------------------------------ public API
    def list_inbox(
        self,
        principal: Principal,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
        unread: bool | None = None,
    ) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.view", resource="notifications.inbox")
        limit = _integer(limit, "limit", 1, MAX_LIMIT)
        offset = _integer(offset, "offset", 0, 1_000_000)
        if unread is not None and not isinstance(unread, bool):
            raise ValidationFailed("unread must be a boolean")
        conditions = [NotificationInbox.recipient_id == principal.actor_id]
        # Legacy notices have no extra grant. Native extension notices retain
        # their required permission so revoked access cannot leak old content.
        grants = self._identity._persisted_permissions(principal)
        conditions.append(
            or_(
                NotificationInbox.required_permission.is_(None),
                NotificationInbox.required_permission.in_(grants),
            )
        )
        if unread is True:
            conditions.append(NotificationInbox.read_at.is_(None))
        elif unread is False:
            conditions.append(NotificationInbox.read_at.is_not(None))
        total = int(
            self._session.execute(
                select(func.count(NotificationInbox.id)).where(*conditions)
            ).scalar_one()
        )
        rows = (
            self._session.execute(
                select(NotificationInbox)
                .where(*conditions)
                .order_by(NotificationInbox.created_at.desc(), NotificationInbox.id.desc())
                .limit(limit)
                .offset(offset)
            )
            .scalars()
            .all()
        )
        return {
            "items": [_inbox_dto(item) for item in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def mark_read(self, principal: Principal, notification_id: str) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.view", resource="notifications.inbox")
        notification_id = _entity_id(notification_id, "notificationId")
        item = self._session.get(NotificationInbox, notification_id)
        if item is None or item.recipient_id != principal.actor_id:
            raise NotFound("notification not found")
        if (
            item.required_permission is not None
            and item.required_permission not in self._identity._persisted_permissions(principal)
        ):
            raise NotFound("notification not found")
        if item.read_at is None:
            item.read_at = utcnow()
            self._session.commit()
        return _inbox_dto(item)

    def get_config(self, principal: Principal) -> dict[str, Any]:
        self._identity.authorize(principal, "config.integrations", resource="notifications.config")
        self._ensure_defaults()
        channels = (
            self._session.execute(
                select(NotificationChannel).order_by(NotificationChannel.created_at)
            )
            .scalars()
            .all()
        )
        rules = (
            self._session.execute(select(NotificationRule).order_by(NotificationRule.created_at))
            .scalars()
            .all()
        )
        return {
            "channels": [_channel_dto(channel, self._settings) for channel in channels],
            "rules": [_rule_dto(rule) for rule in rules],
            "retentionDays": self._settings.notification_retention_days,
            "defaults": {
                "internalChannelId": DEFAULT_CHANNEL_ID,
                "defaultRuleId": DEFAULT_RULE_ID,
            },
        }

    def save_channel(self, principal: Principal, values: Mapping[str, Any]) -> dict[str, Any]:
        self._identity.authorize(principal, "config.integrations", resource="notifications.config")
        if not isinstance(values, Mapping) or not values:
            raise ValidationFailed("channel values are required")
        self._ensure_defaults()
        self._lock_state(utcnow())
        channel_id = values.get("id")
        existing = (
            None
            if channel_id is None
            else self._session.get(NotificationChannel, _entity_id(channel_id, "id"))
        )
        if channel_id is not None and existing is None:
            raise NotFound("channel not found")
        channel = self._channel_row(values, existing)
        self._session.flush()
        self._identity.record_operation(
            principal,
            action="notifications.channel.save",
            resource=f"notification-channel:{channel.id}",
        )
        return _channel_dto(channel, self._settings)

    def save_rule(self, principal: Principal, values: Mapping[str, Any]) -> dict[str, Any]:
        self._identity.authorize(principal, "config.integrations", resource="notifications.config")
        if not isinstance(values, Mapping) or not values:
            raise ValidationFailed("rule values are required")
        self._ensure_defaults()
        self._lock_state(utcnow())
        rule_id = values.get("id")
        existing = (
            None
            if rule_id is None
            else self._session.get(NotificationRule, _entity_id(rule_id, "id"))
        )
        if rule_id is not None and existing is None:
            raise NotFound("rule not found")
        rule = self._rule_row(values, existing)
        self._session.flush()
        self._identity.record_operation(
            principal,
            action="notifications.rule.save",
            resource=f"notification-rule:{rule.id}",
        )
        return _rule_dto(rule)

    def test_channel(self, principal: Principal, channel_id: str) -> dict[str, Any]:
        self._identity.authorize(principal, "config.integrations", resource="notifications.config")
        self._ensure_defaults()
        self._lock_state(utcnow())
        channel_id = _entity_id(channel_id, "channelId")
        channel = self._session.get(NotificationChannel, channel_id)
        if channel is None:
            raise NotFound("channel not found")
        if not channel.enabled:
            raise ValidationFailed("channel is disabled")
        now = utcnow()
        event = NotificationEvent(
            id=str(uuid4()),
            alert_id=f"test:{channel.id}"[:64],
            event_key=f"test:{uuid4()}",
            event_type="test",
            severity="info",
            asset_id=None,
            title="Prueba de notificación",
            body=_text(channel.name, "channel name", 120, required=True),
            url=None,
            occurred_at=now,
            acknowledged=False,
            recovered=False,
            created_at=now,
        )
        self._session.add(event)
        self._session.flush()
        row = NotificationOutbox(
            id=str(uuid4()),
            dedupe_key=_dedupe_key(event, None, principal.actor_id, channel.id, 0),
            event_id=event.id,
            alert_id=event.alert_id,
            rule_id=None,
            recipient_id=principal.actor_id if channel.kind == CHANNEL_INTERNAL else None,
            channel_id=channel.id,
            escalation_bucket=0,
            status=STATUS_PENDING,
            attempts=0,
            max_attempts=1,
            retry_interval_seconds=0,
            severity=event.severity,
            asset_id=None,
            title=event.title,
            body=event.body,
            url=None,
            next_attempt_at=now,
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)
        self._session.flush()
        self._identity.record_operation(
            principal,
            action="notifications.channel.test",
            resource=f"notification-channel:{channel.id}",
        )
        return {"channelId": channel.id, "outboxId": row.id, "state": STATUS_PENDING}

    # ------------------------------------------------------------- ingestion
    def record_alert(
        self,
        *,
        alert_id: str,
        event_key: str,
        event_type: str,
        severity: str,
        asset_id: str | None,
        title: str,
        body: str,
        url: str | None,
        acknowledged: bool = False,
        recovered: bool = False,
        occurred_at: datetime | None = None,
    ) -> dict[str, int | bool]:
        if not isinstance(alert_id, str) or not _IDENTIFIER.fullmatch(alert_id):
            raise ValidationFailed("alert_id is invalid")
        if not isinstance(event_key, str) or not _EVENT_KEY.fullmatch(event_key):
            raise ValidationFailed("event_key is invalid")
        if not isinstance(event_type, str) or not _EVENT_TYPE.fullmatch(event_type):
            raise ValidationFailed("event_type is invalid")
        if severity not in SEVERITIES:
            raise ValidationFailed("severity is invalid")
        if asset_id is not None:
            asset_id = _text(asset_id, "asset_id", 36, required=True)
        title = _text(title, "title", 200, required=True)
        body = _text(body, "body", MAX_EVENT_BODY)
        url = _safe_url(url)
        if not isinstance(acknowledged, bool) or not isinstance(recovered, bool):
            raise ValidationFailed("acknowledged and recovered must be booleans")
        occurred = _timestamp(occurred_at)

        self._ensure_defaults()
        # pysqlite opens its transaction lazily. Force a real UPDATE before
        # any SAVEPOINT; otherwise RELEASE of an outermost savepoint would
        # commit the caller's transaction, breaking the flush-only contract.
        self._lock_state(utcnow())
        existing = self._session.execute(
            select(NotificationEvent).where(
                NotificationEvent.alert_id == alert_id,
                NotificationEvent.event_key == event_key,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return {"created": False, "queued": 0, "suppressed": 0}

        event = NotificationEvent(
            id=str(uuid4()),
            alert_id=alert_id,
            event_key=event_key,
            event_type=event_type,
            severity=severity,
            asset_id=asset_id,
            title=title,
            body=body,
            url=url,
            occurred_at=occurred,
            acknowledged=acknowledged,
            recovered=recovered,
            created_at=utcnow(),
        )
        try:
            with self._session.begin_nested():
                self._session.add(event)
                self._session.flush()
        except IntegrityError:
            return {"created": False, "queued": 0, "suppressed": 0}

        is_ack = acknowledged or event_type in ACK_EVENT_TYPES
        if recovered:
            self._mark_recovered(alert_id, occurred)
        if is_ack:
            self._mark_acknowledged(alert_id, occurred)
            suppressed = self._suppress_pending(alert_id, "alert_acknowledged")
            return {"created": True, "queued": 0, "suppressed": suppressed}
        suppressed = self._suppress_pending(alert_id, "alert_recovered") if recovered else 0
        queued = (
            0
            if self._monitoring.notification_suppressed(alert_id, now=occurred)
            else self._enqueue_rules(event)
        )
        self._session.flush()
        return {"created": True, "queued": queued, "suppressed": suppressed}

    def _mark_acknowledged(self, alert_id: str, occurred: datetime) -> None:
        # alert_id is stable for one monitoring cycle, so every event already
        # recorded for it belongs to the cycle being acknowledged. No time
        # cutoff: a stale firing row must not keep escalating.
        del occurred
        self._session.execute(
            update(NotificationEvent)
            .where(NotificationEvent.alert_id == alert_id)
            .values(acknowledged=True)
            .execution_options(synchronize_session=False)
        )
        self._session.flush()

    def _mark_recovered(self, alert_id: str, occurred: datetime) -> None:
        del occurred
        self._session.execute(
            update(NotificationEvent)
            .where(NotificationEvent.alert_id == alert_id)
            .values(recovered=True)
            .execution_options(synchronize_session=False)
        )
        self._session.flush()

    def _suppress_pending(self, alert_id: str, reason: str) -> int:
        result = self._session.execute(
            update(NotificationOutbox)
            .where(
                NotificationOutbox.alert_id == alert_id,
                NotificationOutbox.status.in_((STATUS_PENDING, STATUS_FAILED)),
            )
            .values(status=STATUS_SUPPRESSED, last_error=reason, updated_at=utcnow())
            .execution_options(synchronize_session=False)
        )
        self._session.flush()
        return int(result.rowcount or 0)

    def _resolve_recipients(self, rule: NotificationRule) -> list[str]:
        policy = PolicyEngine.load(self._session)

        def allowed(identity: Identity) -> bool:
            return (
                identity.active
                and identity.actor_kind == HUMAN_ACTOR_KIND
                and "assets.view" in policy.permissions(identity.role_id)
            )

        stored = list(rule.recipient_ids or [])
        if not stored and rule.built_in:
            identities = self._session.execute(
                select(Identity)
                .where(
                    Identity.active.is_(True),
                    Identity.actor_kind == HUMAN_ACTOR_KIND,
                )
                .order_by(Identity.username)
            ).scalars()
            return [identity.id for identity in identities if allowed(identity)]
        if not stored:
            return []
        identities = {
            identity.id: identity
            for identity in self._session.execute(
                select(Identity).where(Identity.id.in_(stored))
            ).scalars()
        }
        return [
            identity_id
            for identity_id in stored
            if (identity := identities.get(identity_id)) is not None and allowed(identity)
        ]

    def _enqueue_rules(self, event: NotificationEvent) -> int:
        rules = (
            self._session.execute(
                select(NotificationRule)
                .where(NotificationRule.enabled.is_(True))
                .order_by(NotificationRule.created_at)
            )
            .scalars()
            .all()
        )
        queued = 0
        now = utcnow()
        for rule in rules:
            if SEVERITY_RANK[event.severity] < SEVERITY_RANK[rule.minimum_severity]:
                continue
            recipient_ids = self._resolve_recipients(rule)
            channel_ids = list(rule.channel_ids or [])
            if not channel_ids:
                continue
            channels = {
                channel.id: channel
                for channel in self._session.execute(
                    select(NotificationChannel).where(NotificationChannel.id.in_(channel_ids))
                ).scalars()
            }
            deliver_at = _window_start(rule, now)
            for channel_id in channel_ids:
                channel = channels.get(channel_id)
                if channel is None or not channel.enabled:
                    continue
                targets = recipient_ids if channel.kind == CHANNEL_INTERNAL else [None]
                if channel.kind == CHANNEL_INTERNAL and not targets:
                    continue
                for recipient_id in targets:
                    if self._queue_row(
                        event,
                        rule,
                        channel,
                        recipient_id=recipient_id,
                        bucket=0,
                        deliver_at=deliver_at,
                        now=now,
                    ):
                        queued += 1
        return queued

    def _queue_row(
        self,
        event: NotificationEvent,
        rule: NotificationRule | None,
        channel: NotificationChannel,
        *,
        recipient_id: str | None,
        bucket: int,
        deliver_at: datetime,
        now: datetime,
    ) -> bool:
        rule_id = None if rule is None else rule.id
        row = NotificationOutbox(
            id=str(uuid4()),
            dedupe_key=_dedupe_key(event, rule_id, recipient_id, channel.id, bucket),
            event_id=event.id,
            alert_id=event.alert_id,
            rule_id=rule_id,
            recipient_id=recipient_id,
            channel_id=channel.id,
            escalation_bucket=bucket,
            status=STATUS_PENDING,
            attempts=0,
            max_attempts=rule.max_attempts if rule is not None else 1,
            retry_interval_seconds=rule.retry_interval_seconds if rule is not None else 0,
            severity=event.severity,
            asset_id=event.asset_id,
            title=event.title,
            body=event.body,
            url=event.url,
            next_attempt_at=deliver_at,
            created_at=now,
            updated_at=now,
        )
        try:
            with self._session.begin_nested():
                self._session.add(row)
                self._session.flush()
        except IntegrityError:
            return False
        if channel.kind == CHANNEL_INTERNAL and deliver_at <= now and recipient_id:
            self._deliver_internal(row, recipient_id, now)
        return True

    def _deliver_internal(self, row: NotificationOutbox, recipient_id: str, now: datetime) -> None:
        existing = self._session.execute(
            select(NotificationInbox).where(NotificationInbox.outbox_id == row.id)
        ).scalar_one_or_none()
        if existing is None:
            inbox = NotificationInbox(
                id=str(uuid4()),
                outbox_id=row.id,
                recipient_id=recipient_id,
                alert_id=row.alert_id,
                event_key=self._event_key(row.event_id),
                event_type=self._event_type(row.event_id),
                severity=row.severity,
                asset_id=row.asset_id,
                title=row.title,
                body=row.body,
                url=row.url,
                created_at=now,
                read_at=None,
            )
            try:
                with self._session.begin_nested():
                    self._session.add(inbox)
                    self._session.flush()
            except IntegrityError:
                pass
        row.status = STATUS_DELIVERED
        row.delivered_at = now
        row.last_error = None
        row.updated_at = now
        self._session.flush()

    def _event_key(self, event_id: str) -> str:
        event = self._session.get(NotificationEvent, event_id)
        return event.event_key if event is not None else ""

    def _event_type(self, event_id: str) -> str:
        event = self._session.get(NotificationEvent, event_id)
        return event.event_type if event is not None else ""

    # -------------------------------------------------------------- delivery
    def _process(self, as_of: datetime | None) -> dict[str, int]:
        now = _timestamp(as_of)
        self._ensure_defaults()
        self._lock_state(now)
        counts = {
            "delivered": 0,
            "failed": 0,
            "exhausted": 0,
            "uncertain": 0,
            "escalated": 0,
            "suppressed": 0,
            "pruned": 0,
        }
        self._recover_stale(now)
        self._session.commit()

        due = (
            self._session.execute(
                select(NotificationOutbox)
                .where(
                    NotificationOutbox.status.in_((STATUS_PENDING, STATUS_FAILED)),
                    NotificationOutbox.next_attempt_at <= now,
                )
                .order_by(NotificationOutbox.next_attempt_at, NotificationOutbox.id)
                .limit(DELIVERY_BATCH)
            )
            .scalars()
            .all()
        )
        for row in due:
            self._lock_state(now)
            event = self._session.get(NotificationEvent, row.event_id, populate_existing=True)
            if event is not None and (
                event.acknowledged or (event.recovered and event.event_type != "recovered")
            ):
                reason = "alert_acknowledged" if event.acknowledged else "alert_recovered"
                self._finish(row, STATUS_SUPPRESSED, now, reason)
                counts["suppressed"] += 1
                self._session.commit()
                continue
            if self._monitoring.notification_suppressed(row.alert_id, now=now):
                self._session.commit()
                continue
            claimed = self._session.execute(
                update(NotificationOutbox)
                .where(
                    NotificationOutbox.id == row.id,
                    NotificationOutbox.status.in_((STATUS_PENDING, STATUS_FAILED)),
                    NotificationOutbox.next_attempt_at <= now,
                )
                .values(
                    status=STATUS_CLAIMED,
                    claimed_at=now,
                    claim_token=str(uuid4()),
                    updated_at=now,
                )
                .execution_options(synchronize_session=False)
            )
            if claimed.rowcount != 1:
                self._session.rollback()
                continue
            # Claim before any transport attempt: a crashed worker leaves an
            # uncertain row behind instead of a silently duplicated send.
            self._session.commit()
            self._session.refresh(row)
            channel = self._session.get(NotificationChannel, row.channel_id)
            if channel is None or not channel.enabled:
                self._finish(row, STATUS_EXHAUSTED, now, "channel_unavailable")
                counts["exhausted"] += 1
                self._session.commit()
                continue
            if channel.kind == CHANNEL_INTERNAL:
                if not row.recipient_id:
                    self._finish(row, STATUS_EXHAUSTED, now, "recipient_missing")
                    counts["exhausted"] += 1
                else:
                    self._deliver_internal(row, row.recipient_id, now)
                    counts["delivered"] += 1
                self._session.commit()
                continue

            if is_demo(self._session):
                self._finish(row, STATUS_SUPPRESSED, now, "demo_external_delivery_blocked")
                counts["suppressed"] += 1
                self._session.commit()
                continue

            outcome = deliver_external(
                channel.id,
                channel.kind,
                channel.secret_ref,
                dict(channel.config or {}),
                title=row.title,
                body=row.body,
                url=row.url,
                timeout_seconds=self._settings.monitoring_http_timeout_seconds,
                settings=self._settings,
            )
            if outcome.state == "delivered":
                self._finish(row, STATUS_DELIVERED, now, None)
                row.delivered_at = now
                counts["delivered"] += 1
            elif outcome.state == "uncertain":
                self._finish(row, STATUS_UNCERTAIN, now, outcome.error or "transport_uncertain")
                counts["uncertain"] += 1
            elif outcome.state == "unconfigured":
                self._finish(row, STATUS_EXHAUSTED, now, outcome.error or "channel_unconfigured")
                counts["exhausted"] += 1
            else:
                row.attempts = int(row.attempts) + 1
                row.last_error = outcome.error or "transport_failure"
                row.claimed_at = None
                row.claim_token = None
                row.updated_at = now
                if row.attempts >= row.max_attempts:
                    row.status = STATUS_EXHAUSTED
                    counts["exhausted"] += 1
                else:
                    row.status = STATUS_FAILED
                    row.next_attempt_at = now + timedelta(
                        seconds=max(0, row.retry_interval_seconds)
                    )
                    counts["failed"] += 1
            self._session.commit()

        counts["escalated"] = self._escalate(now)
        self._session.commit()
        counts["pruned"] = self._prune(now)
        self._session.execute(
            update(NotificationRuntimeState)
            .where(NotificationRuntimeState.id == 1)
            .values(last_run_at=now, updated_at=utcnow())
        )
        self._session.commit()
        log_event(logger, "notification.processed", **counts)
        return counts

    def _finish(
        self, row: NotificationOutbox, status: str, now: datetime, error: str | None
    ) -> None:
        row.status = status
        row.last_error = error
        row.claimed_at = None
        row.claim_token = None
        row.updated_at = now
        self._session.flush()

    def _recover_stale(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=CLAIM_TIMEOUT_SECONDS)
        self._session.execute(
            update(NotificationOutbox)
            .where(
                NotificationOutbox.status == STATUS_CLAIMED,
                or_(
                    NotificationOutbox.claimed_at.is_(None),
                    NotificationOutbox.claimed_at < cutoff,
                ),
            )
            .values(
                status=STATUS_UNCERTAIN,
                last_error="worker_lost",
                claim_token=None,
                updated_at=now,
            )
            .execution_options(synchronize_session=False)
        )
        self._session.flush()

    def _escalate(self, now: datetime) -> int:
        rules = (
            self._session.execute(
                select(NotificationRule).where(
                    NotificationRule.enabled.is_(True),
                    NotificationRule.escalate_after_seconds > 0,
                )
            )
            .scalars()
            .all()
        )
        created = 0
        for rule in rules:
            escalation_ids = list(rule.escalation_recipient_ids or [])
            if not escalation_ids:
                continue
            threshold = now - timedelta(
                seconds=rule.acknowledge_after_seconds + rule.escalate_after_seconds
            )
            bucket_zero = select(NotificationOutbox.event_id).where(
                NotificationOutbox.rule_id == rule.id,
                NotificationOutbox.escalation_bucket == 0,
            )
            bucket_one = select(NotificationOutbox.event_id).where(
                NotificationOutbox.rule_id == rule.id,
                NotificationOutbox.escalation_bucket == 1,
            )
            events = (
                self._session.execute(
                    select(NotificationEvent)
                    .where(
                        NotificationEvent.acknowledged.is_(False),
                        NotificationEvent.recovered.is_(False),
                        NotificationEvent.occurred_at <= threshold,
                        NotificationEvent.id.in_(bucket_zero),
                        NotificationEvent.id.not_in(bucket_one),
                    )
                    .order_by(NotificationEvent.occurred_at)
                    .limit(ESCALATION_BATCH)
                )
                .scalars()
                .all()
            )
            channels = {
                channel.id: channel
                for channel in self._session.execute(
                    select(NotificationChannel).where(
                        NotificationChannel.id.in_(list(rule.channel_ids or []))
                    )
                ).scalars()
            }
            policy = PolicyEngine.load(self._session)
            recipients = [
                identity.id
                for identity in self._session.execute(
                    select(Identity).where(Identity.id.in_(escalation_ids))
                ).scalars()
                if identity.active
                and identity.actor_kind == HUMAN_ACTOR_KIND
                and "assets.view" in policy.permissions(identity.role_id)
            ]
            if not recipients:
                continue
            deliver_at = _window_start(rule, now)
            for event in events:
                if self._monitoring.notification_suppressed(event.alert_id, now=now):
                    continue
                for channel_id in list(rule.channel_ids or []):
                    channel = channels.get(channel_id)
                    if channel is None or not channel.enabled:
                        continue
                    targets = recipients if channel.kind == CHANNEL_INTERNAL else [None]
                    for recipient_id in targets:
                        if self._queue_row(
                            event,
                            rule,
                            channel,
                            recipient_id=recipient_id,
                            bucket=1,
                            deliver_at=deliver_at,
                            now=now,
                        ):
                            created += 1
            self._session.flush()
        if created:
            log_event(logger, "notification.escalated", count=created)
        return created

    def _prune(self, now: datetime) -> int:
        days = self._settings.notification_retention_days
        cutoff = now - timedelta(days=days)
        pruned = 0
        # Stale in-flight work never becomes a delivery guarantee; retire it
        # instead of deleting an unresolved row silently.
        retired = self._session.execute(
            update(NotificationOutbox)
            .where(
                NotificationOutbox.status.in_((STATUS_PENDING, STATUS_FAILED)),
                NotificationOutbox.created_at < cutoff,
            )
            .values(
                status=STATUS_EXHAUSTED,
                last_error="retention_expired",
                updated_at=now,
            )
            .execution_options(synchronize_session=False)
        )
        if retired.rowcount:
            pruned += int(retired.rowcount)

        terminal_ids = list(
            self._session.execute(
                select(NotificationOutbox.id)
                .where(
                    NotificationOutbox.status.in_(TERMINAL_STATUSES),
                    NotificationOutbox.created_at < cutoff,
                )
                .limit(RETENTION_BATCH)
            ).scalars()
        )
        if terminal_ids:
            inbox_ids = list(
                self._session.execute(
                    select(NotificationInbox.id).where(
                        or_(
                            NotificationInbox.outbox_id.in_(terminal_ids),
                            NotificationInbox.created_at < cutoff,
                        )
                    )
                ).scalars()
            )
            if inbox_ids:
                result = self._session.execute(
                    delete(NotificationInbox).where(NotificationInbox.id.in_(inbox_ids))
                )
                pruned += int(result.rowcount or 0)
            result = self._session.execute(
                delete(NotificationOutbox).where(NotificationOutbox.id.in_(terminal_ids))
            )
            pruned += int(result.rowcount or 0)

        event_ids = list(
            self._session.execute(
                select(NotificationEvent.id)
                .where(
                    NotificationEvent.occurred_at < cutoff,
                    ~select(NotificationOutbox.id)
                    .where(NotificationOutbox.event_id == NotificationEvent.id)
                    .exists(),
                )
                .limit(RETENTION_BATCH)
            ).scalars()
        )
        if event_ids:
            result = self._session.execute(
                delete(NotificationEvent).where(NotificationEvent.id.in_(event_ids))
            )
            pruned += int(result.rowcount or 0)
        self._session.flush()
        return pruned


def record_alert_event(
    session: Session,
    settings: Settings,
    *,
    alert_id: str,
    event_key: str,
    event_type: str,
    severity: str,
    asset_id: str | None,
    title: str,
    body: str,
    url: str | None,
    acknowledged: bool = False,
    recovered: bool = False,
    occurred_at: datetime | None = None,
) -> dict[str, int | bool]:
    """Queue notifications inside the caller's transaction; never commits.

    A repeated ``(alert_id, event_key)`` is a no-op. Acknowledgement suppresses
    pending delivery and escalation; recovery additionally emits a recovery
    notification after suppressing the firing cycle's pending rows.
    """
    return NotificationService(session, settings).record_alert(
        alert_id=alert_id,
        event_key=event_key,
        event_type=event_type,
        severity=severity,
        asset_id=asset_id,
        title=title,
        body=body,
        url=url,
        acknowledged=acknowledged,
        recovered=recovered,
        occurred_at=occurred_at,
    )


def process_notifications(settings: Settings, as_of: datetime | None = None) -> dict[str, int]:
    """Drain the SQL outbox, escalate overdue alerts and prune old records."""
    engine = create_engine_from_settings(settings)
    factory = create_session_factory(engine)
    session = factory()
    try:
        service = NotificationService(session, settings)
        return service._process(as_of)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        engine.dispose()


__all__ = [
    "NotificationBase",
    "NotificationService",
    "process_notifications",
    "record_alert_event",
]
