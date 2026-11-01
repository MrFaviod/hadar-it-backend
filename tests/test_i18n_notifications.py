"""Notifications in the recipient's language: inbox, outbox, Apprise and legacy rows.

An alert stores a stable key plus its parameters once, then every recipient sees
it in their own effective locale while free text stays exactly as it was stored.
"""

from __future__ import annotations

import email
from datetime import timedelta
from typing import Any

import pytest
from itsm.database import create_engine_from_settings
from itsm.i18n import t
from itsm.identity.clock import utcnow
from itsm.identity.service import IdentityService, ValidationFailed
from itsm.monitoring.service import MonitoringService
from itsm.notifications.models import NotificationEvent, NotificationOutbox
from itsm.notifications.service import (
    DEFAULT_CHANNEL_ID,
    DEFAULT_RULE_ID,
    NotificationService,
    process_notifications,
    record_alert_event,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from tests.conftest import run_migrations
from tests.inventory_support import Catalog
from tests.test_phase8_monitoring import Clock, FakeAdapter, MonitoringHarness, am_payload
from tests.test_phase8_notifications import (
    SMTP_SECRET,
    UTC_NOW,
    Harness,
    _record,
    _seed_users,
    _smtp_server,
    _smtp_url,
)

MESSAGE = {
    "title": {
        "key": "api.monitoring.alert.title",
        "params": {"alert": "UPS battery", "asset": "Rack A"},
    },
    "body": {"key": "api.monitoring.alert.severity", "params": {"severity": "critical"}},
}


@pytest.fixture
def harness(settings_factory: Any) -> Any:
    """Isolated database migrated through the real Alembic chain, as phase 8 does."""
    created: list[Harness] = []

    def make(**overrides: Any) -> Harness:
        settings = settings_factory(**overrides)
        applied = run_migrations(settings)
        assert applied.returncode == 0, applied.stdout + applied.stderr
        engine = create_engine_from_settings(settings)
        _seed_users(engine, settings)
        item = Harness(settings=settings, engine=engine)
        created.append(item)
        return item

    yield make
    for item in created:
        item.close()


@pytest.fixture
def freeze(monkeypatch: pytest.MonkeyPatch) -> Any:
    def apply(moment: Any = UTC_NOW) -> Any:
        monkeypatch.setattr("itsm.notifications.service.utcnow", lambda: moment)
        return moment

    return apply


def _record_bilingual_alert(h: Any, session: Session, **overrides: Any) -> dict[str, Any]:
    payload = {
        "alert_id": "alert-i18n",
        "event_key": "alert-i18n:2026-01-15T12:00:00+00:00:firing",
        "event_type": "firing",
        "severity": "critical",
        "asset_id": None,
        "title": "UPS sin batería",
        "body": "La UPS principal no responde.",
        "message": MESSAGE,
        "url": "http://localhost:18080/#/monitoring/alerts/alert-i18n",
        "occurred_at": UTC_NOW,
    }
    payload.update(overrides)
    return record_alert_event(session, h.settings, **payload)


def _prepare(h: Any, session: Session) -> Any:
    """Disable the built-in rule and return access to the notification services."""
    admin = h.admin(session)
    notifications = NotificationService(session, h.settings)
    notifications.get_config(admin)
    notifications.save_rule(admin, {"id": DEFAULT_RULE_ID, "enabled": False})
    return admin, notifications


def _email_text(raw: bytes) -> str:
    parsed = email.message_from_bytes(raw)
    chunks: list[str] = []
    for part in parsed.walk():
        if part.get_content_maintype() != "text":
            continue
        payload = part.get_payload(decode=True) or b""
        chunks.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
    return "\n".join(chunks)


def test_two_recipients_receive_the_same_alert_in_their_own_language(
    harness: Any, freeze: Any
) -> None:
    freeze(UTC_NOW)
    smtp = _smtp_server()
    try:
        h = harness(monitoring_secrets={SMTP_SECRET: _smtp_url(smtp.server_address[1])})
        with h.session() as session:
            admin, notifications = _prepare(h, session)
            operator = h.principal(session, "operator")
            IdentityService(session, h.settings).update_preferences(operator, locale="en")
            channel = notifications.save_channel(
                admin, {"kind": "smtp", "name": "Ops SMTP", "secretRef": SMTP_SECRET}
            )
            notifications.save_rule(
                admin,
                {
                    "name": "Bilingual operations",
                    "recipientIds": [admin.actor_id, operator.actor_id],
                    "channelIds": [DEFAULT_CHANNEL_ID, channel["id"]],
                },
            )
            result = _record_bilingual_alert(h, session)
            session.commit()
            assert result["created"] is True
            assert result["queued"] == 4  # two recipients on two channels

            admin_inbox = notifications.list_inbox(admin)["items"]
            operator_inbox = notifications.list_inbox(operator)["items"]
            assert [item["title"] for item in admin_inbox] == ["UPS battery — Rack A"]
            assert admin_inbox[0]["body"] == "Severidad critical"
            assert [item["title"] for item in operator_inbox] == ["UPS battery — Rack A"]
            assert operator_inbox[0]["body"] == "Severity critical"

        processed = process_notifications(h.settings, as_of=UTC_NOW + timedelta(seconds=5))
        assert processed["delivered"] == 2
        texts = [_email_text(raw) for raw in smtp.messages]
        assert len(texts) == 2
        assert sorted("Severidad critical" in text for text in texts) == [False, True]
        assert sorted("Severity critical" in text for text in texts) == [False, True]

        with Session(h.engine) as observer:
            rows = {
                row.recipient_id: row
                for row in observer.execute(select(NotificationOutbox)).scalars()
            }
            assert set(rows) == {admin.actor_id, operator.actor_id}
            assert rows[admin.actor_id].body == "Severidad critical"
            assert rows[operator.actor_id].body == "Severity critical"
    finally:
        smtp.shutdown()
        smtp.server_close()


def test_monitoring_alerts_store_catalog_keys_and_render_per_locale(
    harness: Any, freeze: Any
) -> None:
    moment = freeze(UTC_NOW)
    h = harness()
    monitoring = MonitoringHarness(
        catalog=Catalog(h.settings, h.engine), clock=Clock(moment), adapter=FakeAdapter()
    )
    asset = monitoring.add_asset("Maintenance server")
    with h.session() as session:
        admin, notifications = _prepare(h, session)
        operator = h.principal(session, "operator")
        IdentityService(session, h.settings).update_preferences(operator, locale="en")
        notifications.save_rule(
            admin,
            {
                "name": "Alert operations",
                "recipientIds": [admin.actor_id, operator.actor_id],
                "channelIds": [DEFAULT_CHANNEL_ID],
            },
        )
        MonitoringService(
            session,
            h.settings,
            adapter=monitoring.adapter,
            notifier=record_alert_event,
            now=monitoring.clock,
        ).ingest_alertmanager(am_payload(asset, starts_at=moment))
        session.commit()

        event = session.execute(select(NotificationEvent)).scalar_one()
        assert event.message is not None
        assert event.message["title"]["key"] == "api.monitoring.alert.title"
        body_key = event.message["body"]["key"]
        assert body_key.startswith("api.monitoring.alert.")

        spanish = notifications.list_inbox(admin)["items"][0]
        english = notifications.list_inbox(operator)["items"][0]
        title_params = event.message["title"]["params"]
        body_params = event.message["body"]["params"]
        assert spanish["title"] == t("api.monitoring.alert.title", "es", **title_params)
        assert english["title"] == t("api.monitoring.alert.title", "en", **title_params)
        assert spanish["body"] == t(body_key, "es", **body_params)
        assert english["body"] == t(body_key, "en", **body_params)
        assert "api.monitoring.alert" not in spanish["body"]


def test_sample_notification_is_localized_for_the_tester(harness: Any) -> None:
    h = harness()
    with h.session() as session:
        admin, notifications = _prepare(h, session)
        identity = IdentityService(session, h.settings)

        identity.update_preferences(admin, locale="en")
        notifications.test_channel(admin, DEFAULT_CHANNEL_ID)
        session.commit()
        identity.update_preferences(admin, locale=None)
        notifications.test_channel(admin, DEFAULT_CHANNEL_ID)
        session.commit()

        processed = process_notifications(h.settings, as_of=utcnow())
        assert processed["delivered"] == 2

        items = {item["body"]: item["title"] for item in notifications.list_inbox(admin)["items"]}
        assert items == {
            "Channel Notificaciones internas": "Test notification",
            "Canal Notificaciones internas": "Prueba de notificación",
        }


def test_legacy_notification_row_keeps_its_stored_text(harness: Any) -> None:
    h = harness()
    with h.session() as session:
        admin, notifications = _prepare(h, session)
        operator = h.principal(session, "operator")
        IdentityService(session, h.settings).update_preferences(operator, locale="en")
        notifications.save_rule(
            admin,
            {
                "name": "Legacy text",
                "recipientIds": [operator.actor_id],
                "channelIds": [DEFAULT_CHANNEL_ID],
            },
        )
        result = _record(h, session)
        session.commit()
        assert result["queued"] == 1

        event = session.execute(select(NotificationEvent)).scalar_one()
        assert event.message is None
        item = notifications.list_inbox(operator)["items"][0]
        assert item["title"] == "UPS sin batería"
        assert item["body"] == "La UPS principal no responde."


@pytest.mark.parametrize(
    "message",
    [
        {"title": {"key": "not a catalog key"}},
        {"body": {"key": "api.notifications.test_title"}},
        {"title": {"key": "api.notifications.test_title", "params": {"Bad Name": 1}}},
        "api.notifications.test_title",
    ],
)
def test_invalid_message_is_rejected_before_anything_is_stored(harness: Any, message: Any) -> None:
    h = harness()
    with h.session() as session:
        with pytest.raises(ValidationFailed):
            _record_bilingual_alert(h, session, message=message)
        session.rollback()
        assert session.scalar(select(func.count(NotificationEvent.id))) == 0
        assert session.scalar(select(func.count(NotificationOutbox.id))) == 0
