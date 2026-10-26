"""Behavioral tests for durable monitoring notifications (T3, S8-S10).

The focused suite applies the real Alembic migration chain (0016 + 0017) to an
isolated SQLite database. All behavior goes through the public service/router
and a real Apprise plugin; SMTP and Telegram are captured on loopback only.
"""

from __future__ import annotations

import json
import logging
import socket
import socketserver
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.identity.clock import utcnow
from itsm.identity.models import Identity, IdentityRole
from itsm.identity.permissions import ROLE_OPERATOR, ROLE_USER
from itsm.identity.service import (
    IdentityService,
    NotFound,
    PermissionDenied,
    Principal,
)
from itsm.monitoring.service import MonitoringService
from itsm.notifications.models import (
    NotificationChannel,
    NotificationEvent,
    NotificationInbox,
    NotificationOutbox,
    NotificationRule,
)
from itsm.notifications.service import (
    DEFAULT_CHANNEL_ID,
    DEFAULT_RULE_ID,
    NotificationService,
    process_notifications,
    record_alert_event,
)
from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session
from tests.conftest import (
    ADMIN_USERNAME,
    bootstrap_superadmin,
    run_migrations,
    sign_in,
)
from tests.inventory_support import Catalog
from tests.test_phase8_monitoring import Clock, FakeAdapter, MonitoringHarness, am_payload

UTC_NOW = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
READER_PASSWORD = "reader-password-2026"
OPERATOR_PASSWORD = "operator-password-2026"
EMPTY_PASSWORD = "empty-password-2026"
SMTP_SECRET = "smtp-ops"
SMTP_PASSWORD = "smtp-super-secret-password"
TELEGRAM_SECRET = "telegram-ops"
TELEGRAM_TOKEN = "123456789:AAEfakeFAKEfakeTOKEN12345"
TELEGRAM_CHAT = "-1001234567890"


@dataclass
class Harness:
    settings: Settings
    engine: Engine

    def session(self) -> Session:
        return Session(self.engine)

    def principal(self, session: Session, username: str) -> Principal:
        identity = session.execute(
            select(Identity).where(Identity.username == username)
        ).scalar_one()
        return Principal(
            actor_id=identity.id,
            kind=identity.actor_kind,
            username=identity.username,
            display_name=identity.name,
            role_id=identity.role_id,
        )

    def admin(self, session: Session) -> Principal:
        return self.principal(session, ADMIN_USERNAME)

    def close(self) -> None:
        self.engine.dispose()


def _seed_users(engine: Engine, settings: Settings) -> None:
    bootstrap_superadmin(settings)
    with Session(engine) as session:
        now = utcnow()
        session.add(IdentityRole(id="empty", name="Sin acceso", built_in=False, created_at=now))
        session.commit()
        admin = session.execute(
            select(Identity).where(Identity.username == ADMIN_USERNAME)
        ).scalar_one()
        principal = Principal(
            actor_id=admin.id,
            kind=admin.actor_kind,
            username=admin.username,
            display_name=admin.name,
            role_id=admin.role_id,
        )
        service = IdentityService(session, settings)
        for username, name, role_id, password in (
            ("operator", "Olga Operator", ROLE_OPERATOR, OPERATOR_PASSWORD),
            ("reader", "Rita Reader", ROLE_USER, READER_PASSWORD),
            ("empty", "Eva Empty", "empty", EMPTY_PASSWORD),
        ):
            service.create_user(
                principal,
                username=username,
                name=name,
                role_id=role_id,
                password=password,
            )


@pytest.fixture
def harness(settings_factory: Any) -> Iterator[Any]:
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


def _record(
    harness: Harness,
    session: Session,
    *,
    event_key: str = "alert-1:2026-01-15T12:00:00+00:00:firing",
    event_type: str = "firing",
    severity: str = "critical",
    alert_id: str = "alert-1",
    occurred_at: datetime = UTC_NOW,
    acknowledged: bool = False,
    recovered: bool = False,
    asset_id: str | None = None,
    title: str = "UPS sin batería",
    body: str = "La UPS principal no responde.",
    url: str | None = "http://localhost:18080/#/monitoring/alerts/alert-1",
) -> dict[str, Any]:
    return record_alert_event(
        session,
        harness.settings,
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


def _add_channel(
    harness: Harness,
    session: Session,
    kind: str,
    *,
    secret_ref: str | None = None,
    config: dict[str, str] | None = None,
    enabled: bool = True,
) -> NotificationChannel:
    service = NotificationService(session, harness.settings)
    values: dict[str, Any] = {
        "kind": kind,
        "name": f"Canal {kind}",
        "enabled": enabled,
        "config": config or {},
    }
    if secret_ref is not None:
        values["secretRef"] = secret_ref
    return service._channel_row(values, None)  # type: ignore[attr-defined]


def _add_rule(
    harness: Harness,
    session: Session,
    *,
    recipients: list[str],
    channels: list[str],
    **overrides: Any,
) -> NotificationRule:
    service = NotificationService(session, harness.settings)
    values: dict[str, Any] = {
        "name": "Regla de prueba",
        "enabled": True,
        "minimumSeverity": "info",
        "recipientIds": recipients,
        "channelIds": channels,
    }
    values.update(overrides)
    return service._rule_row(values, None)  # type: ignore[attr-defined]


# ----------------------------------------------------------------- SMTP capture
class _SmtpCapture(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, mode: str) -> None:
        super().__init__(("127.0.0.1", 0), _SmtpHandler)
        self.mode = mode
        self.messages: list[bytes] = []
        self.connections = 0


class _SmtpHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server: _SmtpCapture = self.server  # type: ignore[assignment]
        server.connections += 1

        def send(line: str) -> None:
            self.wfile.write((line + "\r\n").encode())
            self.wfile.flush()

        send("220 capture ready")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.decode(errors="replace").strip()
            upper = command.upper()
            if upper.startswith("EHLO"):
                send("250-capture")
                send("250 OK")
            elif upper.startswith("HELO"):
                send("250 capture")
            elif upper.startswith("MAIL"):
                send("250 OK")
            elif upper.startswith("RCPT"):
                if server.mode == "reject":
                    send("550 no such recipient")
                else:
                    send("250 OK")
            elif upper.startswith("DATA"):
                send("354 go ahead")
                message: list[bytes] = []
                while True:
                    data = self.rfile.readline()
                    if not data or data.strip() == b".":
                        break
                    message.append(data)
                server.messages.append(b"".join(message))
                if server.mode == "drop":
                    self.wfile.flush()
                    self.connection.close()
                    return
                send("250 queued")
            elif upper.startswith("QUIT"):
                send("221 bye")
                return
            else:
                send("250 OK")


def _smtp_server(mode: str = "accept") -> _SmtpCapture:
    server = _SmtpCapture(mode)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _smtp_url(port: int) -> str:
    return f"mailto://127.0.0.1:{port}?to=ops@example.test&from=itsm@example.test&mode=insecure"


@contextmanager
def _notification_client(settings: Settings) -> Iterator[TestClient]:
    """Minimal real app with identity + notification routers, no MCP mount."""
    from fastapi import FastAPI
    from itsm.identity.api import (
        create_identity_router,
        install_error_handlers,
    )
    from itsm.notifications.api import create_notification_router

    app = FastAPI()
    engine = create_engine_from_settings(settings)
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)
    install_error_handlers(app)
    app.include_router(create_identity_router(), prefix=settings.api_prefix)
    app.include_router(create_notification_router(), prefix=settings.api_prefix)
    try:
        with TestClient(app) as client:
            yield client
    finally:
        engine.dispose()


def _disable_default_rule(session: Session) -> None:
    rule = session.get(NotificationRule, DEFAULT_RULE_ID)
    if rule is not None:
        rule.enabled = False
        session.flush()


@pytest.fixture
def freeze(monkeypatch: pytest.MonkeyPatch) -> Any:
    def apply(moment: datetime = UTC_NOW) -> datetime:
        monkeypatch.setattr("itsm.notifications.service.utcnow", lambda: moment)
        return moment

    return apply


# ------------------------------------------------------------- Telegram capture
class _TelegramCapture(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode: str = "accept") -> None:
        super().__init__(("127.0.0.1", 0), _TelegramHandler)
        self.mode = mode
        self.requests: list[dict[str, Any]] = []


class _TelegramHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"raw": raw.decode(errors="replace")}
        self.server.requests.append({"path": self.path, "payload": payload})  # type: ignore[attr-defined]
        if self.server.mode == "drop":  # type: ignore[attr-defined]
            # Consume the request, then vanish before any HTTP response. The
            # client cannot know whether Telegram processed it.
            self.close_connection = True
            self.connection.close()
            return
        body = b'{"ok":true,"result":{"message_id":1}}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        return


def _telegram_server(mode: str = "accept") -> _TelegramCapture:
    server = _TelegramCapture(mode)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _closed_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


# ----------------------------------------------------------------------- tests
def test_record_alert_event_is_flush_only_and_defaults_are_used(harness: Any) -> None:
    h = harness()
    session = h.session()
    result = _record(h, session)
    assert result["created"] is True
    assert result["queued"] == 3  # admin, operator and reader hold assets.view
    with Session(h.engine) as observer:
        assert observer.scalar(select(func.count(NotificationEvent.id))) == 0
        assert observer.scalar(select(func.count(NotificationInbox.id))) == 0
    session.commit()
    with Session(h.engine) as observer:
        assert observer.scalar(select(func.count(NotificationEvent.id))) == 1
        inboxes = observer.execute(select(NotificationInbox)).scalars().all()
        assert len(inboxes) == 3
        assert {item.recipient_id for item in inboxes} == {
            h.principal(observer, name).actor_id for name in (ADMIN_USERNAME, "operator", "reader")
        }
        assert h.principal(observer, "empty").actor_id not in {
            item.recipient_id for item in inboxes
        }
        outbox = observer.execute(select(NotificationOutbox)).scalars().all()
        assert len(outbox) == 3
        assert all(row.status == "delivered" for row in outbox)
    session.close()


def test_repeated_event_key_creates_no_duplicate(harness: Any) -> None:
    h = harness()
    with h.session() as session:
        first = _record(h, session)
        session.commit()
        second = _record(h, session)
        session.commit()
        assert first["created"] is True
        assert second == {"created": False, "queued": 0, "suppressed": 0}
        assert session.scalar(select(func.count(NotificationEvent.id))) == 1
        assert session.scalar(select(func.count(NotificationOutbox.id))) == 3
        assert session.scalar(select(func.count(NotificationInbox.id))) == 3


def test_concurrent_duplicate_ingestion_is_single_event(harness: Any) -> None:
    h = harness()

    def ingest() -> str:
        session = h.session()
        try:
            result = _record(h, session)
            session.commit()
            return "created" if result["created"] else "duplicate"
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=3) as pool:
        outcomes = list(pool.map(lambda _: ingest(), range(3)))
    assert outcomes.count("created") == 1
    assert outcomes.count("duplicate") == 2
    with Session(h.engine) as observer:
        assert observer.scalar(select(func.count(NotificationEvent.id))) == 1
        assert observer.scalar(select(func.count(NotificationInbox.id))) == 3


def test_inbox_is_owned_and_read_state_is_per_recipient(harness: Any) -> None:
    h = harness()
    with h.session() as session:
        _record(h, session)
        session.commit()
        admin = h.admin(session)
        reader = h.principal(session, "reader")
        service = NotificationService(session, h.settings)
        admin_page = service.list_inbox(admin)
        reader_page = service.list_inbox(reader)
        assert admin_page["total"] == 1 and reader_page["total"] == 1
        item = reader_page["items"][0]
        with pytest.raises(NotFound):
            service.mark_read(admin, item["id"])
        marked = service.mark_read(reader, item["id"])
        assert marked["readAt"] is not None
        assert service.list_inbox(reader, unread=True)["total"] == 0
        assert service.list_inbox(reader, unread=False)["total"] == 1
        assert service.list_inbox(admin, unread=True)["total"] == 1


def test_config_api_permissions_and_secret_safe_dto(harness: Any, freeze: Any) -> None:
    freeze()
    h = harness(monitoring_secrets={SMTP_SECRET: _smtp_url(2525) + f"&password={SMTP_PASSWORD}"})
    with h.session() as session:
        channel = _add_channel(
            h, session, "smtp", secret_ref=SMTP_SECRET, config={"subjectPrefix": "[ITSM]"}
        )
        session.flush()
        channel_id = channel.id
        _record(h, session)
        session.commit()

    with _notification_client(h.settings) as app:
        admin_headers = sign_in(app, h.settings)
        admin_config = app.get(
            f"{h.settings.api_prefix}/notifications/config", headers=admin_headers
        )
        assert admin_config.status_code == 200, admin_config.text
        body = admin_config.json()
        assert {item["id"] for item in body["channels"]} >= {DEFAULT_CHANNEL_ID, channel_id}
        smtp = next(item for item in body["channels"] if item["id"] == channel_id)
        assert smtp["configured"] is True
        assert smtp["secretRef"] == SMTP_SECRET
        assert SMTP_PASSWORD not in admin_config.text
        assert "mailto://" not in admin_config.text
        assert body["retentionDays"] == 90

        reader_login = app.post(
            f"{h.settings.api_prefix}/auth/login",
            json={"username": "reader", "password": READER_PASSWORD},
            headers={"Origin": h.settings.auth_origin},
        )
        assert reader_login.status_code == 200, reader_login.text
        reader_headers = {
            "X-CSRF-Token": reader_login.json()["csrfToken"],
            "Origin": h.settings.auth_origin,
        }
        forbidden = app.get(f"{h.settings.api_prefix}/notifications/config", headers=reader_headers)
        assert forbidden.status_code == 403
        assert forbidden.json()["error"]["code"] == "forbidden"
        inbox = app.get(f"{h.settings.api_prefix}/notifications/inbox", headers=reader_headers)
        assert inbox.status_code == 200
        assert inbox.json()["total"] == 1
        notification_id = inbox.json()["items"][0]["id"]
        admin_headers = sign_in(app, h.settings)
        other = app.post(
            f"{h.settings.api_prefix}/notifications/inbox/{notification_id}/read",
            headers=admin_headers,
        )
        assert other.status_code == 404
        reader_login = app.post(
            f"{h.settings.api_prefix}/auth/login",
            json={"username": "reader", "password": READER_PASSWORD},
            headers={"Origin": h.settings.auth_origin},
        )
        assert reader_login.status_code == 200, reader_login.text
        reader_headers = {
            "X-CSRF-Token": reader_login.json()["csrfToken"],
            "Origin": h.settings.auth_origin,
        }
        own = app.post(
            f"{h.settings.api_prefix}/notifications/inbox/{notification_id}/read",
            headers=reader_headers,
        )
        assert own.status_code == 200 and own.json()["unread"] is False
        denied = app.post(
            f"{h.settings.api_prefix}/notifications/channels",
            json={"kind": "internal", "name": "No"},
            headers=reader_headers,
        )
        assert denied.status_code == 403


def test_channel_and_rule_validation(harness: Any) -> None:
    h = harness()
    with h.session() as session:
        admin = h.admin(session)
        reader = h.principal(session, "reader")
        empty = h.principal(session, "empty")
        service = NotificationService(session, h.settings)
        with pytest.raises(Exception) as raw:
            service.save_channel(
                admin, {"kind": "smtp", "name": "SMTP", "config": {"password": "raw"}}
            )
        assert "secretRef" in str(raw.value)
        with pytest.raises(Exception) as arbitrary:
            service.save_channel(
                admin,
                {
                    "kind": "smtp",
                    "name": "SMTP",
                    "secretRef": "smtp-ops",
                    "config": {"url": "json://evil"},
                },
            )
        assert "unsupported" in str(arbitrary.value)
        channel = service.save_channel(
            admin,
            {
                "kind": "telegram",
                "name": "Telegram",
                "secretRef": "telegram-ops",
                "config": {"chatId": TELEGRAM_CHAT},
            },
        )
        assert channel["config"] == {"chatId": TELEGRAM_CHAT}
        assert channel["configured"] is False
        with pytest.raises(PermissionDenied):
            service.save_channel(reader, {"kind": "internal", "name": "No"})

        rule = service.save_rule(
            admin,
            {
                "name": "Operaciones",
                "minimumSeverity": "warning",
                "recipientIds": [h.admin(session).actor_id],
                "channelIds": [channel["id"]],
                "retryIntervalSeconds": 5,
                "maxAttempts": 2,
            },
        )
        assert rule["schedule"] is None
        assert rule["escalateAfterSeconds"] == 0
        assert rule["builtIn"] is False
        with pytest.raises(Exception) as no_recipients:
            service.save_rule(
                admin,
                {"name": "Vacía", "recipientIds": [], "channelIds": [channel["id"]]},
            )
        assert "recipient" in str(no_recipients.value)
        with pytest.raises(Exception) as no_escalation:
            service.save_rule(
                admin,
                {
                    "name": "Escala",
                    "recipientIds": [h.admin(session).actor_id],
                    "channelIds": [channel["id"]],
                    "escalateAfterSeconds": 60,
                },
            )
        assert "escalation" in str(no_escalation.value)
        with pytest.raises(Exception) as unauthorized_recipient:
            service.save_rule(
                admin,
                {
                    "name": "Fuga",
                    "recipientIds": [empty.actor_id],
                    "channelIds": [channel["id"]],
                },
            )
        assert "assets" in str(unauthorized_recipient.value)
        with pytest.raises(Exception) as timezone:
            service.save_rule(
                admin,
                {
                    "name": "Zona",
                    "recipientIds": [h.admin(session).actor_id],
                    "channelIds": [channel["id"]],
                    "schedule": {
                        "timezone": "Mars/Olympus",
                        "start": "08:00",
                        "end": "18:00",
                    },
                },
            )
        assert "timezone" in str(timezone.value)


def test_smtp_real_apprise_delivery_is_not_repeated(
    harness: Any, events: Any, caplog: pytest.LogCaptureFixture
) -> None:
    smtp = _smtp_server("accept")
    try:
        secret_url = _smtp_url(smtp.server_address[1]) + f"&password={SMTP_PASSWORD}"
        h = harness(monitoring_secrets={SMTP_SECRET: secret_url})
        with h.session() as session:
            channel = _add_channel(h, session, "smtp", secret_ref=SMTP_SECRET)
            _disable_default_rule(session)
            _add_rule(
                h,
                session,
                recipients=[h.admin(session).actor_id],
                channels=[channel.id],
            )
            _record(h, session)
            session.commit()
            service = NotificationService(session, h.settings)
            test = service.test_channel(h.admin(session), channel.id)
            session.commit()
            assert test["state"] == "pending"
            assert smtp.connections == 0  # enqueue is not a delivery claim
            with caplog.at_level(logging.DEBUG):
                first = process_notifications(h.settings, as_of=utcnow())
                assert first["delivered"] == 2
                assert len(smtp.messages) == 2
                assert b"Subject:" in smtp.messages[0]
                assert b"Subject:" in smtp.messages[1]
                assert b"monitoring/alerts/alert-1" in smtp.messages[0]
                second = process_notifications(h.settings, as_of=utcnow())
                assert second["delivered"] == 0
                assert len(smtp.messages) == 2
            with Session(h.engine) as observer:
                delivered = (
                    observer.execute(
                        select(NotificationOutbox).where(
                            NotificationOutbox.channel_id == channel.id
                        )
                    )
                    .scalars()
                    .all()
                )
                assert all(row.status == "delivered" for row in delivered)
                assert len(delivered) == 2
        serialized = json.dumps(events.events)
        assert SMTP_PASSWORD not in serialized
        assert "mailto://" not in serialized
        assert SMTP_PASSWORD not in caplog.text
        assert secret_url not in caplog.text
    finally:
        smtp.shutdown()
        smtp.server_close()


def test_smtp_drop_after_data_is_uncertain_and_never_resent(harness: Any) -> None:
    smtp = _smtp_server("drop")
    try:
        h = harness(monitoring_secrets={SMTP_SECRET: _smtp_url(smtp.server_address[1])})
        with h.session() as session:
            channel = _add_channel(h, session, "smtp", secret_ref=SMTP_SECRET)
            _disable_default_rule(session)
            _add_rule(
                h,
                session,
                recipients=[h.admin(session).actor_id],
                channels=[channel.id],
                maxAttempts=3,
                retryIntervalSeconds=0,
            )
            _record(h, session)
            session.commit()
            first = process_notifications(h.settings, as_of=utcnow())
            assert first["uncertain"] == 1
            assert first["failed"] == 0
            assert len(smtp.messages) == 1
            second = process_notifications(h.settings, as_of=utcnow() + timedelta(minutes=5))
            assert second["uncertain"] == 0
            assert len(smtp.messages) == 1
            with Session(h.engine) as observer:
                row = observer.execute(
                    select(NotificationOutbox).where(NotificationOutbox.channel_id == channel.id)
                ).scalar_one()
                assert row.status == "uncertain"
                assert row.attempts == 0
                assert row.last_error == "transport_unconfirmed"
    finally:
        smtp.shutdown()
        smtp.server_close()


def test_connection_refused_is_confirmed_failure_and_retries(harness: Any) -> None:
    port = _closed_port()
    h = harness(monitoring_secrets={SMTP_SECRET: _smtp_url(port)})
    with h.session() as session:
        channel = _add_channel(h, session, "smtp", secret_ref=SMTP_SECRET)
        _disable_default_rule(session)
        _add_rule(
            h,
            session,
            recipients=[h.admin(session).actor_id],
            channels=[channel.id],
            maxAttempts=2,
            retryIntervalSeconds=0,
        )
        _record(h, session)
        session.commit()
        first = process_notifications(h.settings, as_of=utcnow())
        assert first["failed"] == 1
        with Session(h.engine) as observer:
            row = observer.execute(
                select(NotificationOutbox).where(NotificationOutbox.channel_id == channel.id)
            ).scalar_one()
            assert row.status == "failed" and row.attempts == 1
            assert row.last_error == "transport_refused"
        second = process_notifications(h.settings, as_of=utcnow() + timedelta(seconds=1))
        assert second["exhausted"] == 1
        with Session(h.engine) as observer:
            row = observer.execute(
                select(NotificationOutbox).where(NotificationOutbox.channel_id == channel.id)
            ).scalar_one()
            assert row.status == "exhausted" and row.attempts == 2
        third = process_notifications(h.settings, as_of=utcnow() + timedelta(seconds=2))
        assert third["exhausted"] == 0


def test_telegram_uses_loopback_apprise_plugin(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    telegram = _telegram_server()
    try:
        from apprise.plugins.telegram import NotifyTelegram

        monkeypatch.setattr(
            NotifyTelegram,
            "notify_url",
            f"http://127.0.0.1:{telegram.server_address[1]}/bot",
        )
        h = harness(monitoring_secrets={TELEGRAM_SECRET: TELEGRAM_TOKEN})
        with h.session() as session:
            channel = _add_channel(
                h,
                session,
                "telegram",
                secret_ref=TELEGRAM_SECRET,
                config={"chatId": TELEGRAM_CHAT},
            )
            _disable_default_rule(session)
            _add_rule(
                h,
                session,
                recipients=[h.admin(session).actor_id],
                channels=[channel.id],
            )
            _record(h, session, title="Telegram title", body="Telegram body")
            session.commit()
            result = process_notifications(h.settings, as_of=utcnow())
            assert result["delivered"] == 1
            assert len(telegram.requests) == 1
            request = telegram.requests[0]
            assert "/bot" in request["path"] and "sendMessage" in request["path"]
            assert str(request["payload"]["chat_id"]) == TELEGRAM_CHAT
            assert "Telegram title" in request["payload"]["text"]
            assert "monitoring/alerts/alert-1" in request["payload"]["text"]
            process_notifications(h.settings, as_of=utcnow())
            assert len(telegram.requests) == 1
    finally:
        telegram.shutdown()
        telegram.server_close()


def test_telegram_drop_after_request_is_uncertain(
    harness: Any,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    telegram = _telegram_server("drop")
    try:
        from apprise.plugins.telegram import NotifyTelegram

        monkeypatch.setattr(
            NotifyTelegram,
            "notify_url",
            f"http://127.0.0.1:{telegram.server_address[1]}/bot",
        )
        h = harness(monitoring_secrets={TELEGRAM_SECRET: TELEGRAM_TOKEN})
        with h.session() as session:
            channel = _add_channel(
                h,
                session,
                "telegram",
                secret_ref=TELEGRAM_SECRET,
                config={"chatId": TELEGRAM_CHAT},
            )
            _disable_default_rule(session)
            _add_rule(
                h,
                session,
                recipients=[h.admin(session).actor_id],
                channels=[channel.id],
                maxAttempts=3,
                retryIntervalSeconds=0,
            )
            _record(h, session)
            session.commit()
            with caplog.at_level(logging.DEBUG):
                first = process_notifications(h.settings, as_of=utcnow())
            assert first["uncertain"] == 1
            assert first["failed"] == 0
            assert len(telegram.requests) == 1
            second = process_notifications(h.settings, as_of=utcnow() + timedelta(minutes=5))
            assert second["uncertain"] == 0
            assert len(telegram.requests) == 1
            with Session(h.engine) as observer:
                row = observer.execute(
                    select(NotificationOutbox).where(NotificationOutbox.channel_id == channel.id)
                ).scalar_one()
                assert row.status == "uncertain"
                assert row.attempts == 0
                assert row.last_error == "transport_unconfirmed"
        assert TELEGRAM_TOKEN not in caplog.text
        assert "tgram://" not in caplog.text
    finally:
        telegram.shutdown()
        telegram.server_close()


def test_schedule_boundaries_use_rule_timezone(harness: Any, freeze: Any) -> None:
    freeze(UTC_NOW)
    h = harness()
    with h.session() as session:
        channel = _add_channel(h, session, "internal")
        _disable_default_rule(session)
        _add_rule(
            h,
            session,
            recipients=[h.admin(session).actor_id],
            channels=[channel.id],
            schedule={
                "timezone": "America/Costa_Rica",
                "start": "08:00",
                "end": "18:00",
            },
        )
        _record(h, session, occurred_at=UTC_NOW)
        session.commit()
        service = NotificationService(session, h.settings)
        assert service.list_inbox(h.admin(session))["total"] == 0
        process_notifications(h.settings, as_of=UTC_NOW)
        process_notifications(h.settings, as_of=UTC_NOW + timedelta(minutes=119))
        with Session(h.engine) as observer:
            assert observer.scalar(select(func.count(NotificationInbox.id))) == 0
            row = observer.execute(select(NotificationOutbox)).scalar_one()
            assert row.status == "pending"
        process_notifications(h.settings, as_of=UTC_NOW + timedelta(minutes=120))
        with Session(h.engine) as observer:
            assert observer.scalar(select(func.count(NotificationInbox.id))) == 1

    # At 18:00 local (00:00 UTC next day) the window is closed again.
    freeze(datetime(2026, 1, 16, 0, 0, tzinfo=UTC))
    with h.session() as session:
        _record(
            h,
            session,
            alert_id="alert-2",
            event_key="alert-2:2026-01-16T00:00:00+00:00:firing",
            occurred_at=datetime(2026, 1, 16, 0, 0, tzinfo=UTC),
        )
        session.commit()
        process_notifications(h.settings, as_of=datetime(2026, 1, 16, 0, 0, tzinfo=UTC))
        with Session(h.engine) as observer:
            assert observer.scalar(select(func.count(NotificationInbox.id))) == 1
        process_notifications(h.settings, as_of=datetime(2026, 1, 16, 14, 0, tzinfo=UTC))
        with Session(h.engine) as observer:
            assert observer.scalar(select(func.count(NotificationInbox.id))) == 2


def test_cross_midnight_schedule_is_inside(harness: Any, freeze: Any) -> None:
    freeze(datetime(2026, 1, 15, 5, 0, tzinfo=UTC))
    h = harness()
    with h.session() as session:
        channel = _add_channel(h, session, "internal")
        _disable_default_rule(session)
        _add_rule(
            h,
            session,
            recipients=[h.admin(session).actor_id],
            channels=[channel.id],
            schedule={
                "timezone": "America/Costa_Rica",
                "start": "22:00",
                "end": "06:00",
            },
        )
        # 23:00 local on the previous day.
        _record(
            h,
            session,
            occurred_at=datetime(2026, 1, 15, 5, 0, tzinfo=UTC),
        )
        session.commit()
        with Session(h.engine) as observer:
            assert observer.scalar(select(func.count(NotificationInbox.id))) == 1


def test_acknowledgement_suppresses_pending_and_escalation(harness: Any, freeze: Any) -> None:
    freeze(UTC_NOW)
    h = harness()
    with h.session() as session:
        channel = _add_channel(h, session, "internal")
        _disable_default_rule(session)
        admin = h.admin(session)
        operator = h.principal(session, "operator")
        _add_rule(
            h,
            session,
            recipients=[admin.actor_id],
            channels=[channel.id],
            escalationRecipientIds=[operator.actor_id],
            acknowledgeAfterSeconds=60,
            escalateAfterSeconds=60,
            schedule={
                "timezone": "America/Costa_Rica",
                "start": "08:00",
                "end": "18:00",
            },
        )
        _record(h, session)
        session.commit()
        ack = _record(
            h,
            session,
            event_key="alert-1:2026-01-15T12:01:00+00:00:acknowledged",
            event_type="acknowledged",
            acknowledged=True,
            occurred_at=UTC_NOW + timedelta(minutes=1),
        )
        session.commit()
        assert ack == {"created": True, "queued": 0, "suppressed": 1}
        with Session(h.engine) as observer:
            firing = observer.execute(
                select(NotificationEvent).where(NotificationEvent.event_type == "firing")
            ).scalar_one()
            assert firing.acknowledged is True
            outbox = observer.execute(select(NotificationOutbox)).scalar_one()
            assert outbox.status == "suppressed"
            assert outbox.last_error == "alert_acknowledged"
        process_notifications(h.settings, as_of=UTC_NOW + timedelta(hours=4))
        with Session(h.engine) as observer:
            assert observer.scalar(select(func.count(NotificationInbox.id))) == 0
            assert (
                observer.scalar(
                    select(func.count(NotificationOutbox.id)).where(
                        NotificationOutbox.escalation_bucket == 1
                    )
                )
                == 0
            )


def test_recovery_suppresses_firing_and_delivers_recovery(harness: Any, freeze: Any) -> None:
    freeze(UTC_NOW)
    h = harness()
    with h.session() as session:
        channel = _add_channel(h, session, "internal")
        _disable_default_rule(session)
        _add_rule(
            h,
            session,
            recipients=[h.admin(session).actor_id],
            channels=[channel.id],
            schedule={
                "timezone": "America/Costa_Rica",
                "start": "08:00",
                "end": "18:00",
            },
        )
        _record(h, session)
        session.commit()
        recovery = _record(
            h,
            session,
            event_key="alert-1:2026-01-15T12:05:00+00:00:recovered",
            event_type="recovered",
            recovered=True,
            occurred_at=UTC_NOW + timedelta(minutes=5),
        )
        session.commit()
        assert recovery == {"created": True, "queued": 1, "suppressed": 1}
        with Session(h.engine) as observer:
            events = (
                observer.execute(select(NotificationEvent).order_by(NotificationEvent.occurred_at))
                .scalars()
                .all()
            )
            assert [event.recovered for event in events] == [True, True]
            statuses = (
                observer.execute(
                    select(NotificationOutbox.status).order_by(NotificationOutbox.created_at)
                )
                .scalars()
                .all()
            )
            assert statuses == ["suppressed", "pending"]
        process_notifications(h.settings, as_of=UTC_NOW + timedelta(hours=2))
        with Session(h.engine) as observer:
            inbox = observer.execute(select(NotificationInbox)).scalars().all()
            assert len(inbox) == 1
            assert inbox[0].event_type == "recovered"


def test_escalation_fires_once_and_ack_stops_it(harness: Any, freeze: Any) -> None:
    freeze(UTC_NOW)
    h = harness()
    with h.session() as session:
        channel = _add_channel(h, session, "internal")
        _disable_default_rule(session)
        admin = h.admin(session)
        operator = h.principal(session, "operator")
        _add_rule(
            h,
            session,
            recipients=[admin.actor_id],
            channels=[channel.id],
            escalationRecipientIds=[operator.actor_id],
            acknowledgeAfterSeconds=60,
            escalateAfterSeconds=60,
        )
        _record(h, session, occurred_at=UTC_NOW - timedelta(minutes=5))
        session.commit()
        assert session.scalar(select(func.count(NotificationInbox.id))) == 1
        first = process_notifications(h.settings, as_of=UTC_NOW)
        assert first["escalated"] == 1
        with Session(h.engine) as observer:
            inbox = (
                observer.execute(
                    select(NotificationInbox).where(
                        NotificationInbox.recipient_id == operator.actor_id
                    )
                )
                .scalars()
                .all()
            )
            assert len(inbox) == 1
        second = process_notifications(h.settings, as_of=UTC_NOW + timedelta(minutes=5))
        assert second["escalated"] == 0
        _record(
            h,
            session,
            event_key="alert-1:2026-01-15T12:01:00+00:00:acknowledged",
            event_type="acknowledged",
            acknowledged=True,
            occurred_at=UTC_NOW + timedelta(minutes=6),
        )
        session.commit()
        third = process_notifications(h.settings, as_of=UTC_NOW + timedelta(hours=2))
        assert third["escalated"] == 0
        with Session(h.engine) as observer:
            count = observer.scalar(
                select(func.count(NotificationInbox.id)).where(
                    NotificationInbox.recipient_id == operator.actor_id
                )
            )
            assert count == 1


def test_disallowed_channel_credential_scheme_is_not_sent(harness: Any) -> None:
    h = harness(
        monitoring_secrets={
            "arbitrary": "json://127.0.0.1:9/path",
            "bad-token": "not-a-telegram-token",
        }
    )
    with h.session() as session:
        smtp = _add_channel(h, session, "smtp", secret_ref="arbitrary")
        telegram = _add_channel(
            h,
            session,
            "telegram",
            secret_ref="bad-token",
            config={"chatId": TELEGRAM_CHAT},
        )
        _disable_default_rule(session)
        _add_rule(
            h,
            session,
            recipients=[h.admin(session).actor_id],
            channels=[smtp.id, telegram.id],
        )
        _record(h, session)
        session.commit()
        result = process_notifications(h.settings, as_of=utcnow())
        assert result["exhausted"] == 2
        with Session(h.engine) as observer:
            rows = observer.execute(select(NotificationOutbox)).scalars().all()
            assert {row.last_error for row in rows} == {
                "channel_scheme_not_allowed",
                "channel_invalid_token",
            }
            assert all(row.status == "exhausted" for row in rows)


def test_api_test_channel_never_claims_delivery(harness: Any) -> None:
    smtp = _smtp_server("accept")
    try:
        h = harness(monitoring_secrets={SMTP_SECRET: _smtp_url(smtp.server_address[1])})
        with h.session() as session:
            channel = _add_channel(h, session, "smtp", secret_ref=SMTP_SECRET)
            _disable_default_rule(session)
            session.commit()
            channel_id = channel.id
        with _notification_client(h.settings) as app:
            headers = sign_in(app, h.settings)
            created = app.post(
                f"{h.settings.api_prefix}/notifications/channels",
                json={
                    "id": channel_id,
                    "kind": "smtp",
                    "name": "SMTP ops",
                    "secretRef": SMTP_SECRET,
                },
                headers=headers,
            )
            assert created.status_code == 200, created.text
            tested = app.post(
                f"{h.settings.api_prefix}/notifications/channels/{channel_id}/test",
                json={"url": "http://evil.invalid"},
                headers=headers,
            )
            assert tested.status_code == 202, tested.text
            assert tested.json()["state"] == "pending"
            assert tested.json()["outboxId"]
        with Session(h.engine) as observer:
            row = observer.execute(select(NotificationOutbox)).scalar_one()
            assert row.status == "pending"
        process_notifications(h.settings, as_of=utcnow())
        assert len(smtp.messages) == 1
        with Session(h.engine) as observer:
            row = observer.execute(select(NotificationOutbox)).scalar_one()
            assert row.status == "delivered"
    finally:
        smtp.shutdown()
        smtp.server_close()


def test_retention_prunes_old_delivered_and_keeps_recent(harness: Any) -> None:
    h = harness(notification_retention_days=30)
    old = utcnow() - timedelta(days=60)
    with h.session() as session:
        _record(
            h,
            session,
            alert_id="old-alert",
            event_key="old-alert:2026-01-01T00:00:00+00:00:firing",
            occurred_at=utcnow(),
        )
        session.commit()
        session.execute(
            update(NotificationEvent)
            .where(NotificationEvent.alert_id == "old-alert")
            .values(occurred_at=old)
        )
        session.execute(
            update(NotificationOutbox)
            .where(NotificationOutbox.alert_id == "old-alert")
            .values(created_at=old)
        )
        session.execute(
            update(NotificationInbox)
            .where(NotificationInbox.alert_id == "old-alert")
            .values(created_at=old)
        )
        session.commit()
        _record(
            h,
            session,
            alert_id="recent-alert",
            event_key="recent-alert:2026-01-15T12:00:00+00:00:firing",
            occurred_at=utcnow(),
        )
        session.commit()
        result = process_notifications(h.settings, as_of=utcnow())
        assert result["pruned"] >= 4
        with Session(h.engine) as observer:
            assert (
                observer.scalar(
                    select(func.count(NotificationEvent.id)).where(
                        NotificationEvent.alert_id == "old-alert"
                    )
                )
                == 0
            )
            assert (
                observer.scalar(
                    select(func.count(NotificationInbox.id)).where(
                        NotificationInbox.alert_id == "old-alert"
                    )
                )
                == 0
            )
            assert (
                observer.scalar(
                    select(func.count(NotificationEvent.id)).where(
                        NotificationEvent.alert_id == "recent-alert"
                    )
                )
                == 1
            )
            assert (
                observer.scalar(
                    select(func.count(NotificationInbox.id)).where(
                        NotificationInbox.alert_id == "recent-alert"
                    )
                )
                == 3
            )


def test_empty_role_receives_no_asset_notification(harness: Any) -> None:
    h = harness()
    with h.session() as session:
        _record(h, session)
        session.commit()
        empty = h.principal(session, "empty")
        assert (
            session.scalar(
                select(func.count(NotificationInbox.id)).where(
                    NotificationInbox.recipient_id == empty.actor_id
                )
            )
            == 0
        )
        service = NotificationService(session, h.settings)
        with pytest.raises(Exception) as denied:
            service.save_rule(
                h.admin(session),
                {
                    "name": "Fuga",
                    "recipientIds": [empty.actor_id],
                    "channelIds": [DEFAULT_CHANNEL_ID],
                },
            )
        assert "assets" in str(denied.value)


def test_rule_schedule_validation_and_defaults(harness: Any) -> None:
    h = harness()
    with h.session() as session:
        admin = h.admin(session)
        service = NotificationService(session, h.settings)
        config = service.get_config(admin)
        default_rule = next(rule for rule in config["rules"] if rule["id"] == DEFAULT_RULE_ID)
        assert default_rule["builtIn"] is True
        assert default_rule["recipientIds"] == []
        assert default_rule["schedule"] is None
        assert default_rule["minimumSeverity"] == "info"
        assert default_rule["acknowledgeAfterSeconds"] == 900
        assert default_rule["retryIntervalSeconds"] == 60
        assert default_rule["maxAttempts"] == 3
        assert default_rule["escalateAfterSeconds"] == 0
        assert config["defaults"] == {
            "internalChannelId": DEFAULT_CHANNEL_ID,
            "defaultRuleId": DEFAULT_RULE_ID,
        }
        updated = service.save_rule(
            admin,
            {
                "id": DEFAULT_RULE_ID,
                "name": "Operaciones",
                "schedule": {
                    "timezone": "America/Costa_Rica",
                    "start": "07:30",
                    "end": "19:00",
                },
            },
        )
        assert updated["schedule"] == {
            "timezone": "America/Costa_Rica",
            "start": "07:30",
            "end": "19:00",
        }
        assert updated["builtIn"] is True
        cleared = service.save_rule(
            admin, {"id": DEFAULT_RULE_ID, "name": "Operaciones", "schedule": None}
        )
        assert cleared["schedule"] is None


def test_timezone_boundary_is_dst_safe(harness: Any, freeze: Any) -> None:
    """A US daylight-saving transition must not shift the local window."""
    zone = ZoneInfo("America/New_York")
    moment = datetime(2026, 3, 8, 13, 0, tzinfo=UTC)  # 09:00 EDT after spring forward
    assert moment.astimezone(zone).hour == 9
    freeze(moment)
    h = harness()
    with h.session() as session:
        channel = _add_channel(h, session, "internal")
        _disable_default_rule(session)
        _add_rule(
            h,
            session,
            recipients=[h.admin(session).actor_id],
            channels=[channel.id],
            schedule={
                "timezone": "America/New_York",
                "start": "08:00",
                "end": "18:00",
            },
        )
        _record(h, session, occurred_at=moment)
        session.commit()
        with Session(h.engine) as observer:
            assert observer.scalar(select(func.count(NotificationInbox.id))) == 1


@pytest.mark.parametrize("suppression", ("silence", "window"))
@pytest.mark.parametrize("queued", ("firing", "escalation"))
@pytest.mark.parametrize(
    "transition", ("active", "acknowledged", "recovered", "acknowledged_recovered")
)
def test_monitoring_suppression_preserves_lifecycle_and_queued_delivery(
    harness: Any, freeze: Any, suppression: str, queued: str, transition: str
) -> None:
    """Silence never drops lifecycle, sends queued work, or replays suppressed firing."""
    freeze(UTC_NOW)
    smtp = _smtp_server()
    try:
        h = harness(monitoring_secrets={SMTP_SECRET: _smtp_url(smtp.server_address[1])})
        monitoring = MonitoringHarness(
            catalog=Catalog(h.settings, h.engine), clock=Clock(UTC_NOW), adapter=FakeAdapter()
        )
        asset = monitoring.add_asset("Maintenance server")

        def service(session: Session) -> MonitoringService:
            return MonitoringService(
                session,
                h.settings,
                adapter=monitoring.adapter,
                notifier=record_alert_event,
                now=monitoring.clock,
            )

        with h.session() as session:
            admin = h.admin(session)
            operator = h.principal(session, "operator")
            notifications = NotificationService(session, h.settings)
            channel = notifications.save_channel(
                admin, {"kind": "smtp", "name": "Maintenance SMTP", "secretRef": SMTP_SECRET}
            )
            notifications.save_rule(admin, {"id": DEFAULT_RULE_ID, "enabled": False})
            notifications.save_rule(
                admin,
                {
                    "name": "Maintenance escalation",
                    "recipientIds": [admin.actor_id],
                    "channelIds": [DEFAULT_CHANNEL_ID, channel["id"]],
                    "escalationRecipientIds": [operator.actor_id],
                    "acknowledgeAfterSeconds": 60,
                    "escalateAfterSeconds": 60,
                },
            )
            service(session).ingest_alertmanager(am_payload(asset, starts_at=UTC_NOW))
            alert_id = service(session).list_alerts(admin)["items"][0]["id"]
            inbox = notifications.list_inbox(admin)
            assert inbox["total"] == 1
            assert inbox["items"][0]["alertId"] == alert_id
            assert inbox["items"][0]["eventType"] == "firing"
        assert smtp.connections == 0

        previous_deliveries = 0
        previous_escalations = 0
        if queued == "escalation":
            moment = UTC_NOW + timedelta(minutes=3)
            freeze(moment)
            monitoring.clock.value = moment
            initial = process_notifications(h.settings, as_of=moment)
            assert initial["delivered"] == 1
            assert initial["escalated"] == 2
            previous_deliveries = 1
            previous_escalations = 1
        previous_connections = smtp.connections

        moment = UTC_NOW + timedelta(minutes=4)
        freeze(moment)
        monitoring.clock.value = moment
        with h.session() as session:
            monitor = service(session)
            if suppression == "silence":
                monitor.silence(
                    operator,
                    {
                        "assetId": asset,
                        "endsAt": (UTC_NOW + timedelta(minutes=30)).isoformat(),
                        "comment": "Planned maintenance",
                    },
                )
            else:
                monitor.save_window(
                    operator,
                    {
                        "name": "Planned maintenance",
                        "assetIds": [asset],
                        "daysOfWeek": [UTC_NOW.weekday()],
                        "startTime": "12:04",
                        "endTime": "12:30",
                        "timezone": "UTC",
                    },
                )
            # New firing notifications are dropped, not deferred until expiry.
            monitor.ingest_alertmanager(
                am_payload(asset, fingerprint="duringmaintenance", starts_at=moment)
            )
            if "acknowledged" in transition:
                monitor.acknowledge(operator, alert_id, "Investigating during maintenance")
            if "recovered" in transition:
                monitor.ingest_alertmanager(
                    am_payload(asset, status="resolved", starts_at=UTC_NOW, ends_at=moment)
                )
            detail = monitor.get_alert(admin, alert_id)
            assert detail["silenced"] is True
            assert detail["state"] == ("resolved" if "recovered" in transition else "firing")
            assert detail["acknowledged"] is ("acknowledged" in transition)
            notifications = NotificationService(session, h.settings)
            assert notifications.list_inbox(admin)["total"] == 1
            assert notifications.list_inbox(operator)["total"] == previous_escalations

        during = process_notifications(h.settings, as_of=UTC_NOW + timedelta(minutes=10))
        assert during["delivered"] == 0
        assert during["escalated"] == 0
        assert len(smtp.messages) == previous_deliveries
        assert smtp.connections == previous_connections

        moment = UTC_NOW + timedelta(minutes=30)
        freeze(moment)
        monitoring.clock.value = moment
        with h.session() as session:
            assert service(session).get_alert(admin, alert_id)["silenced"] is False
        expired = process_notifications(h.settings, as_of=moment)
        if transition == "active":
            assert expired["delivered"] == 1
            assert expired["escalated"] == (2 if queued == "firing" else 0)
            follow = process_notifications(h.settings, as_of=moment + timedelta(seconds=1))
            assert follow["delivered"] == (1 if queued == "firing" else 0)
            assert follow["escalated"] == 0
            expected_deliveries = 2
            expected_escalations = 1
        else:
            assert expired["delivered"] == 0
            assert expired["escalated"] == 0
            expected_deliveries = previous_deliveries
            expected_escalations = previous_escalations
        repeated = process_notifications(h.settings, as_of=UTC_NOW + timedelta(hours=1))
        assert repeated["delivered"] == 0
        assert repeated["escalated"] == 0
        assert len(smtp.messages) == expected_deliveries
        with h.session() as session:
            notifications = NotificationService(session, h.settings)
            assert notifications.list_inbox(admin)["total"] == 1
            assert notifications.list_inbox(operator)["total"] == expected_escalations
    finally:
        smtp.shutdown()
        smtp.server_close()
