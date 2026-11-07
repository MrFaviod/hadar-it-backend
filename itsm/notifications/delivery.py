"""Apprise delivery boundary with a deliberately narrow channel vocabulary.

Only the two external kinds exposed by the product may reach Apprise. A stored
secret reference resolves to a deployment-supplied Apprise SMTP URL or a
Telegram bot token (plus a non-secret chat id), so a request can never turn the
server into an arbitrary URL notifier. Apprise exceptions and URLs never leave
this module: callers receive a bounded outcome code.
"""

from __future__ import annotations

import errno
import logging
import re
import socket
import threading
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote, urlsplit

from apprise import Apprise, AppriseResultStatus

from itsm.config import Settings
from itsm.logging import log_event

logger = logging.getLogger("itsm.notifications")
_APPRISE_LOG_LOCK = threading.Lock()
_TRANSPORT_LOGGERS = tuple(
    logging.getLogger(name)
    for name in ("apprise", "urllib3", "requests", "httpx", "httpcore")
)

CHANNEL_INTERNAL = "internal"
CHANNEL_SMTP = "smtp"
CHANNEL_TELEGRAM = "telegram"
CHANNEL_KINDS: tuple[str, ...] = (CHANNEL_INTERNAL, CHANNEL_SMTP, CHANNEL_TELEGRAM)

SMTP_SCHEMES = frozenset({"mailto", "mailtos"})
TELEGRAM_SCHEMES = frozenset({"tgram"})
TELEGRAM_TOKEN = re.compile(r"^[0-9]{5,20}:[A-Za-z0-9_-]{10,}$")
TELEGRAM_CHAT = re.compile(r"^-?[0-9]{1,20}$|^@[A-Za-z0-9_]{3,64}$")
SECRET_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

OutcomeState = Literal["delivered", "failed", "uncertain", "unconfigured"]


@dataclass(frozen=True)
class DeliveryOutcome:
    """The only result shape the service persists; ``error`` is a stable code."""

    state: OutcomeState
    error: str | None = None


def secret_value(settings: Settings, reference: str | None) -> str | None:
    """Resolve one deployment secret reference without ever exposing it."""
    if not reference:
        return None
    secrets = settings.monitoring_secrets or {}
    value = secrets.get(reference)
    if value is None:
        return None
    raw = value.get_secret_value() if hasattr(value, "get_secret_value") else str(value)
    return raw or None


def safe_config(kind: str, values: dict[str, str]) -> dict[str, str]:
    """Validate the non-secret, per-kind configuration allowlist."""
    allowed: dict[str, frozenset[str]] = {
        CHANNEL_INTERNAL: frozenset(),
        CHANNEL_SMTP: frozenset({"subjectPrefix"}),
        CHANNEL_TELEGRAM: frozenset({"chatId"}),
    }
    unknown = set(values) - allowed[kind]
    if unknown:
        raise ValueError("channel config contains unsupported keys")
    cleaned: dict[str, str] = {}
    prefix = values.get("subjectPrefix")
    if prefix is not None:
        if len(prefix) > 80 or any(character in "\r\n" for character in prefix):
            raise ValueError("subjectPrefix is invalid")
        cleaned["subjectPrefix"] = prefix
    chat_id = values.get("chatId")
    if chat_id is not None:
        if not TELEGRAM_CHAT.fullmatch(chat_id):
            raise ValueError("chatId is invalid")
        cleaned["chatId"] = chat_id
    return cleaned


def destination(
    kind: str, secret: str | None, config: dict[str, Any]
) -> tuple[str | None, str | None]:
    """Return an allowed Apprise URL or a terminal configuration error code."""
    if not secret:
        return None, "channel_unconfigured"
    if kind == CHANNEL_SMTP:
        scheme = urlsplit(secret).scheme.lower()
        if scheme not in SMTP_SCHEMES:
            return None, "channel_scheme_not_allowed"
        return secret, None
    if kind == CHANNEL_TELEGRAM:
        if secret.lower().startswith("tgram://"):
            return secret, None
        if not TELEGRAM_TOKEN.fullmatch(secret):
            return None, "channel_invalid_token"
        chat_id = str(config.get("chatId") or "")
        if not TELEGRAM_CHAT.fullmatch(chat_id):
            return None, "channel_chat_missing"
        return f"tgram://{secret}/{quote(chat_id, safe='@-')}", None
    return None, "channel_kind_invalid"


def _classify_failure(result: Any) -> DeliveryOutcome:
    """Retry only failures that prove nothing left the process.

    A generic "connection error" or HTTP 5xx can happen after the peer accepted
    the request but before its response arrived, so neither is proof of
    non-delivery. Only explicit connect-refused/DNS/pre-connect failures,
    authentication refusals and explicit HTTP 4xx responses are retryable;
    everything else stays ``uncertain`` and is never resent automatically.
    """
    messages = " ".join(
        str(log.message) for log in result.logs()
    ).lower()
    if any(
        marker in messages
        for marker in (
            "connection refused",
            "name or service not known",
            "nodename nor servname",
            "temporary failure in name resolution",
            "getaddrinfo failed",
            "failed to establish a new connection",
            "authentication failed",
            "login failed",
            "http error 4",
        )
    ):
        return DeliveryOutcome("failed", "transport_refused")
    return DeliveryOutcome("uncertain", "transport_unconfirmed")


def _smtp_preflight(
    apprise_url: str, timeout_seconds: int
) -> DeliveryOutcome | None:
    """Prove an SMTP endpoint is unreachable before any message can be sent.

    Apprise collapses connection-refused into a generic log line. A TCP
    connect (no SMTP payload) distinguishes a proven pre-send refusal from the
    ambiguous failures that must never be retried. A successful connect simply
    returns ``None``; TLS, authentication and DATA failures stay with Apprise.
    """
    try:
        parts = urlsplit(apprise_url)
        host = parts.hostname
        port = parts.port or (465 if parts.scheme == "mailtos" else 25)
    except ValueError:
        return DeliveryOutcome("unconfigured", "channel_invalid")
    if not host:
        return None
    try:
        with socket.create_connection(
            (host, port), timeout=min(5, max(1, int(timeout_seconds)))
        ):
            return None
    except ConnectionRefusedError:
        return DeliveryOutcome("failed", "transport_refused")
    except socket.gaierror:
        return DeliveryOutcome("failed", "transport_refused")
    except TimeoutError:
        return DeliveryOutcome("uncertain", "transport_timeout")
    except OSError as exc:
        if exc.errno in {errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH}:
            return DeliveryOutcome("failed", "transport_refused")
        return DeliveryOutcome("uncertain", "transport_unconfirmed")


def _apprise_send(
    url: str, title: str, body: str, timeout_seconds: int
) -> DeliveryOutcome:
    """Call the real Apprise plugin for one already-validated URL.

    Apprise logs the full service URL at DEBUG, which can contain a bot token
    or SMTP password. Its own logger is muted while the call runs; the result
    object still carries the structured log entries used to classify failure.
    """
    with _APPRISE_LOG_LOCK:
        previous_levels = [item.level for item in _TRANSPORT_LOGGERS]
        # Apprise and the HTTP transports emit full service URLs (including
        # tokens and passwords) in their own records. Silence every transport
        # level while the call runs; structured ``result.logs()`` still drives
        # failure classification.
        for item in _TRANSPORT_LOGGERS:
            item.setLevel(logging.CRITICAL + 1)
        try:
            return _apprise_send_muted(url, title, body, timeout_seconds)
        finally:
            for item, level in zip(_TRANSPORT_LOGGERS, previous_levels):
                item.setLevel(level)


def _apprise_send_muted(
    url: str, title: str, body: str, timeout_seconds: int
) -> DeliveryOutcome:
    service = Apprise()
    try:
        if not service.add(url):
            return DeliveryOutcome("unconfigured", "channel_invalid")
    except Exception:
        # Invalid configuration is confirmed before any transport attempt.
        return DeliveryOutcome("unconfigured", "channel_invalid")

    try:
        result = service.notify(
            body=body, title=title, timeout=max(1, int(timeout_seconds))
        )
    except Exception:
        # The request may already have left the process: never resend blindly.
        return DeliveryOutcome("uncertain", "transport_uncertain")

    try:
        status = result.status
        if status == AppriseResultStatus.SUCCESS:
            return DeliveryOutcome("delivered", None)
        if status == AppriseResultStatus.TIMEOUT:
            return DeliveryOutcome("uncertain", "transport_timeout")
        if status == AppriseResultStatus.PARTIAL:
            return DeliveryOutcome("uncertain", "transport_partial")
        if status == AppriseResultStatus.NOMATCH:
            return DeliveryOutcome("unconfigured", "channel_invalid")
        return _classify_failure(result)
    except Exception:
        # Plugin result introspection is not a delivery guarantee.
        return DeliveryOutcome("uncertain", "transport_unconfirmed")
    finally:
        try:
            result.close()
        except Exception:
            pass


def _log_failure(
    channel_id: str, kind: str, outcome: DeliveryOutcome
) -> None:
    log_event(
        logger,
        "notification.delivery_failed",
        level=logging.WARNING,
        channel_id=channel_id,
        channel_kind=kind,
        state=outcome.state,
        error=outcome.error,
    )


def deliver_external(
    channel_id: str,
    kind: str,
    secret_ref: str | None,
    config: dict[str, Any],
    *,
    title: str,
    body: str,
    url: str | None,
    timeout_seconds: int,
    settings: Settings,
) -> DeliveryOutcome:
    """Deliver one external notification through Apprise, logging only codes."""
    apprise_url, error = destination(kind, secret_value(settings, secret_ref), config)
    if apprise_url is None:
        log_event(
            logger,
            "notification.delivery_refused",
            level=logging.WARNING,
            channel_id=channel_id,
            channel_kind=kind,
            error=error,
        )
        return DeliveryOutcome("unconfigured", error)

    if kind == CHANNEL_SMTP:
        preflight = _smtp_preflight(apprise_url, timeout_seconds)
        if preflight is not None:
            _log_failure(channel_id, kind, preflight)
            return preflight

    prefix = str(config.get("subjectPrefix") or "").strip()
    subject = f"{prefix} {title}".strip() if prefix else title
    message = f"{body}\n\n{url}" if url else body
    outcome = _apprise_send(apprise_url, subject, message, timeout_seconds)
    if outcome.state != "delivered":
        _log_failure(channel_id, kind, outcome)
    return outcome
