"""JSON structured logging with redaction of configured secrets."""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

REDACTED = "[redacted]"
_MIN_SECRET_LENGTH = 4

_SECRETS: tuple[str, ...] = ()


def sanitize_text(value: str, secrets: Iterable[str] = ()) -> str:
    """Replace configured secret substrings with a stable placeholder."""
    candidates = tuple(secrets) or _SECRETS
    sanitized = value
    for secret in sorted(candidates, key=len, reverse=True):
        if secret and len(secret) >= _MIN_SECRET_LENGTH:
            sanitized = sanitized.replace(secret, REDACTED)
    return sanitized


def _redact(value: Any) -> Any:
    """Redact text before JSON escaping, so secrets with quotes or control characters match."""
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, dict):
        return {sanitize_text(str(key), _SECRETS): _redact(item) for key, item in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_redact(item) for item in value]
    return sanitize_text(str(value), _SECRETS)


class JsonFormatter(logging.Formatter):
    """Render one log record as a single JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        event = getattr(record, "event", None) or record.getMessage()
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": event,
        }
        data = getattr(record, "data", None)
        if isinstance(data, dict):
            payload.update(data)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(_redact(payload), default=str)


def configure_logging(
    level: str,
    secrets: Iterable[str] = (),
    stream: Any | None = None,
) -> logging.Handler:
    """Install a single JSON handler on the root logger.

    Re-invoking replaces the handler previously installed by this module so
    repeated app construction (tests, reloads) does not duplicate output.
    """
    global _SECRETS
    _SECRETS = tuple(sorted({secret for secret in secrets if secret}))

    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_itsm_json_handler", False):
            root.removeHandler(handler)

    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    handler._itsm_json_handler = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(level.upper())
    return handler


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    **fields: Any,
) -> None:
    """Emit a structured event with optional fields."""
    logger.log(level, event, extra={"event": event, "data": fields})
