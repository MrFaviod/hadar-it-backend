"""Tests for JSON structured logging and secret redaction."""

from __future__ import annotations

import io
import json
import logging

from itsm.logging import configure_logging, log_event, sanitize_text


def read_events(stream: io.StringIO) -> list[dict[str, object]]:
    lines = [line for line in stream.getvalue().splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def test_log_event_emits_one_json_object_with_fields() -> None:
    stream = io.StringIO()
    configure_logging("INFO", stream=stream)
    logger = logging.getLogger("itsm.test")

    log_event(logger, "task.completed", task_id="abc123", state="complete")

    events = read_events(stream)
    assert len(events) == 1
    assert events[0]["event"] == "task.completed"
    assert events[0]["task_id"] == "abc123"
    assert events[0]["state"] == "complete"
    assert events[0]["level"] == "INFO"
    assert "timestamp" in events[0]


def test_secrets_are_redacted_from_log_output() -> None:
    stream = io.StringIO()
    configure_logging(
        "INFO",
        secrets=("supersecret", "postgresql+psycopg://itsm:supersecret@db/itsm"),
        stream=stream,
    )
    logger = logging.getLogger("itsm.test")

    log_event(
        logger,
        "database.failed",
        detail="cannot connect to postgresql+psycopg://itsm:supersecret@db/itsm",
    )

    output = stream.getvalue()
    assert "supersecret" not in output
    assert "[redacted]" in output
    assert read_events(stream)[0]["detail"] == "cannot connect to [redacted]"


def test_sanitize_text_without_secrets_is_identity() -> None:
    assert sanitize_text("plain message") == "plain message"


def test_configure_logging_is_idempotent() -> None:
    stream = io.StringIO()
    configure_logging("INFO", stream=stream)
    configure_logging("INFO", stream=stream)
    logger = logging.getLogger("itsm.test")

    log_event(logger, "app.started")

    assert len(read_events(stream)) == 1
