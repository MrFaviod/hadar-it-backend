"""Phase 8 composition and externally supplied configuration boundaries."""

from __future__ import annotations

import io
import logging

import pytest
from itsm.config import Settings
from itsm.logging import configure_logging, log_event
from pydantic import ValidationError


@pytest.mark.parametrize("field", ["prometheus_url", "alertmanager_url", "monitoring_public_url"])
@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://user:private-password@metrics.example",
        "https://metrics.example?token=private-token",
        "https://metrics.example/#private-token",
        "http://metrics.example:invalid",
    ],
)
def test_monitoring_endpoints_reject_non_http_or_embedded_secrets(field, url):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: url})


def test_monitoring_secret_values_are_masked_in_configuration_and_logs():
    secrets = {
        "smtp-primary": "mailtos://operator:smtp-private-password@smtp.example",
        "telegram-primary": "tgram://123456:telegram-private-token/123456789",
    }
    settings = Settings(
        _env_file=None,
        prometheus_token="prometheus-private-token",
        alertmanager_token="alertmanager-private-token",
        monitoring_ingest_token="webhook-private-token",
        monitoring_discovery_token="discovery-private-token",
        monitoring_secrets=secrets,
    )
    private_values = [*secrets.values(), "prometheus-private-token", "webhook-private-token"]
    for value in private_values:
        assert value not in repr(settings)
        assert value not in settings.model_dump_json()
    stream = io.StringIO()
    configure_logging("INFO", stream=stream, secrets=settings.sensitive_values())
    log_event(logging.getLogger("itsm.phase8"), "delivery.failed", detail=" ".join(private_values))
    for value in private_values:
        assert value not in stream.getvalue()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("monitoring_http_timeout_seconds", 0),
        ("monitoring_http_timeout_seconds", 61),
        ("monitoring_poll_seconds", 59),
        ("notification_retention_days", 0),
    ],
)
def test_monitoring_work_and_retention_are_bounded(field, value):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: value})


def test_optional_monitoring_deployment_values_can_be_empty():
    settings = Settings(
        _env_file=None, prometheus_url="", alertmanager_url="  ", monitoring_ingest_token=""
    )
    assert settings.prometheus_url is None
    assert settings.alertmanager_url is None
    assert settings.monitoring_ingest_token is None


def test_public_monitoring_link_origin_cannot_be_empty():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, monitoring_public_url="")
