"""Report URL and renderer resource limits are deployment security boundaries."""

from __future__ import annotations

import pytest
from itsm.config import Settings
from pydantic import ValidationError


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://user:password@example.com",
        "https://example.com/?token=secret",
        "https://example.com/#fragment",
        "https://example.com/bad path",
        "https://example.com:0",
        "https://example.com/?",
        "https://example.com#",
        "https://example.com/a?",
        "https://example.com/a#",
        "https://example.com:",
        "https://example.com/a\x00b",
        "https://example.com/a\x7fb",
        "https://example.com/\\x",
    ],
)
def test_report_base_url_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(ValidationError, match="report_base_url"):
        Settings(_env_file=None, report_base_url=url)


def test_report_base_url_preserves_deployment_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ITSM_REPORT_BASE_URL", "https://example.com/itsm/")
    settings = Settings(_env_file=None)
    assert settings.report_base_url == "https://example.com/itsm"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("report_retention_days", 0),
        ("report_max_assets", 0),
        ("report_max_assets", 10001),
        ("report_max_document_bytes", 0),
        ("report_render_timeout_seconds", 0),
        ("report_render_timeout_seconds", 601),
        ("report_render_memory_mb", 63),
    ],
)
def test_report_resource_limits_cannot_disable_bounds(name: str, value: int) -> None:
    with pytest.raises(ValidationError, match=name):
        Settings(_env_file=None, **{name: value})
