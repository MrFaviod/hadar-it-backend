"""Compose blank optional integration variables disable adapters, not startup."""

from itsm.config import Settings


def test_empty_compose_optional_service_variables_use_disabled_defaults(monkeypatch):
    for key in (
        "ITSM_AI_BROKER_URL",
        "ITSM_AI_BROKER_TOKEN",
        "ITSM_HERMES_INSPECTOR_URL",
        "ITSM_HERMES_INSPECTOR_TOKEN",
    ):
        monkeypatch.setenv(key, "")
    settings = Settings(_env_file=None)
    assert settings.ai_broker_url is None
    assert settings.ai_broker_token is None
    assert settings.hermes_inspector_url is None
    assert settings.hermes_inspector_token is None
