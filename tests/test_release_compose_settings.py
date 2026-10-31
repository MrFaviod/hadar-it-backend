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


def test_the_shipped_image_serves_through_the_proxy_trust_launcher():
    """A bare uvicorn CMD trusts X-Forwarded-For from any loopback peer (R1-02)."""
    import json
    from pathlib import Path

    dockerfile = Path(__file__).resolve().parent.parent / "Dockerfile"
    cmd = [
        line
        for line in dockerfile.read_text().splitlines()
        if line.startswith("CMD ")
    ]
    assert len(cmd) == 1, cmd
    argv = json.loads(cmd[0][len("CMD ") :])
    assert argv[:3] == ["python", "-m", "itsm.main"], argv
    assert "uvicorn" not in dockerfile.read_text().split("CMD ")[0].split("ENTRYPOINT ")[-1]
