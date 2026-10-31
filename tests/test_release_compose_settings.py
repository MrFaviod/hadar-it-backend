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
    cmd = [line for line in dockerfile.read_text().splitlines() if line.startswith("CMD ")]
    assert len(cmd) == 1, cmd
    argv = json.loads(cmd[0][len("CMD ") :])
    assert argv[:3] == ["python", "-m", "itsm.main"], argv
    assert "uvicorn" not in dockerfile.read_text().split("CMD ")[0].split("ENTRYPOINT ")[-1]


def test_the_image_does_not_pre_create_the_demo_directory():
    """`itsm.demo init` refuses an existing directory, so the image must not make it."""
    from pathlib import Path

    dockerfile = Path(__file__).resolve().parent.parent / "Dockerfile"
    created = [
        line
        for line in dockerfile.read_text().splitlines()
        if line.lstrip().startswith(("&& mkdir -p /data", "mkdir -p /data"))
    ]
    assert created, "the image must still create its data directories"
    assert all("/data/demo" not in line for line in created), created


def test_the_demo_overlay_initializes_the_demonstration():
    """A fresh demo volume must end up with the seeded visitor administrator."""
    from pathlib import Path

    overlay = (
        Path(__file__).resolve().parent.parent.parent / "deploy" / "compose.demo.yaml"
    ).read_text()
    assert "ITSM_BOOTSTRAP_PASSWORD" in overlay
    initialize = overlay.split("  initialize:", 1)[1].split("\n  backend:", 1)[0]
    assert "itsm.demo init" in initialize
    assert "/data/demo" in initialize
    # The volume must be mounted at the parent: Docker creates the mount point,
    # and the initializer refuses an existing directory (verified by F-N1).
    mount = [
        line
        for line in overlay.splitlines()
        if "volumes: !override" in line and "demo-data:" in line
    ]
    assert mount == ["  volumes: !override [demo-data:/data]"], mount
