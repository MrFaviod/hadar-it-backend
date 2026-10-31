"""Private-network discovery follows the current demo generation."""

from fastapi.testclient import TestClient
from itsm.demo.seed import seed
from itsm.main import create_app
from tests.test_demo_reset import demo_settings


def test_demo_discovery_and_metrics_follow_reset(settings_factory, monkeypatch, tmp_path):
    settings = demo_settings(settings_factory, monkeypatch, tmp_path)
    with TestClient(create_app(settings)) as client:
        with client.app.state.session_factory() as session:
            seed(session, settings, "admin", "test-only-telemetry-password")
        discovered = client.get("/api/v1/demo/telemetry/targets")
        assert discovered.status_code == 200, discovered.text
        targets = discovered.json()
        assert targets
        item = targets[0]
        assert item["targets"] == ["backend:8000"]
        assert item["labels"]["check_type"] == "node"
        assert item["labels"]["module"] == "node"
        metrics_path = item["labels"]["__metrics_path__"]
        metrics = client.get(metrics_path)
        assert metrics.status_code == 200
        assert "node_cpu_seconds_total" in metrics.text
        assert "node_memory_MemAvailable_bytes" in metrics.text
        assert client.get("/api/v1/demo/telemetry/metrics/not-a-uuid").status_code == 404

        async def reset():
            from itsm.demo.cycle import reset_demo

            gate = client.app.state.demo_controller.gate
            await gate.begin_reset()
            try:
                reset_demo(settings, client.app.state.engine)
            finally:
                gate.end_reset()

        client.portal.call(reset)
        assert client.get(metrics_path).status_code == 404
        after = client.get("/api/v1/demo/telemetry/targets").json()
        assert after and after[0]["labels"]["asset_id"] != item["labels"]["asset_id"]


def test_ordinary_mode_has_no_demo_discovery(settings_factory):
    from tests.conftest import run_migrations

    settings = settings_factory()
    assert run_migrations(settings).returncode == 0
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/demo/telemetry/targets").status_code == 404
