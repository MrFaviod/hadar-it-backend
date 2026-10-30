"""Rejected demo cleanup leaves unrelated and production state unchanged."""

import pytest
from fastapi.testclient import TestClient
from itsm.main import create_app
from itsm.release_identity import DeploymentIdentityError
from tests.test_demo_reset import demo_settings


def test_reset_rejects_non_demo_runtime_without_writes(settings_factory, monkeypatch, tmp_path):
    from itsm.demo.cycle import reset_demo

    settings = demo_settings(settings_factory, monkeypatch, tmp_path)
    with TestClient(create_app(settings)) as client:
        client.get("/api/v1/demo/status")
        database = settings.demo_data_directory / "app.db"
        before = database.read_bytes()
        monkeypatch.setenv("RELEASE_MODE", "prod")
        with pytest.raises(DeploymentIdentityError):
            reset_demo(settings, client.app.state.engine)
        assert database.read_bytes() == before


def test_reset_rejects_linked_attachment_tree_without_writes(
    settings_factory, monkeypatch, tmp_path
):
    from itsm.demo.cycle import reset_demo

    settings = demo_settings(settings_factory, monkeypatch, tmp_path)
    with TestClient(create_app(settings)) as client:
        client.get("/api/v1/demo/status")
        settings.attachment_storage_path.mkdir()
        external = tmp_path / "not-demo"
        external.mkdir()
        sentinel = external / "keep.txt"
        sentinel.write_text("keep")
        (settings.attachment_storage_path / "link").symlink_to(external, target_is_directory=True)
        database = settings.demo_data_directory / "app.db"
        before = database.read_bytes()
        with pytest.raises(DeploymentIdentityError):
            reset_demo(settings, client.app.state.engine)
        assert database.read_bytes() == before
        assert sentinel.read_text() == "keep"
