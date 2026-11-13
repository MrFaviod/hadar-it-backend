"""Installers and the extension CLI read the installation file, not only env."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest


def _installation_file(tmp_path: Path, database_url: str) -> Path:
    directory = tmp_path / "installation"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    path = directory / "installation.json"
    path.write_text(json.dumps({"database_url": database_url}), encoding="utf-8")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


def _only_installation(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv("ITSM_INSTALLATION_CONFIG", str(path))
    monkeypatch.delenv("ITSM_DATABASE_URL", raising=False)


def test_installer_connection_probe_resolves_the_installation_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = f"sqlite:///{tmp_path / 'installed.db'}"
    _only_installation(monkeypatch, _installation_file(tmp_path, database_url))

    from itsm.agent_integrations import providers

    captured: dict[str, str] = {}

    def refuse(settings, secret_ref: str, url: str) -> None:
        captured["database_url"] = settings.database_url
        raise providers.ProviderEndpointError("refused for the test")

    monkeypatch.setattr(providers, "require_secret_destination", refuse)
    from itsm.agent_integrations.installer import verify_connection

    result = asyncio.run(
        verify_connection(
            {
                "url": "http://127.0.0.1:9/mcp",
                "secretRef": "ITSM_TEST_MCP_TOKEN",
                "identityId": "test",
            }
        )
    )
    assert result["verified"] is False
    assert captured["database_url"] == database_url


def test_extension_relocate_resolves_the_installation_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = f"sqlite:///{tmp_path / 'installed.db'}"
    _only_installation(monkeypatch, _installation_file(tmp_path, database_url))

    from itsm.extensions import host

    captured: dict[str, str] = {}

    class FakeHost:
        def __init__(self, settings, session_factory) -> None:
            _ = session_factory
            captured["database_url"] = settings.database_url

        def relocate_legacy(self, *, apply: bool) -> dict[str, bool]:
            assert apply is False
            return {"relocated": False}

    monkeypatch.setattr(host, "ExtensionHostService", FakeHost)
    from itsm.extensions.__main__ import _relocate

    assert _relocate(SimpleNamespace(apply=False)) == 0
    assert captured["database_url"] == database_url
