"""Installer lifecycle: real mounted FastMCP proof plus isolated engine profiles.

Engine config schemas are exercised against temporary profiles only. The catalog is a
test double implementing the fixed sibling contract because the official catalog files
are owned by another writer; no production code is stubbed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from itsm.agent_integrations.installer import (
    InstallerError,
    IntegrationInstaller,
    IntegrationTarget,
    build_request,
    validate_receipt,
    verify_connection,
)
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.main import create_app
from tests.conftest import bootstrap_admin, run_migrations
from tests.inventory_support import Catalog as ItsmCatalog

BACKEND_ROOT = Path(__file__).resolve().parents[1]
TOKEN_ENV = "ITSM_INSTALLER_TOKEN"


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class CatalogDouble:
    """Contract-compatible catalog double with deterministic package digests."""

    def __init__(self, skills: dict[str, dict[str, bytes]] | None = None) -> None:
        self.skills = skills or {
            "itsm-inventory": {
                "SKILL.md": b"---\nname: itsm-inventory\n---\nInventory procedure.\n",
                "references/queries.md": b"Use authorized inventory tools.\n",
            },
            "itsm-monitoring": {
                "SKILL.md": b"---\nname: itsm-monitoring\n---\nMonitoring procedure.\n",
            },
        }
        self.versions = {name: "1.0.0" for name in self.skills}

    def package_digest(self, name: str) -> str:
        value = hashlib.sha256()
        for relative in sorted(self.skills[name]):
            value.update(relative.encode())
            value.update(b"\0")
            value.update(self.skills[name][relative])
            value.update(b"\0")
        return "sha256:" + value.hexdigest()

    def list_skills(self) -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "description": f"{name} skill",
                "version": self.versions[name],
                "module": "itsm",
                "permissions": [],
                "capabilities": [],
                "digest": self.package_digest(name),
            }
            for name in sorted(self.skills)
        ]

    def get_skill(self, name: str) -> dict[str, Any]:
        if name not in self.skills:
            raise KeyError(name)
        metadata = next(item for item in self.list_skills() if item["name"] == name)
        return {**metadata, "files": dict(self.skills[name])}

    def set_file(self, name: str, relative: str, data: bytes) -> None:
        self.skills[name][relative] = data


def strip_jsonc(text: str) -> str:
    """Small independent JSONC stripper for assertions, not production parsing."""
    output: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = len(text) if end < 0 else end + 2
            continue
        output.append(char)
        index += 1
    return "".join(output)


def json_config(path: Path) -> dict[str, Any]:
    return json.loads(strip_jsonc(path.read_text()))


def yaml_config(path: Path) -> dict[str, Any]:
    import yaml

    return yaml.safe_load(path.read_text()) or {}


def checks(receipt: dict[str, Any]) -> dict[str, str]:
    return {item["name"]: item["status"] for item in receipt["checks"]}


def hermes_target(
    root: Path, *, profile: str = "itsm", version: str | None = "0.16.0"
) -> tuple[IntegrationTarget, Path]:
    home = root / "profiles" / profile
    home.mkdir(parents=True)
    (home / "config.yaml").write_text("model: openai/gpt\n")
    return IntegrationTarget("hermes", str(home), profile, version), home


def opencode_target(
    root: Path, *, version: str | None = "2.1.2", config: str | None = None
) -> tuple[IntegrationTarget, Path]:
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    if config is not None:
        (workspace / "opencode.json").write_text(config)
    return IntegrationTarget("opencode", str(workspace), None, version), workspace


def mcp_spec(server: dict[str, Any], identity: str = "integration-1") -> dict[str, Any]:
    return {
        "url": server["url"],
        "secretRef": TOKEN_ENV,
        "identityId": identity,
    }


@pytest.fixture
def catalog() -> CatalogDouble:
    return CatalogDouble()


@pytest.fixture
def installer(catalog: CatalogDouble) -> IntegrationInstaller:
    return IntegrationInstaller(catalog=catalog)


@pytest.fixture(scope="module")
def mcp_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    base = tmp_path_factory.mktemp("installer-mcp")
    (base / "tasks").mkdir()
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{base / 'app.db'}",
        task_sqlite_path=base / "tasks" / "huey.db",
        task_retries=2,
        task_retry_delay_seconds=1.0,
        demo_max_delay_seconds=15,
        demo_message_max_length=50,
        log_level="INFO",
        auth_origin="http://testserver",
        auth_cookie_secure=False,
    )
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    bootstrap_admin(settings)
    engine = create_engine_from_settings(settings)
    itsm = ItsmCatalog(settings=settings, engine=engine)
    _, token = itsm.add_machine("installer-client", "Installer Client")

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    app = create_app(settings)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "uvicorn did not start"
    try:
        yield {
            "url": f"http://127.0.0.1:{port}/api/v1/mcp",
            "token": token,
            "settings": settings,
        }
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        engine.dispose()


@pytest.fixture
def verified_token(mcp_server: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv(TOKEN_ENV, mcp_server["token"])
    return TOKEN_ENV


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


# --------------------------------------------------------------------------- detect


def test_detect_target_reports_hermes_and_both_opencode_generations(tmp_path: Path) -> None:
    installer = IntegrationInstaller(catalog=CatalogDouble())
    hermes, hermes_home = hermes_target(tmp_path / "hermes")
    detected = run(installer.detect_target(hermes))
    assert detected["engine"] == "hermes"
    assert detected["format"] == "hermes"
    assert detected["profile"] == "itsm"
    assert detected["version"] == "0.16.0"
    assert detected["configFile"] == "config.yaml"
    assert detected["skillsDirectory"] == "skills"

    v2, v2_root = opencode_target(
        tmp_path / "v2",
        config='{"permissions": [], "mcp": {"servers": {}}, "agents": {}}',
    )
    detected_v2 = run(installer.detect_target(v2))
    assert detected_v2["format"] == "v2"
    assert detected_v2["configFile"] == "opencode.json"
    assert detected_v2["skillsDirectory"] == ".opencode/skills"
    assert v2_root.is_dir()

    v1, _ = opencode_target(
        tmp_path / "v1", version="1.2.0", config='{"permission": {}, "agent": {}}'
    )
    detected_v1 = run(installer.detect_target(v1))
    assert detected_v1["format"] == "v1"
    assert hermes_home.is_dir()


def test_detect_rejects_relative_mismatched_and_unknown_targets(tmp_path: Path) -> None:
    installer = IntegrationInstaller(catalog=CatalogDouble())
    with pytest.raises(InstallerError) as relative:
        run(installer.detect_target(IntegrationTarget("hermes", "relative/path")))
    assert relative.value.code == "target_path_invalid"

    hermes, _ = hermes_target(tmp_path / "profiles")
    mismatched = IntegrationTarget(hermes.engine, hermes.path, "other", "0.16.0")
    with pytest.raises(InstallerError) as mismatch:
        run(installer.detect_target(mismatched))
    assert mismatch.value.code == "profile_mismatch"

    empty, _ = opencode_target(tmp_path / "empty", version=None, config="{}")
    with pytest.raises(InstallerError) as version:
        run(installer.detect_target(empty))
    assert version.value.code == "version_required"

    broken, _ = opencode_target(tmp_path / "broken", config='{"mcp": {"servers": }')
    with pytest.raises(InstallerError) as malformed:
        run(installer.detect_target(broken))
    assert malformed.value.code == "config_invalid"


# --------------------------------------------------------------------------- Hermes


def test_hermes_install_preserves_user_config_and_verifies_real_mcp(
    tmp_path: Path,
    catalog: CatalogDouble,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, home = hermes_target(tmp_path)
    original = """\
# operator comment stays
model: openai/gpt
agent:
  disabled_toolsets: []
mcp_servers:
  # a user-owned server
  other:
    url: http://example.invalid/mcp
    headers:
      Authorization: Bearer user-token
platform_toolsets:
  cli: [file]
"""
    (home / "config.yaml").write_text(original)
    receipt = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert receipt["status"] == "configured"
    assert receipt["verified"] is False
    assert receipt["mcpVerified"] is True
    assert receipt["profileSafetyVerified"] is False
    assert checks(receipt)["mcp.handshake"] == "pass"
    assert checks(receipt)["mcp.query"] == "pass"
    assert receipt["profile"] == "itsm"
    assert receipt["identityId"] == "integration-1"

    text = (home / "config.yaml").read_text()
    assert "# operator comment stays" in text
    assert "# a user-owned server" in text
    parsed = yaml_config(home / "config.yaml")
    assert parsed["model"] == "openai/gpt"
    assert parsed["agent"] == {"disabled_toolsets": []}
    assert parsed["mcp_servers"]["other"]["headers"]["Authorization"] == "Bearer user-token"
    assert parsed["mcp_servers"]["itsm"] == {
        "url": mcp_server["url"],
        "headers": {"Authorization": f"Bearer ${{{TOKEN_ENV}}}"},
        "enabled": True,
        "tools": {"resources": False, "prompts": False},
    }
    assert parsed["platform_toolsets"]["cli"] == ["file"]
    assert parsed["platform_toolsets"]["api_server"] == ["itsm", "skills"]
    skill = home / "skills" / "itsm-inventory" / "SKILL.md"
    assert skill.read_bytes() == catalog.skills["itsm-inventory"]["SKILL.md"]
    manifest_text = (home / ".itsm-agent" / "manifest.json").read_text()
    assert mcp_server["token"] not in text
    assert mcp_server["token"] not in manifest_text
    assert mcp_server["token"] not in json.dumps(receipt)


def test_hermes_reinstall_is_idempotent_and_update_preserves_user_files(
    tmp_path: Path,
    catalog: CatalogDouble,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, home = hermes_target(tmp_path)
    args = {
        "mcp": mcp_spec(mcp_server),
        "skills": ["itsm-inventory"],
        "operation": "install",
    }
    first = run(installer.apply(target, **args))
    assert first["status"] == "configured"
    assert first["mcpVerified"] is True
    config_before = (home / "config.yaml").read_bytes()
    manifest_before = (home / ".itsm-agent" / "manifest.json").read_bytes()
    second = run(installer.apply(target, **args))
    assert second["status"] == "configured"
    assert second["mcpVerified"] is True
    assert (home / "config.yaml").read_bytes() == config_before
    assert (home / ".itsm-agent" / "manifest.json").read_bytes() == manifest_before

    user_file = home / "skills" / "itsm-inventory" / "USER.md"
    user_file.write_text("my local note\n")
    catalog.set_file("itsm-inventory", "SKILL.md", b"---\nname: itsm-inventory\n---\nv2\n")
    updated = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory", "itsm-monitoring"],
            operation="update",
        )
    )
    assert updated["status"] == "configured"
    assert updated["mcpVerified"] is True
    assert (home / "skills" / "itsm-inventory" / "SKILL.md").read_bytes().endswith(b"v2\n")
    assert user_file.read_text() == "my local note\n"
    assert (home / "skills" / "itsm-monitoring" / "SKILL.md").is_file()

    managed = home / "skills" / "itsm-monitoring" / "SKILL.md"
    managed.write_text("tampered\n")
    conflict = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory", "itsm-monitoring"],
            operation="update",
        )
    )
    assert conflict["status"] == "conflict"
    assert conflict["verified"] is False
    assert managed.read_text() == "tampered\n"
    repaired = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory", "itsm-monitoring"],
            operation="repair",
        )
    )
    assert repaired["status"] == "configured", repaired.get("error")
    assert repaired["mcpVerified"] is True
    assert managed.read_bytes() == catalog.skills["itsm-monitoring"]["SKILL.md"]


def test_hermes_conflicts_preserve_preexisting_and_customized_entries(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, home = hermes_target(tmp_path / "preexisting")
    original = (
        "mcp_servers:\n"
        "  itsm:\n"
        "    url: http://user.invalid/mcp\n"
        "    enabled: true\n"
        "platform_toolsets:\n"
        "  api_server: [itsm, skills]\n"
    )
    (home / "config.yaml").write_text(original)
    receipt = run(
        installer.apply(
            target, mcp=mcp_spec(mcp_server), skills=["itsm-inventory"], operation="install"
        )
    )
    assert receipt["status"] == "conflict"
    assert (home / "config.yaml").read_text() == original
    assert not (home / "skills").exists()
    assert not (home / ".itsm-agent").exists()

    installed, installed_home = hermes_target(tmp_path / "customized")
    assert (
        run(
            installer.apply(
                installed,
                mcp=mcp_spec(mcp_server),
                skills=["itsm-inventory"],
                operation="install",
            )
        )["status"]
        == "configured"
    )
    changed = installed_home / "config.yaml"
    changed.write_text(changed.read_text().replace("enabled: true", "enabled: false # mine"))
    before = changed.read_bytes()
    conflict = run(
        installer.apply(
            installed,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="update",
        )
    )
    assert conflict["status"] == "conflict"
    assert changed.read_bytes() == before

    disabled_target, disabled_home = hermes_target(tmp_path / "disabled")
    (disabled_home / "config.yaml").write_text(
        "agent:\n  disabled_toolsets: [itsm]\nmcp_servers: {}\n"
    )
    disabled = run(
        installer.apply(
            disabled_target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert disabled["status"] == "conflict"
    assert not (disabled_home / "skills").exists()

    other_target, other_home = hermes_target(tmp_path / "other-toolsets")
    (other_home / "config.yaml").write_text("platform_toolsets:\n  api_server: [hermes, web]\n")
    other = run(
        installer.apply(
            other_target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert other["status"] == "conflict"
    assert (other_home / "config.yaml").read_text() == (
        "platform_toolsets:\n  api_server: [hermes, web]\n"
    )


def test_hermes_disable_and_uninstall_remove_only_managed_resources(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, home = hermes_target(tmp_path)
    (home / "config.yaml").write_text(
        "# keep\nmcp_servers:\n  other:\n    url: http://example.invalid/mcp\n"
    )
    assert (
        run(
            installer.apply(
                target,
                mcp=mcp_spec(mcp_server),
                skills=["itsm-inventory"],
                operation="install",
            )
        )["status"]
        == "configured"
    )
    user_file = home / "skills" / "itsm-inventory" / "USER.md"
    user_file.write_text("keep me\n")
    disabled = run(
        installer.apply(
            target, mcp=mcp_spec(mcp_server), skills=["itsm-inventory"], operation="disable"
        )
    )
    assert disabled["status"] == "disabled"
    assert disabled["verified"] is False
    parsed = yaml_config(home / "config.yaml")
    assert parsed["mcp_servers"]["itsm"]["enabled"] is False
    assert not (home / "skills" / "itsm-inventory" / "SKILL.md").exists()
    assert user_file.read_text() == "keep me\n"
    config_bytes = (home / "config.yaml").read_bytes()
    again = run(
        installer.apply(
            target, mcp=mcp_spec(mcp_server), skills=["itsm-inventory"], operation="disable"
        )
    )
    assert again["status"] == "disabled"
    assert (home / "config.yaml").read_bytes() == config_bytes

    removed = run(
        installer.apply(
            target, mcp=mcp_spec(mcp_server), skills=["itsm-inventory"], operation="uninstall"
        )
    )
    assert removed["status"] == "removed", removed.get("error")
    final = yaml_config(home / "config.yaml")
    assert "itsm" not in final["mcp_servers"]
    assert final["mcp_servers"]["other"]["url"] == "http://example.invalid/mcp"
    assert "# keep" in (home / "config.yaml").read_text()
    assert user_file.read_text() == "keep me\n"
    assert not (home / ".itsm-agent").exists()


# --------------------------------------------------------------------------- OpenCode v2


def test_opencode_v2_install_uses_restricted_agent_and_preserves_comments(
    tmp_path: Path,
    catalog: CatalogDouble,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, workspace = opencode_target(
        tmp_path,
        config="""\
{
  // keep this header comment
  "permissions": [
    {"action": "shell", "resource": "git status", "effect": "allow"}
  ],
  "mcp": {
    "servers": {
      "other": {"type": "remote", "url": "http://example.invalid/mcp", "enabled": true}
    }
  },
  "agents": {"other": {"mode": "primary"}}
}
""",
    )
    receipt = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory", "itsm-monitoring"],
            operation="install",
        )
    )
    assert receipt["status"] == "configured"
    assert receipt["mcpVerified"] is True
    assert receipt["profileSafetyVerified"] is False
    assert receipt["format"] == "v2"
    text = (workspace / "opencode.json").read_text()
    assert "// keep this header comment" in text
    parsed = json_config(workspace / "opencode.json")
    assert parsed["permissions"] == [
        {"action": "shell", "resource": "git status", "effect": "allow"}
    ]
    assert parsed["mcp"]["servers"]["other"]["url"] == "http://example.invalid/mcp"
    itsm = parsed["mcp"]["servers"]["itsm"]
    assert itsm["type"] == "remote"
    assert itsm["url"] == mcp_server["url"]
    assert itsm["disabled"] is False
    assert itsm["codemode"] is False
    assert "enabled" not in itsm
    assert itsm["oauth"] is False
    assert itsm["headers"]["Authorization"] == f"Bearer {{env:{TOKEN_ENV}}}"
    agent = parsed["agents"]["itsm"]
    assert agent["mode"] == "primary"
    assert agent["disabled"] is False
    permissions = agent["permissions"]
    assert permissions[0] == {"action": "*", "resource": "*", "effect": "deny"}
    assert {"action": "itsm_*", "resource": "*", "effect": "allow"} in permissions
    assert {
        "action": "skill",
        "resource": "itsm-inventory",
        "effect": "allow",
    } in permissions
    assert {
        "action": "skill",
        "resource": "itsm-monitoring",
        "effect": "allow",
    } in permissions
    assert parsed["default_agent"] == "itsm"
    assert parsed["agents"]["other"] == {"mode": "primary"}
    assert (workspace / ".opencode" / "skills" / "itsm-inventory" / "SKILL.md").is_file()
    assert mcp_server["token"] not in text
    assert mcp_server["token"] not in json.dumps(receipt)


def test_opencode_v2_disable_uses_canonical_mcp_state(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, workspace = opencode_target(tmp_path)
    assert (
        run(
            installer.apply(
                target,
                mcp=mcp_spec(mcp_server),
                skills=["itsm-inventory"],
                operation="install",
            )
        )["status"]
        == "configured"
    )
    disabled = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="disable",
        )
    )
    assert disabled["status"] == "disabled"
    entry = json_config(workspace / "opencode.json")["mcp"]["servers"]["itsm"]
    assert entry["disabled"] is True
    assert entry["codemode"] is False
    assert "enabled" not in entry


def test_opencode_v2_fresh_install_is_byte_idempotent(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, workspace = opencode_target(tmp_path)
    first = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert first["status"] == "configured"
    assert first["mcpVerified"] is True
    before = {
        path.relative_to(workspace).as_posix(): path.read_bytes()
        for path in workspace.rglob("*")
        if path.is_file()
    }
    assert json_config(workspace / ".itsm-agent" / "manifest.json")["config"][
        "existsBefore"
    ] is False
    second = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert second["status"] == "configured"
    assert second["mcpVerified"] is True
    after = {
        path.relative_to(workspace).as_posix(): path.read_bytes()
        for path in workspace.rglob("*")
        if path.is_file()
    }
    assert after == before
    assert json_config(workspace / ".itsm-agent" / "manifest.json")["config"][
        "existsBefore"
    ] is False


def opencode_runtime_evidence(
    receipt: dict[str, Any],
    workspace: Path,
    *,
    permissions: list[dict[str, str]] | None = None,
    saved: list[dict[str, str]] | None = None,
    default_agent: str = "itsm",
    directory: str | None = None,
) -> dict[str, Any]:
    if permissions is None:
        parsed = json_config(workspace / "opencode.json")
        permissions = parsed["agents"]["itsm"]["permissions"]
    return {
        "source": "opencode:http://127.0.0.1:1",
        "verified": True,
        "configDigest": receipt["configDigest"],
        "targetPath": str(workspace),
        "location": {"directory": directory or str(workspace)},
        "agent": {"id": "itsm", "name": "itsm", "mode": "primary", "permissions": permissions},
        "config": [
            {"type": "directory", "path": str(workspace)},
            {
                "type": "document",
                "path": str(workspace / "opencode.json"),
                "info": {"default_agent": default_agent},
            },
        ],
        "savedPermissions": saved or [],
        "checks": [
            {"name": "runtime.agent", "status": "pass", "detail": "agent.itsm inspected"},
            {"name": "runtime.saved", "status": "pass", "detail": "saved permissions inspected"},
        ],
    }


def evidence_inspector(evidence: dict[str, Any] | None) -> Any:
    async def inspect(**_: Any) -> dict[str, Any] | None:
        return evidence

    return inspect


def test_opencode_runtime_effective_permissions_follow_last_match(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, workspace = opencode_target(tmp_path)
    installed = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    actual_rules = [
        {"action": "*", "resource": "*", "effect": "allow"},
        {"action": "read", "resource": "*.env", "effect": "ask"},
        {"action": "read", "resource": "*.env.*", "effect": "ask"},
        {"action": "read", "resource": "*.env.example", "effect": "allow"},
        {"action": "*", "resource": "*", "effect": "deny"},
        {"action": "itsm_*", "resource": "*", "effect": "allow"},
        {"action": "skill", "resource": "*", "effect": "deny"},
        {"action": "skill", "resource": "itsm-inventory", "effect": "allow"},
        {"action": "browser", "resource": "*", "effect": "deny"},
    ]
    evidence = opencode_runtime_evidence(
        installed,
        workspace,
        permissions=actual_rules,
        saved=[
            {"action": "bash", "resource": "*", "effect": "deny"},
            {"action": "skill", "resource": "other", "effect": "deny"},
        ],
    )
    projected = json.loads(json.dumps(evidence))
    projected["agent"].pop("name")
    projected["config"][1].pop("path")
    verified = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="verify",
            profile_inspector=evidence_inspector(projected),
        )
    )
    assert verified["status"] == "verified"
    assert verified["profileSafetyVerified"] is True


def test_opencode_runtime_evidence_is_required_and_validated(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, workspace = opencode_target(tmp_path)
    installed = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert installed["status"] == "configured"
    evidence = opencode_runtime_evidence(installed, workspace)
    captured: dict[str, Any] = {}

    async def inspector(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return evidence

    verified = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="verify",
            profile_inspector=inspector,
        )
    )
    assert verified["status"] == "verified"
    assert verified["verified"] is True
    assert verified["profileSafetyVerified"] is True
    assert checks(verified)["profile.safety"] == "pass"
    assert captured["target"] == target
    assert captured["mcp"] == mcp_spec(mcp_server)
    assert captured["skills"] == ("itsm-inventory",)
    assert captured["config_digest"] == installed["configDigest"]
    assert mcp_server["token"] not in json.dumps(verified)

    unsafe_rules = json.loads(json.dumps(evidence))
    unsafe_rules["agent"]["permissions"].append(
        {"action": "bash", "resource": "*", "effect": "allow"}
    )
    unsafe = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="verify",
            profile_inspector=evidence_inspector(unsafe_rules),
        )
    )
    assert unsafe["status"] == "configured"
    assert unsafe["profileSafetyVerified"] is False
    assert checks(unsafe)["profile.safety"] == "fail"

    saved_override = opencode_runtime_evidence(
        installed,
        workspace,
        saved=[{"action": "bash", "resource": "git status", "effect": "allow"}],
    )
    overridden = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="verify",
            profile_inspector=evidence_inspector(saved_override),
        )
    )
    assert overridden["status"] == "configured"
    assert overridden["profileSafetyVerified"] is False

    saved_ask = opencode_runtime_evidence(
        installed,
        workspace,
        saved=[{"action": "bash", "resource": "git status", "effect": "ask"}],
    )
    approval = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="verify",
            profile_inspector=evidence_inspector(saved_ask),
        )
    )
    assert approval["status"] == "configured"
    assert approval["profileSafetyVerified"] is False

    wrong_workspace = opencode_runtime_evidence(
        installed, workspace, directory=str(tmp_path / "elsewhere")
    )
    mismatch = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="verify",
            profile_inspector=evidence_inspector(wrong_workspace),
        )
    )
    assert mismatch["status"] == "configured"
    assert mismatch["profileSafetyVerified"] is False

    unavailable = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="verify",
            profile_inspector=evidence_inspector(None),
        )
    )
    assert unavailable["status"] == "configured"
    assert unavailable["verified"] is False
    assert checks(unavailable)["profile.safety"] == "fail"

    async def broken(**_: Any) -> dict[str, Any]:
        raise RuntimeError("engine unavailable")

    failed = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="verify",
            profile_inspector=broken,
        )
    )
    assert failed["status"] == "configured"
    assert failed["verified"] is False
    assert failed["profileSafetyVerified"] is False
    assert checks(failed)["profile.safety"] == "fail"


def test_caller_supplied_profile_safety_cannot_verify(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, workspace = opencode_target(tmp_path)
    installed = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    forged = opencode_runtime_evidence(installed, workspace)
    forged["source"] = "opencode:forged"
    result = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="verify",
            profile_safety=forged,
        )
    )
    assert result["status"] == "configured"
    assert result["verified"] is False
    assert result["profileSafetyVerified"] is False
    assert checks(result)["profile.safety"] == "fail"
    detail = next(item["detail"] for item in result["checks"] if item["name"] == "profile.safety")
    assert "untrusted" in detail


def test_initial_install_can_verify_with_trusted_inspector(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, workspace = opencode_target(tmp_path)
    calls: list[tuple[IntegrationTarget, str]] = []

    async def inspector(
        *, target: IntegrationTarget, mcp: Any, skills: Any, config_digest: str
    ) -> dict[str, Any]:
        calls.append((target, config_digest))
        assert target.path == str(workspace)
        assert mcp["url"] == mcp_spec(mcp_server)["url"]
        assert skills == ("itsm-inventory",)
        assert (workspace / "opencode.json").is_file()
        assert (workspace / ".opencode" / "skills" / "itsm-inventory" / "SKILL.md").is_file()
        return opencode_runtime_evidence({"configDigest": config_digest}, workspace)

    receipt = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
            profile_inspector=inspector,
        )
    )
    assert receipt["status"] == "verified"
    assert receipt["verified"] is True
    assert receipt["profileSafetyVerified"] is True
    assert [digest for _, digest in calls] == [receipt["configDigest"]]
    assert calls[0][0].path == str(workspace)
    assert checks(receipt)["profile.safety"] == "pass"


def test_hermes_runtime_evidence_requires_live_profile_binding(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, home = hermes_target(tmp_path)
    installed = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert installed["status"] == "configured"
    evidence = {
        "source": "hermes:http://127.0.0.1:1",
        "verified": True,
        "configDigest": installed["configDigest"],
        "targetPath": str(home),
        "runtime": {
            "profile": "itsm",
            "home": str(home),
            "capabilities": {"chat": True, "mcp": True, "models": ["test-model"]},
        },
        "checks": [{"name": "runtime.profile", "status": "pass", "detail": "profile bound"}],
    }
    verified = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="verify",
            profile_inspector=evidence_inspector(evidence),
        )
    )
    assert verified["status"] == "verified"
    assert verified["profileSafetyVerified"] is True

    yaml_only = dict(evidence)
    yaml_only.pop("runtime")
    unproven = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="verify",
            profile_inspector=evidence_inspector(yaml_only),
        )
    )
    assert unproven["status"] == "configured"
    assert unproven["profileSafetyVerified"] is False

    raw_evidence = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="verify",
            profile_safety=evidence,
        )
    )
    assert raw_evidence["status"] == "configured"
    assert raw_evidence["verified"] is False
    assert raw_evidence["profileSafetyVerified"] is False


def test_duplicate_jsonc_keys_fail_before_any_write(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
) -> None:
    original = """\
{
  // user comment
  "mcp": {"servers": {"other": {"type": "remote", "url": "http://example.invalid/mcp"}}},
  "mcp": {"servers": {}}
}
"""
    target, workspace = opencode_target(tmp_path, config=original)
    receipt = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert receipt["status"] == "failed"
    assert receipt["error"]["code"] == "config_invalid"
    assert (workspace / "opencode.json").read_text() == original
    assert not (workspace / ".opencode").exists()
    assert not (workspace / ".itsm-agent").exists()


def test_opencode_v2_conflicts_preserve_existing_agent_and_default(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    preexisting, _ = opencode_target(
        tmp_path / "preexisting",
        config='{"mcp": {"servers": {"itsm": {"type": "remote", "url": "http://x"}}}}',
    )
    receipt = run(
        installer.apply(
            preexisting,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert receipt["status"] == "conflict"
    assert not (Path(preexisting.path) / ".itsm-agent").exists()

    default, default_root = opencode_target(
        tmp_path / "default", config='{"default_agent": "build"}'
    )
    original = (default_root / "opencode.json").read_bytes()
    conflict = run(
        installer.apply(
            default,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert conflict["status"] == "conflict"
    assert (default_root / "opencode.json").read_bytes() == original

    custom, custom_root = opencode_target(
        tmp_path / "agent", config='{"agents": {"itsm": {"mode": "primary"}}}'
    )
    custom_before = (custom_root / "opencode.json").read_bytes()
    custom_conflict = run(
        installer.apply(
            custom,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert custom_conflict["status"] == "conflict"
    assert (custom_root / "opencode.json").read_bytes() == custom_before


def test_opencode_v2_tamper_conflicts_and_uninstall_preserves_user_sections(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, workspace = opencode_target(
        tmp_path,
        config="""\
{
  // user comment
  "permissions": [{"action": "webfetch", "resource": "*", "effect": "allow"}],
  "mcp": {"servers": {"other": {"type": "remote", "url": "http://example.invalid/mcp"}}}
}
""",
    )
    assert (
        run(
            installer.apply(
                target,
                mcp=mcp_spec(mcp_server),
                skills=["itsm-inventory"],
                operation="install",
            )
        )["status"]
        == "configured"
    )
    text = (workspace / "opencode.json").read_text()
    tampered = text.replace(mcp_server["url"], "http://tampered.invalid/mcp")
    (workspace / "opencode.json").write_text(tampered)
    conflict = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="update",
        )
    )
    assert conflict["status"] == "conflict"
    assert (workspace / "opencode.json").read_text() == tampered

    removed = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="uninstall",
        )
    )
    assert removed["status"] == "removed"
    final_text = (workspace / "opencode.json").read_text()
    assert "// user comment" in final_text
    final = json_config(workspace / "opencode.json")
    assert final["permissions"] == [{"action": "webfetch", "resource": "*", "effect": "allow"}]
    assert final["mcp"]["servers"]["other"]["url"] == "http://example.invalid/mcp"
    assert "itsm" not in final["mcp"]["servers"]
    assert "itsm" not in final.get("agents", {})
    assert "default_agent" not in final
    assert not (workspace / ".opencode" / "skills" / "itsm-inventory" / "SKILL.md").exists()
    assert not (workspace / ".itsm-agent").exists()


# --------------------------------------------------------------------------- OpenCode v1


def test_opencode_v1_install_shapes_and_uninstall_preserve_user_resources(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    target, workspace = opencode_target(
        tmp_path / "v1",
        version="1.2.0",
        config="""\
{
  // v1 comment
  "permission": {"edit": "allow"},
  "mcp": {"other": {"type": "remote", "url": "http://example.invalid/mcp"}},
  "agent": {"other": {"mode": "primary"}}
}
""",
    )
    receipt = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert receipt["status"] == "configured"
    assert receipt["mcpVerified"] is True
    assert receipt["format"] == "v1"
    parsed = json_config(workspace / "opencode.json")
    assert parsed["permission"] == {"edit": "allow"}
    assert parsed["mcp"]["other"]["url"] == "http://example.invalid/mcp"
    assert parsed["mcp"]["itsm"]["enabled"] is True
    assert "disabled" not in parsed["mcp"]["itsm"]
    assert "codemode" not in parsed["mcp"]["itsm"]
    assert parsed["mcp"]["itsm"]["headers"]["Authorization"] == f"Bearer {{env:{TOKEN_ENV}}}"
    assert "servers" not in parsed["mcp"]
    permission = parsed["agent"]["itsm"]["permission"]
    assert permission["*"] == "deny"
    assert permission["itsm_*"] == "allow"
    assert permission["skill"]["*"] == "deny"
    assert permission["skill"]["itsm-inventory"] == "allow"
    removed = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="uninstall",
        )
    )
    assert removed["status"] == "removed"
    final = json_config(workspace / "opencode.json")
    assert final["permission"] == {"edit": "allow"}
    assert final["mcp"]["other"]["url"] == "http://example.invalid/mcp"
    assert "itsm" not in final["mcp"]
    assert "itsm" not in final["agent"]
    assert "// v1 comment" in (workspace / "opencode.json").read_text()


# --------------------------------------------------------------------------- safety


def test_symlink_and_catalog_traversal_are_rejected_without_writes(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    verified_token: str,
    catalog: CatalogDouble,
) -> None:
    target, home = hermes_target(tmp_path / "symlink")
    outside = tmp_path / "outside"
    outside.mkdir()
    (home / "skills").mkdir()
    (home / "skills" / "itsm-inventory").symlink_to(outside, target_is_directory=True)
    receipt = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert receipt["status"] == "failed"
    assert receipt["verified"] is False
    assert list(outside.iterdir()) == []
    assert not (home / ".itsm-agent").exists()

    traversal, traversal_home = hermes_target(tmp_path / "traversal")
    traversal_catalog = CatalogDouble(
        {"itsm-inventory": {"SKILL.md": b"ok", "../escape.md": b"escape"}}
    )
    traversal_installer = IntegrationInstaller(catalog=traversal_catalog)
    escaped = run(
        traversal_installer.apply(
            traversal,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert escaped["status"] == "failed"
    assert not (traversal_home / "escape.md").exists()
    assert not (traversal_home / "skills" / "escape.md").exists()

    link_target, link_home = hermes_target(tmp_path / "config-link")
    real = tmp_path / "real-config.yaml"
    real.write_text("model: keep\n")
    (link_home / "config.yaml").unlink()
    (link_home / "config.yaml").symlink_to(real)
    linked = run(
        installer.apply(
            link_target,
            mcp=mcp_spec(mcp_server),
            skills=[],
            operation="install",
        )
    )
    assert linked["status"] == "failed"
    assert real.read_text() == "model: keep\n"


def test_failed_or_missing_proof_never_claims_installed(
    tmp_path: Path,
    installer: IntegrationInstaller,
    mcp_server: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, home = hermes_target(tmp_path / "missing")
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    missing = run(
        installer.apply(
            target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert missing["status"] == "configured"
    assert missing["verified"] is False
    assert checks(missing)["mcp.secret"] == "fail"
    assert (home / "skills" / "itsm-inventory" / "SKILL.md").is_file()

    wrong_target, _ = hermes_target(tmp_path / "wrong")
    monkeypatch.setenv(TOKEN_ENV, "not-a-valid-token")
    wrong = run(
        installer.apply(
            wrong_target,
            mcp=mcp_spec(mcp_server),
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert wrong["status"] == "configured"
    assert wrong["verified"] is False
    assert checks(wrong)["mcp.handshake"] == "fail"

    closed_target, _ = hermes_target(tmp_path / "closed")
    monkeypatch.setenv(TOKEN_ENV, mcp_server["token"])
    unreachable = run(
        installer.apply(
            closed_target,
            mcp={
                "url": "http://127.0.0.1:1/mcp",
                "secretRef": TOKEN_ENV,
                "identityId": "integration-1",
            },
            skills=["itsm-inventory"],
            operation="install",
        )
    )
    assert unreachable["status"] == "configured"
    assert unreachable["verified"] is False


# --------------------------------------------------------------------------- remote helper


def canonical_helper_root() -> Path:
    import itsm.agent_integrations.catalog as module

    return Path(module.__file__).absolute().parents[2]


def normalized_digest(value: str) -> str:
    return value if value.startswith("sha256:") else f"sha256:{value}"


def test_remote_request_helper_round_trip_and_receipt_validation(
    tmp_path: Path,
    mcp_server: dict[str, Any],
    verified_token: str,
) -> None:
    pytest.importorskip(
        "itsm.agent_integrations.catalog",
        reason="canonical skill catalog is not available to this helper",
    )
    from itsm.agent_integrations.catalog import SkillCatalog

    canonical = SkillCatalog()
    helper_root = canonical_helper_root()
    target, home = hermes_target(tmp_path / "remote")
    request = build_request(
        target,
        mcp=mcp_spec(mcp_server),
        skills=["itsm-inventory"],
        operation="install",
        catalog=canonical,
    )
    assert request["schemaVersion"] == 1
    assert request["kind"] == "itsm-agent-installer-request"
    assert request["skillDigests"]["itsm-inventory"] == normalized_digest(
        canonical.get_skill("itsm-inventory")["digest"]
    )
    assert request["requestDigest"].startswith("sha256:")
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request))
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    environment["PYTHONPATH"] = str(helper_root)
    environment[TOKEN_ENV] = mcp_server["token"]
    process = subprocess.run(
        [sys.executable, "-m", "itsm.agent_integrations", "--request", str(request_path)],
        cwd=helper_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert process.returncode == 0, (process.stderr, process.stdout)
    receipt = json.loads(process.stdout)
    assert receipt["kind"] == "itsm-agent-installer-receipt"
    assert receipt["requestDigest"] == request["requestDigest"]
    assert receipt["status"] == "configured"
    assert receipt["verified"] is False
    assert receipt["mcpVerified"] is True
    assert receipt["profileSafetyVerified"] is False
    assert receipt["identityId"] == "integration-1"
    assert receipt["configDigest"].startswith("sha256:")
    assert receipt["manifestDigest"].startswith("sha256:")
    assert receipt["skillDigests"]["itsm-inventory"] == normalized_digest(
        canonical.get_skill("itsm-inventory")["digest"]
    )
    assert receipt["receiptDigest"].startswith("sha256:")
    assert mcp_server["token"] not in process.stdout
    assert (home / ".itsm-agent" / "manifest.json").is_file()
    validation = validate_receipt(receipt, request=request)
    assert validation["valid"] is True, validation["errors"]
    tampered = json.loads(json.dumps(receipt))
    tampered["configDigest"] = "sha256:" + "0" * 64
    assert validate_receipt(tampered, request=request)["valid"] is False
    connection = run(verify_connection(mcp_spec(mcp_server)))
    assert connection["verified"] is True
    assert connection["toolCount"] and connection["toolCount"] > 1


def test_remote_helper_rejects_request_tamper_and_expected_manifest_mismatch(
    tmp_path: Path,
    catalog: CatalogDouble,
    mcp_server: dict[str, Any],
) -> None:
    pytest.importorskip(
        "itsm.agent_integrations.catalog",
        reason="canonical skill catalog is not available to this helper",
    )
    from itsm.agent_integrations.catalog import SkillCatalog

    canonical = SkillCatalog()
    helper_root = canonical_helper_root()
    target, home = opencode_target(tmp_path / "remote", version="2.1.2")
    request = build_request(
        target,
        mcp=mcp_spec(mcp_server),
        skills=["itsm-inventory"],
        operation="install",
        catalog=catalog,
    )
    request["skillDigests"]["itsm-inventory"] = "sha256:" + "0" * 64
    request_path = tmp_path / "tampered.json"
    request_path.write_text(json.dumps(request))
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    environment["PYTHONPATH"] = str(helper_root)
    environment[TOKEN_ENV] = mcp_server["token"]
    process = subprocess.run(
        [sys.executable, "-m", "itsm.agent_integrations", "--request", str(request_path)],
        cwd=helper_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert process.returncode == 1
    failed = json.loads(process.stdout)
    assert failed["status"] in {"failed", "conflict"}
    assert failed["verified"] is False
    assert not (home / "opencode.json").exists()
    assert not (home / ".itsm-agent").exists()

    valid_request = build_request(
        target,
        mcp=mcp_spec(mcp_server),
        skills=["itsm-inventory"],
        operation="update",
        expected_manifest_digest="sha256:" + "0" * 64,
        catalog=canonical,
    )
    valid_path = tmp_path / "expected.json"
    valid_path.write_text(json.dumps(valid_request))
    mismatch = subprocess.run(
        [sys.executable, "-m", "itsm.agent_integrations", "--request", str(valid_path)],
        cwd=helper_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert mismatch.returncode == 1
    assert json.loads(mismatch.stdout)["status"] == "failed"
    assert not (home / "opencode.json").exists()


def test_cli_rejects_malformed_request_file(tmp_path: Path, mcp_server: dict[str, Any]) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    environment["PYTHONPATH"] = str(BACKEND_ROOT)
    process = subprocess.run(
        [sys.executable, "-m", "itsm.agent_integrations", "--request", str(broken)],
        cwd=BACKEND_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert process.returncode == 1
    receipt = json.loads(process.stdout)
    assert receipt["status"] == "failed"
    assert receipt["verified"] is False
    assert receipt["error"]["code"] == "request_invalid"
