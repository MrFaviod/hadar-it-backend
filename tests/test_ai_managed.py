"""Disposable managed-run lifecycle: real loopback child, isolated profiles, no inference.

Every test drives a real ``serve`` process (a generated Python stand-in that
listens on the assigned loopback port and forks a grandchild) through the public
runner API. Adapters are injected so the tests exercise process ownership,
profile material and lease-key isolation without speaking a native protocol.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from itsm.agents.engines import EngineConfig, EngineError, EngineInfo
from itsm.agents.hermes import HermesEngine
from itsm.agents.managed import (
    ADMISSION_ONLY,
    GATEWAY_KEY_ENV,
    GATEWAY_PROVIDER_ID,
    ManagedEngineError,
    ManagedEngineRunner,
    ManagedEngineSettings,
    ManagedProfileInputs,
    native_engine,
)
from itsm.agents.opencode import OpenCodeEngine

GATEWAY = "http://127.0.0.1:8123/api/v1/agent/gateway/v1"
LEASE_TOKEN = "run-scoped-opaque-token"
MCP_TOKEN = "integration-identity-token"
MODEL = "gpt-5-mini"

_FAKE_ENGINE = """#!{python}
import json
import os
import base64
import pathlib
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

IGNORE_SIGTERM = {ignore}
CONFIG_CASE = {config_case!r}
OBSERVATION = {observation!r}


def _option(argv, *names):
    for index, value in enumerate(argv):
        if value in names and index + 1 < len(argv):
            return argv[index + 1]
    return None


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/api/config":
            expected = "Basic " + base64.b64encode(
                ("opencode:" + os.environ.get("OPENCODE_SERVER_PASSWORD", "")).encode()
            ).decode()
            if self.headers.get("Authorization") != expected:
                self.send_error(401)
                return
            profile = pathlib.Path.cwd()
            if parse_qs(parsed.query).get("location[directory]") != [str(profile)]:
                self.send_error(400)
                return
            entries = [
                {{"type": "directory", "path": str(profile / ".opencode")}},
                {{"type": "document", "path": str(profile / "opencode.json"), "info": {{}}}},
            ]
            case = CONFIG_CASE
            changed = profile / "config-evidence.json"
            if changed.exists():
                entries = json.loads(changed.read_text())
            elif case == "foreign_directory":
                entries[0]["path"] = str(profile.parent / "foreign")
            elif case == "foreign_document":
                entries[1]["path"] = str(profile.parent / "external.json")
                entries[1]["info"] = {{"apiKey": "foreign-secret-do-not-log"}}
            elif case == "system":
                entries.append({{"type": "directory", "path": "/etc/opencode"}})
            elif case == "pathless":
                entries[1].pop("path")
            elif case == "duplicate":
                entries.append(entries[1])
            elif case == "missing_directory":
                entries.pop(0)
            elif case == "nested_directory":
                entries[0]["path"] = str(profile / ".opencode" / "unapproved")
            elif case == "malformed":
                entries = {{"data": entries}}
            elif case == "unknown_kind":
                entries[0]["type"] = "other"
            body = json.dumps(entries).encode()
            content_type = "application/json"
        else:
            body = b"ok"
            content_type = "text/plain"
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


def main():
    argv = sys.argv[1:]
    profile = pathlib.Path.cwd()
    host = _option(argv, "--host", "--hostname") or "127.0.0.1"
    port = int(_option(argv, "--port"))
    grandchild_code = (
        "import signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "time.sleep(120)"
    )
    grandchild = subprocess.Popen([sys.executable, "-c", grandchild_code])
    record = {{
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "argv": argv,
        "cwd": str(profile),
        "grandchild": grandchild.pid,
        "env": {{
            name: os.environ.get(name)
            for name in (
                "ITSM_AI_GATEWAY_TOKEN",
                "HOME",
                "HERMES_HOME",
                "OPENCODE_CONFIG",
                "OPENCODE_CONFIG_DIR",
                "OPENCODE_DISABLE_PROJECT_CONFIG",
                "OPENCODE_TEST_HOME",
                "OPENCODE_DISABLE_CLAUDE_CODE",
                "OPENCODE_DISABLE_CLAUDE_CODE_SKILLS",
                "OPENCODE_DISABLE_MODELS_FETCH",
                "XDG_CONFIG_HOME",
                "XDG_DATA_HOME",
                "XDG_STATE_HOME",
                "XDG_CACHE_HOME",
                "ITSM_AGENT_MCP_TOKEN",
                "HERMES_DASHBOARD_BASIC_AUTH_USERNAME",
                "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD",
                "HERMES_DASHBOARD_BASIC_AUTH_SECRET",
                "OPENCODE_SERVER_PASSWORD",
            )
        }},
        "envNames": sorted(os.environ),
    }}
    (profile / "engine-run.json").write_text(json.dumps(record), encoding="utf-8")
    pathlib.Path(OBSERVATION).write_text(json.dumps(record), encoding="utf-8")
    server = ThreadingHTTPServer((host, port), _Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def _stop(*_args):
        (profile / "terminated").write_text("graceful", encoding="utf-8")
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, signal.SIG_IGN if IGNORE_SIGTERM else _stop)
    while True:
        time.sleep(0.05)


main()
"""


def _write_fake_engine(
    tmp_path: Path, *, ignore_sigterm: bool = False, config_case: str = "valid"
) -> Path:
    path = tmp_path / "fake-native-engine"
    path.write_text(
        _FAKE_ENGINE.format(
            python=sys.executable,
            ignore=ignore_sigterm,
            config_case=config_case,
            observation=str(tmp_path / "native-observed.json"),
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _settings(tmp_path: Path, binary: Path, **overrides: Any) -> ManagedEngineSettings:
    values: dict[str, Any] = {
        "hermes_binary": str(binary),
        "opencode_binary": str(binary),
        "profile_root": str(tmp_path / "profiles"),
        "startup_timeout_seconds": 5.0,
        "shutdown_timeout_seconds": 1.0,
    }
    values.update(overrides)
    return ManagedEngineSettings(**values)


@dataclass(frozen=True, slots=True)
class _Lease:
    lease_id: str = "lease-1"
    bearer_token: str = LEASE_TOKEN
    run_id: str = "run-1"
    model: str = MODEL
    context_tokens: int = 20_000
    output_tokens: int = 1_000


class _FakeAdapter:
    """Loopback adapter that proves the managed child is the one answering."""

    def __init__(self, behavior: str = "ready") -> None:
        self.behavior = behavior
        self.engine: str | None = None
        self.config: EngineConfig | None = None
        self.profile: Path | None = None
        self.record: dict[str, Any] | None = None
        self.calls: list[tuple[Any, ...]] = []
        self.closed = False
        self.discoveries = 0

    async def _load_record(self) -> dict[str, Any]:
        assert self.profile is not None
        path = self.profile / "engine-run.json"
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if path.exists():
                payload = json.loads(path.read_text(encoding="utf-8"))
                self.record = payload
                return payload
            await asyncio.sleep(0.02)
        raise EngineError("unreachable", "engine is unreachable", retryable=True)

    async def discover(self) -> EngineInfo:
        self.discoveries += 1
        assert self.config is not None
        record = await self._load_record()
        if self.behavior == "auth_failure":
            raise EngineError("forbidden", "engine rejected the request", retryable=False)
        if self.behavior == "never_ready":
            raise EngineError("unreachable", "engine is unreachable", retryable=True)
        assert record["cwd"] == str(self.profile)
        try:
            async with httpx.AsyncClient(timeout=1.0) as client:
                response = await client.get(self.config.base_url + "/ready")
        except httpx.HTTPError:
            raise EngineError("unreachable", "engine is unreachable", retryable=True) from None
        if response.status_code != 200:
            raise EngineError("unreachable", "engine is unreachable", retryable=True)
        return EngineInfo(version="fake-1.0", models=[], capabilities={"sessions": True})

    async def create_session(self) -> str:
        self.calls.append(("create_session",))
        return "session-1"

    async def stream(self, message: str, *, session_id: str, **kwargs: Any):
        self.calls.append(("stream", message, session_id, kwargs.get("model")))
        yield {"type": "session", "sessionId": session_id}
        yield {"type": "final", "text": f"echo:{message}"}

    async def cancel(self, session_id: str) -> None:
        self.calls.append(("cancel", session_id))

    async def close(self) -> None:
        self.calls.append(("close",))
        self.closed = True


def _factory(holder: dict[str, Any], behavior: str = "ready"):
    def build(engine: str, config: EngineConfig) -> _FakeAdapter:
        adapter = _FakeAdapter(behavior)
        adapter.engine = engine
        adapter.config = config
        adapter.profile = Path(config.directory or "")
        holder["adapter"] = adapter
        return adapter

    return build


def _instance(engine: str) -> SimpleNamespace:
    return SimpleNamespace(engine=engine, name=f"Managed {engine}")


def _skill_tree(root: Path, name: str = "itsm-inventory") -> Path:
    skill = root / "skills" / name
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: inventory help\n---\n\n# {name}\n",
        encoding="utf-8",
    )
    (skill / "references").mkdir()
    (skill / "references" / "guide.md").write_text("guía\n", encoding="utf-8")
    return skill


def _profile_inputs(root: Path, *, skills: bool = True, mcp: bool = True) -> ManagedProfileInputs:
    return ManagedProfileInputs(
        mcp_url="http://127.0.0.1:8000/api/v1/mcp" if mcp else None,
        mcp_token=MCP_TOKEN if mcp else None,
        skill_paths=(str(_skill_tree(root)),) if skills else (),
        project_root=str(root),
    )


def _wait_dead(pid: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return True
        time.sleep(0.05)
    return False


def _assert_dead(pid: int) -> None:
    assert _wait_dead(pid), f"process {pid} is still alive"


def _text_files(root: Path) -> str:
    """Profile text written by the runner; the stand-in's own record is excluded."""

    return "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in root.rglob("*")
        if path.is_file() and path.name != "engine-run.json"
    )


def test_opencode_run_is_disposable_and_isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-inherited")
    binary = _write_fake_engine(tmp_path)
    profile_root = tmp_path / "project"
    profile_root.mkdir()
    inputs = _profile_inputs(profile_root)

    async def scenario() -> tuple[Path, dict[str, Any], dict[str, Any], Path]:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary),
            _instance("opencode"),
            _Lease(),
            GATEWAY,
            profile=inputs,
            engine_factory=_factory(holder),
        )
        async with runner as active:
            assert active is runner
            assert runner.pid is not None
            assert os.getpgid(runner.pid) == runner.pid
            profile = runner.profile_dir
            assert profile is not None
            record = holder["adapter"].record
            while record is None:
                await asyncio.sleep(0.02)
                record = holder["adapter"].record
            config = json.loads((profile / "opencode.json").read_text(encoding="utf-8"))
            events = [event async for event in runner.stream("hola", session_id="session-1")]
            assert events[-1] == {"type": "final", "text": "echo:hola"}
            adapter_config = holder["adapter"].config
            assert record["env"]["OPENCODE_SERVER_PASSWORD"] == adapter_config.password
            assert adapter_config.username == "opencode"
            assert adapter_config.password != LEASE_TOKEN
            assert adapter_config.password != MCP_TOKEN
            assert runner.native_model == f"{GATEWAY_PROVIDER_ID}/{MODEL}"
            assert runner.status()["enforcement"] == ADMISSION_ONLY
            assert runner.status()["strict"] is False
            assert profile.is_dir()
        assert not profile.exists()
        assert holder["adapter"].closed is True
        return profile, record, config, profile

    profile, record, config, _ = asyncio.run(scenario())

    assert record["argv"][0] == "serve"
    assert record["argv"][1:3] == ["--hostname", "127.0.0.1"]
    assert record["ppid"] > 0
    provider = config["provider"][GATEWAY_PROVIDER_ID]
    assert provider["npm"] == "@ai-sdk/openai-compatible"
    assert provider["options"]["baseURL"] == GATEWAY
    assert provider["options"]["apiKey"] == f"{{env:{GATEWAY_KEY_ENV}}}"
    assert list(provider["models"]) == [MODEL]
    assert provider["models"][MODEL]["limit"] == {
        "context": 21_000,
        "input": 20_000,
        "output": 1_000,
    }
    assert config["model"] == f"{GATEWAY_PROVIDER_ID}/{MODEL}"
    permissions = config["agents"]["itsm"]["permissions"]
    assert {"action": "itsm_*", "resource": "*", "effect": "allow"} in permissions
    assert {"action": "*", "resource": "*", "effect": "deny"} in permissions
    mcp = config["mcp"]["servers"]["itsm"]
    assert mcp["url"] == "http://127.0.0.1:8000/api/v1/mcp"
    assert mcp["headers"]["Authorization"] == "Bearer {env:ITSM_AGENT_MCP_TOKEN}"
    assert mcp["disabled"] is False

    env = record["env"]
    assert env[GATEWAY_KEY_ENV] == LEASE_TOKEN
    assert env["ITSM_AGENT_MCP_TOKEN"] == MCP_TOKEN
    assert env["HOME"] == str(profile / "home")
    assert env["OPENCODE_CONFIG"] == str(profile / "opencode.json")
    assert env["OPENCODE_CONFIG_DIR"] == str(profile / ".opencode")
    assert env["OPENCODE_DISABLE_PROJECT_CONFIG"] == "1"
    assert env["OPENCODE_TEST_HOME"] == str(profile / "home")
    assert env["OPENCODE_DISABLE_CLAUDE_CODE"] == "1"
    assert env["OPENCODE_DISABLE_CLAUDE_CODE_SKILLS"] == "1"
    assert env["OPENCODE_DISABLE_MODELS_FETCH"] == "1"
    for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"):
        assert env[key] == str(profile / key.removeprefix("XDG_").removesuffix("_HOME").lower())
    assert not any("API_KEY" in name for name in record["envNames"])
    assert "OPENAI_API_KEY" not in record["envNames"]
    assert "ITSM_AI_GATEWAY_TOKEN" in record["envNames"]


@pytest.mark.parametrize(
    "config_case",
    [
        "foreign_directory",
        "foreign_document",
        "system",
        "pathless",
        "duplicate",
        "missing_directory",
        "nested_directory",
        "malformed",
        "unknown_kind",
    ],
)
def test_opencode_foreign_config_fails_before_discovery_or_dispatch(
    tmp_path: Path, config_case: str, caplog: pytest.LogCaptureFixture
):
    binary = _write_fake_engine(tmp_path, config_case=config_case)

    async def scenario() -> None:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary),
            _instance("opencode"),
            _Lease(),
            GATEWAY,
            engine_factory=_factory(holder),
        )
        try:
            with pytest.raises(ManagedEngineError) as error:
                await runner.start()
            assert error.value.code == "startup_failed"
            assert "foreign-secret" not in error.value.message
            adapter = holder["adapter"]
            assert adapter.discoveries == 0
            assert adapter.calls == [("close",)]
            assert runner.profile_dir is None
        finally:
            await runner.aclose()

    asyncio.run(scenario())
    record = json.loads((tmp_path / "native-observed.json").read_text())
    _assert_dead(record["pid"])
    _assert_dead(record["grandchild"])
    assert not Path(record["cwd"]).exists()
    assert "foreign-secret" not in caplog.text
    assert "/etc/opencode" not in caplog.text


def test_opencode_rechecks_origins_before_dispatch(tmp_path: Path):
    binary = _write_fake_engine(tmp_path)

    async def scenario() -> None:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary),
            _instance("opencode"),
            _Lease(),
            GATEWAY,
            engine_factory=_factory(holder),
        )
        async with runner:
            profile = runner.profile_dir
            assert profile is not None
            assert await runner.create_session() == "session-1"
            (profile / "config-evidence.json").write_text(
                json.dumps(
                    [
                        {"type": "directory", "path": "/etc/opencode"},
                    ]
                )
            )
            with pytest.raises(ManagedEngineError):
                async for _ in runner.stream("do not dispatch", session_id="session-1"):
                    pass
            assert holder["adapter"].calls == [("create_session",)]
            await runner.cancel("session-1")
            assert holder["adapter"].calls[-1] == ("cancel", "session-1")

    asyncio.run(scenario())


@pytest.mark.parametrize("field", ["context_tokens", "output_tokens"])
@pytest.mark.parametrize("value", [None, True, 0, -1, "10", 1.5, 10_000_001])
def test_lease_bounds_fail_before_native_launch(tmp_path: Path, field: str, value: Any):
    fields = {
        "lease_id": "lease-1",
        "run_id": "run-1",
        "bearer_token": LEASE_TOKEN,
        "model": MODEL,
        "context_tokens": 20_000,
        "output_tokens": 1_000,
    }
    fields[field] = value
    with pytest.raises(ManagedEngineError) as error:
        ManagedEngineRunner(
            _settings(tmp_path, _write_fake_engine(tmp_path)),
            _instance("opencode"),
            SimpleNamespace(**fields),
            GATEWAY,
        )
    assert error.value.code == "misconfigured"
    assert not (tmp_path / "profiles").exists()
    assert not (tmp_path / "native-observed.json").exists()


def test_each_run_gets_a_fresh_profile(tmp_path: Path):
    binary = _write_fake_engine(tmp_path)

    async def scenario() -> tuple[Path, Path]:
        seen: list[Path] = []
        for _ in range(2):
            holder: dict[str, Any] = {}
            runner = ManagedEngineRunner(
                _settings(tmp_path, binary),
                _instance("hermes"),
                _Lease(),
                GATEWAY,
                engine_factory=_factory(holder),
            )
            async with runner:
                assert runner.profile_dir is not None
                seen.append(runner.profile_dir)
            assert not seen[-1].exists()
        return seen[0], seen[1]

    first, second = asyncio.run(scenario())
    assert first != second


def test_hermes_profile_pins_gateway_and_safe_toolsets(tmp_path: Path):
    binary = _write_fake_engine(tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    inputs = _profile_inputs(project)

    async def scenario() -> tuple[Path, dict[str, Any]]:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary),
            _instance("hermes"),
            _Lease(),
            GATEWAY,
            profile=inputs,
            engine_factory=_factory(holder),
        )
        async with runner:
            profile = runner.profile_dir
            assert profile is not None
            record = holder["adapter"].record
            while record is None:
                await asyncio.sleep(0.02)
                record = holder["adapter"].record
            body = (profile / "config.yaml").read_text(encoding="utf-8")
            copied = (profile / "skills" / "itsm-inventory" / "SKILL.md").read_text(
                encoding="utf-8"
            )
            assert "name: itsm-inventory" in copied
            assert (profile / "skills" / "itsm-inventory" / "references" / "guide.md").is_file()
            assert LEASE_TOKEN not in body
            assert MCP_TOKEN not in body
            profile_text = _text_files(profile)
            assert LEASE_TOKEN not in profile_text
            assert MCP_TOKEN not in profile_text
            adapter_config = holder["adapter"].config
            assert record["env"]["HERMES_DASHBOARD_BASIC_AUTH_USERNAME"] == "admin"
            assert record["env"]["HERMES_DASHBOARD_BASIC_AUTH_PASSWORD"] == adapter_config.password
            assert record["env"]["HERMES_DASHBOARD_BASIC_AUTH_SECRET"]
            assert adapter_config.username == "admin"
            assert adapter_config.password != LEASE_TOKEN
            assert adapter_config.password not in profile_text
            assert record["env"]["HERMES_DASHBOARD_BASIC_AUTH_SECRET"] not in profile_text
        return body, record

    body, record = asyncio.run(scenario())
    import yaml

    config = yaml.safe_load(body)
    assert config["model"] == {"provider": GATEWAY_PROVIDER_ID, "default": MODEL}
    provider = config["providers"][GATEWAY_PROVIDER_ID]
    assert provider["base_url"] == GATEWAY
    assert provider["key_env"] == GATEWAY_KEY_ENV
    assert config["platform_toolsets"]["cli"] == ["itsm", "skills"]
    mcp = config["mcp_servers"]["itsm"]
    assert mcp["url"] == "http://127.0.0.1:8000/api/v1/mcp"
    assert mcp["headers"]["Authorization"] == "Bearer ${ITSM_AGENT_MCP_TOKEN}"
    assert mcp["enabled"] is True

    assert record["argv"][0] == "serve"
    assert record["argv"][1:2] == ["--isolated"]
    assert record["env"]["HERMES_HOME"] == record["cwd"]
    assert record["env"][GATEWAY_KEY_ENV] == LEASE_TOKEN


def test_hermes_without_skills_uses_only_itsm_toolset(tmp_path: Path):
    binary = _write_fake_engine(tmp_path)

    async def scenario() -> str:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary),
            _instance("hermes"),
            _Lease(),
            GATEWAY,
            engine_factory=_factory(holder),
        )
        async with runner:
            profile = runner.profile_dir
            assert profile is not None
            return (profile / "config.yaml").read_text(encoding="utf-8")

    import yaml

    config = yaml.safe_load(asyncio.run(scenario()))
    assert config["platform_toolsets"]["cli"] == ["itsm"]
    assert "mcp_servers" not in config


def test_stream_is_pinned_to_the_lease_model(tmp_path: Path):
    binary = _write_fake_engine(tmp_path)

    async def scenario() -> list[tuple[Any, ...]]:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary),
            _instance("opencode"),
            _Lease(),
            GATEWAY,
            engine_factory=_factory(holder),
        )
        async with runner:
            assert await runner.create_session() == "session-1"
            events = [event async for event in runner.stream("hola", session_id="session-1")]
            assert events[0]["sessionId"] == "session-1"
            events = [
                event
                async for event in runner.stream(
                    "hola", session_id="session-1", model=runner.native_model
                )
            ]
            assert events
            with pytest.raises(ManagedEngineError):
                async for _ in runner.stream("hola", session_id="session-1", model="other-model"):
                    pass
            await runner.cancel("session-1")
            adapter = holder["adapter"]
            assert adapter.calls == [
                ("create_session",),
                ("stream", "hola", "session-1", None),
                ("stream", "hola", "session-1", None),
                ("cancel", "session-1"),
            ]
            return adapter.calls

    asyncio.run(scenario())


def test_missing_binary_fails_closed_before_any_profile(tmp_path: Path):
    settings = ManagedEngineSettings(
        hermes_binary=str(tmp_path / "missing-hermes"),
        profile_root=str(tmp_path / "profiles"),
    )
    runner = ManagedEngineRunner(settings, _instance("hermes"), _Lease(), GATEWAY)

    async def scenario() -> None:
        with pytest.raises(ManagedEngineError) as error:
            await runner.start()
        assert error.value.code in {"misconfigured", "unavailable"}
        assert runner.profile_dir is None

    asyncio.run(scenario())
    assert not (tmp_path / "profiles").exists() or list((tmp_path / "profiles").iterdir()) == []


def test_unconfigured_native_engine_fails_closed(tmp_path: Path):
    settings = ManagedEngineSettings(profile_root=str(tmp_path / "profiles"))
    runner = ManagedEngineRunner(settings, _instance("opencode"), _Lease(), GATEWAY)

    async def scenario() -> None:
        with pytest.raises(ManagedEngineError) as error:
            await runner.start()
        assert error.value.code == "misconfigured"

    asyncio.run(scenario())


def test_unsupported_engine_is_rejected(tmp_path: Path):
    with pytest.raises(ManagedEngineError) as error:
        ManagedEngineRunner(
            _settings(tmp_path, _write_fake_engine(tmp_path)),
            _instance("pydantic"),
            _Lease(),
            GATEWAY,
        )
    assert error.value.code == "unsupported"


@pytest.mark.parametrize(
    "gateway",
    [
        "http://user:secret@127.0.0.1:8123/api/v1/agent/gateway/v1",
        "https://127.0.0.1:8123/api/v1/agent/gateway",
        "ftp://127.0.0.1:8123/api/v1/agent/gateway/v1",
        "http://127.0.0.1:8123/api/v1/agent/gateway/v1?key=raw",
        "not-a-url",
    ],
)
def test_gateway_url_must_be_credential_free_v1(tmp_path: Path, gateway: str):
    with pytest.raises(ManagedEngineError) as error:
        ManagedEngineRunner(
            _settings(tmp_path, _write_fake_engine(tmp_path)),
            _instance("hermes"),
            _Lease(),
            gateway,
        )
    assert error.value.code == "misconfigured"


@pytest.mark.parametrize("token", ["", " ", "with\nnewline"])
def test_lease_token_must_be_opaque_and_non_empty(tmp_path: Path, token: str):
    with pytest.raises(ManagedEngineError) as error:
        ManagedEngineRunner(
            _settings(tmp_path, _write_fake_engine(tmp_path)),
            _instance("hermes"),
            _Lease(bearer_token=token),
            GATEWAY,
        )
    assert error.value.code == "misconfigured"


def test_profile_inputs_reject_paths_outside_the_project(tmp_path: Path):
    outside = tmp_path / "outside"
    skill = _skill_tree(outside)
    with pytest.raises(ManagedEngineError):
        ManagedProfileInputs(
            skill_paths=(str(skill),),
            project_root=str(tmp_path / "project"),
        )
    with pytest.raises(ManagedEngineError):
        ManagedProfileInputs(skill_paths=(str(skill),))
    with pytest.raises(ManagedEngineError):
        ManagedProfileInputs(mcp_token=MCP_TOKEN)
    with pytest.raises(ManagedEngineError):
        ManagedProfileInputs(mcp_url="http://127.0.0.1:8000/mcp", mcp_token_env="9bad-name")
    with pytest.raises(ManagedEngineError):
        ManagedProfileInputs(mcp_url="file:///tmp/mcp", mcp_token=MCP_TOKEN)


def test_skill_packages_materialize_exact_bytes_without_project_root(tmp_path: Path):
    binary = _write_fake_engine(tmp_path)
    package = {
        "SKILL.md": b"---\nname: itsm-catalog\ndescription: catalog help\n---\n\n# catalog\n",
        "references/data.bin": bytes(range(256)),
    }

    async def scenario() -> tuple[str, bytes]:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary),
            _instance("hermes"),
            _Lease(),
            GATEWAY,
            profile=ManagedProfileInputs(skill_packages={"itsm-catalog": package}),
            engine_factory=_factory(holder),
        )
        async with runner:
            profile = runner.profile_dir
            assert profile is not None
            body = (profile / "config.yaml").read_text(encoding="utf-8")
            written = (profile / "skills" / "itsm-catalog" / "references" / "data.bin").read_bytes()
            assert holder["adapter"].record is not None
        assert not profile.exists()
        return body, written

    body, written = asyncio.run(scenario())
    import yaml

    config = yaml.safe_load(body)
    assert config["platform_toolsets"]["cli"] == ["itsm", "skills"]
    assert written == package["references/data.bin"]


def test_skill_packages_are_allowed_by_the_opencode_agent(tmp_path: Path):
    binary = _write_fake_engine(tmp_path)

    async def scenario() -> dict[str, Any]:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary),
            _instance("opencode"),
            _Lease(),
            GATEWAY,
            profile=ManagedProfileInputs(
                skill_packages={"itsm-catalog": {"SKILL.md": b"# catalog\n"}}
            ),
            engine_factory=_factory(holder),
        )
        async with runner:
            profile = runner.profile_dir
            assert profile is not None
            assert (
                profile / ".opencode" / "skills" / "itsm-catalog" / "SKILL.md"
            ).read_bytes() == b"# catalog\n"
            return json.loads((profile / "opencode.json").read_text(encoding="utf-8"))

    config = asyncio.run(scenario())
    permissions = config["agents"]["itsm"]["permissions"]
    assert {"action": "skill", "resource": "itsm-catalog", "effect": "allow"} in permissions
    assert {"action": "skill", "resource": "*", "effect": "deny"} in permissions


@pytest.mark.parametrize(
    "packages",
    [
        {"../escape": {"SKILL.md": b"x"}},
        {"itsm-catalog": {"SKILL.md": b"x", "../escape.md": b"x"}},
        {"itsm-catalog": {"SKILL.md": b"x", "/absolute.md": b"x"}},
        {"itsm-catalog": {"SKILL.md": b"x", "nested\\escape.md": b"x"}},
        {"itsm-catalog": {"SKILL.md": "not bytes"}},
        {"itsm-catalog": {"README.md": b"x"}},
        {"itsm-catalog": {"SKILL.md": b"x", "refs": b"x", "refs/file.md": b"y"}},
        {"itsm-catalog": {"SKILL.md": b"x" * (2 * 1024 * 1024 + 1)}},
        {"itsm-catalog": b"not a mapping"},
    ],
)
def test_skill_packages_reject_unsafe_inputs(packages: dict[str, Any]):
    with pytest.raises(ManagedEngineError) as error:
        ManagedProfileInputs(skill_packages=packages)
    assert error.value.code == "misconfigured"


def test_skill_packages_share_the_path_skill_namespace(tmp_path: Path):
    project = tmp_path / "project"
    skill = _skill_tree(project)
    with pytest.raises(ManagedEngineError):
        ManagedProfileInputs(
            skill_paths=(str(skill),),
            skill_packages={"itsm-inventory": {"SKILL.md": b"# duplicate\n"}},
            project_root=str(project),
        )


def test_readiness_auth_failure_kills_the_run(tmp_path: Path):
    binary = _write_fake_engine(tmp_path)

    async def scenario() -> tuple[dict[str, Any], Path | None]:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary, startup_timeout_seconds=5.0),
            _instance("hermes"),
            _Lease(),
            GATEWAY,
            engine_factory=_factory(holder, "auth_failure"),
        )
        with pytest.raises(ManagedEngineError) as error:
            await runner.start()
        assert error.value.code == "startup_failed"
        adapter = holder["adapter"]
        assert adapter.record is not None
        return adapter.record, runner.profile_dir

    record, profile = asyncio.run(scenario())
    _assert_dead(record["pid"])
    _assert_dead(record["grandchild"])
    assert profile is None


def test_readiness_timeout_kills_child_and_grandchild(tmp_path: Path):
    binary = _write_fake_engine(tmp_path)

    async def scenario() -> tuple[dict[str, Any], Path | None, float]:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary, startup_timeout_seconds=0.5),
            _instance("opencode"),
            _Lease(),
            GATEWAY,
            engine_factory=_factory(holder, "never_ready"),
        )
        started = time.monotonic()
        with pytest.raises(ManagedEngineError) as error:
            await runner.start()
        elapsed = time.monotonic() - started
        assert error.value.code == "startup_failed"
        assert holder["adapter"].discoveries > 1
        return holder["adapter"].record, runner.profile_dir, elapsed

    record, profile, elapsed = asyncio.run(scenario())
    _assert_dead(record["pid"])
    _assert_dead(record["grandchild"])
    assert profile is None
    assert elapsed < 20


def test_close_terminates_owned_group_and_spares_other_processes(tmp_path: Path):
    binary = _write_fake_engine(tmp_path)
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])

    async def scenario() -> tuple[dict[str, Any], Path]:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary, shutdown_timeout_seconds=5.0),
            _instance("hermes"),
            _Lease(),
            GATEWAY,
            engine_factory=_factory(holder),
        )
        async with runner:
            adapter = holder["adapter"]
            while adapter.record is None:
                await asyncio.sleep(0.02)
            profile = runner.profile_dir
            assert profile is not None
        return adapter.record, profile

    try:
        record, profile = asyncio.run(scenario())
        assert unrelated.poll() is None
        _assert_dead(record["pid"])
        _assert_dead(record["grandchild"])
        assert not profile.exists()
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=10)


def test_ignored_sigterm_escalates_without_leaking_the_profile(tmp_path: Path):
    binary = _write_fake_engine(tmp_path, ignore_sigterm=True)

    async def scenario() -> tuple[dict[str, Any], Path, Path | None, float]:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary, shutdown_timeout_seconds=0.3),
            _instance("opencode"),
            _Lease(),
            GATEWAY,
            engine_factory=_factory(holder),
        )
        await runner.start()
        adapter = holder["adapter"]
        assert adapter.record is not None
        profile = runner.profile_dir
        assert profile is not None
        started = time.monotonic()
        await runner.aclose()
        return adapter.record, profile, runner.profile_dir, time.monotonic() - started

    record, profile, remaining, elapsed = asyncio.run(scenario())
    _assert_dead(record["pid"])
    _assert_dead(record["grandchild"])
    assert remaining is None
    assert not profile.exists()
    assert elapsed < 20


def test_each_run_gets_fresh_native_credentials(tmp_path: Path):
    binary = _write_fake_engine(tmp_path)

    async def scenario() -> list[tuple[str, str, str]]:
        seen: list[tuple[str, str, str]] = []
        for _ in range(2):
            holder: dict[str, Any] = {}
            runner = ManagedEngineRunner(
                _settings(tmp_path, binary),
                _instance("hermes"),
                _Lease(),
                GATEWAY,
                engine_factory=_factory(holder),
            )
            async with runner:
                adapter = holder["adapter"]
                while adapter.record is None:
                    await asyncio.sleep(0.02)
                record = adapter.record
                seen.append(
                    (
                        adapter.config.password,
                        record["env"]["HERMES_DASHBOARD_BASIC_AUTH_PASSWORD"],
                        record["env"]["HERMES_DASHBOARD_BASIC_AUTH_SECRET"],
                    )
                )
        return seen

    first, second = asyncio.run(scenario())
    assert first[0] == first[1]
    assert second[0] == second[1]
    assert first[0] != second[0]
    assert first[2] != second[2]


def test_leader_exit_does_not_orphan_an_ignoring_grandchild(tmp_path: Path):
    binary = _write_fake_engine(tmp_path)

    async def scenario() -> tuple[dict[str, Any], Path, Path | None]:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary, shutdown_timeout_seconds=0.3),
            _instance("hermes"),
            _Lease(),
            GATEWAY,
            engine_factory=_factory(holder),
        )
        await runner.start()
        adapter = holder["adapter"]
        assert adapter.record is not None
        profile = runner.profile_dir
        assert profile is not None
        await runner.aclose()
        return adapter.record, profile, runner.profile_dir

    record, profile, remaining = asyncio.run(scenario())
    _assert_dead(record["pid"])
    _assert_dead(record["grandchild"])
    assert remaining is None
    assert not profile.exists()


def test_cancelled_run_still_tears_down(tmp_path: Path):
    binary = _write_fake_engine(tmp_path)

    async def scenario() -> tuple[dict[str, Any], Path, Path | None]:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary, shutdown_timeout_seconds=1.0),
            _instance("hermes"),
            _Lease(),
            GATEWAY,
            engine_factory=_factory(holder),
        )
        entered = asyncio.Event()

        async def body() -> None:
            async with runner:
                adapter = holder["adapter"]
                while adapter.record is None:
                    await asyncio.sleep(0.02)
                entered.set()
                await asyncio.Event().wait()

        task = asyncio.create_task(body())
        await asyncio.wait_for(entered.wait(), timeout=10)
        adapter = holder["adapter"]
        assert adapter.record is not None
        profile = runner.profile_dir
        assert profile is not None
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert adapter.closed is True
        return adapter.record, profile, runner.profile_dir

    record, profile, remaining = asyncio.run(scenario())
    _assert_dead(record["pid"])
    _assert_dead(record["grandchild"])
    assert remaining is None
    assert not profile.exists()


def test_native_engine_factory_selects_both_adapters():
    hermes = native_engine("hermes", EngineConfig(base_url="http://127.0.0.1:1", directory="/tmp"))
    opencode = native_engine(
        "opencode", EngineConfig(base_url="http://127.0.0.1:1", directory="/tmp")
    )
    assert isinstance(hermes, HermesEngine)
    assert isinstance(opencode, OpenCodeEngine)

    async def close() -> None:
        await hermes.close()
        await opencode.close()

    asyncio.run(close())
    with pytest.raises(ManagedEngineError):
        native_engine("pydantic", EngineConfig(base_url="http://127.0.0.1:1"))


def test_run_scoped_key_is_the_only_ai_credential_in_a_personal_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """S11 guard: a personal provider key in the parent environment never reaches
    the disposable profile, the child environment or the native argv."""

    personal_key = "sk-personal-provider-must-stay-out"
    monkeypatch.setenv("OPENAI_API_KEY", personal_key)
    monkeypatch.setenv("ITSM_PERSONAL_PROVIDER_KEY", personal_key)
    binary = _write_fake_engine(tmp_path)
    profile_root = tmp_path / "project"
    profile_root.mkdir()
    inputs = _profile_inputs(profile_root)

    async def scenario() -> tuple[dict[str, Any], str]:
        holder: dict[str, Any] = {}
        runner = ManagedEngineRunner(
            _settings(tmp_path, binary),
            _instance("opencode"),
            _Lease(),
            GATEWAY,
            profile=inputs,
            engine_factory=_factory(holder),
        )
        async with runner as active:
            record = holder["adapter"].record
            while record is None:
                await asyncio.sleep(0.02)
                record = holder["adapter"].record
            profile = active.profile_dir
            assert profile is not None
            written = _text_files(profile)
            [event async for event in active.stream("hola", session_id="session-1")]
            return record, written

    record, written = asyncio.run(scenario())
    assert record["env"][GATEWAY_KEY_ENV] == LEASE_TOKEN
    assert not any("API_KEY" in name for name in record["envNames"])
    assert all(value is None or personal_key not in value for value in record["env"].values())
    assert all(personal_key not in argument for argument in record["argv"])
    assert personal_key not in written
    assert personal_key not in json.dumps(record["envNames"])
    assert GATEWAY_KEY_ENV in written


# ------------------------------------------------------- multimodal delivery
def _attachment(filename: str, media_type: str) -> Any:
    from itsm.agent_integrations.attachments import ChatAttachmentInput

    return ChatAttachmentInput(
        filename=filename, media_type=media_type, kind="image", data=b"\x89PNG\r\n\x1a\n"
    )


def test_opencode_v1_prompt_carries_documented_file_parts() -> None:
    from itsm.agents.opencode import _file_parts

    parts = _file_parts(
        [_attachment("foto.png", "image/png"), _attachment("informe.pdf", "application/pdf")]
    )

    assert parts == [
        {
            "type": "file",
            "mime": "image/png",
            "filename": "foto.png",
            "url": "data:image/png;base64,iVBORw0KGgo=",
        },
        {
            "type": "file",
            "mime": "application/pdf",
            "filename": "informe.pdf",
            "url": "data:application/pdf;base64,iVBORw0KGgo=",
        },
    ]


def test_opencode_v2_refuses_attachments_before_prompting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError("a refused attachment must not reach the engine")

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            engine = OpenCodeEngine(EngineConfig("http://127.0.0.1:9999"), client=client)
            engine._variant = "v2"
            stream = engine.stream(
                "mirá",
                session_id="ses_1",
                attachments=[_attachment("foto.png", "image/png")],
            )
            with pytest.raises(EngineError) as refused:
                await stream.__anext__()
            assert refused.value.code == "engine_attachments_unsupported"

    asyncio.run(run())
    assert calls == []


def test_hermes_refuses_attachments_instead_of_inventing_a_field() -> None:
    async def run() -> None:
        engine = HermesEngine(EngineConfig("http://127.0.0.1:9999"))
        stream = engine.stream(
            "mirá", session_id="ses_1", attachments=[_attachment("foto.png", "image/png")]
        )
        with pytest.raises(EngineError) as refused:
            await stream.__anext__()
        assert refused.value.code == "engine_attachments_unsupported"
        assert "text prompts only" in str(refused.value)

    asyncio.run(run())


@pytest.mark.parametrize(
    "name",
    [
        "ITSM_AI_GATEWAY_TOKEN",
        "itsm_ai_gateway_token",
        "HOME",
        "PATH",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
        "HERMES_HOME",
        "HERMES_DASHBOARD_BASIC_AUTH_USERNAME",
        "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD",
        "HERMES_DASHBOARD_BASIC_AUTH_SECRET",
        "OPENCODE_CONFIG",
        "OPENCODE_CONFIG_DIR",
        "OPENCODE_CONFIG_CONTENT",
        "OPENCODE_SERVER_PASSWORD",
        "OPENCODE_PASSWORD",
        "OPENCODE_TEST_HOME",
        "OPENCODE_DISABLE_PROJECT_CONFIG",
        "OPENCODE_DISABLE_CLAUDE_CODE",
        "OPENCODE_DISABLE_CLAUDE_CODE_SKILLS",
        "OPENCODE_DISABLE_MODELS_FETCH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
    ],
)
def test_reserved_mcp_environment_is_rejected_before_launch(name: str):
    with pytest.raises(ManagedEngineError, match="reserved"):
        ManagedProfileInputs(
            mcp_url="http://127.0.0.1:8000/mcp", mcp_token=MCP_TOKEN, mcp_token_env=name
        )


def test_dedicated_mcp_environment_remains_supported():
    inputs = ManagedProfileInputs(
        mcp_url="http://127.0.0.1:8000/mcp",
        mcp_token=MCP_TOKEN,
        mcp_token_env="ITSM_CUSTOM_MCP_TOKEN",
    )
    assert inputs.mcp_token_env == "ITSM_CUSTOM_MCP_TOKEN"
