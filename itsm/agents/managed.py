"""Disposable, one-run native engine processes for managed inference.

A managed run does not reuse a shared Hermes/OpenCode instance and never mutates
its provider settings: the runner prepares a fresh profile, launches the native
``serve`` binary as its own process group, binds that profile to the ITSM
gateway with an opaque run-scoped key, and tears the whole profile down when the
run ends. The generated profile and explicit child environment receive only
gateway/MCP credentials, not provider credentials. Host-file access and native
startup behavior are not sandboxed by this runner.

Enforcement is deliberately reported as ``admission_only``. The gateway can
enforce budget admission, model pinning, output caps and per-call accounting, but
this runner cannot prove the native process uses no other provider. Network
isolation is not implemented here, so nothing in this module may be described as
strict enforcement.

Transport translation stays in :mod:`itsm.agents.engines`: the runner delegates
``discover``/``create_session``/``stream``/``cancel``/``close`` to the existing
adapters. Lease revocation, ledger reservation and profile policy stay with the
caller; this module never releases or refunds quota.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import tempfile
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx
import yaml
from itsm.agent_integrations.installer import (
    DEFAULT_AGENT,
    SECRET_REFERENCE,
    _opencode_agent,
    _opencode_mcp,
)
from itsm.agents.engines import EngineConfig, EngineError
from itsm.agents.hermes import HermesEngine
from itsm.agents.opencode import OpenCodeEngine
from itsm.ai_gateway.service import MAX_CONTEXT_TOKENS, MAX_OUTPUT_TOKENS

logger = logging.getLogger(__name__)

GATEWAY_KEY_ENV = "ITSM_AI_GATEWAY_TOKEN"
GATEWAY_PROVIDER_ID = "itsm-quota"
GATEWAY_PROVIDER_NAME = "ITSM managed"
ADMISSION_ONLY = "admission_only"
ADMISSION_REASON = (
    "the run-scoped gateway key, model pinning and output caps are enforced, but the native "
    "process egress is not isolated or proven"
)

_ENGINES = frozenset({"hermes", "opencode"})
_LOOPBACK = "127.0.0.1"
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_SKILL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_READY_ATTEMPT_SECONDS = 2.0
_READY_POLL_SECONDS = 0.05
_KILL_WAIT_SECONDS = 5.0
_GROUP_POLL_SECONDS = 0.02
_MAX_SKILL_BYTES = 2 * 1024 * 1024
_MAX_SKILL_FILES = 200
_MAX_PROFILE_SKILLS = 20
_MAX_PROFILE_SKILL_BYTES = 8 * 1024 * 1024
_MAX_PROFILE_SKILL_FILES = 600
_BASE_ENV = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR")
_PROFILE_DIRS = ("home", "config", "data", "state", "cache")
_NATIVE_USERNAMES = {"hermes": "admin", "opencode": "opencode"}


class ManagedEngineError(EngineError):
    """Public, redacted managed-run failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, retryable=False)


class ManagedInstance(Protocol):
    """The persisted instance fields a managed run needs, nothing else."""

    engine: str
    name: str


class ManagedLease(Protocol):
    """Duck-compatible with the gateway's issued lease; only the run authority."""

    lease_id: str
    bearer_token: str
    run_id: str
    model: str
    context_tokens: int
    output_tokens: int


EngineFactory = Callable[[str, EngineConfig], Any]


@dataclass(frozen=True, slots=True)
class ManagedEngineSettings:
    """Server-resolved managed-run settings; never accepted from a chat client."""

    hermes_binary: str | None = None
    opencode_binary: str | None = None
    profile_root: str | None = None
    startup_timeout_seconds: float = 30.0
    shutdown_timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        for label, value, ceiling in (
            ("startup_timeout_seconds", self.startup_timeout_seconds, 300.0),
            ("shutdown_timeout_seconds", self.shutdown_timeout_seconds, 120.0),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not (0 < value <= ceiling)
            ):
                raise ManagedEngineError(
                    "misconfigured", f"{label} must be a positive number up to {ceiling:g}"
                )
        if self.profile_root is not None and not isinstance(self.profile_root, str):
            raise ManagedEngineError("misconfigured", "profile_root must be a path string")


@dataclass(frozen=True, slots=True)
class ManagedProfileInputs:
    """Verified, server-controlled profile material: MCP identity and skills.

    The caller resolves and attests the ITSM integration identity and the skill
    descriptors before constructing this value. Neither field accepts provider
    credentials, argv fragments or a shell environment.
    """

    mcp_url: str | None = None
    mcp_token: str | None = None
    mcp_token_env: str = "ITSM_AGENT_MCP_TOKEN"
    skill_paths: tuple[str, ...] = ()
    skill_packages: Mapping[str, Mapping[str, bytes]] = field(default_factory=dict)
    project_root: str | None = None

    def __post_init__(self) -> None:
        paths = self.skill_paths
        if not isinstance(paths, (tuple, list)):
            raise ManagedEngineError("misconfigured", "skill_paths must be a sequence of paths")
        object.__setattr__(self, "skill_paths", tuple(paths))
        packages = self.skill_packages
        if not isinstance(packages, Mapping):
            raise ManagedEngineError("misconfigured", "skill_packages must be a mapping")
        if self.mcp_url is None:
            if self.mcp_token is not None:
                raise ManagedEngineError(
                    "misconfigured", "an MCP token requires a server-controlled MCP URL"
                )
        else:
            _validate_mcp(self.mcp_url, self.mcp_token, self.mcp_token_env)
        root = _project_root(self.project_root) if self.project_root is not None else None
        if self.skill_paths and root is None:
            raise ManagedEngineError(
                "misconfigured", "verified skills require the project root they belong to"
            )
        names: set[str] = set()
        resolved: list[str] = []
        for raw in self.skill_paths:
            path = _skill_path(raw, root)
            folded = path.name.casefold()
            if folded in names:
                raise ManagedEngineError(
                    "misconfigured", f"duplicate managed skill name: {path.name}"
                )
            names.add(folded)
            resolved.append(str(path))
        object.__setattr__(self, "skill_paths", tuple(resolved))
        checked_packages: dict[str, Mapping[str, bytes]] = {}
        for name, files in packages.items():
            checked_name = _package_name(name)
            if checked_name.casefold() in names:
                raise ManagedEngineError(
                    "misconfigured", f"duplicate managed skill name: {checked_name}"
                )
            names.add(checked_name.casefold())
            checked_packages[checked_name] = MappingProxyType(_package_files(checked_name, files))
        object.__setattr__(self, "skill_packages", MappingProxyType(checked_packages))
        if root is not None:
            object.__setattr__(self, "project_root", str(root))


def native_engine(engine: str, config: EngineConfig) -> Any:
    """Build the native adapter for one managed engine; the default factory."""

    if engine == "hermes":
        return HermesEngine(config)
    if engine == "opencode":
        return OpenCodeEngine(config)
    raise ManagedEngineError("unsupported", "managed execution supports Hermes and OpenCode only")


class ManagedEngineRunner:
    """Own one disposable native engine process, profile and adapter.

    Construction validates every server-resolved input and fails closed. The
    run starts on :meth:`start` (or the async context manager) and is torn down
    exactly once by :meth:`aclose`; a cancelled run still terminates the owned
    process group and removes the profile before the cancellation propagates.
    """

    def __init__(
        self,
        settings: ManagedEngineSettings,
        instance: ManagedInstance,
        lease: ManagedLease,
        gateway_url: str,
        *,
        profile: ManagedProfileInputs | None = None,
        engine_factory: EngineFactory | None = None,
    ) -> None:
        if not isinstance(settings, ManagedEngineSettings):
            raise ManagedEngineError("misconfigured", "managed settings are required")
        self._settings = settings
        self._engine = _engine_name(instance)
        (
            self._lease_id,
            self._run_id,
            self._token,
            self._model,
            self._context_tokens,
            self._output_tokens,
        ) = _lease_fields(lease)
        self._gateway_url = _gateway_url(gateway_url)
        self._profile_inputs = profile
        self._factory = engine_factory or native_engine
        self._native_username = _NATIVE_USERNAMES[self._engine]
        self._native_password = secrets.token_urlsafe(32)
        self._native_secret = secrets.token_urlsafe(32)
        self._process: asyncio.subprocess.Process | None = None
        self._pgid: int | None = None
        self._adapter: Any = None
        self._port: int | None = None
        self._profile_path: Path | None = None
        self._cleanup_task: asyncio.Task[None] | None = None
        self._closed = False

    @property
    def engine(self) -> str:
        return self._engine

    @property
    def lease_id(self) -> str:
        return self._lease_id

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def profile_dir(self) -> Path | None:
        """The live private profile; ``None`` once the run is torn down."""

        return self._profile_path

    @property
    def pid(self) -> int | None:
        return self._process.pid if self._process is not None else None

    @property
    def base_url(self) -> str:
        if self._port is None:
            raise ManagedEngineError("unavailable", "the managed run is not active")
        return f"http://{_LOOPBACK}:{self._port}"

    @property
    def native_model(self) -> str:
        """The model reference the native engine must use for this run."""

        if self._engine == "opencode":
            return f"{GATEWAY_PROVIDER_ID}/{self._model}"
        return self._model

    def status(self) -> dict[str, object]:
        """Truthful capability summary; never claims strict enforcement."""

        return {
            "mode": "managed",
            "engine": self._engine,
            "enforcement": ADMISSION_ONLY,
            "strict": False,
            "reason": ADMISSION_REASON,
            "leaseId": self._lease_id,
            "runId": self._run_id,
            "model": self.native_model,
        }

    async def __aenter__(self) -> ManagedEngineRunner:
        return await self.start()

    async def __aexit__(self, *_exc_info: object) -> None:
        await self.aclose()

    async def start(self) -> ManagedEngineRunner:
        if self._closed:
            raise ManagedEngineError("unavailable", "the managed run is closed")
        if self._process is not None:
            raise ManagedEngineError("unavailable", "the managed run is already active")
        binary = _resolve_binary(self._settings, self._engine)
        profile = self._prepare_profile()
        self._profile_path = profile
        self._port = _reserve_loopback_port()
        argv = _argv(self._engine, binary, self._port)
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(profile),
                env=self._child_env(profile),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
            self._process = process
            if os.name == "posix":
                try:
                    if os.getpgid(process.pid) == process.pid:
                        self._pgid = process.pid
                except ProcessLookupError:
                    self._pgid = None
            self._adapter = self._factory(
                self._engine,
                EngineConfig(
                    base_url=self.base_url,
                    username=self._native_username,
                    password=self._native_password,
                    directory=str(profile),
                    agent=DEFAULT_AGENT,
                ),
            )
            await self._wait_ready()
        except BaseException:
            await self.aclose()
            raise
        return self

    async def discover(self) -> Any:
        await self._verify_opencode_profile()
        return await self._active().discover()

    async def create_session(self) -> str:
        await self._verify_opencode_profile()
        return await self._active().create_session()

    async def stream(
        self,
        message: str,
        *,
        session_id: str,
        model: str | None = None,
        history: object = None,
        attachments: Sequence[Any] = (),
    ) -> AsyncIterator[dict[str, object]]:
        adapter = self._active()
        if model is not None and model != self.native_model:
            raise ManagedEngineError(
                "misconfigured", "the managed run is pinned to its lease model"
            )
        await self._verify_opencode_profile()
        async for event in adapter.stream(
            message,
            session_id=session_id,
            model=None,
            history=history,
            attachments=attachments,
        ):
            yield event

    async def cancel(self, session_id: str) -> None:
        await self._active().cancel(session_id)

    async def aclose(self) -> None:
        """Terminate the child, reap it and delete the profile; idempotent."""

        if self._cleanup_task is None:
            if self._closed:
                return
            self._closed = True
            self._cleanup_task = asyncio.ensure_future(self._teardown())
        cleanup = self._cleanup_task
        cancelled = False
        while True:
            try:
                await asyncio.shield(cleanup)
                break
            except asyncio.CancelledError:
                cancelled = True
                if cleanup.done():
                    break
        if cancelled:
            raise asyncio.CancelledError

    def _active(self) -> Any:
        if self._closed or self._adapter is None:
            raise ManagedEngineError("unavailable", "the managed run is not active")
        return self._adapter

    def _prepare_profile(self) -> Path:
        configured_root = self._settings.profile_root
        root = Path(configured_root).expanduser() if configured_root else None
        profile: Path | None = None
        try:
            if root is not None:
                root.mkdir(mode=0o700, parents=True, exist_ok=True)
            profile = Path(
                tempfile.mkdtemp(prefix=f"itsm-managed-{self._engine}-", dir=str(root or None))
            )
            for name in _PROFILE_DIRS:
                (profile / name).mkdir(mode=0o700, exist_ok=True)
            if self._engine == "hermes":
                self._write_hermes_profile(profile)
            else:
                self._write_opencode_profile(profile)
        except ManagedEngineError:
            if profile is not None:
                shutil.rmtree(profile, ignore_errors=True)
            raise
        except OSError as exc:
            logger.warning("managed profile preparation failed: %s", type(exc).__name__)
            if profile is not None:
                shutil.rmtree(profile, ignore_errors=True)
            raise ManagedEngineError(
                "misconfigured", "the managed engine profile could not be prepared"
            ) from None
        return profile

    def _write_hermes_profile(self, profile: Path) -> None:
        inputs = self._profile_inputs
        skills = self._copy_skills(profile / "skills") if inputs is not None else []
        config: dict[str, Any] = {
            "model": {"provider": GATEWAY_PROVIDER_ID, "default": self._model},
            "providers": {
                GATEWAY_PROVIDER_ID: {
                    "name": GATEWAY_PROVIDER_NAME,
                    "base_url": self._gateway_url,
                    "key_env": GATEWAY_KEY_ENV,
                }
            },
            # The canonical safe CLI allowlist; no shell/filesystem/native toolset.
            "platform_toolsets": {"cli": ["itsm"] + (["skills"] if skills else [])},
        }
        if inputs is not None and inputs.mcp_url is not None:
            config["mcp_servers"] = {
                "itsm": {
                    "url": inputs.mcp_url,
                    "headers": {
                        "Authorization": f"Bearer ${{{inputs.mcp_token_env}}}",
                    },
                    "enabled": True,
                }
            }
        body = yaml.safe_dump(config, sort_keys=False)
        _write_private(profile / "config.yaml", body)

    def _write_opencode_profile(self, profile: Path) -> None:
        inputs = self._profile_inputs
        (profile / ".opencode").mkdir(mode=0o700, exist_ok=True)
        skill_names = (
            self._copy_skills(profile / ".opencode" / "skills") if inputs is not None else []
        )
        config: dict[str, Any] = {
            "provider": {
                GATEWAY_PROVIDER_ID: {
                    "npm": "@ai-sdk/openai-compatible",
                    "name": GATEWAY_PROVIDER_NAME,
                    "options": {
                        "baseURL": self._gateway_url,
                        "apiKey": f"{{env:{GATEWAY_KEY_ENV}}}",
                    },
                    "models": {
                        self._model: {
                            "name": self._model,
                            "limit": {
                                "input": self._context_tokens,
                                "output": self._output_tokens,
                                "context": self._context_tokens + self._output_tokens,
                            },
                        }
                    },
                }
            },
            # Pin the session default; the adapter never overrides the lease model.
            "model": self.native_model,
            "default_agent": DEFAULT_AGENT,
            # Reuse the installer's canonical agent ceiling instead of a new one.
            "agents": {DEFAULT_AGENT: _opencode_agent(skill_names)},
        }
        if inputs is not None and inputs.mcp_url is not None:
            config["mcp"] = {
                "servers": {
                    "itsm": _opencode_mcp(
                        {
                            "url": inputs.mcp_url,
                            "secretRef": inputs.mcp_token_env,
                        },
                        True,
                    )
                }
            }
        _write_private(profile / "opencode.json", json.dumps(config, indent=2) + "\n")

    def _copy_skills(self, destination: Path) -> list[str]:
        inputs = self._profile_inputs
        assert inputs is not None
        root = _project_root(inputs.project_root) if inputs.project_root else None
        if not inputs.skill_paths and not inputs.skill_packages:
            return []
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        names: list[str] = []
        total = [0, 0]
        for raw in inputs.skill_paths:
            source = _skill_path(raw, root)
            target = destination / source.name
            if target.exists():
                raise ManagedEngineError(
                    "misconfigured", f"duplicate managed skill name: {source.name}"
                )
            budget = [_MAX_SKILL_BYTES, _MAX_SKILL_FILES]
            _copy_skill_tree(source, target, budget)
            total[0] += _MAX_SKILL_BYTES - budget[0]
            total[1] += _MAX_SKILL_FILES - budget[1]
            names.append(source.name)
        for name in sorted(inputs.skill_packages):
            files = inputs.skill_packages[name]
            target = destination / name
            if target.exists():
                raise ManagedEngineError("misconfigured", f"duplicate managed skill name: {name}")
            budget = [_MAX_SKILL_BYTES, _MAX_SKILL_FILES]
            _write_skill_package(files, target, budget)
            total[0] += _MAX_SKILL_BYTES - budget[0]
            total[1] += _MAX_SKILL_FILES - budget[1]
            names.append(name)
        if (
            len(names) > _MAX_PROFILE_SKILLS
            or total[0] > _MAX_PROFILE_SKILL_BYTES
            or total[1] > _MAX_PROFILE_SKILL_FILES
        ):
            raise ManagedEngineError("misconfigured", "the managed skill set is too large")
        return names

    def _child_env(self, profile: Path) -> dict[str, str]:
        env = {name: os.environ[name] for name in _BASE_ENV if name in os.environ}
        env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
        env.update(
            {
                "HOME": str(profile / "home"),
                "XDG_CONFIG_HOME": str(profile / "config"),
                "XDG_DATA_HOME": str(profile / "data"),
                "XDG_STATE_HOME": str(profile / "state"),
                "XDG_CACHE_HOME": str(profile / "cache"),
                GATEWAY_KEY_ENV: self._token,
            }
        )
        if self._engine == "hermes":
            env["HERMES_HOME"] = str(profile)
            env["HERMES_DASHBOARD_BASIC_AUTH_USERNAME"] = self._native_username
            env["HERMES_DASHBOARD_BASIC_AUTH_PASSWORD"] = self._native_password
            env["HERMES_DASHBOARD_BASIC_AUTH_SECRET"] = self._native_secret
        else:
            env["OPENCODE_CONFIG"] = str(profile / "opencode.json")
            env["OPENCODE_CONFIG_DIR"] = str(profile / ".opencode")
            env["OPENCODE_TEST_HOME"] = str(profile / "home")
            env["OPENCODE_DISABLE_PROJECT_CONFIG"] = "1"
            env["OPENCODE_DISABLE_CLAUDE_CODE"] = "1"
            env["OPENCODE_DISABLE_CLAUDE_CODE_SKILLS"] = "1"
            env["OPENCODE_DISABLE_MODELS_FETCH"] = "1"
            env["OPENCODE_SERVER_PASSWORD"] = self._native_password
        inputs = self._profile_inputs
        if inputs is not None and inputs.mcp_token is not None:
            env[inputs.mcp_token_env] = inputs.mcp_token
        return env

    async def _verify_opencode_profile(self) -> None:
        """Reject foreign effective sources before ITSM dispatch, without logging them.

        This post-start check is not a filesystem or plugin-startup sandbox. It
        reuses the canonical native Config.Entry validator, not a permissive
        descendant-path test. Native versions without this evidence fail closed.
        """

        if self._engine != "opencode":
            return
        self._active()
        profile = self._profile_path
        assert profile is not None
        from itsm.agent_integrations.service import _config_profile_entries

        try:
            async with httpx.AsyncClient(trust_env=False, timeout=_READY_ATTEMPT_SECONDS) as client:
                response = await client.get(
                    self.base_url + "/api/config",
                    params={"location[directory]": str(profile)},
                    auth=(self._native_username, self._native_password),
                )
        except httpx.HTTPError:
            raise EngineError(
                "unreachable", "managed profile inspection is unavailable", retryable=True
            ) from None
        invalid = ManagedEngineError(
            "startup_failed", "the managed OpenCode configuration sources could not be verified"
        )
        if response.status_code != 200:
            raise invalid
        try:
            entries = response.json()
        except ValueError:
            raise invalid from None
        binding = _config_profile_entries(entries, str(profile))
        if binding is None:
            raise invalid
        _, documents = binding
        if os.path.realpath(documents[0]["path"]) != str(profile / "opencode.json"):
            raise invalid

    async def _wait_ready(self) -> None:
        adapter = self._adapter
        assert adapter is not None
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._settings.startup_timeout_seconds
        while True:
            process = self._process
            if process is not None and process.returncode is not None:
                raise ManagedEngineError(
                    "startup_failed",
                    f"the managed {self._engine} process exited before it was ready",
                )
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise ManagedEngineError(
                    "startup_failed",
                    f"the managed {self._engine} engine did not become ready in time",
                )
            try:
                async with asyncio.timeout(min(remaining, _READY_ATTEMPT_SECONDS)):
                    await self._verify_opencode_profile()
                    await adapter.discover()
                return
            except EngineError as exc:
                if not exc.retryable:
                    raise ManagedEngineError(
                        "startup_failed",
                        f"the managed {self._engine} engine failed discovery: {exc.message}",
                    ) from None
            except TimeoutError:
                pass
            except Exception as exc:  # public boundary: never leak transport details
                logger.warning("managed discovery failed: %s", type(exc).__name__)
                raise ManagedEngineError(
                    "startup_failed", "the managed engine discovery failed"
                ) from None
            await asyncio.sleep(_READY_POLL_SECONDS)

    async def _teardown(self) -> None:
        adapter, self._adapter = self._adapter, None
        if adapter is not None:
            try:
                async with asyncio.timeout(self._settings.shutdown_timeout_seconds):
                    await adapter.close()
            except Exception as exc:
                logger.warning("managed adapter close failed: %s", type(exc).__name__)
        process, self._process = self._process, None
        stopped = True
        if process is not None:
            stopped = await self._stop_process(process)
        profile, self._profile_path = self._profile_path, None
        if profile is not None:
            if stopped:
                shutil.rmtree(profile, ignore_errors=True)
            else:
                self._profile_path = profile
                raise ManagedEngineError(
                    "teardown_failed",
                    "the managed engine process did not exit; its profile was kept",
                )

    async def _stop_process(self, process: asyncio.subprocess.Process) -> bool:
        pgid = self._pgid
        if os.name != "posix" or pgid is None:
            return await self._stop_leader(process)
        if process.returncode is not None and not self._group_alive(pgid):
            return True
        self._kill_group(pgid, signal.SIGTERM)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(process.wait(), timeout=self._settings.shutdown_timeout_seconds)
        # The leader can exit while descendants in its group survive and ignore
        # SIGTERM; the group, not the leader, is the teardown boundary.
        if self._group_alive(pgid):
            self._kill_group(pgid, signal.SIGKILL)
            await self._wait_group_gone(pgid, _KILL_WAIT_SECONDS)
        if process.returncode is None:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(process.wait(), timeout=_KILL_WAIT_SECONDS)
        return not self._group_alive(pgid)

    async def _stop_leader(self, process: asyncio.subprocess.Process) -> bool:
        if process.returncode is not None:
            return True
        self._signal_leader(process, signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), timeout=self._settings.shutdown_timeout_seconds)
            return True
        except TimeoutError:
            pass
        self._signal_leader(process, signal.SIGKILL)
        try:
            await asyncio.wait_for(process.wait(), timeout=_KILL_WAIT_SECONDS)
            return True
        except TimeoutError:
            return False

    @staticmethod
    def _signal_leader(process: asyncio.subprocess.Process, sig: int) -> None:
        if process.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            process.send_signal(sig)

    @staticmethod
    def _kill_group(pgid: int, sig: int) -> None:
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return
        except OSError as exc:
            logger.warning("managed process-group signal failed: %s", type(exc).__name__)

    @staticmethod
    def _group_alive(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return True
        return True

    @staticmethod
    async def _wait_group_gone(pgid: int, timeout: float) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if not ManagedEngineRunner._group_alive(pgid):
                return
            await asyncio.sleep(_GROUP_POLL_SECONDS)


def _engine_name(instance: ManagedInstance) -> str:
    engine = getattr(instance, "engine", None)
    if not isinstance(engine, str) or engine not in _ENGINES:
        raise ManagedEngineError(
            "unsupported", "managed execution supports Hermes and OpenCode only"
        )
    return engine


def _bounded_text(value: object, label: str, limit: int = 200) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ManagedEngineError("misconfigured", f"the managed lease {label} is invalid")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ManagedEngineError("misconfigured", f"the managed lease {label} is invalid")
    return value


def _lease_fields(lease: ManagedLease) -> tuple[str, str, str, str, int, int]:
    lease_id = _bounded_text(getattr(lease, "lease_id", None), "lease_id")
    run_id = _bounded_text(getattr(lease, "run_id", None), "run_id")
    token = getattr(lease, "bearer_token", None)
    if (
        not isinstance(token, str)
        or not token
        or len(token) > 4096
        or any(char.isspace() or ord(char) < 0x20 for char in token)
    ):
        raise ManagedEngineError("misconfigured", "the managed lease token is invalid")
    model = getattr(lease, "model", None)
    if not isinstance(model, str) or _MODEL.fullmatch(model) is None:
        raise ManagedEngineError("misconfigured", "the managed lease model is invalid")
    bounds: list[int] = []
    for name, ceiling in (
        ("context_tokens", MAX_CONTEXT_TOKENS),
        ("output_tokens", MAX_OUTPUT_TOKENS),
    ):
        value = getattr(lease, name, None)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= ceiling:
            raise ManagedEngineError("misconfigured", f"the managed lease {name} is invalid")
        bounds.append(value)
    return lease_id, run_id, token, model, bounds[0], bounds[1]


def _gateway_url(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2000:
        raise ManagedEngineError("misconfigured", "the managed gateway URL is invalid")
    try:
        parts = urlsplit(value)
        _ = parts.port  # validates a numeric port without keeping it
    except ValueError:
        raise ManagedEngineError("misconfigured", "the managed gateway URL is invalid") from None
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        raise ManagedEngineError(
            "misconfigured", "the managed gateway URL must be a credential-free http(s) URL"
        )
    path = parts.path.rstrip("/")
    if not path.endswith("/v1"):
        raise ManagedEngineError(
            "misconfigured", "the managed gateway URL must be the OpenAI-compatible /v1 base"
        )
    return value.rstrip("/")


def _validate_mcp(url: str, token: str | None, token_env: str) -> None:
    if not isinstance(token_env, str) or SECRET_REFERENCE.fullmatch(token_env) is None:
        raise ManagedEngineError(
            "misconfigured", "the MCP token environment name must be an environment variable name"
        )
    if not isinstance(url, str) or len(url) > 2000:
        raise ManagedEngineError("misconfigured", "the MCP URL is invalid")
    try:
        parts = urlsplit(url)
        _ = parts.port
    except ValueError:
        raise ManagedEngineError("misconfigured", "the MCP URL is invalid") from None
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.fragment
    ):
        raise ManagedEngineError(
            "misconfigured", "the MCP URL must be an http(s) URL without credentials or fragments"
        )
    if (
        not isinstance(token, str)
        or not token
        or len(token) > 4096
        or any(char.isspace() or ord(char) < 0x20 for char in token)
    ):
        raise ManagedEngineError("misconfigured", "the MCP integration token is invalid")


def _project_root(value: str) -> Path:
    path = Path(value).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise ManagedEngineError(
            "misconfigured", "the managed skill project root does not exist"
        ) from None
    if not resolved.is_dir():
        raise ManagedEngineError(
            "misconfigured", "the managed skill project root is not a directory"
        )
    return resolved


def _skill_path(value: str, root: Path | None) -> Path:
    if not isinstance(value, str) or not value:
        raise ManagedEngineError("misconfigured", "a managed skill path is invalid")
    path = Path(value).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise ManagedEngineError("misconfigured", "a managed skill path does not exist") from None
    if not resolved.is_dir() or not (resolved / "SKILL.md").is_file():
        raise ManagedEngineError(
            "misconfigured", "a managed skill path must be a directory with SKILL.md"
        )
    if _SKILL_NAME.fullmatch(resolved.name) is None:
        raise ManagedEngineError("misconfigured", "a managed skill name is invalid")
    if root is not None and not resolved.is_relative_to(root):
        raise ManagedEngineError(
            "misconfigured", "verified skills must live below the project root"
        )
    return resolved


def _package_name(value: object) -> str:
    if not isinstance(value, str) or _SKILL_NAME.fullmatch(value) is None:
        raise ManagedEngineError("misconfigured", "a managed skill package name is invalid")
    return value


def _package_path(value: object) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or len(value) > 240:
        raise ManagedEngineError("misconfigured", "a managed skill file path is invalid")
    if "\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ManagedEngineError("misconfigured", "a managed skill file path is invalid")
    parts = tuple(value.split("/"))
    if len(parts) > 20 or any(not part or part in {".", ".."} or len(part) > 128 for part in parts):
        raise ManagedEngineError("misconfigured", "a managed skill file path is invalid")
    return parts


def _package_files(name: str, files: object) -> dict[str, bytes]:
    """Validate and copy an inert catalog package's byte map without altering it."""

    if not isinstance(files, Mapping) or not files:
        raise ManagedEngineError("misconfigured", f"managed skill {name} has no files")
    checked: dict[str, bytes] = {}
    for relative, content in files.items():
        key = "/".join(_package_path(relative))
        if key in checked:
            raise ManagedEngineError("misconfigured", f"managed skill {name} repeats a file path")
        if isinstance(content, (bytearray, memoryview)):
            content = bytes(content)
        if not isinstance(content, bytes):
            raise ManagedEngineError(
                "misconfigured", f"managed skill {name} contains a non-bytes file"
            )
        checked[key] = content
    directories = {
        "/".join(key.split("/")[:index])
        for key in checked
        for index in range(1, len(key.split("/")))
    }
    if directories.intersection(checked):
        raise ManagedEngineError(
            "misconfigured", f"managed skill {name} has conflicting file paths"
        )
    if "SKILL.md" not in checked:
        raise ManagedEngineError("misconfigured", f"managed skill {name} must contain SKILL.md")
    if len(checked) > _MAX_SKILL_FILES or sum(map(len, checked.values())) > _MAX_SKILL_BYTES:
        raise ManagedEngineError("misconfigured", f"managed skill {name} is too large")
    return checked


def _write_skill_package(files: Mapping[str, bytes], target: Path, budget: list[int]) -> None:
    target.mkdir(mode=0o700)
    for relative in sorted(files):
        parts = relative.split("/")
        parent = target
        for part in parts[:-1]:
            parent = parent / part
            if not parent.exists():
                parent.mkdir(mode=0o700)
            elif not parent.is_dir():
                raise ManagedEngineError(
                    "misconfigured", "a managed skill file path conflicts with a file"
                )
        destination = parent / parts[-1]
        if destination.exists():
            raise ManagedEngineError("misconfigured", "a managed skill file path is repeated")
        content = files[relative]
        budget[0] -= len(content)
        budget[1] -= 1
        if budget[0] < 0 or budget[1] < 0:
            raise ManagedEngineError("misconfigured", "the managed skill is too large")
        destination.write_bytes(content)
        os.chmod(destination, 0o600)


def _copy_skill_tree(source: Path, target: Path, budget: list[int]) -> None:
    target.mkdir(mode=0o700)
    for entry in sorted(source.iterdir(), key=lambda item: item.name):
        if entry.is_symlink():
            raise ManagedEngineError(
                "misconfigured", "managed skills must not contain symbolic links"
            )
        destination = target / entry.name
        if entry.is_dir():
            _copy_skill_tree(entry, destination, budget)
        elif entry.is_file():
            size = entry.stat().st_size
            budget[0] -= size
            budget[1] -= 1
            if budget[0] < 0 or budget[1] < 0:
                raise ManagedEngineError("misconfigured", "the managed skill is too large")
            shutil.copyfile(entry, destination)
            os.chmod(destination, 0o600)
        else:
            raise ManagedEngineError(
                "misconfigured", "managed skills must contain regular files only"
            )


def _resolve_binary(settings: ManagedEngineSettings, engine: str) -> str:
    configured = settings.hermes_binary if engine == "hermes" else settings.opencode_binary
    if not configured:
        raise ManagedEngineError("misconfigured", f"the managed {engine} binary is not configured")
    candidate = Path(configured).expanduser()
    if not candidate.is_absolute():
        located = shutil.which(configured)
        if located is None:
            raise ManagedEngineError(
                "misconfigured", f"the managed {engine} binary is not installed"
            )
        candidate = Path(located)
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise ManagedEngineError("misconfigured", f"the managed {engine} binary is not executable")
    return str(candidate)


def _reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((_LOOPBACK, 0))
        return int(sock.getsockname()[1])


def _argv(engine: str, binary: str, port: int) -> tuple[str, ...]:
    if engine == "hermes":
        return (
            binary,
            "serve",
            "--isolated",
            "--skip-build",
            "--host",
            _LOOPBACK,
            "--port",
            str(port),
        )
    return (binary, "serve", "--hostname", _LOOPBACK, "--port", str(port))


def _write_private(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    os.chmod(path, 0o600)


__all__ = [
    "ADMISSION_ONLY",
    "GATEWAY_KEY_ENV",
    "GATEWAY_PROVIDER_ID",
    "EngineFactory",
    "ManagedEngineError",
    "ManagedEngineRunner",
    "ManagedEngineSettings",
    "ManagedInstance",
    "ManagedLease",
    "ManagedProfileInputs",
    "native_engine",
]
