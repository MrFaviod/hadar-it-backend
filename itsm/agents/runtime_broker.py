"""Authenticated host-side broker that owns ordinary-user AI containers.

The API sends one bounded ``run.start`` frame over an authenticated WebSocket.
The broker launches exactly one fresh, server-configured container for that run,
relays tool calls to the API and the API's results back, then tears the
container down. The API has no Docker authority and the worker has no database,
filesystem, shell or credential environment.

Only server environment selects the image, command, network and limits. Every
frame is strict: client fields such as image, command, mounts, environment,
ports, network or principal are rejected, never interpreted.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import signal
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from itsm.agents.isolation import (
    QuotaResult,
    RunStart,
    ToolResult,
    WorkerError,
    WorkerFinal,
    WorkerQuotaCall,
    WorkerReady,
    WorkerToolCall,
    WorkerUsage,
)

logger = logging.getLogger("itsm.agent.broker")

_MAX_FRAME_BYTES: Final[int] = 512 * 1024
_MAX_CONTAINER_OUTPUT: Final[int] = 512 * 1024
_IMAGE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,199}$")
_NETWORK_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_MEMORY_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[1-9][0-9]{0,5}[mg]$")
_CPUS_PATTERN: Final[re.Pattern[str]] = re.compile(r"^(0\.[1-9][0-9]?|[1-9][0-9]?)$")
_DOCKER_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")


class BrokerConfigError(ValueError):
    """The host broker was started without a safe server-side configuration."""


@dataclass(frozen=True)
class BrokerConfig:
    token: str
    image: str
    command: tuple[str, ...]
    network: str = "bridge"
    memory: str = "256m"
    cpus: str = "0.5"
    pids_limit: int = 64
    max_output_bytes: int = 48 * 1024
    host: str = "127.0.0.1"
    port: int = 8765
    path: str = "/runs"
    docker: str = "docker"
    connect_timeout: int = 20

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> BrokerConfig:
        values = os.environ if environ is None else environ
        token = values.get("ITSM_AI_BROKER_TOKEN", "")
        if len(token) < 32 or any(character.isspace() for character in token):
            raise BrokerConfigError("ITSM_AI_BROKER_TOKEN must be at least 32 characters")
        image = values.get("ITSM_AI_BROKER_IMAGE", "")
        if not _IMAGE_PATTERN.fullmatch(image):
            raise BrokerConfigError("ITSM_AI_BROKER_IMAGE must be a plain image reference")
        raw_command = values.get("ITSM_AI_BROKER_COMMAND", "")
        command = tuple(part for part in raw_command.split(" ") if part)
        if not command or any(len(part) > 200 or "\x00" in part for part in command):
            raise BrokerConfigError("ITSM_AI_BROKER_COMMAND must be a bounded argv")
        network = values.get("ITSM_AI_BROKER_NETWORK", "bridge")
        if not _NETWORK_PATTERN.fullmatch(network):
            raise BrokerConfigError("ITSM_AI_BROKER_NETWORK must be a Docker network name")
        memory = values.get("ITSM_AI_BROKER_MEMORY", "256m")
        if not _MEMORY_PATTERN.fullmatch(memory):
            raise BrokerConfigError("ITSM_AI_BROKER_MEMORY must look like 256m")
        cpus = values.get("ITSM_AI_BROKER_CPUS", "0.5")
        if not _CPUS_PATTERN.fullmatch(cpus):
            raise BrokerConfigError("ITSM_AI_BROKER_CPUS must be a positive decimal")
        try:
            pids = int(values.get("ITSM_AI_BROKER_PIDS_LIMIT", "64"))
            port = int(values.get("ITSM_AI_BROKER_PORT", "8765"))
            timeout = int(values.get("ITSM_AI_BROKER_START_TIMEOUT", "20"))
        except ValueError:
            raise BrokerConfigError("broker limits and port must be integers") from None
        if not 8 <= pids <= 512 or not 1 <= port <= 65535 or not 5 <= timeout <= 60:
            raise BrokerConfigError("broker limits, port or timeout are out of range")
        host = values.get("ITSM_AI_BROKER_HOST", "127.0.0.1")
        if host not in {"127.0.0.1", "::1", "0.0.0.0", "::"}:
            raise BrokerConfigError("ITSM_AI_BROKER_HOST must be a literal bind address")
        path = values.get("ITSM_AI_BROKER_PATH", "/runs")
        if not path.startswith("/") or "?" in path or "#" in path or " " in path:
            raise BrokerConfigError("ITSM_AI_BROKER_PATH must be an absolute path")
        docker = values.get("ITSM_AI_BROKER_DOCKER", "docker")
        if not _DOCKER_PATTERN.fullmatch(docker):
            raise BrokerConfigError("ITSM_AI_BROKER_DOCKER must be a binary path")
        return cls(
            token=token,
            image=image,
            command=command,
            network=network,
            memory=memory,
            cpus=cpus,
            pids_limit=pids,
            host=host,
            port=port,
            path=path,
            docker=docker,
            connect_timeout=timeout,
        )


@dataclass
class _Container:
    run_id: str
    user_id: str
    name: str
    process: asyncio.subprocess.Process | None = None
    stderr: asyncio.Task[None] | None = None
    stopped: bool = field(default=False)


class Broker:
    """One WebSocket lifecycle per run, one freshly named container per run."""

    def __init__(self, config: BrokerConfig) -> None:
        self._config = config
        self._active: dict[str, _Container] = {}
        self._lock = asyncio.Lock()

    async def handle(self, connection: Any) -> None:
        try:
            raw = await asyncio.wait_for(connection.recv(), timeout=self._config.connect_timeout)
        except Exception:
            await connection.close(code=1008, reason="missing start")
            return
        start = self._start(raw)
        if start is None:
            await connection.close(code=1008, reason="invalid start")
            return
        container = _Container(
            run_id=start.run_id,
            user_id=start.user_id,
            name=self._container_name(start),
        )
        async with self._lock:
            if start.run_id in self._active or any(
                item.name == container.name for item in self._active.values()
            ):
                await connection.close(code=1013, reason="run already active")
                return
            self._active[start.run_id] = container
        try:
            await self._serve(connection, start, container)
        finally:
            async with self._lock:
                self._active.pop(start.run_id, None)

    def authorized_request(self, connection: Any, request: Any) -> Any:
        path = getattr(request, "path", "")
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if path != self._config.path or scheme.lower() != "bearer" or not token:
            return connection.respond(401, "unauthorized\n")
        if not hmac.compare_digest(token, self._config.token):
            return connection.respond(401, "unauthorized\n")
        return None

    def _start(self, raw: str | bytes) -> RunStart | None:
        if isinstance(raw, bytes):
            return None
        if len(raw.encode("utf-8")) > _MAX_FRAME_BYTES:
            return None
        try:
            payload = json.loads(raw)
            start = RunStart.model_validate(payload)
        except Exception:
            return None
        if not self._valid_start(start):
            return None
        return start

    def _valid_start(self, start: RunStart) -> bool:
        if len(_encode(start)) > _MAX_FRAME_BYTES:
            return False
        if any(len(_encode(tool.parameters)) > 32 * 1024 for tool in start.tools):
            return False
        for tool in start.tools:
            properties = tool.parameters.get("properties", {})
            if not isinstance(properties, dict) or not all(
                isinstance(name, str) for name in properties
            ):
                return False
        return True

    def _container_name(self, start: RunStart) -> str:
        user = hashlib.sha256(start.user_id.encode("utf-8")).hexdigest()[:32]
        return f"itsm-ai-{user}-{start.run_id[:8]}"

    async def _serve(self, connection: Any, start: RunStart, container: _Container) -> None:
        name = container.name
        command = [
            self._config.docker,
            "run",
            "--rm",
            "--interactive",
            "--name",
            name,
            "--label",
            f"itsm.ai.user={hashlib.sha256(start.user_id.encode()).hexdigest()[:32]}",
            "--label",
            f"itsm.ai.run={start.run_id}",
            "--network",
            self._config.network,
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--user",
            "65534:65534",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(self._config.pids_limit),
            "--memory",
            self._config.memory,
            "--cpus",
            self._config.cpus,
            "--ulimit",
            "nofile=256:256",
            self._config.image,
            *self._config.command,
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=_MAX_CONTAINER_OUTPUT,
            )
        except OSError:
            logger.warning("broker.docker_unavailable")
            await self._send_error(connection, "worker_unavailable")
            await connection.close(code=1011, reason="worker unavailable")
            return
        container.process = process
        try:
            if process.stderr is not None:
                container.stderr = asyncio.create_task(self._drain(process.stderr, start.run_id))
            assert process.stdin is not None and process.stdout is not None
            process.stdin.write((_encode(start) + "\n").encode("utf-8"))
            await process.stdin.drain()

            async with asyncio.timeout(start.timeout_seconds):
                await self._relay(connection, process, start)
        except BrokenPipeError:
            logger.warning("broker.worker_start_failed", extra={"run": start.run_id})
            await self._send_error(connection, "worker_failed")
        except TimeoutError:
            await self._send_error(connection, "timeout")
        except _RelayClosed:
            await self._send_error(connection, "worker_failed")
        except Exception:
            logger.warning("broker.run_failed", extra={"run": start.run_id})
            await self._send_error(connection, "worker_failed")
        finally:
            await self._stop(container)
            with contextlib.suppress(Exception):
                await connection.close(code=1000, reason="run finished")

    async def _relay(
        self,
        connection: Any,
        process: asyncio.subprocess.Process,
        start: RunStart,
    ) -> None:
        state = _CallState()
        reader = asyncio.create_task(self._from_container(connection, process, start, state))
        writer = asyncio.create_task(self._to_container(connection, process, state))
        try:
            done, pending = await asyncio.wait(
                {reader, writer}, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                exception = task.exception()
                if isinstance(exception, _RelayClosed):
                    raise exception
                if exception is not None:
                    raise exception
        finally:
            for task in (reader, writer):
                if not task.done():
                    task.cancel()
            await asyncio.gather(reader, writer, return_exceptions=True)

    async def _to_container(
        self,
        connection: Any,
        process: asyncio.subprocess.Process,
        state: _CallState,
    ) -> None:
        assert process.stdin is not None
        while True:
            raw = await connection.recv()
            if isinstance(raw, bytes):
                raise _RelayClosed()
            if len(raw.encode("utf-8")) > _MAX_FRAME_BYTES:
                raise _RelayClosed()
            try:
                payload = json.loads(raw)
                result = (
                    QuotaResult.model_validate(payload)
                    if payload.get("type") == "quota.result"
                    else ToolResult.model_validate(payload)
                )
            except Exception:
                raise _RelayClosed() from None
            expected = state.pending.get(result.call_id)
            actual = "quota.result" if isinstance(result, QuotaResult) else "tool.result"
            if expected != actual:
                raise _RelayClosed()
            state.pending.pop(result.call_id)
            if (
                isinstance(result, ToolResult)
                and result.ok
                and len(_encode(result.result)) > self._config.max_output_bytes
            ):
                result = ToolResult(call_id=result.call_id, ok=False)
            process.stdin.write((_encode(result) + "\n").encode("utf-8"))
            await process.stdin.drain()

    async def _from_container(
        self,
        connection: Any,
        process: asyncio.subprocess.Process,
        start: RunStart,
        state: _CallState,
    ) -> None:
        assert process.stdout is not None
        names = {tool.name for tool in start.tools}
        properties = {
            tool.name: frozenset(tool.parameters.get("properties", {})) for tool in start.tools
        }
        total = 0
        while True:
            line = await process.stdout.readline()
            if not line:
                raise _RelayClosed()
            total += len(line)
            if total > _MAX_CONTAINER_OUTPUT:
                raise _RelayClosed()
            if len(line) > _MAX_FRAME_BYTES:
                raise _RelayClosed()
            try:
                payload = json.loads(line)
            except ValueError:
                raise _RelayClosed() from None
            if not isinstance(payload, dict):
                raise _RelayClosed()
            kind = payload.get("type")
            if kind == "ready":
                WorkerReady.model_validate(payload)
                await connection.send(_encode(WorkerReady()))
                continue
            if kind == "usage":
                usage = WorkerUsage.model_validate(payload)
                await connection.send(_encode(usage))
                continue
            if kind == "quota.call":
                call = WorkerQuotaCall.model_validate(payload)
                if not start.quota_enabled or call.call_id in state.pending:
                    raise _RelayClosed()
                state.pending[call.call_id] = "quota.result"
                await connection.send(_encode(call))
                continue
            if kind == "tool.call":
                call = WorkerToolCall.model_validate(payload)
                if call.name not in names:
                    raise _RelayClosed()
                allowed = properties.get(call.name, frozenset())
                if not set(call.arguments).issubset(allowed):
                    raise _RelayClosed()
                if call.call_id in state.pending:
                    raise _RelayClosed()
                state.pending[call.call_id] = "tool.result"
                await connection.send(_encode(call))
                continue
            if kind == "final":
                final = WorkerFinal.model_validate(payload)
                await connection.send(_encode(final))
                return
            if kind == "error":
                error = WorkerError.model_validate(payload)
                await connection.send(_encode(error))
                return
            raise _RelayClosed()

    async def _drain(self, stream: asyncio.StreamReader, run_id: str) -> None:
        total = 0
        try:
            while True:
                line = await stream.readline()
                if not line:
                    return
                total += len(line)
                if total > _MAX_CONTAINER_OUTPUT:
                    return
        except Exception:
            return

    async def _send_error(self, connection: Any, code: str) -> None:
        with contextlib.suppress(Exception):
            await connection.send(
                _encode(WorkerError(code=code, message="the isolated worker is unavailable"))
            )

    async def _stop(self, container: _Container) -> None:
        if container.stopped:
            return
        container.stopped = True
        process = container.process
        if process is not None and process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
            try:
                async with asyncio.timeout(5):
                    await process.wait()
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                try:
                    async with asyncio.timeout(5):
                        await process.wait()
                except TimeoutError:
                    pass
        if container.stderr is not None:
            container.stderr.cancel()
        await self._remove(container.name)

    async def _remove(self, name: str) -> None:
        try:
            process = await asyncio.create_subprocess_exec(
                self._config.docker,
                "rm",
                "--force",
                name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            async with asyncio.timeout(10):
                await process.wait()
        except Exception:
            logger.warning("broker.cleanup_failed")


class _RelayClosed(Exception):
    pass


@dataclass
class _CallState:
    pending: dict[str, str] = field(default_factory=dict)


def _encode(payload: Any) -> str:
    if hasattr(payload, "model_dump_json"):
        return payload.model_dump_json(by_alias=True, exclude_none=True)
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)


async def serve(config: BrokerConfig) -> None:
    from websockets.asyncio.server import serve as ws_serve

    broker = Broker(config)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in ("SIGINT", "SIGTERM"):
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(getattr(signal, name), stop.set)
    async with ws_serve(
        broker.handle,
        config.host,
        config.port,
        process_request=broker.authorized_request,
        max_size=_MAX_FRAME_BYTES,
        compression=None,
        ping_interval=20,
        ping_timeout=20,
        close_timeout=5,
    ):
        logger.info(
            "broker.started",
            extra={"host": config.host, "port": config.port, "image": config.image},
        )
        await stop.wait()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        config = BrokerConfig.from_env()
    except BrokerConfigError as exc:
        print(f"broker configuration error: {exc}", file=sys.stderr)
        return 2
    try:
        asyncio.run(serve(config))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":  # pragma: no cover - host entrypoint
    raise SystemExit(main())
