"""Bounded fixed-action executor: operator helper, wire contract and HTTP client.

The helper runs separately from the web application, under its own OS account.
Only an installation operator configures the per-action argv arrays; requests
can select one of three fixed actions and carry no arguments, paths, commands
or endpoints. Each child runs without a shell, in its own process group, with a
timeout and bounded drained output. Raw output is never returned: an action may
emit one strict JSON object using the documented fixed fields.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from itsm.config import Settings

ACTION_NAMES: Final[tuple[str, ...]] = (
    "deployment.status",
    "update.prepare",
    "backup.create",
)
ACTION_ENV: Final[dict[str, str]] = {
    "deployment.status": "ITSM_EXECUTOR_ACTION_DEPLOYMENT_STATUS",
    "update.prepare": "ITSM_EXECUTOR_ACTION_UPDATE_PREPARE",
    "backup.create": "ITSM_EXECUTOR_ACTION_BACKUP_CREATE",
}
RESULT_KEYS: Final[frozenset[str]] = frozenset(
    {"status", "reference", "artifact", "restored", "files", "revision", "message"}
)
ARTIFACT_KEYS: Final[frozenset[str]] = frozenset({"name", "bytes", "sha256", "verified"})
MAX_OUTPUT_BYTES: Final[int] = 8192
MAX_REQUEST_BYTES: Final[int] = 4096
MAX_RESPONSE_BYTES: Final[int] = 64 * 1024
MAX_MESSAGE: Final[int] = 500
SAFE_REFERENCE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")
SAFE_ARTIFACT: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_REVISION: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
REDACTED: Final[str] = "[redacted]"
SECRET_MIN_LENGTH: Final[int] = 16
DRAIN_JOIN_SECONDS: Final[float] = 2.0


class ExecutorConfigError(RuntimeError):
    """The operator-supplied helper configuration is unusable."""


@dataclass(frozen=True)
class ActionCommand:
    argv: tuple[str, ...]


@dataclass(frozen=True)
class ExecutorConfig:
    secret: str
    host: str
    port: int
    timeout_seconds: float
    workdir: Path | None
    redactions: tuple[str, ...]
    actions: Mapping[str, ActionCommand]

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> ExecutorConfig:
        secret = (environ.get("ITSM_EXECUTOR_SECRET") or "").strip()
        if len(secret) < SECRET_MIN_LENGTH:
            raise ExecutorConfigError("ITSM_EXECUTOR_SECRET must be at least 16 characters")
        host = (environ.get("ITSM_EXECUTOR_HOST") or "127.0.0.1").strip()
        try:
            port = int(environ.get("ITSM_EXECUTOR_PORT") or "18091")
        except ValueError:
            raise ExecutorConfigError("ITSM_EXECUTOR_PORT must be an integer") from None
        if not 0 <= port <= 65535:
            raise ExecutorConfigError("ITSM_EXECUTOR_PORT is outside the TCP range")
        try:
            timeout = float(environ.get("ITSM_EXECUTOR_TIMEOUT_SECONDS") or "60")
        except ValueError:
            raise ExecutorConfigError("ITSM_EXECUTOR_TIMEOUT_SECONDS must be a number") from None
        if not 1 <= timeout <= 300:
            raise ExecutorConfigError("ITSM_EXECUTOR_TIMEOUT_SECONDS must be 1..300")
        workdir_value = (environ.get("ITSM_EXECUTOR_WORKDIR") or "").strip()
        workdir = Path(workdir_value) if workdir_value else None
        if workdir is not None and not workdir.is_dir():
            raise ExecutorConfigError("ITSM_EXECUTOR_WORKDIR must be an existing directory")
        redactions = tuple(
            item.strip()
            for item in (environ.get("ITSM_EXECUTOR_REDACT") or "").split(",")
            if item.strip()
        )
        actions: dict[str, ActionCommand] = {}
        for action, variable in ACTION_ENV.items():
            raw = (environ.get(variable) or "").strip()
            if not raw:
                continue
            try:
                argv = json.loads(raw)
            except json.JSONDecodeError:
                raise ExecutorConfigError(f"{variable} must be a JSON array") from None
            if (
                not isinstance(argv, list)
                or not argv
                or any(not isinstance(item, str) or not item for item in argv)
            ):
                raise ExecutorConfigError(f"{variable} must be a non-empty JSON string array")
            actions[action] = ActionCommand(tuple(argv))
        return cls(
            secret=secret,
            host=host,
            port=port,
            timeout_seconds=timeout,
            workdir=workdir,
            redactions=tuple(dict.fromkeys((secret, *redactions))),
            actions=actions,
        )


# ------------------------------------------------------------------- validation


def _bounded_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def normalize_action_result(value: Any) -> dict[str, Any] | None:
    """Validate one action result and return the fixed public shape."""
    if not isinstance(value, Mapping) or set(value) - RESULT_KEYS:
        return None
    status = value.get("status")
    if status not in {"ok", "failed"}:
        return None
    reference = value.get("reference")
    if reference is not None and (
        not isinstance(reference, str) or not SAFE_REFERENCE.fullmatch(reference)
    ):
        return None
    revision = value.get("revision")
    if revision is not None and (
        not isinstance(revision, str) or not SAFE_REVISION.fullmatch(revision)
    ):
        return None
    message = value.get("message")
    if message is not None and (not isinstance(message, str) or len(message) > MAX_MESSAGE):
        return None
    restored = value.get("restored")
    if restored is not None and not isinstance(restored, bool):
        return None
    files = value.get("files")
    if files is not None and _bounded_int(files) is None:
        return None
    artifact = value.get("artifact")
    normalized_artifact: dict[str, Any] | None = None
    if artifact is not None:
        if not isinstance(artifact, Mapping) or set(artifact) - ARTIFACT_KEYS:
            return None
        name = artifact.get("name")
        size = _bounded_int(artifact.get("bytes"))
        digest = artifact.get("sha256")
        verified = artifact.get("verified")
        if (
            not isinstance(name, str)
            or not SAFE_ARTIFACT.fullmatch(name)
            or size is None
            or (
                digest is not None
                and (not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest))
            )
            or (verified is not None and not isinstance(verified, bool))
        ):
            return None
        normalized_artifact = {
            "name": name,
            "bytes": size,
            "sha256": digest,
            "verified": verified,
        }
    return {
        "status": status,
        "reference": reference,
        "artifact": normalized_artifact,
        "restored": restored,
        "files": files,
        "revision": revision,
        "message": message,
    }


def _redact_text(value: str, redactions: tuple[str, ...]) -> str:
    text = value
    for token in redactions:
        if token:
            text = text.replace(token, REDACTED)
    return text[:MAX_MESSAGE]


def _redact_value(value: Any, redactions: tuple[str, ...]) -> Any:
    if isinstance(value, str):
        return _redact_text(value, redactions)
    if isinstance(value, Mapping):
        return {key: _redact_value(item, redactions) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, redactions) for item in value]
    return value


# ---------------------------------------------------------------------- runner


def _drain(stream: Any, buffer: bytearray, overflow: list[bool]) -> None:
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                return
            remaining = MAX_OUTPUT_BYTES - len(buffer)
            if remaining <= 0:
                overflow[0] = True
                continue
            buffer.extend(chunk[:remaining])
            if len(chunk) > remaining:
                overflow[0] = True
    except OSError, ValueError:
        return


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    # The child is its own session, so its PID is also the process-group id.
    # Kill the group even after a clean child exit: a grandchild may still hold
    # the output pipes open.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError, PermissionError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):  # pragma: no cover - defensive
        process.wait(timeout=5)


_CHILD_ENV = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR")


def run_action(config: ExecutorConfig, action: str) -> dict[str, Any]:
    """Execute one configured action and return the bounded public envelope."""
    command = config.actions[action]
    started = datetime.now(UTC)
    clock = time.monotonic()
    # Same base allowlist as the managed agent runtime: the host's secrets never reach an action.
    child_env = {key: os.environ[key] for key in _CHILD_ENV if key in os.environ}
    try:
        process = subprocess.Popen(
            list(command.argv),
            shell=False,
            cwd=None if config.workdir is None else str(config.workdir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env=child_env,
        )
    except OSError:
        return _envelope(
            action,
            "failed",
            None,
            None,
            started,
            time.monotonic() - clock,
            "action executable could not be started",
        )
    stdout = bytearray()
    stderr = bytearray()
    overflow = [False]
    stdout_thread = threading.Thread(
        target=_drain, args=(process.stdout, stdout, overflow), daemon=True
    )
    stderr_thread = threading.Thread(
        target=_drain, args=(process.stderr, stderr, overflow), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()
    timed_out = False
    try:
        process.wait(timeout=config.timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
    # Always reap descendants and drain pipes, including a grandchild that
    # outlives a successful direct child.
    _kill_group(process)
    stdout_thread.join(timeout=DRAIN_JOIN_SECONDS)
    stderr_thread.join(timeout=DRAIN_JOIN_SECONDS)
    streams_open = stdout_thread.is_alive() or stderr_thread.is_alive()
    if streams_open:
        for stream in (process.stdout, process.stderr):
            with contextlib.suppress(OSError, ValueError):
                stream.close()  # type: ignore[union-attr]
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)
        streams_open = stdout_thread.is_alive() or stderr_thread.is_alive()
    returncode = process.returncode
    duration = time.monotonic() - clock
    if timed_out:
        return _envelope(
            action,
            "failed",
            None,
            returncode,
            started,
            duration,
            "action timed out",
        )
    if overflow[0]:
        return _envelope(
            action,
            "failed",
            None,
            returncode,
            started,
            duration,
            "action output exceeded the limit",
        )
    if streams_open:
        return _envelope(
            action,
            "failed",
            None,
            returncode,
            started,
            duration,
            "action left output streams open",
        )
    text = bytes(stdout).decode("utf-8", "replace").strip()
    parsed: Any = None
    if text:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
    normalized = normalize_action_result(parsed)
    if normalized is None:
        message = (
            f"action exited with status {returncode}"
            if returncode not in (0, None)
            else "action output was not a valid result"
        )
        return _envelope(action, "failed", None, returncode, started, duration, message)
    redacted = _redact_value(normalized, config.redactions)
    assert isinstance(redacted, dict)
    completed = returncode == 0 and redacted["status"] == "ok"
    message = redacted["message"]
    if not completed and not message:
        message = (
            f"action exited with status {returncode}"
            if returncode not in (0, None)
            else "action reported a failed status"
        )
    return _envelope(
        action,
        "completed" if completed else "failed",
        redacted,
        returncode,
        started,
        duration,
        message,
        redactions=config.redactions,
    )


def _envelope(
    action: str,
    state: str,
    result: dict[str, Any] | None,
    exit_code: int | None,
    started: datetime,
    duration: float,
    message: str | None,
    *,
    redactions: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "action": action,
        "state": state,
        "exitCode": exit_code,
        "startedAt": started.isoformat(),
        "durationMs": max(0, int(duration * 1000)),
        "result": result,
        "message": None if message is None else _redact_text(message, redactions),
    }


# ---------------------------------------------------------------------- helper


class _ExecutorServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    config: ExecutorConfig


class _ExecutorHandler(BaseHTTPRequestHandler):
    server_version = "ITSMExecutor/1"
    protocol_version = "HTTP/1.1"

    @property
    def config(self) -> ExecutorConfig:
        server = self.server
        assert isinstance(server, _ExecutorServer)
        return server.config

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _authorized(self) -> bool:
        scheme, _, token = (self.headers.get("Authorization") or "").partition(" ")
        return scheme == "Bearer" and hmac.compare_digest(
            token.encode("utf-8", "surrogatepass"), self.config.secret.encode("utf-8")
        )

    def _send(self, status: int, payload: Mapping[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if not self._authorized():
            self._send(401, {"message": "unauthorized"})
            return
        if urlsplit(self.path).path != "/healthz":
            self._send(404, {"message": "not found"})
            return
        self._send(
            200,
            {"status": "ok", "actions": sorted(self.config.actions)},
        )

    def do_POST(self) -> None:
        if not self._authorized():
            self._send(401, {"message": "unauthorized"})
            return
        path = urlsplit(self.path).path
        prefix = "/v1/actions/"
        if not path.startswith(prefix):
            self._send(404, {"message": "not found"})
            return
        action = path[len(prefix) :]
        if action not in ACTION_NAMES:
            self._send(404, {"message": "unknown action"})
            return
        if action not in self.config.actions:
            self._send(503, {"message": "action is not configured"})
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self._send(400, {"message": "invalid body"})
            return
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._send(413, {"message": "request body is too large"})
            return
        raw = self.rfile.read(length) if length else b""
        if raw.strip():
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                self._send(400, {"message": "body must be an empty JSON object"})
                return
            if payload != {}:
                self._send(400, {"message": "actions accept no arguments"})
                return
        self._send(200, run_action(self.config, action))


def build_server(config: ExecutorConfig) -> _ExecutorServer:
    server = _ExecutorServer((config.host, config.port), _ExecutorHandler)
    server.config = config
    return server


def main() -> int:
    try:
        config = ExecutorConfig.from_env(os.environ)
    except ExecutorConfigError as exc:
        print(json.dumps({"event": "executor.error", "message": str(exc)}), file=sys.stderr)
        return 2
    server = build_server(config)
    print(
        json.dumps({"event": "executor.ready", "port": server.server_address[1]}),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - operator stop
        pass
    finally:
        server.server_close()
    return 0


# ---------------------------------------------------------------------- client


@dataclass(frozen=True)
class ExecutorOutcome:
    action: str
    state: str
    result: dict[str, Any] | None = None
    exit_code: int | None = None
    started_at: str | None = None
    duration_ms: int | None = None
    message: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "state": self.state,
            "result": self.result,
            "reference": None if self.result is None else self.result.get("reference"),
            "exitCode": self.exit_code,
            "startedAt": self.started_at,
            "durationMs": self.duration_ms,
            "message": self.message,
        }


class SystemExecutor:
    """HTTP client for the operator-deployed fixed-action executor."""

    def __init__(self, settings: Settings) -> None:
        raw_url = getattr(settings, "system_executor_url", "") or ""
        self._base_url = raw_url.rstrip("/")
        token = getattr(settings, "system_executor_token", None)
        if token is None:
            self._token = ""
        elif hasattr(token, "get_secret_value"):
            self._token = str(token.get_secret_value())
        else:
            self._token = str(token)
        timeout = getattr(settings, "system_executor_timeout_seconds", 10.0)
        self._timeout = float(timeout)
        self._redactions = (self._token,) if self._token else ()

    @property
    def configured(self) -> bool:
        return bool(self._base_url and self._token)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    def _redact(self, value: str) -> str:
        return _redact_text(value, self._redactions)

    def availability(self) -> dict[str, Any]:
        if not self.configured:
            return {
                "configured": False,
                "available": False,
                "actions": [],
                "detail": "system executor is not configured",
            }
        try:
            with httpx.stream(
                "GET",
                f"{self._base_url}/healthz",
                headers=self._headers(),
                timeout=self._timeout,
                follow_redirects=False,
            ) as response:
                if 300 <= response.status_code < 400:
                    detail = "system executor redirected the request"
                elif response.status_code in (401, 403):
                    detail = "system executor rejected the configured credential"
                elif response.status_code != 200:
                    detail = "system executor health check failed"
                else:
                    body = _read_bounded(response)
                    if body is None:
                        detail = "system executor health response is oversized"
                    else:
                        try:
                            payload = json.loads(body)
                        except ValueError:
                            payload = None
                        actions = payload.get("actions") if isinstance(payload, Mapping) else None
                        if not isinstance(actions, list):
                            detail = "system executor returned an invalid health response"
                        else:
                            allowed = sorted(
                                action
                                for action in actions
                                if isinstance(action, str) and action in ACTION_NAMES
                            )
                            return {
                                "configured": True,
                                "available": True,
                                "actions": allowed,
                                "detail": None,
                            }
        except httpx.HTTPError, ValueError:
            return {
                "configured": True,
                "available": False,
                "actions": [],
                "detail": "system executor is not reachable",
            }
        return {
            "configured": True,
            "available": False,
            "actions": [],
            "detail": self._redact(detail),
        }

    def execute(self, action: str) -> ExecutorOutcome:
        if action not in ACTION_NAMES:
            raise ValueError("unknown system action")
        if not self.configured:
            return ExecutorOutcome(
                action=action,
                state="unavailable",
                message="system executor is not configured",
            )
        try:
            with httpx.stream(
                "POST",
                f"{self._base_url}/v1/actions/{action}",
                headers=self._headers(),
                json={},
                timeout=self._timeout,
                follow_redirects=False,
            ) as response:
                if 300 <= response.status_code < 400:
                    return ExecutorOutcome(
                        action=action,
                        state="unavailable",
                        message="system executor redirected the request",
                    )
                if response.status_code in (401, 403):
                    return ExecutorOutcome(
                        action=action,
                        state="unavailable",
                        message="system executor rejected the configured credential",
                    )
                if response.status_code == 503:
                    body = _read_bounded(response)
                    return ExecutorOutcome(
                        action=action,
                        state="unavailable",
                        message=self._redact(
                            _error_message_from_body(body, "action is not configured")
                        ),
                    )
                if response.status_code == 404:
                    return ExecutorOutcome(
                        action=action,
                        state="unavailable",
                        message="system executor does not support this action",
                    )
                if response.status_code != 200:
                    return ExecutorOutcome(
                        action=action,
                        state="unavailable",
                        message="system executor returned an unexpected response",
                    )
                body = _read_bounded(response)
        except httpx.TimeoutException:
            return ExecutorOutcome(
                action=action,
                state="unavailable",
                message="system executor did not respond in time",
            )
        except httpx.HTTPError, ValueError:
            return ExecutorOutcome(
                action=action,
                state="unavailable",
                message="system executor is not reachable",
            )
        if body is None:
            return ExecutorOutcome(
                action=action,
                state="failed",
                message="system executor returned an oversized response",
            )
        try:
            payload = json.loads(body)
        except ValueError:
            payload = None
        if not isinstance(payload, dict):
            return ExecutorOutcome(
                action=action,
                state="failed",
                message="system executor returned an invalid response",
            )
        state = payload.get("state")
        if state not in {"completed", "failed"}:
            return ExecutorOutcome(
                action=action,
                state="failed",
                message="system executor returned an invalid state",
            )
        result = normalize_action_result(payload.get("result"))
        if result is not None:
            result = _redact_value(result, self._redactions)
        if state == "completed" and (result is None or result["status"] != "ok"):
            return ExecutorOutcome(
                action=action,
                state="failed",
                message="system executor returned an invalid completion",
            )
        exit_code = _bounded_int(payload.get("exitCode"))
        duration = _bounded_int(payload.get("durationMs"))
        started_at = payload.get("startedAt")
        if started_at is not None and not isinstance(started_at, str):
            started_at = None
        message = payload.get("message")
        if not isinstance(message, str):
            message = None
        return ExecutorOutcome(
            action=action,
            state=state,
            result=result,
            exit_code=exit_code,
            started_at=started_at,
            duration_ms=duration,
            message=None if message is None else self._redact(message),
        )


def _read_bounded(response: httpx.Response) -> bytes | None:
    """Read at most MAX_RESPONSE_BYTES, returning None as soon as it overflows."""
    body = bytearray()
    for chunk in response.iter_bytes():
        body.extend(chunk)
        if len(body) > MAX_RESPONSE_BYTES:
            return None
    return bytes(body)


def _error_message_from_body(body: bytes | None, fallback: str) -> str:
    if body is None:
        return "system executor response is oversized"
    try:
        payload = json.loads(body)
    except ValueError:
        return fallback
    message = payload.get("message") if isinstance(payload, dict) else None
    return (message if isinstance(message, str) else fallback)[:MAX_MESSAGE]


__all__ = [
    "ACTION_ENV",
    "ACTION_NAMES",
    "ActionCommand",
    "ExecutorConfig",
    "ExecutorConfigError",
    "ExecutorOutcome",
    "SystemExecutor",
    "build_server",
    "main",
    "normalize_action_result",
    "run_action",
]


if __name__ == "__main__":
    raise SystemExit(main())
