"""Sandboxed module execution and host-side package materialization.

The executable backend never runs in the API or worker process.  For every
invocation the host extracts the reviewed package into a per-digest read-only
cache directory and starts a fresh ``python -I -S -B runner.py`` process with a
cleared environment, the module data directory as its working directory, a new
process session, a wall-clock deadline and bounded output and capability
budgets.  Any failure is closed: the process group is killed and the caller
receives a generic host error.
"""

from __future__ import annotations

import hashlib
import contextlib
import json
import logging
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from itsm.extensions.errors import (
    ExtensionHandlerFailed,
    ExtensionIdempotencyConflict,
    ExtensionNotFound,
    ExtensionSandboxUnavailable,
    ExtensionStoreConflict,
    ExtensionStoreValidation,
    ExtensionValidationFailed,
)
from itsm.extensions.runtime import sandbox as primitives
from itsm.extensions.runtime import sqlite_store
from itsm.identity.service import NotFound, PermissionDenied

LOGGER = logging.getLogger("itsm.extensions.sandbox")
RUNNER_PATH = Path(__file__).resolve().parent / "runtime" / "runner.py"
PACKAGE_CACHE_DIRNAME = ".packages"
MAX_PACKAGE_MEMBERS = 400
MAX_MEMBER_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class SandboxLimits:
    """Explicit resources granted to one executable-module invocation."""

    wall_timeout_seconds: float = 30.0
    cpu_seconds: int = 20
    memory_mb: int = 256
    file_size_bytes: int = 16 * 1024 * 1024
    open_files: int = 64
    max_output_bytes: int = 1024 * 1024
    max_line_bytes: int = 1024 * 1024
    max_capability_calls: int = 200


class SandboxModuleError(Exception):
    """A module reported a typed failure from inside the sandbox."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def sandbox_availability() -> dict[str, Any]:
    """Probe the kernel without mutating it; used by status and health views."""
    return primitives.availability()


def package_cache_root(settings: Any) -> Path:
    return Path(settings.extension_data_path) / PACKAGE_CACHE_DIRNAME


def prepare_package(settings: Any, digest: str, package_bytes: bytes) -> Path:
    """Extract a reviewed package once into a 0500/0400 read-only cache dir."""
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ExtensionValidationFailed("package digest must be lowercase SHA-256 hex")
    if hashlib.sha256(package_bytes).hexdigest() != digest:
        raise ExtensionValidationFailed("package bytes do not match their digest")
    root = package_cache_root(settings)
    target = root / digest
    if (target / ".complete").is_file():
        return target
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{digest[:12]}-", dir=root))
    try:
        with zipfile.ZipFile(_BytesReader(package_bytes)) as archive:
            members = archive.infolist()
            if len(members) > MAX_PACKAGE_MEMBERS:
                raise ExtensionValidationFailed("package declares too many members")
            for member in members:
                name = member.filename
                if name.endswith("/") or "\\" in name or name.startswith("/"):
                    raise ExtensionValidationFailed("package member path is invalid")
                parts = name.split("/")
                if any(part in ("", ".", "..") for part in parts):
                    raise ExtensionValidationFailed("package member path is invalid")
                if member.file_size > MAX_MEMBER_BYTES:
                    raise ExtensionValidationFailed("package member exceeds the size limit")
                destination = staging.joinpath(*parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(member))
        (staging / ".complete").write_text("ok", encoding="utf-8")
        for path in sorted(staging.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            os.chmod(path, 0o500 if path.is_dir() else 0o400)
        os.chmod(staging, 0o500)
        try:
            staging.rename(target)
        except OSError:
            if not (target / ".complete").is_file():
                raise
    finally:
        if staging.exists():
            _discard_tree(staging)
    return target


class _BytesReader:
    """Minimal seekable file object so zipfile can read package bytes."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            chunk = self._payload[self._offset :]
            self._offset = len(self._payload)
            return chunk
        chunk = self._payload[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self._offset = offset
        elif whence == 1:
            self._offset += offset
        else:
            self._offset = len(self._payload) + offset
        return self._offset

    def tell(self) -> int:
        return self._offset

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False


def _discard_tree(root: Path) -> None:
    for directory in sorted(root.rglob("*"), key=lambda item: len(item.parts)):
        if directory.is_dir():
            try:
                os.chmod(directory, 0o700)
            except OSError:  # pragma: no cover
                continue
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        try:
            if path.is_dir():
                path.rmdir()
            else:
                path.unlink()
        except OSError:  # pragma: no cover - best-effort staging cleanup
            continue
    try:
        os.chmod(root, 0o700)
        root.rmdir()
    except OSError:  # pragma: no cover
        pass


def _error_from_code(code: str, message: str) -> Exception:
    if code == "permission_denied":
        # An authorization denial inside the sandbox stays an authorization
        # denial outside it, so HTTP callers keep the 403 contract.
        return PermissionDenied("permission denied")
    mapping: dict[str, type[Exception]] = {
        "store_conflict": ExtensionStoreConflict,
        "store_validation": ExtensionStoreValidation,
        "capability_denied": ExtensionValidationFailed,
        "idempotency_conflict": ExtensionIdempotencyConflict,
        "not_found": ExtensionNotFound,
    }
    kind = mapping.get(code)
    if kind is None:
        return ExtensionHandlerFailed("extension operation failed")
    return kind(message)


def run_module(
    *,
    settings: Any,
    limits: SandboxLimits,
    digest: str,
    package_bytes: bytes,
    data_dir: Path,
    request: Mapping[str, Any],
    declared: Mapping[str, list[str]],
    handle_call: Callable[[str, Mapping[str, Any]], Any],
) -> Any:
    """Run one handler in a fresh sandbox and return its JSON result."""
    availability = sandbox_availability()
    if not availability["available"]:
        raise ExtensionSandboxUnavailable("sandboxed module execution is unavailable on this host")
    package_dir = prepare_package(settings, digest, package_bytes)
    read_paths = _read_paths(package_dir)
    init = {
        "type": "run",
        "packageDir": str(package_dir),
        "backend": "backend.py",
        "dataDir": str(data_dir),
        "dataPath": str(sqlite_store.database_path(Path(data_dir).parent, Path(data_dir).name)),
        "readOnlyPaths": read_paths,
        "declared": dict(declared),
        "request": dict(request),
        "limits": {
            "cpuSeconds": limits.cpu_seconds,
            "memoryMb": limits.memory_mb,
            "fileSizeBytes": limits.file_size_bytes,
            "openFiles": limits.open_files,
        },
    }
    # The handle must outlive Popen and is closed in the caller's finally block.
    stderr_file = tempfile.TemporaryFile()  # noqa: SIM115
    process = subprocess.Popen(
        [sys.executable, "-E", "-s", "-S", "-B", str(RUNNER_PATH)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=stderr_file,
        cwd=str(data_dir),
        env={},
        start_new_session=True,
        close_fds=True,
        bufsize=0,
    )
    deadline = time.monotonic() + limits.wall_timeout_seconds
    assert process.stdin is not None
    assert process.stdout is not None
    try:
        _write_line(process.stdin, init)
        result = _serve(
            process,
            deadline=deadline,
            limits=limits,
            handle_call=handle_call,
        )
    finally:
        _terminate(process)
        _log_stderr(stderr_file)
        stderr_file.close()
    return result


def _log_stderr(stream: Any) -> None:
    try:
        stream.seek(0)
        detail = stream.read(4096)
    except OSError, ValueError:  # pragma: no cover
        return
    if detail:
        LOGGER.warning(
            "extension sandbox stderr: %s",
            detail.decode("utf-8", "replace")[-1500:],
        )


def _read_paths(package_dir: Path) -> list[str]:
    return primitives.default_read_paths(str(package_dir), str(RUNNER_PATH.parent))


def _write_line(stream: Any, message: Mapping[str, Any]) -> None:
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"
    stream.write(payload)
    stream.flush()


def _terminate(process: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):  # pragma: no cover
        process.wait(timeout=5)


def _serve(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
    limits: SandboxLimits,
    handle_call: Callable[[str, Mapping[str, Any]], Any],
) -> Any:
    assert process.stdin is not None
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    buffer = bytearray()
    total = 0
    calls = 0
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ExtensionHandlerFailed("extension invocation exceeded its time limit")
            if not selector.select(min(remaining, 0.5)):
                if process.poll() is not None:
                    break
                continue
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limits.max_output_bytes:
                raise ExtensionHandlerFailed("extension output exceeded its size limit")
            buffer.extend(chunk)
            while True:
                newline = buffer.find(b"\n")
                if newline < 0:
                    break
                if newline > limits.max_line_bytes:
                    raise ExtensionHandlerFailed("extension output exceeded its size limit")
                line = bytes(buffer[:newline])
                del buffer[: newline + 1]
                message = _decode(line)
                kind = message.get("type")
                if kind == "fatal":
                    raise ExtensionSandboxUnavailable(
                        str(message.get("message") or "sandbox unavailable")
                    )
                if kind == "error":
                    LOGGER.warning(
                        "extension sandbox error frame: %s %s",
                        message.get("code"),
                        str(message.get("message"))[:300],
                    )
                    raise _error_from_code(
                        str(message.get("code")), str(message.get("message") or "")
                    )
                if kind == "result":
                    return message.get("result")
                if kind == "call":
                    calls += 1
                    if calls > limits.max_capability_calls:
                        raise ExtensionHandlerFailed(
                            "extension exceeded its capability call budget"
                        )
                    _answer(process.stdin, message, handle_call)
                    continue
                if kind == "log":
                    LOGGER.info(
                        "extension log",
                        extra={"extensionMessage": str(message.get("message"))[:200]},
                    )
                    continue
                raise ExtensionHandlerFailed("extension sent an unknown message")
        raise ExtensionHandlerFailed("extension process ended before returning a result")
    finally:
        selector.close()


def _decode(line: bytes) -> dict[str, Any]:
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        raise ExtensionHandlerFailed("extension sent malformed output") from None
    if not isinstance(message, dict):
        raise ExtensionHandlerFailed("extension sent malformed output")
    return message


def _answer(
    stream: Any,
    message: Mapping[str, Any],
    handle_call: Callable[[str, Mapping[str, Any]], Any],
) -> None:
    request_id = message.get("id")
    capability = str(message.get("capability"))
    request = message.get("request") or {}
    if not isinstance(request, dict):
        _reply(stream, request_id, None, "capability_denied", "request must be an object")
        return
    try:
        result = handle_call(capability, request)
    except ExtensionStoreConflict as exc:
        _reply(stream, request_id, None, "store_conflict", str(exc))
    except ExtensionStoreValidation as exc:
        _reply(stream, request_id, None, "store_validation", str(exc))
    except ExtensionValidationFailed as exc:
        _reply(stream, request_id, None, "capability_denied", str(exc))
    except ExtensionIdempotencyConflict as exc:
        _reply(stream, request_id, None, "idempotency_conflict", str(exc))
    except NotFound as exc:
        _reply(stream, request_id, None, "not_found", str(exc))
    except PermissionDenied as exc:
        _reply(stream, request_id, None, "permission_denied", str(exc))
    except Exception:
        LOGGER.exception("extension capability failed", extra={"capability": capability})
        _reply(stream, request_id, None, "handler_failed", "capability failed")
    else:
        _reply(stream, request_id, _jsonable(result), None, "")


def _reply(
    stream: Any,
    request_id: Any,
    result: Any,
    code: str | None,
    message: str,
) -> None:
    if code is None:
        frame = {"type": "response", "id": request_id, "ok": True, "result": result}
    else:
        frame = {
            "type": "response",
            "id": request_id,
            "ok": False,
            "code": code,
            "message": message,
        }
    with contextlib.suppress(BrokenPipeError, OSError):  # module already gone
        _write_line(stream, frame)


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


__all__ = [
    "PACKAGE_CACHE_DIRNAME",
    "RUNNER_PATH",
    "SandboxLimits",
    "SandboxModuleError",
    "package_cache_root",
    "prepare_package",
    "run_module",
    "sandbox_availability",
]
