"""Host wrapper around the fixed validator container.

The wrapper only builds a bounded stdin frame and runs a server-owned image
command. Candidate paths, argv, environment, image names and dependencies are
never accepted from a workspace or model. The container has no network, no
mounts, no Docker socket and no inherited credentials, runs read-only as a
non-root user with dropped capabilities and bounded CPU/memory/PIDs/output.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import selectors
import subprocess
import socket
import threading
from collections.abc import Collection
import time
from datetime import datetime
from typing import Any
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

from .sdk.validator.protocol import (
    DEFAULT_LIMITS,
    MAX_OUTPUT_BYTES,
    ProtocolError,
    build_frame,
)

REPORT_KEYS = frozenset(
    {
        "status",
        "digest",
        "sdkVersion",
        "checks",
        "errors",
        "container",
        "completedAt",
    }
)
CHECK_KEYS = frozenset({"name", "status", "detail"})
IMAGE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._/:@-]{0,200}$")
DOCKER_PATTERN = re.compile(r"^[A-Za-z0-9_./-]{1,120}$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ValidatorUnavailable(RuntimeError):
    """The fixed validator runtime cannot be reached."""


class ContainerValidator:
    """Run one candidate through the fixed image and return a trusted report."""

    def __init__(
        self,
        *,
        core_permissions: Collection[str] = (),
        docker: str = "docker",
        image: str = "itsm-extension-validator:1",
        timeout: float = 60.0,
        max_output: int = MAX_OUTPUT_BYTES,
    ) -> None:
        if not isinstance(docker, str) or not DOCKER_PATTERN.fullmatch(docker):
            raise ValueError("docker executable must be a safe path")
        if not isinstance(image, str) or not IMAGE_PATTERN.fullmatch(image):
            raise ValueError("validator image reference is invalid")
        if image.startswith("-") or "--rm" in image:
            raise ValueError("validator image reference is invalid")
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 5 <= timeout <= 300
        ):
            raise ValueError("validator timeout must be between 5 and 300 seconds")
        if (
            not isinstance(max_output, int)
            or isinstance(max_output, bool)
            or not 1024 <= max_output <= 1024 * 1024
        ):
            raise ValueError("validator output limit must be between 1 KiB and 1 MiB")
        self._docker = docker
        self._image = image
        self._timeout = float(timeout)
        self._max_output = max_output
        self._core_permissions = tuple(sorted(set(core_permissions)))
        self._semaphore = threading.BoundedSemaphore(2)
        self._names_lock = threading.Lock()

    @property
    def image(self) -> str:
        return self._image

    def available(self) -> bool:
        """Return whether Docker can see the fixed local image, without running it."""
        try:
            completed = subprocess.run(
                [self._docker, "image", "inspect", self._image],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0

    def _container_name(self) -> str:
        return f"itsm-extension-validator-{secrets.token_hex(12)}"

    def _command(self, name: str) -> list[str]:
        return [
            self._docker,
            "run",
            "--rm",
            "--name",
            name,
            "--pull=never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "10001:10001",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            "--cpus",
            "0.5",
            "--memory-swap",
            "256m",
            "--log-driver",
            "none",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
            "--ulimit",
            "nofile=256:256",
            "-i",
            self._image,
            "python",
            "-I",
            "-B",
            "/validator/itsm/extensions/sdk/validator/run.py",
        ]

    def validate(self, package_bytes: bytes, *, digest: str | None = None) -> dict[str, Any]:
        """Validate exact bytes, retaining the expected digest in rejection reports."""
        if not isinstance(package_bytes, bytes):
            return self._failed("", "package bytes must be bytes")
        actual = hashlib.sha256(package_bytes).hexdigest()
        expected = digest or actual
        if not isinstance(expected, str) or not DIGEST_PATTERN.fullmatch(expected):
            return self._failed("", "package digest is invalid")
        if expected != actual:
            return self._failed(expected, "package bytes do not match the expected digest")
        try:
            frame = build_frame(
                package_bytes,
                digest=actual,
                known_core_permissions=self._core_permissions,
                limits=DEFAULT_LIMITS,
            )
        except ProtocolError as exc:
            return self._failed(expected, f"validator protocol rejected the package: {exc}")

        name = self._container_name()
        with self._semaphore:
            try:
                returncode, output, failure = self._run_bounded(self._command(name), frame)
            except FileNotFoundError as exc:
                raise ValidatorUnavailable("Docker is not available") from exc
            except OSError as exc:
                raise ValidatorUnavailable("validator container could not start") from exc
            finally:
                self._remove_container(name)
        if failure:
            return self._failed(expected, failure)
        if returncode != 0:
            return self._failed(expected, f"validator container exited with {returncode}")
        try:
            report = json.loads(output.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._failed(expected, "validator did not return a JSON report")
        return self._checked(report, expected)

    def _run_bounded(self, command: list[str], frame: bytes) -> tuple[int, bytes, str | None]:
        """Drain both pipes while bounding total bytes and wall-clock duration."""
        environment = {"PATH": os.defpath, "HOME": "/nonexistent", "DOCKER_CONFIG": "/nonexistent"}
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=environment,
        )
        output = bytearray()
        received = 0
        offset = 0
        failure = None
        deadline = time.monotonic() + self._timeout
        assert process.stdin is not None and process.stdout is not None and process.stderr is not None
        with selectors.DefaultSelector() as selector:
            for stream, event, kind in (
                (process.stdin, selectors.EVENT_WRITE, "input"),
                (process.stdout, selectors.EVENT_READ, "output"),
                (process.stderr, selectors.EVENT_READ, "error"),
            ):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, event, kind)
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        failure = "validator container exceeded its time limit"
                        break
                    for key, _ in selector.select(min(remaining, 0.2)):
                        stream = key.fileobj
                        if key.data == "input":
                            try:
                                offset += os.write(stream.fileno(), frame[offset:offset + 16384])
                            except BrokenPipeError:
                                offset = len(frame)
                            if offset == len(frame):
                                selector.unregister(stream)
                                stream.close()
                            continue
                        chunk = os.read(stream.fileno(), 16384)
                        if not chunk:
                            selector.unregister(stream)
                            stream.close()
                            continue
                        received += len(chunk)
                        if received > self._max_output:
                            failure = "validator output exceeded its limit"
                            break
                        if key.data == "output":
                            output.extend(chunk)
                    if failure:
                        break
                if failure:
                    process.kill()
                try:
                    process.wait(timeout=max(0.1, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    failure = "validator container exceeded its time limit"
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()
        return process.returncode, bytes(output), failure

    def _remove_container(self, name: str) -> None:
        try:
            subprocess.run(
                [self._docker, "rm", "--force", name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=10, check=False,
                env={"PATH": os.defpath, "HOME": "/nonexistent", "DOCKER_CONFIG": "/nonexistent"},
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    def _checked(self, report: Any, expected: str) -> dict[str, Any]:
        error = _report_error(report, expected)
        if error:
            return self._failed(expected, error)
        report["container"] = {**report["container"], "image": self._image, "wrapper": "fixed-docker"}
        return report

    def _failed(self, digest: str, error: str) -> dict[str, Any]:
        return {
            "status": "failed",
            "digest": digest if DIGEST_PATTERN.fullmatch(digest or "") else "",
            "sdkVersion": 1,
            "checks": [{"name": "validator", "status": "failed", "detail": error}],
            "errors": [error],
            "container": {
                "image": self._image,
                "runtime": "docker",
                "network": "none",
                "readOnly": True,
                "nonRoot": True,
                "capabilities": "dropped",
                "engine": "unavailable",
                "limits": (
                    f"archive={DEFAULT_LIMITS['archiveBytes']}; "
                    f"expanded={DEFAULT_LIMITS['expandedBytes']}; "
                    f"entries={DEFAULT_LIMITS['entries']}; "
                    f"file={DEFAULT_LIMITS['fileBytes']}"
                ),
            },
            "completedAt": datetime.now().astimezone().isoformat(),
        }


def _report_error(report: Any, expected: str) -> str | None:
    if not isinstance(report, dict) or set(report) != REPORT_KEYS:
        return "validator report has an unexpected shape"
    if report["status"] not in ("passed", "failed"):
        return "validator report status is invalid"
    if report["digest"] != expected or not DIGEST_PATTERN.fullmatch(expected):
        return "validator report digest does not match the package"
    if type(report["sdkVersion"]) is not int or report["sdkVersion"] != 1:
        return "validator report sdkVersion is invalid"
    errors = report["errors"]
    if not isinstance(errors, list) or len(errors) > 40 or any(
        not isinstance(item, str) or len(item) > 1200 for item in errors
    ):
        return "validator errors are malformed"
    checks = report["checks"]
    if not isinstance(checks, list) or not 1 <= len(checks) <= 200:
        return "validator checks are malformed"
    names: set[str] = set()
    for check in checks:
        if not isinstance(check, dict) or set(check) != CHECK_KEYS:
            return "validator check has an unexpected shape"
        if check["status"] not in ("passed", "failed"):
            return "validator check status is invalid"
        if not isinstance(check["name"], str) or not 1 <= len(check["name"]) <= 128 or check["name"] in names:
            return "validator check name is invalid"
        names.add(check["name"])
        if not isinstance(check["detail"], str) or len(check["detail"]) > 1200:
            return "validator check detail is invalid"
    if not isinstance(report["container"], dict):
        return "validator container metadata is invalid"
    try:
        completed = datetime.fromisoformat(report["completedAt"].replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return "validator completion time is invalid"
    if completed.tzinfo is None:
        return "validator completion time lacks a timezone"
    if report["status"] == "passed" and (errors or any(item["status"] != "passed" for item in checks)):
        return "validator reported failed checks or errors as passed"
    if report["status"] == "failed" and not errors:
        return "validator reported failure without errors"
    return None


def _broker_token(token: str) -> str:
    if not isinstance(token, str) or not 32 <= len(token) <= 512 or any(
        ord(character) < 33 or ord(character) > 126 for character in token
    ):
        raise ValueError("validator broker token must contain 32..512 printable ASCII characters")
    return token


class RemoteContainerValidator:
    """Call only the operator-configured broker; never use ambient HTTP proxies."""

    def __init__(self, url: str, *, token: str, timeout: float = 75, max_output: int = MAX_OUTPUT_BYTES) -> None:
        parts = urlsplit(url)
        try:
            port = parts.port
        except ValueError as exc:
            raise ValueError("validator broker URL port is invalid") from exc
        if (
            parts.scheme not in ("http", "https") or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.path not in ("", "/") or parts.query or parts.fragment
            or port == 0 or any(character.isspace() for character in url)
        ):
            raise ValueError("validator broker URL must be an HTTP(S) server base URL without credentials, path, query or fragment")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 5 <= timeout <= 315:
            raise ValueError("validator broker timeout must be between 5 and 315 seconds")
        if type(max_output) is not int or not 1024 <= max_output <= MAX_OUTPUT_BYTES:
            raise ValueError("validator broker output limit must be between 1 KiB and 256 KiB")
        self._scheme, self._hostname, self._port = parts.scheme, parts.hostname, port
        self._token = _broker_token(token)
        self._timeout, self._max_output = float(timeout), max_output

    def validate(self, package_bytes: bytes, *, digest: str | None = None) -> dict[str, Any]:
        if not isinstance(package_bytes, bytes) or not 1 <= len(package_bytes) <= DEFAULT_LIMITS["archiveBytes"]:
            raise ValueError("validator package must contain 1..4194304 bytes")
        actual = hashlib.sha256(package_bytes).hexdigest()
        if digest is not None and digest != actual:
            raise ValueError("validator package digest does not match its bytes")
        connection_type = http.client.HTTPSConnection if self._scheme == "https" else http.client.HTTPConnection
        connection = connection_type(self._hostname, self._port, timeout=self._timeout)
        try:
            connection.request("POST", "/validate", body=package_bytes, headers={
                "Authorization": "Bearer " + self._token,
                "Content-Type": "application/zip", "X-ITSM-Extension-Digest": actual,
            })
            response = connection.getresponse()
            if response.status == 401:
                raise ValidatorUnavailable("validator broker authorization failed")
            if response.status != 200:
                raise ValidatorUnavailable(f"validator broker returned HTTP {response.status}")
            output = response.read(self._max_output + 1)
            if len(output) > self._max_output:
                raise ValidatorUnavailable("validator broker output exceeded its limit")
            try:
                report = json.loads(output.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidatorUnavailable("validator broker returned invalid JSON") from exc
            error = _report_error(report, actual)
            if error:
                raise ValidatorUnavailable(error)
            return report
        except (OSError, http.client.HTTPException) as exc:
            raise ValidatorUnavailable("validator broker could not be reached") from exc
        finally:
            connection.close()


def create_validator_server(
    *, validator: ContainerValidator, token: str, host: str = "127.0.0.1",
    port: int = 8766, read_timeout: float = 10,
) -> HTTPServer:
    """Build a one-request-at-a-time broker. The caller owns its lifecycle."""
    expected_auth = "Bearer " + _broker_token(token)
    if not isinstance(read_timeout, (int, float)) or not 1 <= read_timeout <= 30:
        raise ValueError("broker request read timeout must be between 1 and 30 seconds")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(read_timeout)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _reply(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_POST(self) -> None:
            authorization = self.headers.get_all("Authorization", [])
            if len(authorization) != 1 or not hmac.compare_digest(authorization[0], expected_auth):
                self._reply(401, {"error": "validator authorization required"})
                return
            if self.path != "/validate":
                self._reply(404, {"error": "validator endpoint not found"})
                return
            if sum(len(key) + len(value) + 4 for key, value in self.headers.items()) > 8192:
                self._reply(431, {"error": "validator headers exceed their limit"})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) != 1:
                self._reply(411, {"error": "validator requires one Content-Length"})
                return
            try:
                length = int(lengths[0])
            except ValueError:
                length = 0
            if not 1 <= length <= DEFAULT_LIMITS["archiveBytes"]:
                self._reply(413, {"error": "validator archive exceeds its limit"})
                return
            digests = self.headers.get_all("X-ITSM-Extension-Digest", [])
            if len(digests) != 1 or not DIGEST_PATTERN.fullmatch(digests[0]):
                self._reply(422, {"error": "validator digest is required"})
                return
            if self.headers.get("Content-Type") != "application/zip":
                self._reply(415, {"error": "validator requires application/zip"})
                return
            try:
                data = self.rfile.read(length)
                if len(data) != length or hashlib.sha256(data).hexdigest() != digests[0]:
                    self._reply(422, {"error": "validator package digest does not match its bytes"})
                    return
                report = validator.validate(data, digest=digests[0])
                if _report_error(report, digests[0]):
                    self._reply(502, {"error": "validator returned an invalid report"})
                    return
                self._reply(200, report)
            except (OSError, socket.timeout, ValidatorUnavailable):
                self._reply(503, {"error": "validator runtime is unavailable"})

    server = HTTPServer((host, port), Handler)
    server.timeout = read_timeout
    return server


def serve_validator(**arguments: Any) -> None:
    server = create_validator_server(**arguments)
    try:
        server.serve_forever()
    finally:
        server.server_close()
