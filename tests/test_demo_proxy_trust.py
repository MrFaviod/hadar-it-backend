"""Forwarded headers are honoured only when the demo explicitly trusts a proxy.

The application-level ``ITSM_TRUSTED_PROXY`` setting is useless if the ASGI server
already rewrote the client address from a client-supplied ``X-Forwarded-For``
(uvicorn trusts ``127.0.0.1`` by default). The documented launcher
``python -m itsm.main`` therefore derives the server's proxy-header trust from the
same setting, and these tests drive that launcher as a real process.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]


def demo_environment(root: Path) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    env.pop("RELEASE_MODE", None)
    env.update(
        RELEASE_MODE="demo",
        ITSM_ENVIRONMENT="test",
        ITSM_DATABASE_URL=f"sqlite:///{root / 'app.db'}",
        ITSM_TASK_SQLITE_PATH=str(root / "tasks.db"),
        ITSM_ATTACHMENT_STORAGE_PATH=str(root / "attachments"),
        ITSM_DEMO_DATA_DIRECTORY=str(root),
        ITSM_AUTH_ORIGIN="http://127.0.0.1",
        ITSM_AUTH_COOKIE_SECURE="false",
        ITSM_LOG_LEVEL="WARNING",
        ITSM_DEMO_RATE_LIMIT_BURST="2",
        ITSM_DEMO_RATE_LIMIT_PER_MINUTE="1",
        ITSM_DEMO_LOGIN_RATE_BURST="1000",
        ITSM_DEMO_LOGIN_RATE_PER_MINUTE="1000",
        PYTHONPATH=str(BACKEND_ROOT),
        PYTHONDONTWRITEBYTECODE="1",
    )
    return env


def free_port() -> int:
    with socket.socket() as bound:
        bound.bind(("127.0.0.1", 0))
        return int(bound.getsockname()[1])


@contextmanager
def launcher(root: Path, **overrides: str) -> Iterator[tuple[str, Path]]:
    """Start the documented launcher and wait for its liveness route."""
    assert (
        subprocess.run(
            [sys.executable, "-m", "itsm.deployment", "prepare"],
            env=demo_environment(root),
            capture_output=True,
            text=True,
            timeout=60,
        ).returncode
        == 0
    )
    port = free_port()
    env = demo_environment(root)
    env["ITSM_AUTH_ORIGIN"] = f"http://127.0.0.1:{port}"
    env.update(overrides)
    log = root / "api.log"
    with log.open("w") as output:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "itsm.main",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--no-access-log",
            ],
            env=env,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 20
            while True:
                try:
                    with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/api/v1/health/live", timeout=1
                    ) as response:
                        if response.status == 200:
                            break
                except urllib.error.URLError, TimeoutError:
                    assert process.poll() is None, log.read_text()[-2000:]
                    assert time.monotonic() < deadline, log.read_text()[-2000:]
                    time.sleep(0.1)
            yield f"http://127.0.0.1:{port}", log
        finally:
            process.terminate()
            process.wait(timeout=15)


def statuses(base_url: str, headers: dict[str, str] | None = None, count: int = 4) -> list[int]:
    observed: list[int] = []
    for index in range(count):
        request = urllib.request.Request(f"{base_url}/api/v1/health/live")
        for name, value in (headers or {}).items():
            request.add_header(name, value.replace("{index}", str(index)))
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                observed.append(response.status)
        except urllib.error.HTTPError as error:
            observed.append(error.code)
    return observed


def test_spoofed_forwarded_for_cannot_mint_a_new_bucket(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    root.mkdir()
    with launcher(root) as (base_url, _):
        assert statuses(base_url, count=3) == [200, 429, 429]
        spoofed = statuses(base_url, {"X-Forwarded-For": "203.0.113.{index}"})
        assert spoofed == [429, 429, 429, 429], spoofed


def test_trusted_proxy_honours_the_rightmost_forwarded_entry(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    root.mkdir()
    with launcher(root, ITSM_TRUSTED_PROXY="true", ITSM_DEMO_RATE_LIMIT_BURST="1") as (base_url, _):
        # Each distinct forwarded client is its own bucket: burst 1, one per minute.
        spoofed = statuses(base_url, {"X-Forwarded-For": "203.0.113.{index}"})
        assert spoofed == [200, 200, 200, 200], spoofed
        # The rightmost entry is the one the trusted hop appended.
        appended = statuses(base_url, {"X-Forwarded-For": "198.51.100.9, 203.0.113.250"}, count=3)
        assert appended == [200, 429, 429], appended
