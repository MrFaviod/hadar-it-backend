"""Launch three real mode-owned HTTP processes and refuse every cross-mode DB."""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def environment(root: Path, mode: str) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("ITSM_")}
    env.update(
        RELEASE_MODE=mode,
        ITSM_DATABASE_URL=f"sqlite:///{root / 'app.db'}",
        ITSM_TASK_SQLITE_PATH=str(root / "tasks.db"),
        ITSM_ATTACHMENT_STORAGE_PATH=str(root / "attachments"),
        ITSM_DEV_ADMIN_PASSWORD="launch-test-password-9876",
        ITSM_OPS_BACKUP_ROOT=str(root / "backups"),
        ITSM_ENVIRONMENT="test",
        ITSM_AUTH_ORIGIN="http://127.0.0.1",
        ITSM_AUTH_COOKIE_SECURE="false",
    )
    if mode == "demo":
        env["ITSM_DEMO_DATA_DIRECTORY"] = str(root)
    return env


def test_real_three_mode_launch_and_all_cross_mode_refusals(tmp_path):
    databases = {}
    for mode in ("dev", "prod", "demo"):
        root = tmp_path / mode
        root.mkdir()
        env = environment(root, mode)
        prepared = subprocess.run(
            [sys.executable, "-m", "itsm.deployment", "prepare"],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert prepared.returncode == 0, (prepared.stdout, prepared.stderr)
        with socket.socket() as bound:
            bound.bind(("127.0.0.1", 0))
            port = bound.getsockname()[1]
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
                ],
                env=env,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 15
                while True:
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/api/v1/health/ready", timeout=1
                        ) as response:
                            payload = json.load(response)
                            break
                    except urllib.error.URLError, TimeoutError:
                        assert process.poll() is None, log.read_text()[-2000:]
                        assert time.monotonic() < deadline, log.read_text()[-2000:]
                        time.sleep(0.1)
                assert payload["releaseMode"] == mode
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/api/v1/demo/status", timeout=2
                ) as response:
                    status = json.load(response)
                assert status["enabled"] is (mode == "demo")
                if mode == "demo":
                    assert status["generation"] == 1
            finally:
                process.terminate()
                process.wait(timeout=10)
        databases[mode] = env
    for owner, env in databases.items():
        before = Path(env["ITSM_DATABASE_URL"].removeprefix("sqlite:///")).read_bytes()
        for requested in ("dev", "prod", "demo"):
            if requested == owner:
                continue
            cross = dict(env, RELEASE_MODE=requested)
            result = subprocess.run(
                [sys.executable, "-m", "itsm.deployment", "prepare"],
                env=cross,
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode != 0, (owner, requested, result.stdout)
            assert Path(env["ITSM_DATABASE_URL"].removeprefix("sqlite:///")).read_bytes() == before
