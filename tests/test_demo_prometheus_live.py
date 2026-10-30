"""Opt-in real Prometheus scrape against an isolated demo API, no image pulls."""

import http.cookiejar
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from uuid import uuid4

import pytest
import yaml
from tests.test_release_launch import environment


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def read(url):
    with urllib.request.urlopen(url, timeout=2) as response:
        return json.load(response)


@pytest.mark.skipif(
    os.environ.get("ITSM_TEST_DEMO_PROMETHEUS") != "1", reason="explicit local-container opt-in"
)
def test_real_prometheus_scrapes_current_demo_nodes(tmp_path):
    api_port, prom_port = port(), port()
    env = environment(tmp_path, "demo")
    env["ITSM_PROMETHEUS_URL"] = f"http://127.0.0.1:{prom_port}"
    prepare = subprocess.run(
        [sys.executable, "-m", "itsm.deployment", "prepare"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert prepare.returncode == 0, (prepare.stdout, prepare.stderr)
    # Only this verification substitutes loopback addresses. Compose uses private DNS.
    config = {
        "global": {"scrape_interval": "1s"},
        "scrape_configs": [
            {
                "job_name": "demo-node",
                "http_sd_configs": [
                    {
                        "url": f"http://127.0.0.1:{api_port}/api/v1/demo/telemetry/targets",
                        "refresh_interval": "1s",
                    }
                ],
                "relabel_configs": [
                    {"target_label": "__address__", "replacement": f"127.0.0.1:{api_port}"}
                ],
            }
        ],
    }
    config_path = tmp_path / "prometheus.yml"
    config_path.write_text(yaml.safe_dump(config))
    config_path.chmod(0o644)
    name = f"itsm-telemetry-proof-{uuid4().hex[:12]}"
    with (tmp_path / "api.log").open("w") as log:
        api = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "itsm.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(api_port),
            ],
            env=env,
            stdout=log,
            stderr=log,
        )
        created = False
        try:
            deadline = time.monotonic() + 15
            while True:
                try:
                    targets = read(f"http://127.0.0.1:{api_port}/api/v1/demo/telemetry/targets")
                    assert targets
                    break
                except OSError:
                    assert api.poll() is None and time.monotonic() < deadline
                    time.sleep(0.1)
            command = [
                "docker",
                "run",
                "--pull=never",
                "-d",
                "--name",
                name,
                "--network",
                "host",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt",
                "no-new-privileges",
                "--tmpfs",
                "/tmp",
                "-v",
                f"{config_path}:/etc/prometheus/prometheus.yml:ro,Z",
                "prom/prometheus:v3.14.0",
                "--config.file=/etc/prometheus/prometheus.yml",
                "--storage.tsdb.path=/tmp/data",
                f"--web.listen-address=127.0.0.1:{prom_port}",
            ]
            started = subprocess.run(command, capture_output=True, text=True, timeout=15)
            created = started.returncode == 0
            assert created, started.stderr
            deadline = time.monotonic() + 25
            while True:
                try:
                    result = read(
                        f"http://127.0.0.1:{prom_port}/api/v1/query?query=node_memory_MemAvailable_bytes"
                    )
                    samples = result["data"]["result"]
                    if len(samples) == len(targets):
                        assert all(float(item["value"][1]) > 0 for item in samples)
                        assert all(item["metric"]["asset_id"] for item in samples)
                        break
                except OSError:
                    pass
                assert time.monotonic() < deadline, "real Prometheus never produced node samples"
                time.sleep(0.5)
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            login = urllib.request.Request(
                f"http://127.0.0.1:{api_port}/api/v1/auth/login",
                data=json.dumps({"username": "admin", "password": "admin"}).encode(),
                headers={"Content-Type": "application/json", "Origin": env["ITSM_AUTH_ORIGIN"]},
            )
            with opener.open(login, timeout=3) as response:
                assert response.status == 200
            asset_id = targets[0]["labels"]["asset_id"]
            with opener.open(
                f"http://127.0.0.1:{api_port}/api/v1/monitoring/devices/{asset_id}", timeout=8
            ) as response:
                device = json.load(response)
            assert device["provenance"]["prometheusConfigured"] is True
            assert device["series"], device
            # A newly started TSDB has no 24h query-range grid history yet.
            # Current availability must nevertheless consume the real scrape.
            assert device["uptime"]["samples"] > 0, device
            assert device["uptime"]["percent"] == 100.0, device
        finally:
            api.terminate()
            api.wait(timeout=10)
            if created:
                removed = subprocess.run(
                    ["docker", "rm", "-f", name], capture_output=True, text=True, timeout=15
                )
                assert removed.returncode == 0, removed.stderr
