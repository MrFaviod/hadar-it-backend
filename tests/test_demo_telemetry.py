"""Public demo telemetry: explicit setup, loopback exporter and real exposition.

Every test drives the installed CLI and the exporter over HTTP; nothing imports a
private helper, so the checks describe the operator-visible contract. Disposable
databases only: each test owns a fresh directory created by the demo initializer.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import yaml

PASSWORD = "Demo-Telemetry-Test-Password-42"
REFUSAL_KEYS = {"status", "code", "message"}


def _env(**overrides: str) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    env.update(ITSM_ENVIRONMENT="test", ITSM_BOOTSTRAP_PASSWORD=PASSWORD)
    env.update(overrides)
    return env


def _cli(args: list[str], **overrides: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "itsm.demo", *args],
        env=_env(**overrides),
        capture_output=True,
        text=True,
        timeout=120,
    )


def _initialize(directory: Path) -> dict:
    result = _cli(["init", "--directory", str(directory), "--username", "demo.owner"])
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stderr == ""
    return json.loads(result.stdout)


def _setup(directory: Path, output: Path, *extra: str, **overrides: str):
    return _cli(
        [
            "setup",
            "--directory",
            str(directory),
            "--username",
            "demo.owner",
            "--output",
            str(output),
            *extra,
        ],
        **overrides,
    )


def _refusal(result: subprocess.CompletedProcess[str]) -> dict:
    assert result.returncode == 1
    assert result.stdout == ""
    payload = json.loads(result.stderr)
    assert set(payload) == REFUSAL_KEYS
    assert payload["status"] == "error"
    assert payload["code"] == "demo_refused"
    return payload


def _state(directory: Path) -> dict[str, object]:
    """Canonical row counts plus the raw file, so a refused run proves no change."""
    database = directory / "demo.db"
    connection = sqlite3.connect(database)
    try:
        tables = [
            row[0]
            for row in connection.execute("select name from sqlite_master where type='table'")
        ]
        counts = {
            table: connection.execute(f"select count(*) from {table}").fetchone()[0]
            for table in ("assets", "monitor_assets", "monitor_exporters")
            if table in tables
        }
    finally:
        connection.close()
    return {"counts": counts, "bytes": database.read_bytes()}


def _asset_rows(directory: Path) -> list[tuple[str, str, str | None]]:
    connection = sqlite3.connect(directory / "demo.db")
    try:
        return list(connection.execute("select id, name, category from assets order by quick_code"))
    finally:
        connection.close()


def _unmarked_database(directory: Path) -> Path:
    """A migrated but unmarked installation, as a production database would be."""
    directory.mkdir()
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        env=_env(ITSM_DATABASE_URL=f"sqlite:///{directory / 'demo.db'}"),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return directory


def _get(url: str) -> tuple[int, str, str]:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            content_type = response.headers.get("Content-Type", "")
            return response.status, content_type, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get("Content-Type", ""), error.read().decode()


def _post(url: str) -> int:
    request = urllib.request.Request(url, data=b"", method="POST")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code


def _free_port() -> int:
    """Ask the kernel for a loopback port; the caller binds it immediately."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@contextlib.contextmanager
def _exporter(directory: Path, port: int = 0) -> Iterator[tuple[dict, subprocess.Popen[str]]]:
    command = [
        sys.executable,
        "-m",
        "itsm.demo",
        "exporter",
        "--directory",
        str(directory),
        "--port",
        str(port),
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_env(),
    )
    try:
        line = process.stdout.readline() if process.stdout else ""
        assert line, process.stderr.read() if process.stderr else ""
        yield json.loads(line), process
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive cleanup only
            process.kill()
            process.wait()


def _sample(body: str, name: str, labels: str = "") -> float:
    pattern = rf"^{re.escape(name)}(?:\{{([^}}]*)\}})? ([0-9.e+-]+)$"
    for match in re.finditer(pattern, body, re.MULTILINE):
        if labels in (match.group(1) or ""):
            return float(match.group(2))
    raise AssertionError(f"missing {name}{{{labels}}} in:\n{body}")


def test_setup_configures_node_monitoring_and_generated_prometheus_config(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    _initialize(directory)
    output = tmp_path / "prometheus.yml"
    result = _setup(directory, output, "--exporter-port", "19101")
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    assert payload["mode"] == "demo"
    assert payload["checkType"] == "node"
    assert payload["exporterAddress"] == "127.0.0.1:19101"
    assert payload["dataset"] == "fictional-infrastructure-v1"
    assert payload["prometheusConfig"] == str(output)
    asset_ids = payload["assetIds"]
    assert len(asset_ids) >= 2
    assert all(re.fullmatch(r"[0-9a-f-]{36}", asset_id) for asset_id in asset_ids)

    config = yaml.safe_load(output.read_text())
    assert config["global"]["scrape_interval"] == "15s"
    assert "alerting" not in config
    assert "rule_files" not in config
    jobs = {job["job_name"]: job for job in config["scrape_configs"]}
    for asset_id in asset_ids:
        job = jobs[f"demo-node-{asset_id[:8]}"]
        assert job["metrics_path"] == f"/metrics/{asset_id}"
        static = job["static_configs"][0]
        assert static["targets"] == ["127.0.0.1:19101"]
        assert static["labels"] == {
            "asset_id": asset_id,
            "check_type": "node",
            "module": "node",
            "dataset": "fictional-infrastructure-v1",
        }
    serialized = output.read_text()
    assert "alertmanager" not in serialized
    assert "9090" not in serialized

    connection = sqlite3.connect(directory / "demo.db")
    try:
        exporters = list(
            connection.execute("select name, kind, module, address, enabled from monitor_exporters")
        )
        assert exporters == [("Demo node exporter", "node", "node", "127.0.0.1:19101", 1)]
        monitored = list(
            connection.execute(
                "select asset_id, enabled, check_type, target, exporter_id, metrics"
                " from monitor_assets order by asset_id"
            )
        )
    finally:
        connection.close()
    assert [row[0] for row in monitored] == sorted(asset_ids)
    for row in monitored:
        assert row[1:4] == (1, "node", "127.0.0.1:19101")
        assert json.loads(row[5]) == ["cpu", "memory", "disk", "temperature"]


def test_generated_targets_reach_a_live_exporter_on_the_configured_port(tmp_path: Path) -> None:
    """The scraped target must be the port the exporter is actually listening on.

    A generated file that names a different port than the running exporter is the
    defect this pins: Prometheus would scrape nothing and the dashboard would show
    no telemetry without any error.
    """
    directory = tmp_path / "demo"
    _initialize(directory)
    output = tmp_path / "prometheus.yml"
    port = _free_port()
    result = _setup(directory, output, "--exporter-port", str(port))
    assert result.returncode == 0, result.stdout + result.stderr
    config = yaml.safe_load(output.read_text())
    with _exporter(directory, port) as (ready, _process):
        assert (ready["host"], ready["port"]) == ("127.0.0.1", port)
        jobs = config["scrape_configs"]
        assert len(jobs) == len(json.loads(result.stdout)["assetIds"])
        for job in jobs:
            target = job["static_configs"][0]["targets"][0]
            assert target == f"127.0.0.1:{port}"
            status, content_type, body = _get(f"http://{target}{job['metrics_path']}")
            assert status == 200
            assert "text/plain" in content_type
            assert _sample(body, "node_cpu_seconds_total", 'mode="idle"') >= 0


def test_init_seeds_synthetic_nodes_but_leaves_the_exporter_unconfigured(
    tmp_path: Path,
) -> None:
    """The first generation carries its node checks; the exporter stays opt-in."""
    directory = tmp_path / "demo"
    _initialize(directory)
    connection = sqlite3.connect(directory / "demo.db")
    try:
        assert connection.execute("select count(*) from monitor_exporters").fetchone()[0] == 0
        rows = connection.execute(
            "select assets.name, monitor_assets.enabled, monitor_assets.check_type,"
            " monitor_assets.target, monitor_assets.exporter_id"
            " from monitor_assets join assets on assets.id = monitor_assets.asset_id"
            " order by assets.name"
        ).fetchall()
    finally:
        connection.close()
    assert [row[0] for row in rows] == ["Hipervisor Norte · DEMO", "Hipervisor Sur · DEMO"]
    assert [row[1:] for row in rows] == [
        (1, "node", "backend:8000", None),
        (1, "node", "backend:8000", None),
    ]


def test_setup_refuses_unmarked_database_before_any_change(tmp_path: Path) -> None:
    directory = _unmarked_database(tmp_path / "production")
    before = _state(directory)
    output = tmp_path / "prometheus.yml"
    payload = _refusal(_setup(directory, output))
    assert payload["message"] == "demo database is not marked as a demonstration installation"
    assert _state(directory) == before
    assert not output.exists()


def test_setup_refuses_existing_output_before_any_change(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    _initialize(directory)
    output = tmp_path / "prometheus.yml"
    output.write_text("existing file must not change\n")
    before = _state(directory)
    payload = _refusal(_setup(directory, output))
    assert payload["message"] == "generated Prometheus configuration already exists"
    assert output.read_text() == "existing file must not change\n"
    assert _state(directory) == before


def test_setup_refuses_production_environment_before_any_change(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    _initialize(directory)
    output = tmp_path / "prometheus.yml"
    before = _state(directory)
    payload = _refusal(_setup(directory, output, ITSM_ENVIRONMENT="production"))
    assert payload["message"] == "demo telemetry is forbidden in production"
    assert _state(directory) == before
    assert not output.exists()


def test_setup_refuses_missing_demo_database(tmp_path: Path) -> None:
    directory = tmp_path / "missing"
    directory.mkdir()
    payload = _refusal(_setup(directory, tmp_path / "prometheus.yml"))
    assert payload["message"] == "demo database does not exist"
    assert list(directory.iterdir()) == []


def test_exporter_refuses_database_without_demo_marker(tmp_path: Path) -> None:
    directory = _unmarked_database(tmp_path / "production")
    before = _state(directory)
    result = _cli(["exporter", "--directory", str(directory), "--port", "0"])
    payload = _refusal(result)
    assert payload["message"] == "demo database is not marked as a demonstration installation"
    assert _state(directory) == before


def test_exporter_exposes_real_node_counters_for_monitored_assets(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    _initialize(directory)
    setup = _setup(directory, tmp_path / "prometheus.yml")
    assert setup.returncode == 0, setup.stdout + setup.stderr
    asset_id = json.loads(setup.stdout)["assetIds"][0]
    before = _state(directory)
    with _exporter(directory) as (ready, process):
        assert ready["status"] == "ready"
        assert ready["host"] == "127.0.0.1"
        assert ready["dataset"] == "fictional-infrastructure-v1"
        base = f"http://127.0.0.1:{ready['port']}"
        status, content_type, first_body = _get(f"{base}/metrics/{asset_id}")
        assert status == 200
        assert content_type == "text/plain; version=0.0.4; charset=utf-8"
        time.sleep(1.2)
        status, _, second_body = _get(f"{base}/metrics/{asset_id}")
        assert status == 200
        first_idle = _sample(first_body, "node_cpu_seconds_total", 'mode="idle"')
        second_idle = _sample(second_body, "node_cpu_seconds_total", 'mode="idle"')
        assert second_idle > first_idle
        total = _sample(second_body, "node_memory_MemTotal_bytes")
        available = _sample(second_body, "node_memory_MemAvailable_bytes")
        assert 0 < available < total
        size = _sample(second_body, "node_filesystem_size_bytes", 'mountpoint="/"')
        free = _sample(second_body, "node_filesystem_avail_bytes", 'mountpoint="/"')
        assert 0 < free < size
        assert 0 < _sample(second_body, "node_hwmon_temp_celsius") < 100
        assert "# TYPE node_cpu_seconds_total counter" in second_body
        # Prometheus owns the target series and labels; the exporter never fakes them.
        assert not re.search(r"^up[{ ]", second_body, re.MULTILINE)
        assert 'asset_id="' not in second_body
        assert "check_type=" not in second_body
        status, _, body = _get(f"{base}/healthz")
        assert (status, body) == (200, "ok\n")
        process.terminate()
        assert process.wait(timeout=10) == 0
        assert process.stderr.read() == ""
    assert _state(directory) == before


def test_exporter_denies_missing_malformed_and_unmonitored_assets(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    _initialize(directory)
    setup = _setup(directory, tmp_path / "prometheus.yml")
    assert setup.returncode == 0, setup.stdout + setup.stderr
    monitored = json.loads(setup.stdout)["assetIds"]
    switch = next(asset for asset in _asset_rows(directory) if asset[2] == "switches")
    before = _state(directory)
    with _exporter(directory) as (ready, process):
        base = f"http://127.0.0.1:{ready['port']}"
        status, _, body = _get(f"{base}/metrics")
        assert (status, body) == (400, "asset uuid required: /metrics/<asset-uuid>\n")
        status, _, body = _get(f"{base}/metrics/not-a-uuid")
        assert (status, body) == (400, "invalid asset uuid\n")
        status, _, body = _get(f"{base}/metrics/00000000-0000-4000-8000-000000000000")
        assert (status, body) == (404, "asset uuid is not in the demo dataset\n")
        status, _, body = _get(f"{base}/metrics/{switch[0]}")
        assert (status, body) == (404, "asset is not configured for node monitoring\n")
        assert switch[0] not in monitored
        status, _, body = _get(f"{base}/unknown")
        assert (status, body) == (404, "not found\n")
        assert _post(f"{base}/metrics/{monitored[0]}") == 405
        process.terminate()
        assert process.wait(timeout=10) == 0
        assert process.stderr.read() == ""
    assert _state(directory) == before


def test_exporter_refuses_production_environment_and_remote_binding(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    _initialize(directory)
    before = _state(directory)
    payload = _refusal(
        _cli(
            ["exporter", "--directory", str(directory), "--port", "0"],
            ITSM_ENVIRONMENT="production",
        )
    )
    assert payload["message"] == "demo telemetry is forbidden in production"
    rejected = _cli(["exporter", "--directory", str(directory), "--port", "0", "--host", "0.0.0.0"])
    assert rejected.returncode == 2
    assert rejected.stdout == ""
    assert "unrecognized arguments: --host 0.0.0.0" in rejected.stderr
    assert _state(directory) == before


def test_cpu_counters_remain_monotonic_over_sustained_operation():
    from itsm.demo.exporter import exposition

    for asset in ["00000000-0000-4000-8000-000000000001", "ffffffff-0000-4000-8000-000000000001"]:
        previous = {}
        for elapsed in range(0, 7201, 15):
            counters = {
                line.split()[0]: float(line.split()[1])
                for line in exposition(asset, elapsed).splitlines()
                if line.startswith("node_cpu_seconds_total{")
            }
            assert all(value >= previous.get(key, 0) for key, value in counters.items())
            previous = counters
