"""Loopback-only synthetic node exporter for a marked demonstration installation.

The exporter serves real Prometheus exposition text. Values are deterministic
synthetic counters and gauges derived from the browser's index in the canonical
dataset and from elapsed time; they are never stored in the database, never sent
anywhere, and never read from a device. Target labels (``instance``, ``job``,
``up``) are produced by Prometheus itself from the generated scrape file.
"""

from __future__ import annotations

import json
import math
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from itsm.demo.telemetry import (
    CHECK_TYPE,
    LOOPBACK,
    demo_dataset,
    demo_session,
    refuse_production,
)
from itsm.inventory.models import Asset
from itsm.monitoring.models import MonitorAsset
from itsm.monitoring.prometheus import UUID_PATTERN

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
CPU_COUNT = 8
MEMORY_TOTAL = 32 * 1024**3
FILESYSTEM_SIZE = 512 * 1024**3
_CPU_MODES = ("idle", "user", "system", "iowait")


class _NotFound(Exception):
    """The request names an asset this exporter must not serve."""


def _number(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:.6f}"


def _labels(**labels: str) -> str:
    return ",".join(f'{key}="{value}"' for key, value in labels.items())


def _phase(asset_id: str) -> float:
    """Deterministic per-asset offset so no two fictional nodes look identical."""
    return math.radians(int(asset_id[:8], 16) % 360)


def exposition(asset_id: str, elapsed: float) -> str:
    """Return a node-exporter-shaped body for one fictional asset."""
    phase = _phase(asset_id)
    idle_share = 0.80 + 0.06 * math.sin(elapsed / 45 + phase)
    total_seconds = elapsed * CPU_COUNT
    lines: list[str] = []
    lines.append("# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.")
    lines.append("# TYPE node_cpu_seconds_total counter")
    shares = {
        "idle": idle_share,
        "user": (1 - idle_share) * 0.62,
        "system": (1 - idle_share) * 0.28,
        "iowait": (1 - idle_share) * 0.10,
    }
    for cpu in range(CPU_COUNT):
        for mode in _CPU_MODES:
            seconds = total_seconds * shares[mode]
            lines.append(
                f"node_cpu_seconds_total{{{_labels(cpu=str(cpu), mode=mode)}}} {_number(seconds)}"
            )
    available = MEMORY_TOTAL * (0.52 + 0.10 * math.sin(elapsed / 70 + phase))
    lines.append("# HELP node_memory_MemTotal_bytes Memory information field MemTotal_bytes.")
    lines.append("# TYPE node_memory_MemTotal_bytes gauge")
    lines.append(f"node_memory_MemTotal_bytes {_number(MEMORY_TOTAL)}")
    lines.append(
        "# HELP node_memory_MemAvailable_bytes Memory information field MemAvailable_bytes."
    )
    lines.append("# TYPE node_memory_MemAvailable_bytes gauge")
    lines.append(f"node_memory_MemAvailable_bytes {_number(available)}")
    filesystem_avail = FILESYSTEM_SIZE * (0.66 + 0.08 * math.sin(elapsed / 90 + phase))
    lines.append("# HELP node_filesystem_size_bytes Filesystem size in bytes.")
    lines.append("# TYPE node_filesystem_size_bytes gauge")
    lines.append(
        f"node_filesystem_size_bytes{{{_labels(device='/dev/demo0', mountpoint='/')}}}"
        f" {_number(FILESYSTEM_SIZE)}"
    )
    lines.append(
        "# HELP node_filesystem_avail_bytes Filesystem space available to non-root users in bytes."
    )
    lines.append("# TYPE node_filesystem_avail_bytes gauge")
    lines.append(
        f"node_filesystem_avail_bytes{{{_labels(device='/dev/demo0', mountpoint='/')}}}"
        f" {_number(filesystem_avail)}"
    )
    temperature = 42 + 6 * math.sin(elapsed / 60 + phase)
    lines.append("# HELP node_hwmon_temp_celsius Hardware monitor for temperature (input).")
    lines.append("# TYPE node_hwmon_temp_celsius gauge")
    lines.append(f"node_hwmon_temp_celsius {_number(temperature)}")
    return "\n".join(lines) + "\n"


def _monitored_asset(directory: Path, asset_id: str) -> str:
    """Return the canonical asset id, or raise the exact refusal reason."""
    with demo_session(directory) as (session, _settings):
        asset = session.get(Asset, asset_id)
        if asset is None:
            raise _NotFound("asset uuid is not in the demo dataset\n")
        config = session.get(MonitorAsset, asset_id)
        if config is None or config.enabled is not True or config.check_type != CHECK_TYPE:
            raise _NotFound("asset is not configured for node monitoring\n")
        return asset.id


class _Handler(BaseHTTPRequestHandler):
    server_version = "itsm-demo-exporter"
    sys_version = ""

    def log_message(self, *_args: object) -> None:
        """Stay silent: the exporter owns stdout/stderr for its ready line only."""

    def _send(self, status: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", CONTENT_TYPE)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._send(200, "ok\n")
            return
        if not path.startswith("/metrics"):
            self._send(404, "not found\n")
            return
        asset_id = path.removeprefix("/metrics")
        if not asset_id.startswith("/"):
            self._send(400, "asset uuid required: /metrics/<asset-uuid>\n")
            return
        asset_id = asset_id[1:]
        if not UUID_PATTERN.match(asset_id):
            self._send(400, "invalid asset uuid\n")
            return
        server: _Server = self.server
        try:
            canonical = _monitored_asset(server.directory, asset_id)
        except _NotFound as refusal:
            self._send(404, str(refusal))
            return
        except Exception:
            # A refusal must never crash the loop or leak the underlying error.
            self._send(503, "demo database unavailable\n")
            return
        self._send(200, exposition(canonical, time.monotonic() - server.started))

    def _method_not_allowed(self) -> None:
        self._send(405, "method not allowed\n")

    do_POST = _method_not_allowed
    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], directory: Path) -> None:
        self.directory = directory
        self.started = time.monotonic()
        super().__init__(address, _Handler)


def serve(directory: Path, port: int) -> int:
    """Serve the demo exposition on the loopback interface until a stop signal."""
    refuse_production()
    directory = directory.absolute()
    with demo_session(directory) as (session, _settings):
        dataset = demo_dataset(session)
    server = _Server((LOOPBACK, port), directory)
    host, bound_port = server.server_address[0], server.server_address[1]
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    previous = signal.signal(signal.SIGTERM, request_stop)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True
    )
    try:
        thread.start()
        print(
            json.dumps(
                {
                    "status": "ready",
                    "host": str(host),
                    "port": bound_port,
                    "dataset": dataset,
                    "database": f"sqlite:///{directory / 'demo.db'}",
                }
            ),
            flush=True,
        )
        stop.wait()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        signal.signal(signal.SIGTERM, previous)
    return 0
