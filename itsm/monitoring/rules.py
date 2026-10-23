"""Bounded monitoring vocabulary: check types, metric catalog, presets and defaults.

The catalog is deliberately small and explicit. A metric exists only when a real
exporter series is queried for the check type (see ``PROMETHEUS.md`` in
``docs/monitoring.md``); thresholds cannot be configured for a metric the adapter
never reads, so the API never promises supervision it cannot deliver.
"""

from __future__ import annotations

import re
from typing import Final

CHECK_TYPES: Final[tuple[str, ...]] = ("icmp", "http", "tcp", "dns", "snmp", "node", "windows")
PROBE_CHECK_TYPES: Final[frozenset[str]] = frozenset({"icmp", "http", "tcp", "dns"})
EXPORTER_CHECK_TYPES: Final[frozenset[str]] = frozenset({"snmp", "node", "windows"})

PERIOD_PRESETS: Final[dict[str, int]] = {
    "24h": 24 * 3600,
    "7d": 7 * 24 * 3600,
    "30d": 30 * 24 * 3600,
}
DEFAULT_PERIOD: Final[str] = "24h"
INTERVAL_PRESETS: Final[tuple[int, ...]] = (30, 60, 300, 900)
MINIMUM_DURATION_PRESETS: Final[tuple[int, ...]] = (0, 60, 300, 900)
DEFAULT_INTERVAL: Final[int] = 60
DEFAULT_MINIMUM_DURATION: Final[int] = 300

MAX_SERIES_POINTS: Final[int] = 300
MAX_SERIES: Final[int] = 4
MAX_DEVICES: Final[int] = 200
MAX_ALERTS_PER_INGEST: Final[int] = 500
MAX_INGEST_BYTES: Final[int] = 1024 * 1024
MAX_SD_ASSETS: Final[int] = 5000
RULE_BUNDLE_VERSION: Final[str] = "phase8-1"
MAX_SILENCE_SECONDS: Final[int] = 30 * 24 * 3600
MAX_LIMIT: Final[int] = 200
DEFAULT_LIMIT: Final[int] = 50

# ``metric -> (unit, label)``. ``latency`` is seconds; the rest are percent or Celsius.
METRIC_CATALOG: Final[dict[str, tuple[str, str]]] = {
    "latency": ("seconds", "Latencia"),
    "cpu": ("percent", "CPU"),
    "memory": ("percent", "Memoria"),
    "disk": ("percent", "Almacenamiento"),
    "temperature": ("celsius", "Temperatura"),
}

CHECK_METRICS: Final[dict[str, tuple[str, ...]]] = {
    "icmp": ("latency",),
    "http": ("latency",),
    "tcp": ("latency",),
    "dns": ("latency",),
    "snmp": (),
    "node": ("cpu", "memory", "disk", "temperature"),
    "windows": ("cpu", "memory", "disk"),
}

DEFAULT_MODULE: Final[dict[str, str]] = {
    "icmp": "icmp",
    "http": "http_2xx",
    "tcp": "tcp_connect",
    "dns": "dns",
    "snmp": "if_mib",
    "node": "node",
    "windows": "windows",
}

EXPORTER_KINDS: Final[tuple[str, ...]] = ("blackbox", "snmp", "node", "windows")
EXPORTER_FOR_CHECK: Final[dict[str, str]] = {
    "icmp": "blackbox",
    "http": "blackbox",
    "tcp": "blackbox",
    "dns": "blackbox",
    "snmp": "snmp",
    "node": "node",
    "windows": "windows",
}

SEVERITIES: Final[tuple[str, ...]] = ("info", "warning", "critical")
ALERT_STATES: Final[tuple[str, ...]] = ("pending", "firing", "resolved")
ALERT_SOURCES: Final[tuple[str, ...]] = ("alertmanager", "prometheus")

SLUG_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TIME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^([01][0-9]|2[0-3]):([0-5][0-9])$")
HOST_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$"
)
HOST_PORT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?:([0-9]{1,5})$"
)

# Categories keep the installation vocabulary (Spanish ids); the default profile
# is derived from stable tokens so an administrator can still override any of it.
_INFRASTRUCTURE_TOKENS: Final[tuple[str, ...]] = (
    "servidor",
    "server",
    "switch",
    "gateway",
    "router",
    "firewall",
    "biometric",
    "reloj",
    "ups",
    "nas",
    "storage",
    "almacenamiento",
    "access",
    "punto",
    "red",
)
_WORKSTATION_TOKENS: Final[tuple[str, ...]] = (
    "computadora",
    "workstation",
    "notebook",
    "laptop",
    "desktop",
    "escritorio",
)
_SNMP_TOKENS: Final[tuple[str, ...]] = (
    "switch",
    "gateway",
    "router",
    "firewall",
    "ups",
    "nas",
    "red",
    "access",
    "punto",
)
_BIOMETRIC_TOKENS: Final[tuple[str, ...]] = ("biometric", "reloj")


def _matches(category: str, tokens: tuple[str, ...]) -> bool:
    return any(token in category for token in tokens)


def default_profile(category: str | None, asset_type: str | None = None) -> dict[str, object]:
    """Built-in category defaults, computed on read and never materialized."""
    normalized = (category or "").strip().lower()
    kind = (asset_type or "").strip().lower()
    enabled = _matches(normalized, _INFRASTRUCTURE_TOKENS)
    if _matches(normalized, _WORKSTATION_TOKENS):
        enabled = False
    if _matches(normalized, _BIOMETRIC_TOKENS):
        check_type: str | None = "icmp"
    elif _matches(normalized, ("servidor", "server")):
        check_type = "windows" if "windows" in kind else "node"
    elif _matches(normalized, _SNMP_TOKENS):
        check_type = "snmp"
    elif normalized:
        check_type = "icmp"
    else:
        check_type = None
    return {
        "enabled": enabled,
        "checkType": check_type,
        "intervalSeconds": DEFAULT_INTERVAL,
        "metrics": list(CHECK_METRICS.get(check_type or "", ())),
        "thresholds": {},
        "minimumDurationSeconds": DEFAULT_MINIMUM_DURATION,
        "exporterId": None,
        "snmpModule": None,
        "snmpAuthRef": None,
        "configured": False,
    }


__all__ = [
    "ALERT_SOURCES",
    "ALERT_STATES",
    "CHECK_METRICS",
    "CHECK_TYPES",
    "DEFAULT_LIMIT",
    "DEFAULT_MINIMUM_DURATION",
    "DEFAULT_MODULE",
    "DEFAULT_PERIOD",
    "EXPORTER_CHECK_TYPES",
    "EXPORTER_FOR_CHECK",
    "EXPORTER_KINDS",
    "HOST_PATTERN",
    "HOST_PORT_PATTERN",
    "INTERVAL_PRESETS",
    "MAX_ALERTS_PER_INGEST",
    "MAX_DEVICES",
    "MAX_INGEST_BYTES",
    "MAX_LIMIT",
    "MAX_SERIES",
    "MAX_SERIES_POINTS",
    "MAX_SILENCE_SECONDS",
    "METRIC_CATALOG",
    "MINIMUM_DURATION_PRESETS",
    "PERIOD_PRESETS",
    "PROBE_CHECK_TYPES",
    "SEVERITIES",
    "SLUG_PATTERN",
    "TIME_PATTERN",
    "default_profile",
]
