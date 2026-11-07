"""Bounded read adapter for Prometheus and Alertmanager; no raw PromQL leaves this module.

Only administrator-controlled endpoints from settings are contacted. Request
bodies and responses are bounded, redirects are refused, and every query is
built here from a fixed expression catalog plus a validated asset UUID, so no
client can supply PromQL, an arbitrary host or an outbound URL.
"""

from __future__ import annotations

import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from itsm.config import Settings
from itsm.identity.clock import as_utc, utcnow
from itsm.monitoring.rules import (
    CHECK_METRICS,
    EXPORTER_CHECK_TYPES,
    MAX_DEVICES,
    MAX_SERIES_POINTS,
    PERIOD_PRESETS,
    PROBE_CHECK_TYPES,
)

MAX_RESPONSE_BYTES: Final[int] = 4 * 1024 * 1024
MAX_VECTOR_LENGTH: Final[int] = 2000
RATE_WINDOW: Final[str] = "5m"
UUID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class MonitoringUnavailable(Exception):
    """The monitoring backend could not provide a trustworthy answer."""


@dataclass(frozen=True)
class RangeWindow:
    """One of the three admitted periods, aligned to a bounded number of points."""

    preset: str
    start: datetime
    end: datetime
    step_seconds: int

    @property
    def selector(self) -> str:
        return f"{PERIOD_PRESETS[self.preset]}s"


def range_window(period: str, *, now: datetime | None = None) -> RangeWindow:
    if period not in PERIOD_PRESETS:
        raise ValueError("unsupported period")
    end = as_utc(now or utcnow())
    seconds = PERIOD_PRESETS[period]
    start = end - timedelta(seconds=seconds)
    step = max(60, math.ceil(seconds / max(1, MAX_SERIES_POINTS - 1)))
    return RangeWindow(preset=period, start=start, end=end, step_seconds=step)


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _asset_matcher(asset_ids: list[str]) -> str:
    if not 0 < len(asset_ids) <= MAX_DEVICES:
        raise MonitoringUnavailable("asset selection exceeds the bounded query size")
    for asset_id in asset_ids:
        if not UUID_PATTERN.fullmatch(asset_id):
            raise MonitoringUnavailable("invalid asset selection")
    if len(asset_ids) == 1:
        return f'asset_id="{_escape_label(asset_ids[0])}"'
    joined = "|".join(re.escape(asset_id) for asset_id in asset_ids)
    return f'asset_id=~"{_escape_label(joined)}"'


def _checked_signal(check_type: str) -> str:
    if check_type not in PROBE_CHECK_TYPES and check_type not in EXPORTER_CHECK_TYPES:
        raise MonitoringUnavailable("unsupported check type")
    return "probe_success" if check_type in PROBE_CHECK_TYPES else "up"


def _typed_selectors(
    assets: list[tuple[str, str]], signal: str
) -> list[str]:
    """One selector per check type so stale series from a previous check never leak."""
    grouped: dict[str, list[str]] = {}
    for asset_id, check_type in assets:
        _checked_signal(check_type)
        grouped.setdefault(check_type, []).append(asset_id)
    return [
        (
            f"{signal}{{{_asset_matcher(grouped[check_type])},"
            f'check_type="{_escape_label(check_type)}"}}'
        )
        for check_type in sorted(grouped)
    ]


def _weighted_uptime_query(
    selectors: list[str], window: RangeWindow
) -> tuple[str, str]:
    """Sample-count-weighted uptime across label churn for the selected check type."""
    numerator = " or ".join(
        f"sum_over_time({selector}[{window.selector}])" for selector in selectors
    )
    denominator = " or ".join(
        f"count_over_time({selector}[{window.selector}])" for selector in selectors
    )
    percentage = (
        f"(sum by (asset_id) ({numerator})"
        f" / sum by (asset_id) ({denominator})) * 100"
    )
    return percentage, f"sum by (asset_id) ({denominator})"


# Fixed expressions: one per (check type, metric). ``{selector}`` is substituted
# with a validated asset matcher; nothing else from the request reaches PromQL.
_METRIC_EXPRESSIONS: Final[dict[tuple[str, str], str]] = {
    ("node", "cpu"): (
        "100 * (1 - avg by (asset_id) "
        "(rate(node_cpu_seconds_total{{{selector},mode=\"idle\"}}[5m])))"
    ),
    ("node", "memory"): (
        "100 * (1 - (max by (asset_id) (node_memory_MemAvailable_bytes{{{selector}}}) "
        "/ max by (asset_id) (node_memory_MemTotal_bytes{{{selector}}})))"
    ),
    ("node", "disk"): (
        "100 * (1 - (max by (asset_id) "
        "(node_filesystem_avail_bytes{{{selector},mountpoint=\"/\"}}) "
        "/ max by (asset_id) "
        "(node_filesystem_size_bytes{{{selector},mountpoint=\"/\"}})))"
    ),
    ("node", "temperature"): "max by (asset_id) (node_hwmon_temp_celsius{{{selector}}})",
    ("windows", "cpu"): (
        "100 * (1 - avg by (asset_id) "
        "(rate(windows_cpu_time_total{{{selector},mode=\"idle\"}}[5m])))"
    ),
    ("windows", "memory"): (
        "100 * (1 - (max by (asset_id) (windows_memory_available_bytes{{{selector}}}) "
        "/ max by (asset_id) (windows_cs_physical_memory_bytes{{{selector}}})))"
    ),
    ("windows", "disk"): (
        "100 * (1 - (max by (asset_id) "
        "(windows_logical_disk_free_bytes{{{selector},volume=\"C:\"}}) "
        "/ max by (asset_id) "
        "(windows_logical_disk_size_bytes{{{selector},volume=\"C:\"}})))"
    ),
}


def metric_expression(check_type: str, metric: str, asset_id: str) -> str | None:
    """Return the fixed expression or ``None`` when the metric is unavailable."""
    if metric == "latency" and check_type in PROBE_CHECK_TYPES:
        return f'max by (asset_id) (probe_duration_seconds{{{_asset_matcher([asset_id])}}})'
    if metric not in CHECK_METRICS.get(check_type, ()):
        return None
    template = _METRIC_EXPRESSIONS.get((check_type, metric))
    if template is None:
        return None
    return template.format(selector=_asset_matcher([asset_id]))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PrometheusAdapter:
    """Thin Prometheus/Alertmanager client with fixed, bounded requests."""

    def __init__(self, settings: Settings, *, opener: Any | None = None) -> None:
        self._settings = settings
        self._opener = opener or urllib.request.build_opener(_NoRedirect)

    @property
    def configured(self) -> bool:
        return bool(self._settings.prometheus_url)

    @property
    def alertmanager_configured(self) -> bool:
        return bool(self._settings.alertmanager_url)

    # ------------------------------------------------------------------ http
    def _token(self, alertmanager: bool) -> str | None:
        secret = (
            self._settings.alertmanager_token
            if alertmanager
            else self._settings.prometheus_token
        )
        if secret is None:
            return None
        return secret.get_secret_value() or None

    def _request(
        self,
        base: str | None,
        path: str,
        *,
        alertmanager: bool = False,
        method: str = "GET",
        params: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        if not base:
            raise MonitoringUnavailable("monitoring endpoint is not configured")
        url = base + path
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        headers = {"Accept": "application/json"}
        token = self._token(alertmanager)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        timeout = self._settings.monitoring_http_timeout_seconds
        try:
            with self._opener.open(request, timeout=timeout) as response:
                status = getattr(response, "status", None) or response.getcode()
                if status not in {200, 202, 204}:
                    raise MonitoringUnavailable("monitoring endpoint rejected the request")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except MonitoringUnavailable:
            raise
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
            raise MonitoringUnavailable("monitoring endpoint is unavailable") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise MonitoringUnavailable("monitoring response exceeds the bounded size")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MonitoringUnavailable("monitoring response is not valid JSON") from exc

    def _prometheus(self, path: str, params: dict[str, str]) -> Any:
        payload = self._request(self._settings.prometheus_url, path, params=params)
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise MonitoringUnavailable("prometheus query failed")
        return payload.get("data")

    # ------------------------------------------------------------- parsing
    @staticmethod
    def _number(value: Any) -> float | None:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        return number if math.isfinite(number) else None

    def _vector_samples(
        self, data: Any
    ) -> list[tuple[dict[str, str], float, float | None]]:
        if not isinstance(data, dict):
            raise MonitoringUnavailable("prometheus response has no data")
        result = data.get("result")
        if not isinstance(result, list) or len(result) > MAX_VECTOR_LENGTH:
            raise MonitoringUnavailable("prometheus response is unbounded")
        values: list[tuple[dict[str, str], float, float | None]] = []
        for item in result:
            if not isinstance(item, dict):
                continue
            metric = item.get("metric") if isinstance(item.get("metric"), dict) else {}
            sample = item.get("value")
            if not isinstance(sample, (list, tuple)) or len(sample) != 2:
                continue
            number = self._number(sample[1])
            if number is not None:
                values.append((metric, number, self._number(sample[0])))
        return values

    def _vector(self, data: Any) -> list[tuple[dict[str, str], float]]:
        return [(metric, number) for metric, number, _ in self._vector_samples(data)]

    def _single_value(self, data: Any) -> float | None:
        values = self._vector(data)
        return values[0][1] if values else None

    @staticmethod
    def _bounded_points(points: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(points) <= MAX_SERIES_POINTS:
            return points
        keep = MAX_SERIES_POINTS - 2
        stride = (len(points) - 2) / keep
        sampled = [points[0]]
        for index in range(keep):
            sampled.append(points[1 + int(index * stride)])
        sampled.append(points[-1])
        return sampled

    # --------------------------------------------------------------- reads
    def _matrix(self, expression: str, window: RangeWindow) -> list[dict[str, Any]]:
        data = self._prometheus(
            "/api/v1/query_range",
            {
                "query": expression,
                "start": f"{window.start.timestamp():.0f}",
                "end": f"{window.end.timestamp():.0f}",
                "step": str(window.step_seconds),
            },
        )
        if not isinstance(data, dict):
            raise MonitoringUnavailable("prometheus response has no data")
        result = data.get("result")
        if not isinstance(result, list) or len(result) > MAX_VECTOR_LENGTH:
            raise MonitoringUnavailable("prometheus response is unbounded")
        if not result:
            return []
        series = result[0] if isinstance(result[0], dict) else {}
        values = series.get("values")
        if not isinstance(values, list):
            return []
        points: list[dict[str, Any]] = []
        for sample in values:
            if not isinstance(sample, (list, tuple)) or len(sample) != 2:
                continue
            at = self._number(sample[0])
            value = self._number(sample[1])
            if at is None or value is None:
                continue
            points.append(
                {
                    "at": datetime.fromtimestamp(at, tz=UTC).isoformat().replace(
                        "+00:00", "Z"
                    ),
                    "value": round(value, 4),
                }
            )
        return self._bounded_points(points)

    def current_states(
        self, assets: list[tuple[str, str]], *, now: datetime | None = None
    ) -> dict[str, dict[str, float | None]]:
        """Batched current state for a bounded device page (two queries at most)."""
        if not self.configured or not assets:
            return {}
        probe_assets = [(asset_id, kind) for asset_id, kind in assets if kind in PROBE_CHECK_TYPES]
        exporter_assets = [
            (asset_id, kind) for asset_id, kind in assets if kind not in PROBE_CHECK_TYPES
        ]
        states: dict[str, dict[str, Any]] = {
            asset_id: {"success": None, "latency": None, "up": None, "at": None}
            for asset_id, _ in assets
        }
        if probe_assets:
            success = " or ".join(_typed_selectors(probe_assets, "probe_success"))
            data = self._prometheus(
                "/api/v1/query",
                {"query": f"max by (asset_id) ({success})"},
            )
            for metric, value, sample_at in self._vector_samples(data):
                asset_id = metric.get("asset_id")
                if asset_id in states:
                    states[asset_id]["success"] = value
                    states[asset_id]["at"] = _iso(sample_at)
            duration = " or ".join(
                _typed_selectors(probe_assets, "probe_duration_seconds")
            )
            data = self._prometheus(
                "/api/v1/query",
                {"query": f"max by (asset_id) ({duration})"},
            )
            for metric, value, sample_at in self._vector_samples(data):
                asset_id = metric.get("asset_id")
                if asset_id in states:
                    states[asset_id]["latency"] = value
                    states[asset_id]["at"] = _iso(sample_at)
        if exporter_assets:
            exporter_up = " or ".join(_typed_selectors(exporter_assets, "up"))
            data = self._prometheus(
                "/api/v1/query", {"query": f"max by (asset_id) ({exporter_up})"}
            )
            for metric, value, sample_at in self._vector_samples(data):
                asset_id = metric.get("asset_id")
                if asset_id in states:
                    states[asset_id]["up"] = value
                    states[asset_id]["at"] = _iso(sample_at)
        return states

    def page_availability(
        self, assets: list[tuple[str, str]], window: RangeWindow
    ) -> dict[str, dict[str, Any]]:
        """Batched window uptime for one device page (four queries at most)."""
        result: dict[str, dict[str, Any]] = {
            asset_id: {"percent": None, "samples": 0} for asset_id, _ in assets
        }
        if not self.configured:
            return result
        groups = [
            (
                [(asset_id, kind) for asset_id, kind in assets if kind in PROBE_CHECK_TYPES],
                "probe_success",
            ),
            (
                [
                    (asset_id, kind)
                    for asset_id, kind in assets
                    if kind not in PROBE_CHECK_TYPES
                ],
                "up",
            ),
        ]
        for typed_assets, signal in groups:
            if not typed_assets:
                continue
            selectors = _typed_selectors(typed_assets, signal)
            percentage, counts = _weighted_uptime_query(selectors, window)
            averages = self._prometheus(
                "/api/v1/query", {"query": percentage}
            )
            samples = self._prometheus("/api/v1/query", {"query": counts})
            for metric, value in self._vector(averages):
                asset_id = metric.get("asset_id")
                if asset_id in result:
                    result[asset_id]["percent"] = round(value, 3)
            for metric, value in self._vector(samples):
                asset_id = metric.get("asset_id")
                if asset_id in result:
                    result[asset_id]["samples"] = int(value)
        return result

    def availability(
        self, asset_id: str, check_type: str, window: RangeWindow
    ) -> dict[str, Any]:
        if not self.configured:
            raise MonitoringUnavailable("prometheus is not configured")
        signal = _checked_signal(check_type)
        selectors = _typed_selectors([(asset_id, check_type)], signal)
        percentage, counts = _weighted_uptime_query(selectors, window)
        average = self._single_value(
            self._prometheus("/api/v1/query", {"query": percentage})
        )
        samples = self._single_value(
            self._prometheus("/api/v1/query", {"query": counts})
        )
        return {
            "percent": round(average, 3) if average is not None else None,
            "samples": int(samples) if samples is not None else 0,
        }

    def latency(self, asset_id: str, check_type: str, window: RangeWindow) -> dict[str, Any] | None:
        if check_type not in PROBE_CHECK_TYPES or not self.configured:
            return None
        selectors = _typed_selectors([(asset_id, check_type)], "probe_duration_seconds")
        duration = " or ".join(selectors)
        current = self._single_value(
            self._prometheus(
                "/api/v1/query",
                {"query": f"max by (asset_id) ({duration})"},
            )
        )
        average = self._single_value(
            self._prometheus(
                "/api/v1/query",
                {
                    "query": (
                        f"avg_over_time({duration}"
                        f"[{window.selector}])"
                    )
                },
            )
        )
        p95 = self._single_value(
            self._prometheus(
                "/api/v1/query",
                {
                    "query": (
                        f"quantile_over_time(0.95, {duration}"
                        f"[{window.selector}])"
                    )
                },
            )
        )
        if current is None and average is None and p95 is None:
            return None
        return {
            "currentMs": round(current * 1000, 2) if current is not None else None,
            "averageMs": round(average * 1000, 2) if average is not None else None,
            "p95Ms": round(p95 * 1000, 2) if p95 is not None else None,
        }

    def metric_series(
        self, asset_id: str, check_type: str, metric: str, window: RangeWindow
    ) -> list[dict[str, Any]] | None:
        expression = metric_expression(check_type, metric, asset_id)
        if expression is None or not self.configured:
            return None
        return self._matrix(expression, window)

    def alerts(self) -> list[dict[str, Any]]:
        data = self._prometheus("/api/v1/alerts", {})
        if not isinstance(data, dict):
            raise MonitoringUnavailable("prometheus alerts response has no data")
        alerts = data.get("alerts")
        if not isinstance(alerts, list) or len(alerts) > MAX_VECTOR_LENGTH:
            raise MonitoringUnavailable("prometheus alerts response is unbounded")
        parsed: list[dict[str, Any]] = []
        for item in alerts:
            if not isinstance(item, dict):
                continue
            labels = item.get("labels")
            annotations = item.get("annotations")
            if not isinstance(labels, dict) or not isinstance(annotations, dict):
                continue
            parsed.append(
                {
                    "labels": {str(key): str(value) for key, value in labels.items()},
                    "annotations": {
                        str(key): str(value) for key, value in annotations.items()
                    },
                    "state": str(item.get("state") or ""),
                    "activeAt": item.get("activeAt"),
                }
            )
        return parsed

    # ----------------------------------------------------------- alertmanager
    def create_silence(
        self,
        *,
        matchers: list[dict[str, Any]],
        starts_at: datetime,
        ends_at: datetime,
        comment: str,
        created_by: str,
    ) -> str:
        if not matchers or len(matchers) > 100:
            raise MonitoringUnavailable("silence matchers are required and bounded")
        if as_utc(ends_at) <= as_utc(starts_at):
            raise MonitoringUnavailable("silence end must follow its start")
        payload = {
            "matchers": matchers,
            "startsAt": _rfc3339(starts_at),
            "endsAt": _rfc3339(ends_at),
            "createdBy": created_by,
            "comment": comment,
        }
        data = self._request(
            self._settings.alertmanager_url,
            "/api/v2/silences",
            alertmanager=True,
            method="POST",
            body=payload,
        )
        if not isinstance(data, dict) or not isinstance(data.get("silenceID"), str):
            raise MonitoringUnavailable("alertmanager did not return a silence id")
        return data["silenceID"]

    def delete_silence(self, silence_id: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", silence_id):
            raise MonitoringUnavailable("invalid silence id")
        self._request(
            self._settings.alertmanager_url,
            f"/api/v2/silence/{silence_id}",
            alertmanager=True,
            method="DELETE",
        )

    def silences(self) -> list[dict[str, Any]]:
        data = self._request(
            self._settings.alertmanager_url, "/api/v2/silences", alertmanager=True
        )
        if not isinstance(data, list) or len(data) > MAX_VECTOR_LENGTH:
            raise MonitoringUnavailable("alertmanager silences response is unbounded")
        return [item for item in data if isinstance(item, dict)]


def _rfc3339(value: datetime) -> str:
    return as_utc(value).isoformat().replace("+00:00", "Z")


def _iso(value: float | None) -> str | None:
    if value is None:
        return None
    return (
        datetime.fromtimestamp(value, tz=UTC)
        .isoformat()
        .replace("+00:00", "Z")
    )


__all__ = [
    "MAX_RESPONSE_BYTES",
    "MonitoringUnavailable",
    "PrometheusAdapter",
    "RangeWindow",
    "metric_expression",
    "range_window",
]
