"""Authorized monitoring configuration, bounded reads, alert lifecycle and silences.

Every public method is one logical operation: references and permissions are
validated before any mutation or external request, then the business state and
exactly one terminal identity audit are committed together. Reads never write:
profiles and overrides are computed in memory, and an unreachable Prometheus is
reported as ``unavailable`` instead of inventing device failures.

Alert ingestion is separate from delivery: an event is written once per
``(alert cycle, event)`` key and the optional notifier callable (the notification
module's flush-only ``record_alert_event``) is invoked inside the same
transaction. Monitoring never imports the notification module and never commits
a caller-owned session.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.identity.clock import as_utc, utcnow
from itsm.identity.service import (
    Conflict,
    IdentityService,
    NotFound,
    Principal,
    ValidationFailed,
)
from itsm.interventions.models import Incident
from itsm.interventions.service import InterventionService
from itsm.inventory.codes import serialized
from itsm.inventory.models import Asset
from itsm.logging import log_event
from itsm.monitoring import rules
from itsm.monitoring.models import (
    MaintenanceWindow,
    MonitorAsset,
    MonitorExporter,
    MonitoringAlert,
    MonitoringAlertEvent,
    MonitoringSilence,
    MonitorProfile,
)
from itsm.monitoring.prometheus import (
    MonitoringUnavailable,
    PrometheusAdapter,
    RangeWindow,
    range_window,
)

logger = logging.getLogger("itsm.monitoring")

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TIME = re.compile(r"^([01][0-9]|2[0-3]):([0-5][0-9])$")

CONFIG_KEYS = (
    "enabled",
    "checkType",
    "target",
    "intervalSeconds",
    "metrics",
    "thresholds",
    "minimumDurationSeconds",
    "exporterId",
    "snmpModule",
    "snmpAuthRef",
)
PROFILE_KEYS = tuple(key for key in CONFIG_KEYS if key != "target")
EXPORTER_KEYS = ("id", "name", "kind", "module", "address", "enabled")
WINDOW_KEYS = (
    "id",
    "name",
    "assetIds",
    "daysOfWeek",
    "startTime",
    "endTime",
    "timezone",
    "enabled",
)
SILENCE_KEYS = ("assetId", "alertId", "endsAt", "comment")
ACTIVE_ALERT_STATES = ("pending", "firing")
_PRIORITY_BY_SEVERITY = {"critical": "critical", "warning": "high", "info": "normal"}

Notifier = Callable[..., Any]


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return as_utc(value).isoformat().replace("+00:00", "Z")


def _text(value: Any, field: str, *, max_length: int, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValidationFailed(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise ValidationFailed(f"{field} must be a string")
    cleaned = value.strip()
    if required and not cleaned:
        raise ValidationFailed(f"{field} is required")
    if len(cleaned) > max_length:
        raise ValidationFailed(f"{field} must be at most {max_length} characters")
    if any(ord(character) < 32 for character in cleaned):
        raise ValidationFailed(f"{field} contains control characters")
    return cleaned or None


def _uuid(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _UUID.fullmatch(value.strip()):
        raise ValidationFailed(f"{field} must be a UUID")
    return str(UUID(value.strip()))


def _bounded(limit: Any, offset: Any) -> tuple[int, int]:
    try:
        bounded_limit = int(limit)
        bounded_offset = int(offset)
    except (TypeError, ValueError) as exc:
        raise ValidationFailed("limit and offset must be integers") from exc
    if not 1 <= bounded_limit <= rules.MAX_LIMIT:
        raise ValidationFailed(f"limit must be between 1 and {rules.MAX_LIMIT}")
    if bounded_offset < 0:
        raise ValidationFailed("offset must be zero or greater")
    return bounded_limit, bounded_offset


def _datetime_arg(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationFailed(f"{field} must be an ISO-8601 datetime") from exc
    else:
        raise ValidationFailed(f"{field} must be an ISO-8601 datetime")
    if parsed.tzinfo is None:
        raise ValidationFailed(f"{field} must include a timezone")
    return as_utc(parsed)


def _fingerprint(labels: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        {str(key): str(value) for key, value in labels.items()},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _severity(value: Any) -> str:
    candidate = str(value or "").strip().lower()
    return candidate if candidate in rules.SEVERITIES else "info"


def _slug(value: Any, field: str, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValidationFailed(f"{field} is required")
        return None
    if not isinstance(value, str) or not rules.SLUG_PATTERN.fullmatch(value.strip()):
        raise ValidationFailed(f"{field} must be 1-64 letters, digits, dots, dashes or underscores")
    return value.strip()


def _host_port(value: str) -> tuple[str | None, int | None, str]:
    """Split ``host[:port]``/``[v6]:port``; returns host, port and any path part."""
    try:
        parts = urlsplit(f"//{value}")
        port = parts.port
    except ValueError as exc:
        raise ValidationFailed("target has an invalid port") from exc
    if parts.username is not None or parts.password is not None:
        raise ValidationFailed("target must not carry credentials")
    host = parts.hostname
    path = parts.path.rstrip("/")
    return host, port, path


def _validate_target(value: Any, check_type: str | None) -> str | None:
    target = _text(value, "target", max_length=500)
    if target is None:
        return None
    if any(character.isspace() for character in target):
        raise ValidationFailed("target must not contain whitespace")
    if check_type == "http":
        try:
            parts = urlsplit(target)
            port = parts.port
        except ValueError as exc:
            raise ValidationFailed("target must be a valid http(s) URL") from exc
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValidationFailed("target must be an http(s) URL without credentials or fragment")
        return target
    if "://" in target or "/" in target or "?" in target or "#" in target:
        raise ValidationFailed("target must be a host or host:port")
    host, port, path = _host_port(target)
    if not host or path:
        raise ValidationFailed("target must be a host or host:port")
    if port is not None and not 1 <= port <= 65535:
        raise ValidationFailed("target port must be between 1 and 65535")
    if check_type in {"node", "windows", "tcp"} and port is None:
        raise ValidationFailed(f"target for {check_type} checks must include a port")
    return target


def _threshold_bounds(metric: str) -> tuple[float, float]:
    unit = rules.METRIC_CATALOG[metric][0]
    if unit == "seconds":
        return 0.0, 3600.0
    if unit == "percent":
        return 0.0, 100.0
    return -100.0, 200.0


def _validate_thresholds(value: Any, check_type: str | None) -> dict[str, dict[str, float]]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > len(rules.METRIC_CATALOG):
        raise ValidationFailed("thresholds must be an object with bounded metric keys")
    allowed = set(rules.CHECK_METRICS.get(check_type or "", ()))
    cleaned: dict[str, dict[str, float]] = {}
    for metric, bounds in value.items():
        if metric not in allowed:
            raise ValidationFailed(
                f"threshold metric '{metric}' is not available for this check type"
            )
        if not isinstance(bounds, Mapping) or not bounds or set(bounds) - {"warning", "critical"}:
            raise ValidationFailed(f"thresholds for '{metric}' must use warning and/or critical")
        low, high = _threshold_bounds(metric)
        entry: dict[str, float] = {}
        for severity in ("warning", "critical"):
            if severity not in bounds:
                continue
            raw = bounds[severity]
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise ValidationFailed(f"{metric}.{severity} must be a number")
            number = float(raw)
            if not math.isfinite(number) or not low < number <= high:
                raise ValidationFailed(
                    f"{metric}.{severity} must be greater than {low} and at most {high}"
                )
            entry[severity] = round(number, 4)
        if "warning" in entry and "critical" in entry and entry["warning"] >= entry["critical"]:
            raise ValidationFailed(f"{metric}.warning must be lower than {metric}.critical")
        cleaned[metric] = entry
    return cleaned


def _validate_metrics(value: Any, check_type: str | None) -> list[str]:
    if not isinstance(value, list) or len(value) > len(rules.METRIC_CATALOG):
        raise ValidationFailed("metrics must be a bounded list")
    allowed = rules.CHECK_METRICS.get(check_type or "", ())
    requested: list[str] = []
    for metric in value:
        if not isinstance(metric, str) or metric not in allowed:
            raise ValidationFailed(f"metric '{metric}' is not available for this check type")
        if metric not in requested:
            requested.append(metric)
    return [metric for metric in allowed if metric in requested]


def _validate_check_type(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in rules.CHECK_TYPES:
        raise ValidationFailed("checkType is not a supported check type")
    return value


def _validate_interval(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value not in rules.INTERVAL_PRESETS:
        raise ValidationFailed("intervalSeconds must be one of 30, 60, 300 or 900")
    return value


def _validate_minimum_duration(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value not in rules.MINIMUM_DURATION_PRESETS
    ):
        raise ValidationFailed("minimumDurationSeconds must be one of 0, 60, 300 or 900")
    return value


def _normalize_asset_mapping(values: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "enabled": values.get("enabled"),
        "checkType": values.get("checkType"),
        "target": values.get("target"),
        "intervalSeconds": values.get("intervalSeconds"),
        "metrics": values.get("metrics"),
        "thresholds": values.get("thresholds"),
        "minimumDurationSeconds": values.get("minimumDurationSeconds"),
        "exporterId": values.get("exporterId"),
        "snmpModule": values.get("snmpModule"),
        "snmpAuthRef": values.get("snmpAuthRef"),
    }


class MonitoringService:
    """Single implementation of monitoring rules for REST, agents and the worker."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        identity: IdentityService | None = None,
        source: str = "rest",
        adapter: PrometheusAdapter | None = None,
        notifier: Notifier | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._identity = identity or IdentityService(session, settings)
        self._source = source
        self._adapter = adapter
        self._notifier = notifier
        self._clock = now or utcnow

    # ------------------------------------------------------------- plumbing
    def _now(self) -> datetime:
        return as_utc(self._clock())

    def _monitor_adapter(self) -> PrometheusAdapter:
        if self._adapter is None:
            self._adapter = PrometheusAdapter(self._settings)
        return self._adapter

    def _asset(self, asset_id: Any) -> Asset:
        key = _uuid(asset_id, "assetId")
        asset = self._session.get(Asset, key)
        if asset is None:
            raise NotFound("asset not found")
        return asset

    def _exporter(self, exporter_id: Any) -> MonitorExporter:
        key = _uuid(exporter_id, "exporterId")
        row = self._session.get(MonitorExporter, key)
        if row is None:
            raise NotFound("exporter not found")
        return row

    def _alert(self, alert_id: Any) -> MonitoringAlert:
        key = _uuid(alert_id, "alertId")
        row = self._session.get(MonitoringAlert, key)
        if row is None:
            raise NotFound("alert not found")
        return row

    def _event(self, alert: MonitoringAlert, event_key: str) -> bool:
        return (
            self._session.scalar(
                select(MonitoringAlertEvent.id).where(
                    MonitoringAlertEvent.alert_id == alert.id,
                    MonitoringAlertEvent.event_key == event_key,
                )
            )
            is not None
        )

    def _append_event(
        self,
        alert: MonitoringAlert,
        *,
        action: str,
        from_state: str | None,
        to_state: str | None,
        note: str | None = None,
        changes: dict[str, Any] | None = None,
        actor: Principal | None = None,
        source: str | None = None,
        event_key: str | None = None,
    ) -> bool:
        if event_key is not None and self._event(alert, event_key):
            return False
        event = MonitoringAlertEvent(
            id=str(uuid4()),
            alert_id=alert.id,
            action=action,
            from_state=from_state,
            to_state=to_state,
            note=note,
            changes=changes,
            actor_id=actor.actor_id if actor else None,
            actor_username=actor.username if actor else None,
            source=source or self._source,
            event_key=event_key,
            created_at=self._now(),
        )
        self._session.add(event)
        self._session.flush()
        return True

    def _audit(self, principal: Principal, action: str, resource: str) -> None:
        self._identity.record_operation(principal, action=action, resource=resource)

    # ------------------------------------------------------ profile/override
    def _profile_payload(
        self, row: MonitorProfile | None, category: str, asset_type: str | None = None
    ) -> dict[str, Any]:
        defaults = rules.default_profile(category, asset_type)
        if row is None:
            return {"category": category, **defaults}
        return {
            "category": category,
            "enabled": row.enabled,
            "checkType": row.check_type,
            "intervalSeconds": row.interval_seconds,
            "metrics": list(row.metrics or []),
            "thresholds": dict(row.thresholds or {}),
            "minimumDurationSeconds": row.minimum_duration_seconds,
            "exporterId": row.exporter_id,
            "snmpModule": row.snmp_module,
            "snmpAuthRef": row.snmp_auth_ref,
            "configured": True,
            "updatedAt": _iso(row.updated_at),
        }

    def _profile_for(self, category: str | None, asset_type: str | None) -> dict[str, Any]:
        row = self._session.get(MonitorProfile, category) if category else None
        return self._profile_payload(row, category or "", asset_type)

    def _effective(self, asset: Asset) -> dict[str, Any]:
        profile = self._profile_for(asset.category, asset.type)
        override = self._session.get(MonitorAsset, asset.id)
        values: dict[str, Any] = {
            "enabled": profile["enabled"],
            "checkType": profile["checkType"],
            "target": None,
            "intervalSeconds": profile["intervalSeconds"],
            "metrics": list(profile["metrics"]),
            "thresholds": dict(profile["thresholds"]),
            "minimumDurationSeconds": profile["minimumDurationSeconds"],
            "exporterId": profile["exporterId"],
            "snmpModule": profile["snmpModule"],
            "snmpAuthRef": profile["snmpAuthRef"],
        }
        overridden: list[str] = []
        if override is not None:
            for key, column in (
                ("enabled", override.enabled),
                ("checkType", override.check_type),
                ("target", override.target),
                ("intervalSeconds", override.interval_seconds),
                ("metrics", override.metrics),
                ("thresholds", override.thresholds),
                ("minimumDurationSeconds", override.minimum_duration_seconds),
                ("exporterId", override.exporter_id),
                ("snmpModule", override.snmp_module),
                ("snmpAuthRef", override.snmp_auth_ref),
            ):
                if column is not None:
                    values[key] = (
                        list(column)
                        if key == "metrics"
                        else (dict(column) if key == "thresholds" else column)
                    )
                    overridden.append(key)
        target = values.get("target") or (asset.ip or None)
        if target is not None:
            try:
                target = _validate_target(target, values.get("checkType"))
            except ValidationFailed:
                target = None
        values["target"] = target
        values["targetPresent"] = target is not None and bool(values.get("checkType"))
        exporter = (
            self._session.get(MonitorExporter, values["exporterId"])
            if values.get("exporterId")
            else None
        )
        values["module"] = (
            exporter.module
            if exporter
            else rules.DEFAULT_MODULE.get(values.get("checkType") or "", "")
        )
        values["profileCategory"] = asset.category
        values["overridden"] = overridden
        values["configured"] = bool(profile.get("configured") or overridden)
        return values

    # -------------------------------------------------------------- profiles
    def get_config(self, principal: Principal) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.view", resource="monitoring:config")
        rows = self._session.scalars(
            select(MonitorProfile).order_by(MonitorProfile.category).limit(rules.MAX_LIMIT)
        ).all()
        by_category = {row.category: row for row in rows}
        categories = set(by_category)
        categories.update(
            category
            for category in self._session.scalars(
                select(Asset.category)
                .where(Asset.category.is_not(None))
                .distinct()
                .limit(rules.MAX_LIMIT)
            )
            if category
        )
        profiles = [
            self._profile_payload(by_category.get(category), category)
            for category in sorted(categories)
        ]
        exporters = [
            self._exporter_payload(row)
            for row in self._session.scalars(
                select(MonitorExporter).order_by(MonitorExporter.name).limit(rules.MAX_LIMIT)
            )
        ]
        windows = [
            self._window_payload(row, now=self._now())
            for row in self._session.scalars(
                select(MaintenanceWindow).order_by(MaintenanceWindow.name).limit(rules.MAX_LIMIT)
            )
        ]
        return {
            "prometheus": {"configured": bool(self._settings.prometheus_url)},
            "alertmanager": {"configured": bool(self._settings.alertmanager_url)},
            "presets": {
                "periods": list(rules.PERIOD_PRESETS),
                "intervals": list(rules.INTERVAL_PRESETS),
                "minimumDurations": list(rules.MINIMUM_DURATION_PRESETS),
                "metrics": [
                    {"id": key, "label": label, "unit": unit}
                    for key, (unit, label) in rules.METRIC_CATALOG.items()
                ],
                "checkTypes": [
                    {"id": value, "label": label}
                    for value, label in (
                        ("icmp", "ICMP"),
                        ("http", "HTTP"),
                        ("tcp", "TCP"),
                        ("dns", "DNS"),
                        ("snmp", "SNMP"),
                        ("node", "Node exporter"),
                        ("windows", "Windows exporter"),
                    )
                ],
                "exporterKinds": list(rules.EXPORTER_KINDS),
            },
            "profiles": profiles,
            "exporters": exporters,
            "windows": windows,
            "sources": {
                "prometheusConfigured": bool(self._settings.prometheus_url),
                "alertmanagerConfigured": bool(self._settings.alertmanager_url),
            },
        }

    def _profile_candidate(
        self, category: str, values: Mapping[str, Any], current: dict[str, Any]
    ) -> dict[str, Any]:
        if not isinstance(values, Mapping):
            raise ValidationFailed("profile values must be an object")
        unknown = set(values) - set(PROFILE_KEYS)
        if unknown:
            raise ValidationFailed(f"unsupported profile field: {sorted(unknown)[0]}")
        candidate = dict(current)
        if "enabled" in values:
            if not isinstance(values["enabled"], bool):
                raise ValidationFailed("enabled must be a boolean")
            candidate["enabled"] = values["enabled"]
        if "checkType" in values:
            candidate["checkType"] = _validate_check_type(values["checkType"])
        check_type = candidate.get("checkType")
        if candidate.get("enabled") and check_type is None:
            raise ValidationFailed("checkType is required when monitoring is enabled")
        if "intervalSeconds" in values:
            candidate["intervalSeconds"] = _validate_interval(values["intervalSeconds"])
        if "minimumDurationSeconds" in values:
            candidate["minimumDurationSeconds"] = _validate_minimum_duration(
                values["minimumDurationSeconds"]
            )
        if "metrics" in values:
            candidate["metrics"] = _validate_metrics(values["metrics"], check_type)
        else:
            candidate["metrics"] = _validate_metrics(candidate.get("metrics") or [], check_type)
        if "thresholds" in values:
            candidate["thresholds"] = _validate_thresholds(values["thresholds"], check_type)
        else:
            candidate["thresholds"] = _validate_thresholds(
                candidate.get("thresholds") or {}, check_type
            )
        if "exporterId" in values:
            exporter_id = values["exporterId"]
            candidate["exporterId"] = (
                self._exporter(exporter_id).id if exporter_id is not None else None
            )
        if "snmpModule" in values:
            candidate["snmpModule"] = _slug(values["snmpModule"], "snmpModule")
        if "snmpAuthRef" in values:
            candidate["snmpAuthRef"] = _slug(values["snmpAuthRef"], "snmpAuthRef")
        exporter_id = candidate.get("exporterId")
        if exporter_id:
            exporter = self._session.get(MonitorExporter, exporter_id)
            expected = rules.EXPORTER_FOR_CHECK.get(check_type or "")
            if exporter is not None and expected and exporter.kind != expected:
                raise ValidationFailed(f"exporter kind must be {expected} for {check_type} checks")
        return candidate

    def update_profile(
        self, principal: Principal, category: Any, values: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._identity.authorize(principal, "config.categories", resource="monitoring:profile")
        key = _slug(category, "category", required=True)
        row = self._session.get(MonitorProfile, key)
        current = self._profile_payload(row, key)
        candidate = self._profile_candidate(key, values or {}, current)
        now = self._now()
        if row is None:
            row = MonitorProfile(category=key, created_at=now, updated_at=now)
            self._session.add(row)
        row.enabled = bool(candidate["enabled"])
        row.check_type = candidate.get("checkType")
        row.interval_seconds = int(candidate["intervalSeconds"])
        row.metrics = list(candidate["metrics"])
        row.thresholds = dict(candidate["thresholds"])
        row.minimum_duration_seconds = int(candidate["minimumDurationSeconds"])
        row.exporter_id = candidate.get("exporterId")
        row.snmp_module = candidate.get("snmpModule")
        row.snmp_auth_ref = candidate.get("snmpAuthRef")
        row.updated_by = principal.actor_id
        row.updated_at = now
        self._session.flush()
        payload = self._profile_payload(row, key)
        self._audit(principal, "monitoring.profile_updated", f"monitoring:profile:{key}")
        return payload

    def update_asset(
        self, principal: Principal, asset_id: Any, values: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.edit", resource="monitoring:assets")
        asset = self._asset(asset_id)
        if not isinstance(values, Mapping):
            raise ValidationFailed("asset monitoring values must be an object")
        unknown = set(values) - set(CONFIG_KEYS)
        if unknown:
            raise ValidationFailed(f"unsupported monitoring field: {sorted(unknown)[0]}")
        effective = self._effective(asset)
        candidate = dict(effective)
        for key in CONFIG_KEYS:
            if key in values:
                candidate[key] = values[key]
        if (
            "enabled" in values
            and values["enabled"] is not None
            and not isinstance(values["enabled"], bool)
        ):
            raise ValidationFailed("enabled must be a boolean or null")
        candidate["checkType"] = _validate_check_type(candidate.get("checkType"))
        check_type = candidate.get("checkType")
        if candidate.get("enabled") and check_type is None:
            raise ValidationFailed("checkType is required when monitoring is enabled")
        candidate["intervalSeconds"] = _validate_interval(
            candidate.get("intervalSeconds", rules.DEFAULT_INTERVAL)
        )
        candidate["minimumDurationSeconds"] = _validate_minimum_duration(
            candidate.get("minimumDurationSeconds", rules.DEFAULT_MINIMUM_DURATION)
        )
        candidate["metrics"] = _validate_metrics(candidate.get("metrics") or [], check_type)
        candidate["thresholds"] = _validate_thresholds(
            candidate.get("thresholds") or {}, check_type
        )
        exporter_id = candidate.get("exporterId")
        if exporter_id is not None:
            exporter = self._exporter(exporter_id)
            expected = rules.EXPORTER_FOR_CHECK.get(check_type or "")
            if expected and exporter.kind != expected:
                raise ValidationFailed(f"exporter kind must be {expected} for {check_type} checks")
        candidate["target"] = _validate_target(candidate.get("target"), check_type)
        candidate["snmpModule"] = _slug(candidate.get("snmpModule"), "snmpModule")
        candidate["snmpAuthRef"] = _slug(candidate.get("snmpAuthRef"), "snmpAuthRef")

        row = self._session.get(MonitorAsset, asset.id)
        if row is None:
            row = MonitorAsset(asset_id=asset.id, created_at=self._now(), updated_at=self._now())
            self._session.add(row)
        for key, attribute in (
            ("enabled", "enabled"),
            ("checkType", "check_type"),
            ("target", "target"),
            ("intervalSeconds", "interval_seconds"),
            ("metrics", "metrics"),
            ("thresholds", "thresholds"),
            ("minimumDurationSeconds", "minimum_duration_seconds"),
            ("exporterId", "exporter_id"),
            ("snmpModule", "snmp_module"),
            ("snmpAuthRef", "snmp_auth_ref"),
        ):
            if key in values:
                setattr(row, attribute, values[key])
        row.updated_by = principal.actor_id
        row.updated_at = self._now()
        if all(
            value is None
            for value in (
                row.enabled,
                row.check_type,
                row.target,
                row.interval_seconds,
                row.metrics,
                row.thresholds,
                row.minimum_duration_seconds,
                row.exporter_id,
                row.snmp_module,
                row.snmp_auth_ref,
            )
        ):
            self._session.delete(row)
        self._session.flush()
        self._audit(principal, "monitoring.asset_updated", f"asset:{asset.id}")
        return {"assetId": asset.id, "config": self._effective(asset)}

    # -------------------------------------------------------------- exporters
    def _exporter_payload(self, row: MonitorExporter) -> dict[str, Any]:
        return {
            "id": row.id,
            "name": row.name,
            "kind": row.kind,
            "module": row.module,
            "address": row.address,
            "enabled": row.enabled,
        }

    def save_exporter(self, principal: Principal, values: Mapping[str, Any]) -> dict[str, Any]:
        self._identity.authorize(principal, "config.integrations", resource="monitoring:exporters")
        if not isinstance(values, Mapping):
            raise ValidationFailed("exporter values must be an object")
        unknown = set(values) - set(EXPORTER_KEYS)
        if unknown:
            raise ValidationFailed(f"unsupported exporter field: {sorted(unknown)[0]}")
        name = _text(values.get("name"), "name", max_length=64, required=True)
        kind = values.get("kind")
        if kind not in rules.EXPORTER_KINDS:
            raise ValidationFailed("kind must be blackbox, snmp, node or windows")
        module = _slug(values.get("module"), "module", required=True)
        address = None
        if values.get("address") is not None:
            address = _text(values["address"], "address", max_length=200)
            if address is not None:
                if "://" in address:
                    raise ValidationFailed("address must be host:port")
                host, port, path = _host_port(address)
                if not host or path or port is None:
                    raise ValidationFailed("address must be host:port")
        enabled = values.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValidationFailed("enabled must be a boolean")
        row = None
        if values.get("id") is not None:
            row = self._exporter(values["id"])
        else:
            row = self._session.scalar(
                select(MonitorExporter).where(func.lower(MonitorExporter.name) == name.lower())
            )
        duplicate = self._session.scalar(
            select(MonitorExporter.id).where(
                func.lower(MonitorExporter.name) == name.lower(),
                MonitorExporter.id != (row.id if row else ""),
            )
        )
        if duplicate is not None:
            raise Conflict("an exporter with that name already exists")
        now = self._now()
        if row is None:
            row = MonitorExporter(id=str(uuid4()), created_at=now, updated_at=now)
            self._session.add(row)
        row.name = name
        row.kind = kind
        row.module = module
        row.address = address
        row.enabled = enabled
        row.updated_at = now
        self._session.flush()
        payload = self._exporter_payload(row)
        self._audit(principal, "monitoring.exporter_saved", f"monitoring:exporter:{row.id}")
        return payload

    # ---------------------------------------------------------------- devices
    def _state_for(self, state: Mapping[str, Any] | None, check_type: str) -> float | None:
        if not state:
            return None
        value = state.get("success")
        if value is None:
            value = state.get("up")
        return value

    @staticmethod
    def _threshold_severity(
        thresholds: Mapping[str, Mapping[str, float]], metric: str, value: float | None
    ) -> str | None:
        if value is None:
            return None
        bounds = thresholds.get(metric) or {}
        if "critical" in bounds and value >= bounds["critical"]:
            return "critical"
        if "warning" in bounds and value >= bounds["warning"]:
            return "warning"
        return None

    def _device_state(
        self,
        config: Mapping[str, Any],
        state: Mapping[str, Any] | None,
        *,
        adapter_error: bool,
    ) -> tuple[str, str | None]:
        if not config["enabled"]:
            return "unmonitored", None
        if not config.get("targetPresent"):
            return "no_data", "target_missing"
        if not self._settings.prometheus_url:
            return "unavailable", "prometheus_not_configured"
        if adapter_error:
            return "unavailable", "prometheus_unavailable"
        success = self._state_for(state, config["checkType"] or "")
        if success is None:
            return "no_data", None
        if success < 1:
            return "down", None
        latency = (state or {}).get("latency")
        severity = self._threshold_severity(config.get("thresholds") or {}, "latency", latency)
        return ("degraded", None) if severity else ("up", None)

    def _device_item(
        self,
        asset: Asset,
        config: Mapping[str, Any],
        state: Mapping[str, Any] | None,
        uptime: Mapping[str, Any] | None,
        active_alerts: int,
        *,
        adapter_error: bool,
    ) -> dict[str, Any]:
        status, reason = self._device_state(config, state, adapter_error=adapter_error)
        latency = (state or {}).get("latency")
        severity = self._threshold_severity(config.get("thresholds") or {}, "latency", latency)
        return {
            "assetId": asset.id,
            "quickCode": asset.quick_code,
            "name": asset.name,
            "category": asset.category,
            "site": asset.site,
            "siteId": asset.site_id,
            "monitoringEnabled": bool(config["enabled"]),
            "status": status,
            "reason": reason,
            "checkType": config.get("checkType"),
            "target": config.get("target"),
            "intervalSeconds": config.get("intervalSeconds"),
            "lastCheckAt": (state or {}).get("at"),
            "latencyMs": round(latency * 1000, 2) if latency is not None else None,
            "uptime": (dict(uptime) if uptime is not None else {"percent": None, "samples": 0}),
            "activeAlerts": active_alerts,
            "severity": severity,
        }

    def _counts(self, asset_ids: Sequence[str]) -> dict[str, int]:
        if not asset_ids:
            return {}
        rows = self._session.execute(
            select(MonitoringAlert.asset_id, func.count(MonitoringAlert.id))
            .where(
                MonitoringAlert.asset_id.in_(list(asset_ids)),
                MonitoringAlert.state.in_(ACTIVE_ALERT_STATES),
            )
            .group_by(MonitoringAlert.asset_id)
        )
        return {asset_id: int(count) for asset_id, count in rows}

    def dashboard_devices(
        self,
        principal: Principal,
        *,
        period: str = "24h",
        category: str | None = None,
        site_id: str | None = None,
    ) -> dict[str, Any]:
        """Bounded full-scope device aggregate for the operations dashboard.

        Unlike ``list_devices`` this intentionally reads every scoped asset (no
        page) so the dashboard never derives installation totals from one page.
        Prometheus is still queried in bounded chunks and every preset trend is
        an aggregate of the same fixed availability query, never an invented
        series. An unreachable source yields ``unknown`` states.
        """
        self._identity.authorize(principal, "assets.view", resource="monitoring:dashboard")
        if period not in rules.PERIOD_PRESETS:
            raise ValidationFailed("period must be one of 24h, 7d or 30d")
        filters = [Asset.archived_at.is_(None)]
        if category is not None:
            cleaned_category = _text(category, "category", max_length=64)
            if cleaned_category:
                filters.append(Asset.category == cleaned_category)
        if site_id is not None:
            filters.append(Asset.site_id == _uuid(site_id, "siteId"))
        assets = list(
            self._session.scalars(
                select(Asset).where(*filters).order_by(Asset.quick_code, Asset.id)
            )
        )
        configs = {asset.id: self._effective(asset) for asset in assets}
        pairs = [
            (asset.id, configs[asset.id]["checkType"] or "")
            for asset in assets
            if configs[asset.id]["enabled"] and configs[asset.id].get("targetPresent")
        ]
        adapter = self._monitor_adapter() if self._settings.prometheus_url else None
        states: dict[str, Mapping[str, Any]] = {}
        adapter_error = False
        if adapter is not None:
            for start in range(0, len(pairs), rules.MAX_DEVICES):
                chunk = pairs[start : start + rules.MAX_DEVICES]
                try:
                    states.update(adapter.current_states(chunk))
                except MonitoringUnavailable:
                    adapter_error = True
                    logger.warning("monitoring.dashboard_source_unavailable")
                    break
        availability: dict[str, dict[str, Any]] = {}
        device_availability: dict[str, dict[str, Any]] = {}
        for preset in rules.PERIOD_PRESETS:
            availability[preset] = {"percent": None, "samples": 0}
            if adapter is None or adapter_error:
                continue
            window = range_window(preset, now=self._now())
            weighted = 0.0
            samples = 0
            failed = False
            for start in range(0, len(pairs), rules.MAX_DEVICES):
                chunk = pairs[start : start + rules.MAX_DEVICES]
                try:
                    result = adapter.page_availability(chunk, window)
                    if preset == period:
                        device_availability.update(result)
                except MonitoringUnavailable:
                    adapter_error = True
                    failed = True
                    logger.warning("monitoring.dashboard_source_unavailable")
                    break
                for value in result.values():
                    count = int(value.get("samples") or 0)
                    if count:
                        weighted += float(value.get("percent") or 0.0) * count
                        samples += count
            if not failed and samples:
                availability[preset] = {
                    "percent": round(weighted / samples, 3),
                    "samples": samples,
                }
            elif failed:
                availability[preset] = {"percent": None, "samples": 0}
            if failed and preset == period:
                device_availability.clear()
        alert_counts: dict[str, int] = {}
        if assets:
            alert_counts = {
                asset_id: int(count)
                for asset_id, count in self._session.execute(
                    select(MonitoringAlert.asset_id, func.count())
                    .where(
                        MonitoringAlert.state.in_(ACTIVE_ALERT_STATES),
                        MonitoringAlert.asset_id.in_([asset.id for asset in assets]),
                    )
                    .group_by(MonitoringAlert.asset_id)
                )
            }
        items: list[dict[str, Any]] = []
        latencies: list[float] = []
        last_checks: list[str] = []
        for asset in assets:
            config = configs[asset.id]
            state = states.get(asset.id)
            raw_state, reason = self._device_state(config, state, adapter_error=adapter_error)
            status = {
                "up": "up",
                "degraded": "degraded",
                "down": "down",
                "unmonitored": "unmonitored",
            }.get(raw_state, "unknown")
            if state is not None:
                latency = state.get("latency")
                if isinstance(latency, (int, float)):
                    latencies.append(float(latency))
                at = state.get("at")
                if isinstance(at, str) and at:
                    last_checks.append(at)
            monitored = bool(config["enabled"] and config.get("targetPresent"))
            items.append(
                {
                    "assetId": asset.id,
                    "quickCode": asset.quick_code,
                    "name": asset.name,
                    "category": asset.category,
                    "type": asset.type,
                    "siteId": asset.site_id,
                    "site": asset.site,
                    "status": status,
                    "reason": reason,
                    "monitored": monitored,
                    "uptimePct": device_availability.get(asset.id, {}).get("percent")
                    if monitored
                    else None,
                    "latencyMs": state.get("latency") if state is not None else None,
                    "lastCheckAt": state.get("at") if state is not None else None,
                    "activeAlerts": alert_counts.get(asset.id, 0),
                }
            )
        return {
            "items": items,
            "total": len(assets),
            "prometheusConfigured": bool(self._settings.prometheus_url),
            "sourceError": adapter_error,
            "availability": {
                "configured": bool(self._settings.prometheus_url),
                "current": availability[period]["percent"],
                "samples": [
                    {
                        "label": preset,
                        "value": availability[preset]["percent"],
                    }
                    for preset in rules.PERIOD_PRESETS
                ],
                "samplesCount": availability[period]["samples"],
                "lastCheckAt": max(last_checks) if last_checks else None,
            },
            "latency": {
                "current": round(sum(latencies) / len(latencies), 3) if latencies else None
            },
        }

    def list_devices(
        self,
        principal: Principal,
        *,
        limit: int = rules.DEFAULT_LIMIT,
        offset: int = 0,
        category: str | None = None,
        site_id: str | None = None,
        period: str = rules.DEFAULT_PERIOD,
    ) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.view", resource="monitoring:devices")
        bounded_limit, bounded_offset = _bounded(limit, offset)
        if period not in rules.PERIOD_PRESETS:
            raise ValidationFailed("period must be 24h, 7d or 30d")
        statement = select(Asset)
        conditions = []
        if category:
            conditions.append(Asset.category == category)
        if site_id:
            conditions.append(Asset.site_id == site_id)
        if conditions:
            statement = statement.where(*conditions)
        total = int(self._session.scalar(select(func.count(Asset.id)).where(*conditions)) or 0)
        assets = list(
            self._session.scalars(
                statement.order_by(Asset.quick_code).limit(bounded_limit).offset(bounded_offset)
            )
        )
        configs = [(asset, self._effective(asset)) for asset in assets]
        monitored = [
            (asset.id, config["checkType"])
            for asset, config in configs
            if config["enabled"] and config["targetPresent"] and config["checkType"]
        ]
        states: dict[str, dict[str, Any]] = {}
        uptimes: dict[str, dict[str, Any]] = {}
        adapter_error = False
        if monitored and self._settings.prometheus_url:
            try:
                adapter = self._monitor_adapter()
                states = adapter.current_states(monitored)
                uptimes = adapter.page_availability(
                    monitored, range_window(period, now=self._now())
                )
            except MonitoringUnavailable:
                adapter_error = True
                log_event(logger, "monitoring.source_unavailable", source="prometheus")
        counts = self._counts([asset.id for asset, _ in configs])
        items = [
            self._device_item(
                asset,
                config,
                states.get(asset.id),
                uptimes.get(asset.id),
                counts.get(asset.id, 0),
                adapter_error=adapter_error,
            )
            for asset, config in configs
        ]
        return {
            "items": items,
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
            "period": period,
        }

    def _series(
        self, asset_id: str, check_type: str, metrics: Sequence[str], window: RangeWindow
    ) -> list[dict[str, Any]]:
        adapter = self._monitor_adapter()
        result: list[dict[str, Any]] = []
        for metric in list(metrics)[: rules.MAX_SERIES]:
            points = adapter.metric_series(asset_id, check_type, metric, window)
            if points is None:
                continue
            result.append(
                {
                    "metric": metric,
                    "label": rules.METRIC_CATALOG[metric][1],
                    "unit": rules.METRIC_CATALOG[metric][0],
                    "points": points,
                    "pointCount": len(points),
                }
            )
        return result

    def _alert_lines(self, alert: MonitoringAlert, *, silenced: bool) -> dict[str, Any]:
        return {
            "id": alert.id,
            "alertName": alert.alert_name,
            "severity": alert.severity,
            "state": alert.state,
            "silenced": silenced,
            "acknowledged": alert.acknowledged_at is not None,
            "startsAt": _iso(alert.starts_at),
            "endsAt": _iso(alert.ends_at),
            "summary": alert.summary,
            "incidentId": alert.incident_id,
        }

    def get_device(
        self, principal: Principal, asset_id: Any, period: str = rules.DEFAULT_PERIOD
    ) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.view", resource="monitoring:devices")
        if period not in rules.PERIOD_PRESETS:
            raise ValidationFailed("period must be 24h, 7d or 30d")
        asset = self._asset(asset_id)
        config = self._effective(asset)
        now = self._now()
        window = range_window(period, now=now)
        provenance = {
            "source": "prometheus",
            "prometheusConfigured": bool(self._settings.prometheus_url),
            "period": {
                "preset": period,
                "from": _iso(window.start),
                "to": _iso(window.end),
                "stepSeconds": window.step_seconds,
            },
        }
        base: dict[str, Any] = {
            "asset": {
                "assetId": asset.id,
                "quickCode": asset.quick_code,
                "name": asset.name,
                "category": asset.category,
                "site": asset.site,
                "siteId": asset.site_id,
            },
            "config": {
                "enabled": config["enabled"],
                "checkType": config.get("checkType"),
                "target": config.get("target"),
                "targetPresent": config["targetPresent"],
                "intervalSeconds": config.get("intervalSeconds"),
                "metrics": list(config.get("metrics") or []),
                "thresholds": dict(config.get("thresholds") or {}),
                "minimumDurationSeconds": config.get("minimumDurationSeconds"),
                "exporterId": config.get("exporterId"),
                "snmpModule": config.get("snmpModule"),
                "snmpAuthRef": config.get("snmpAuthRef"),
                "profileCategory": config.get("profileCategory"),
                "overridden": list(config.get("overridden") or []),
            },
            "provenance": provenance,
            "uptime": {"percent": None, "samples": 0},
            "latency": None,
            "series": [],
            "checks": [],
            "alerts": self._asset_alerts(asset.id),
        }
        state: dict[str, Any] | None = None
        adapter_error = False
        if config["enabled"] and config["targetPresent"] and self._settings.prometheus_url:
            check_type = config["checkType"] or ""
            try:
                adapter = self._monitor_adapter()
                states = adapter.current_states([(asset.id, check_type)])
                state = states.get(asset.id)
                if state is not None:
                    base["uptime"] = adapter.availability(asset.id, check_type, window) or {
                        "percent": None,
                        "samples": 0,
                    }
                    base["latency"] = adapter.latency(asset.id, check_type, window)
                    base["series"] = self._series(
                        asset.id, check_type, config.get("metrics") or [], window
                    )
            except MonitoringUnavailable:
                adapter_error = True
                base["uptime"] = {"percent": None, "samples": 0}
                base["latency"] = None
                base["series"] = []
                log_event(logger, "monitoring.source_unavailable", source="prometheus")
        status, reason = self._device_state(config, state, adapter_error=adapter_error)
        severity = self._threshold_severity(
            config.get("thresholds") or {}, "latency", (state or {}).get("latency")
        )
        for item in base["series"]:
            if not item["points"]:
                continue
            latest = item["points"][-1]["value"]
            found = self._threshold_severity(config.get("thresholds") or {}, item["metric"], latest)
            if found == "critical" or (found == "warning" and severity != "critical"):
                severity = found
        if status in {"up", "degraded"}:
            status = "degraded" if severity else "up"
        check_type = config.get("checkType")
        base["checks"] = (
            [
                {
                    "checkType": check_type,
                    "module": config.get("module"),
                    "state": status,
                    "lastCheckAt": (state or {}).get("at"),
                    "latencyMs": (
                        round((state or {})["latency"] * 1000, 2)
                        if (state or {}).get("latency") is not None
                        else None
                    ),
                }
            ]
            if check_type
            else []
        )
        base["status"] = status
        base["reason"] = reason
        base["severity"] = severity
        return base

    def _asset_alerts(self, asset_id: str) -> dict[str, Any]:
        now = self._now()
        silences = self._active_silences(now)
        alert_rows = list(
            self._session.scalars(
                select(MonitoringAlert)
                .where(MonitoringAlert.asset_id == asset_id)
                .order_by(MonitoringAlert.starts_at.desc())
                .limit(10)
            )
        )
        recent = [
            self._alert_lines(row, silenced=self._silenced(row, silences, now))
            for row in alert_rows[:5]
        ]
        active = sum(1 for row in alert_rows if row.state in ACTIVE_ALERT_STATES)
        recoveries = [row.ends_at for row in alert_rows if row.state == "resolved" and row.ends_at]
        return {
            "active": active,
            "lastRecoveryAt": _iso(max(as_utc(value) for value in recoveries))
            if recoveries
            else None,
            "recent": recent,
            "history": [
                {
                    "id": row.id,
                    "alertName": row.alert_name,
                    "severity": row.severity,
                    "state": row.state,
                    "startsAt": _iso(row.starts_at),
                    "endsAt": _iso(row.ends_at),
                }
                for row in alert_rows
            ],
        }

    # ----------------------------------------------------------------- alerts
    def _asset_index(self, asset_ids: Sequence[str]) -> dict[str, tuple[str, str]]:
        keys = sorted({key for key in asset_ids if key})
        if not keys:
            return {}
        rows = self._session.execute(
            select(Asset.id, Asset.name, Asset.quick_code).where(Asset.id.in_(keys))
        )
        return {row[0]: (row[1], row[2]) for row in rows}

    def _active_silences(self, now: datetime) -> list[MonitoringSilence]:
        return list(
            self._session.scalars(
                select(MonitoringSilence)
                .where(
                    MonitoringSilence.starts_at <= now,
                    MonitoringSilence.ends_at > now,
                )
                .order_by(MonitoringSilence.ends_at)
                .limit(rules.MAX_LIMIT)
            )
        )

    @staticmethod
    def _silence_matches(silence: MonitoringSilence, alert: MonitoringAlert) -> bool:
        if silence.alert_id is not None:
            return silence.alert_id == alert.id
        return silence.asset_id is not None and silence.asset_id == alert.asset_id

    def _enabled_windows(self) -> list[MaintenanceWindow]:
        return list(
            self._session.scalars(
                select(MaintenanceWindow)
                .where(MaintenanceWindow.enabled.is_(True))
                .limit(rules.MAX_LIMIT)
            )
        )

    def _silenced(
        self,
        alert: MonitoringAlert,
        silences: Sequence[MonitoringSilence],
        now: datetime,
        windows: Sequence[MaintenanceWindow] | None = None,
    ) -> bool:
        if any(self._silence_matches(silence, alert) for silence in silences):
            return True
        for window in windows if windows is not None else self._enabled_windows():
            if self._window_active(window, alert.asset_id, now):
                return True
        return False

    def notification_suppressed(self, alert_id: str, *, now: datetime | None = None) -> bool:
        """Evaluate current monitoring suppression for notification work, without writes."""
        alert = self._session.get(MonitoringAlert, alert_id)
        if alert is None:
            return False
        current = as_utc(now) if now is not None else self._now()
        return self._silenced(alert, self._active_silences(current), current)

    def _alert_payload(
        self,
        alert: MonitoringAlert,
        *,
        silences: Sequence[MonitoringSilence],
        windows: Sequence[MaintenanceWindow],
        assets: Mapping[str, tuple[str, str]],
        now: datetime,
        include_events: bool = False,
    ) -> dict[str, Any]:
        silenced = self._silenced(alert, silences, now, windows)
        name, quick_code = assets.get(alert.asset_id, (None, None))
        active_window = next(
            (window for window in windows if self._window_active(window, alert.asset_id, now)),
            None,
        )
        incident = None
        if alert.incident_id:
            row = self._session.get(Incident, alert.incident_id)
            if row is not None:
                incident = {
                    "id": row.id,
                    "status": row.status,
                    "suggestedClose": row.status not in {"resolved", "closed"}
                    and alert.state == "resolved",
                }
        payload = {
            "id": alert.id,
            "fingerprint": alert.fingerprint,
            "alertName": alert.alert_name,
            "severity": alert.severity,
            "assetId": alert.asset_id,
            "assetName": name,
            "quickCode": quick_code,
            "state": alert.state,
            "silenced": silenced,
            "acknowledged": alert.acknowledged_at is not None,
            "acknowledgedAt": _iso(alert.acknowledged_at),
            "acknowledgedBy": alert.acknowledged_by,
            "notes": alert.acknowledged_notes,
            "startsAt": _iso(alert.starts_at),
            "endsAt": _iso(alert.ends_at),
            "lastSeenAt": _iso(alert.last_seen_at),
            "source": alert.source,
            "groupKey": alert.group_key,
            "summary": alert.summary,
            "description": alert.description,
            "incident": incident,
            "maintenanceWindow": {"id": active_window.id, "name": active_window.name}
            if active_window
            else None,
            "labels": dict(alert.labels or {}),
            "annotations": dict(alert.annotations or {}),
        }
        if include_events:
            payload["events"] = self._event_payloads(alert.id, limit=200)
            payload["silences"] = [
                self._silence_payload(silence, now=now)
                for silence in silences
                if self._silence_matches(silence, alert)
            ]
        return payload

    def _event_payloads(
        self, alert_id: str, *, limit: int, offset: int = 0
    ) -> list[dict[str, Any]]:
        rows = self._session.scalars(
            select(MonitoringAlertEvent)
            .where(MonitoringAlertEvent.alert_id == alert_id)
            .order_by(MonitoringAlertEvent.created_at, MonitoringAlertEvent.id)
            .limit(limit)
            .offset(offset)
        )
        return [
            {
                "id": row.id,
                "action": row.action,
                "fromState": row.from_state,
                "toState": row.to_state,
                "note": row.note,
                "actor": row.actor_username,
                "source": row.source,
                "changes": dict(row.changes or {}),
                "createdAt": _iso(row.created_at),
            }
            for row in rows
        ]

    def list_alerts(
        self,
        principal: Principal,
        *,
        limit: int = rules.DEFAULT_LIMIT,
        offset: int = 0,
        state: str | None = None,
        asset_id: str | None = None,
    ) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.view", resource="monitoring:alerts")
        bounded_limit, bounded_offset = _bounded(limit, offset)
        conditions = []
        if state is not None:
            if state not in rules.ALERT_STATES:
                raise ValidationFailed("state must be pending, firing or resolved")
            conditions.append(MonitoringAlert.state == state)
        if asset_id is not None:
            conditions.append(MonitoringAlert.asset_id == _uuid(asset_id, "assetId"))
        total = int(
            self._session.scalar(select(func.count(MonitoringAlert.id)).where(*conditions)) or 0
        )
        rows = list(
            self._session.scalars(
                select(MonitoringAlert)
                .where(*conditions)
                .order_by(MonitoringAlert.starts_at.desc(), MonitoringAlert.id)
                .limit(bounded_limit)
                .offset(bounded_offset)
            )
        )
        now = self._now()
        silences = self._active_silences(now)
        windows = self._enabled_windows()
        assets = self._asset_index([row.asset_id for row in rows])
        items = [
            self._alert_payload(row, silences=silences, windows=windows, assets=assets, now=now)
            for row in rows
        ]
        return {
            "items": items,
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
        }

    def get_alert(self, principal: Principal, alert_id: Any) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.view", resource="monitoring:alerts")
        alert = self._alert(alert_id)
        now = self._now()
        silences = self._active_silences(now)
        assets = self._asset_index([alert.asset_id])
        return self._alert_payload(
            alert,
            silences=silences,
            windows=self._enabled_windows(),
            assets=assets,
            now=now,
            include_events=True,
        )

    def history(
        self,
        principal: Principal,
        alert_id: Any,
        *,
        limit: int = rules.DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.view", resource="monitoring:alerts")
        alert = self._alert(alert_id)
        bounded_limit, bounded_offset = _bounded(limit, offset)
        total = int(
            self._session.scalar(
                select(func.count(MonitoringAlertEvent.id)).where(
                    MonitoringAlertEvent.alert_id == alert.id
                )
            )
            or 0
        )
        return {
            "items": self._event_payloads(alert.id, limit=bounded_limit, offset=bounded_offset),
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
        }

    def acknowledge(self, principal: Principal, alert_id: Any, notes: str = "") -> dict[str, Any]:
        self._identity.authorize(principal, "assets.edit", resource="monitoring:alerts")
        alert = self._alert(alert_id)
        cleaned = _text(notes, "notes", max_length=2000) or ""
        if alert.acknowledged_at is not None:
            return self.get_alert(principal, alert.id)
        now = self._now()
        alert.acknowledged_at = now
        alert.acknowledged_by = principal.username
        alert.acknowledged_notes = cleaned or None
        alert.updated_at = now
        self._append_event(
            alert,
            action="acknowledged",
            from_state=alert.state,
            to_state=alert.state,
            note=cleaned or "Acknowledged without notes",
            actor=principal,
            source=self._source,
            event_key=f"{alert.id}:acknowledged",
        )
        self._notify(alert, "acknowledged", now=now, acknowledged=True)
        self._audit(principal, "monitoring.alert_acknowledged", f"alert:{alert.id}")
        return self.get_alert(principal, alert.id)

    # ------------------------------------------------------------------ silence
    def _silence_payload(self, silence: MonitoringSilence, *, now: datetime) -> dict[str, Any]:
        return {
            "id": silence.id,
            "assetId": silence.asset_id,
            "alertId": silence.alert_id,
            "comment": silence.comment,
            "startsAt": _iso(silence.starts_at),
            "endsAt": _iso(silence.ends_at),
            "source": silence.source,
            "nativeId": silence.native_id,
            "active": as_utc(silence.starts_at) <= now < as_utc(silence.ends_at),
        }

    def silence(self, principal: Principal, values: Mapping[str, Any]) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.edit", resource="monitoring:silences")
        if not isinstance(values, Mapping):
            raise ValidationFailed("silence values must be an object")
        unknown = set(values) - set(SILENCE_KEYS)
        if unknown:
            raise ValidationFailed(f"unsupported silence field: {sorted(unknown)[0]}")
        alert_id = values.get("alertId")
        asset_id = values.get("assetId")
        if bool(alert_id) == bool(asset_id):
            raise ValidationFailed("a silence targets exactly one alert or asset")
        alert = self._alert(alert_id) if alert_id else None
        asset = self._asset(asset_id) if asset_id else None
        comment = _text(values.get("comment"), "comment", max_length=200, required=True)
        ends_at = _datetime_arg(values.get("endsAt"), "endsAt")
        now = self._now()
        if ends_at <= now:
            raise ValidationFailed("endsAt must be in the future")
        if ends_at > now + timedelta(seconds=rules.MAX_SILENCE_SECONDS):
            raise ValidationFailed("endsAt must be within 30 days")
        if alert is not None:
            asset_id = alert.asset_id
        native_id = None
        source = "local"
        if self._settings.alertmanager_url:
            matchers = [
                {
                    "name": "asset_id",
                    "value": asset_id,
                    "isRegex": False,
                    "isEqual": True,
                }
            ]
            if alert is not None:
                matchers.append(
                    {
                        "name": "alertname",
                        "value": alert.alert_name,
                        "isRegex": False,
                        "isEqual": True,
                    }
                )
            native_id = self._monitor_adapter().create_silence(
                matchers=matchers,
                starts_at=now,
                ends_at=ends_at,
                comment=comment or "ITSM temporary silence",
                created_by=f"itsm:{principal.username}",
            )
            source = "alertmanager"
        row = MonitoringSilence(
            id=str(uuid4()),
            asset_id=None if alert is not None else asset.id,
            alert_id=alert.id if alert is not None else None,
            comment=comment or "",
            starts_at=now,
            ends_at=ends_at,
            source=source,
            native_id=native_id,
            created_by=principal.actor_id,
            created_at=now,
        )
        self._session.add(row)
        self._session.flush()
        targets = (
            [alert]
            if alert is not None
            else list(
                self._session.scalars(
                    select(MonitoringAlert)
                    .where(
                        MonitoringAlert.asset_id == asset.id,
                        MonitoringAlert.state.in_(ACTIVE_ALERT_STATES),
                    )
                    .limit(rules.MAX_LIMIT)
                )
            )
        )
        for target in targets:
            self._append_event(
                target,
                action="silenced",
                from_state=target.state,
                to_state=target.state,
                note=comment,
                actor=principal,
                source=self._source,
                event_key=f"{target.id}:silenced:{row.id}",
            )
        payload = self._silence_payload(row, now=now)
        self._audit(principal, "monitoring.silence_created", f"monitoring:silence:{row.id}")
        return payload

    # ---------------------------------------------------------------- windows
    @staticmethod
    def _window_occurrence(
        window: MaintenanceWindow, now: datetime
    ) -> tuple[datetime, datetime] | None:
        if not window.enabled:
            return None
        try:
            zone = ZoneInfo(window.timezone)
            start_hour, start_minute = (int(part) for part in window.start_time.split(":"))
            end_hour, end_minute = (int(part) for part in window.end_time.split(":"))
        except ZoneInfoNotFoundError, ValueError:
            return None
        local = as_utc(now).astimezone(zone)
        days = set(window.days_of_week or [])
        for offset in range(-1, 9):
            day = (local + timedelta(days=offset)).date()
            if days and day.weekday() not in days:
                continue
            start_local = datetime(
                day.year, day.month, day.day, start_hour, start_minute, tzinfo=zone
            )
            end_day = day
            if (end_hour, end_minute) <= (start_hour, start_minute):
                end_day = day + timedelta(days=1)
            end_local = datetime(
                end_day.year, end_day.month, end_day.day, end_hour, end_minute, tzinfo=zone
            )
            if as_utc(end_local) <= now:
                continue
            return as_utc(start_local), as_utc(end_local)
        return None

    def _window_active(self, window: MaintenanceWindow, asset_id: str, now: datetime) -> bool:
        if window.asset_ids and asset_id not in window.asset_ids:
            return False
        occurrence = self._window_occurrence(window, now)
        if occurrence is None:
            return False
        start, end = occurrence
        return start <= now < end

    def _window_payload(self, window: MaintenanceWindow, *, now: datetime) -> dict[str, Any]:
        occurrence = self._window_occurrence(window, now)
        active = bool(occurrence and occurrence[0] <= now < occurrence[1])
        if not self._settings.alertmanager_url:
            alertmanager_sync = "not_configured"
        elif not window.enabled:
            alertmanager_sync = "disabled"
        elif window.am_silence_id:
            alertmanager_sync = "synced"
        else:
            alertmanager_sync = "pending"
        return {
            "id": window.id,
            "name": window.name,
            "assetIds": list(window.asset_ids or []),
            "daysOfWeek": list(window.days_of_week or []),
            "startTime": window.start_time,
            "endTime": window.end_time,
            "timezone": window.timezone,
            "enabled": window.enabled,
            "active": active,
            "nextOccurrence": {
                "startsAt": _iso(occurrence[0]),
                "endsAt": _iso(occurrence[1]),
            }
            if occurrence
            else None,
            "nativeSilenceId": window.am_silence_id,
            "alertmanagerSync": alertmanager_sync,
        }

    def _window_values(
        self,
        values: Mapping[str, Any],
        *,
        current: MaintenanceWindow | None,
        window_id: str | None,
    ) -> dict[str, Any]:
        if not isinstance(values, Mapping):
            raise ValidationFailed("window values must be an object")
        unknown = set(values) - set(WINDOW_KEYS)
        if unknown:
            raise ValidationFailed(f"unsupported window field: {sorted(unknown)[0]}")
        name = (
            _text(values.get("name"), "name", max_length=120, required=True)
            if "name" in values or current is None
            else current.name
        )
        asset_ids = values.get("assetIds")
        if asset_ids is None and current is not None:
            asset_ids = list(current.asset_ids or [])
        if asset_ids is None:
            asset_ids = []
        if not isinstance(asset_ids, list) or len(asset_ids) > 50:
            raise ValidationFailed("assetIds must be a bounded list")
        clean_assets: list[str] = []
        for asset_id in asset_ids:
            key = _uuid(asset_id, "assetIds")
            self._asset(key)
            if key not in clean_assets:
                clean_assets.append(key)
        days = values.get("daysOfWeek")
        if days is None and current is not None:
            days = list(current.days_of_week or [])
        if days is None:
            days = []
        if not isinstance(days, list) or len(days) > 7:
            raise ValidationFailed("daysOfWeek must be a bounded list")
        clean_days: list[int] = []
        for day in days:
            if isinstance(day, bool) or not isinstance(day, int) or not 0 <= day <= 6:
                raise ValidationFailed("daysOfWeek values must be between 0 and 6")
            if day not in clean_days:
                clean_days.append(day)
        start_time = values.get("startTime", current.start_time if current else None)
        end_time = values.get("endTime", current.end_time if current else None)
        if not isinstance(start_time, str) or not _TIME.fullmatch(start_time):
            raise ValidationFailed("startTime must use HH:MM")
        if not isinstance(end_time, str) or not _TIME.fullmatch(end_time):
            raise ValidationFailed("endTime must use HH:MM")
        if start_time == end_time:
            raise ValidationFailed("endTime must differ from startTime")
        timezone_name = values.get("timezone", current.timezone if current else None)
        if not isinstance(timezone_name, str) or len(timezone_name) > 64:
            raise ValidationFailed("timezone must be an IANA timezone name")
        try:
            ZoneInfo(timezone_name)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValidationFailed("timezone must be an IANA timezone name") from exc
        enabled = values.get("enabled", current.enabled if current else True)
        if not isinstance(enabled, bool):
            raise ValidationFailed("enabled must be a boolean")
        return {
            "id": window_id,
            "name": name,
            "asset_ids": clean_assets,
            "days_of_week": sorted(clean_days),
            "start_time": start_time,
            "end_time": end_time,
            "timezone": timezone_name,
            "enabled": enabled,
        }

    def save_window(self, principal: Principal, values: Mapping[str, Any]) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.edit", resource="monitoring:windows")
        if not isinstance(values, Mapping):
            raise ValidationFailed("window values must be an object")
        window_id = values.get("id")
        current = None
        if window_id is not None:
            key = _uuid(window_id, "id")
            current = self._session.get(MaintenanceWindow, key)
            if current is None:
                raise NotFound("maintenance window not found")
        clean = self._window_values(
            values, current=current, window_id=current.id if current else None
        )
        now = self._now()
        row = current
        if row is None:
            row = MaintenanceWindow(
                id=str(uuid4()), created_by=principal.actor_id, created_at=now, updated_at=now
            )
            self._session.add(row)
        changed_schedule = (
            current is None
            or current.enabled != clean["enabled"]
            or list(current.asset_ids or []) != clean["asset_ids"]
            or list(current.days_of_week or []) != clean["days_of_week"]
            or current.start_time != clean["start_time"]
            or current.end_time != clean["end_time"]
            or current.timezone != clean["timezone"]
        )
        row.name = clean["name"]
        row.asset_ids = clean["asset_ids"]
        row.days_of_week = clean["days_of_week"]
        row.start_time = clean["start_time"]
        row.end_time = clean["end_time"]
        row.timezone = clean["timezone"]
        row.enabled = clean["enabled"]
        row.updated_at = now
        if changed_schedule:
            row.am_occurrence_start = None
        self._session.flush()
        payload = self._window_payload(row, now=now)
        self._audit(principal, "monitoring.window_saved", f"monitoring:window:{row.id}")
        if self._settings.alertmanager_url:
            payload = self._sync_window(row, now=now)
            self._session.commit()
        return payload

    def list_windows(
        self,
        principal: Principal,
        *,
        limit: int = rules.DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.view", resource="monitoring:windows")
        bounded_limit, bounded_offset = _bounded(limit, offset)
        total = int(self._session.scalar(select(func.count(MaintenanceWindow.id))) or 0)
        rows = self._session.scalars(
            select(MaintenanceWindow)
            .order_by(MaintenanceWindow.name)
            .limit(bounded_limit)
            .offset(bounded_offset)
        )
        now = self._now()
        return {
            "items": [self._window_payload(row, now=now) for row in rows],
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
        }

    def _window_matchers(self, window: MaintenanceWindow) -> list[dict[str, Any]]:
        if window.asset_ids:
            value = "|".join(re.escape(asset_id) for asset_id in window.asset_ids)
        else:
            value = ".+"
        return [{"name": "asset_id", "value": value, "isRegex": True, "isEqual": True}]

    def _sync_window(
        self, window: MaintenanceWindow, *, now: datetime | None = None
    ) -> dict[str, Any]:
        now = now or self._now()
        adapter = self._monitor_adapter()
        occurrence = self._window_occurrence(window, now)
        try:
            if not window.enabled or occurrence is None:
                if window.am_silence_id:
                    adapter.delete_silence(window.am_silence_id)
                window.am_silence_id = None
                window.am_occurrence_start = None
                return self._window_payload(window, now=now)
            start, end = occurrence
            if (
                window.am_occurrence_start is not None
                and _iso(window.am_occurrence_start) == _iso(start)
                and window.am_silence_id
            ):
                return self._window_payload(window, now=now)
            if window.am_silence_id:
                adapter.delete_silence(window.am_silence_id)
                window.am_silence_id = None
            window.am_silence_id = adapter.create_silence(
                matchers=self._window_matchers(window),
                starts_at=start,
                ends_at=end,
                comment=f"ITSM maintenance window {window.id}: {window.name}"[:200],
                created_by="itsm-monitoring",
            )
            window.am_occurrence_start = start
            window.updated_at = now
            self._session.flush()
        except MonitoringUnavailable:
            log_event(logger, "monitoring.alertmanager_sync_pending", window_id=window.id)
            return {
                **self._window_payload(window, now=now),
                "alertmanagerSync": "pending",
            }
        return self._window_payload(window, now=now)

    def sync_maintenance_windows(self, *, now: datetime | None = None) -> dict[str, int]:
        """Worker entry: keep one native Alertmanager silence per actual occurrence."""
        if not self._settings.alertmanager_url:
            return {"windows": 0, "silences": 0, "pending": 0}
        current = now or self._now()
        windows = 0
        silences = 0
        pending = 0
        for window in self._session.scalars(
            select(MaintenanceWindow).where(MaintenanceWindow.enabled.is_(True))
        ):
            windows += 1
            before = window.am_silence_id
            payload = self._sync_window(window, now=current)
            if payload.get("alertmanagerSync") == "pending":
                pending += 1
            elif window.am_silence_id and window.am_silence_id != before:
                silences += 1
        self._session.commit()
        return {"windows": windows, "silences": silences, "pending": pending}

    # --------------------------------------------------------------- incidents
    def _incident_priority(self, severity: str) -> str:
        return _PRIORITY_BY_SEVERITY.get(severity, "normal")

    def link_incident(
        self, principal: Principal, alert_id: Any, incident_id: Any = None
    ) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.edit", resource="monitoring:incidents")
        alert = self._alert(alert_id)
        asset = self._asset(alert.asset_id)
        actions = InterventionService(
            self._session, self._settings, identity=self._identity, source=self._source
        )
        created = False
        if incident_id is None:
            if alert.incident_id is not None:
                return self.get_alert(principal, alert.id)
            values = {
                "primaryAssetId": alert.asset_id,
                "description": (
                    f"Alerta {alert.alert_name} en {asset.name}: "
                    f"{alert.summary or alert.alert_name}"
                )[:2000],
                "priority": self._incident_priority(alert.severity),
            }
            incident = actions.create_incident_in_transaction(principal, values)
            incident_id = incident.id
            created = True
        else:
            incident_id = _uuid(incident_id, "incidentId")
            incident = self._session.get(Incident, incident_id)
            if incident is None:
                raise NotFound("incident not found")
            if alert.incident_id == incident_id:
                return self.get_alert(principal, alert.id)
            if alert.incident_id is not None:
                raise Conflict("alert is already linked to another incident")
            if incident.status == "closed":
                raise Conflict("cannot link an alert to a closed incident")
        alert.incident_id = incident_id
        alert.updated_at = self._now()
        event_key = f"{alert.id}:incident:{incident_id}"
        self._append_event(
            alert,
            action="incident_created" if created else "incident_linked",
            from_state=alert.state,
            to_state=alert.state,
            note=f"Incident {incident_id}",
            changes={"incidentId": incident_id, "created": created},
            actor=principal,
            source=self._source,
            event_key=event_key,
        )
        self._audit(
            principal,
            "monitoring.incident_created" if created else "monitoring.incident_linked",
            f"alert:{alert.id}",
        )
        self._session.commit()
        return self.get_alert(principal, alert.id)

    def prepare_maintenance(self, principal: Principal, alert_id: Any) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.edit", resource="monitoring:alerts")
        alert = self._alert(alert_id)
        asset = self._asset(alert.asset_id)
        now = self._now()
        windows = self._enabled_windows()
        existing = next(
            (window for window in windows if not window.asset_ids or asset.id in window.asset_ids),
            None,
        )
        next_hour = (now + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
        end_hour = next_hour + timedelta(hours=1)
        return {
            "assetId": asset.id,
            "suggested": {
                "name": f"Mantenimiento: {asset.name}"[:120],
                "assetIds": [asset.id],
                "daysOfWeek": [0, 1, 2, 3, 4, 5, 6],
                "startTime": next_hour.strftime("%H:%M"),
                "endTime": end_hour.strftime("%H:%M"),
                "timezone": "UTC",
            },
            "existingWindow": (
                self._window_payload(existing, now=now) if existing is not None else None
            ),
            "alert": {
                "id": alert.id,
                "alertName": alert.alert_name,
                "severity": alert.severity,
                "state": alert.state,
            },
        }

    # -------------------------------------------------------------- ingestion
    def _notify(
        self,
        alert: MonitoringAlert,
        event_type: str,
        *,
        now: datetime,
        acknowledged: bool = False,
        recovered: bool = False,
    ) -> bool:
        if self._notifier is None:
            return False
        silences = self._active_silences(now)
        if not (acknowledged or recovered) and self._silenced(alert, silences, now):
            return False
        assets = self._asset_index([alert.asset_id])
        name = assets.get(alert.asset_id, (alert.labels.get("asset_name") or "", ""))[0]
        asset_label = name or alert.asset_id
        title = f"{alert.alert_name} — {asset_label}"[:160]
        if alert.summary:
            body_key, body_params = "api.monitoring.alert.summary", {"summary": alert.summary}
        elif alert.description:
            body_key, body_params = (
                "api.monitoring.alert.description",
                {"description": alert.description},
            )
        else:
            body_key, body_params = "api.monitoring.alert.severity", {"severity": alert.severity}
        body = (alert.summary or alert.description or f"Severity {alert.severity}")[:1000]
        url = (
            f"{self._settings.monitoring_public_url.rstrip('/')}/#/supervision/alerta/{alert.id}"
        )[:500]
        self._notifier(
            self._session,
            self._settings,
            alert_id=alert.id,
            event_key=f"{alert.id}:{_iso(alert.starts_at)}:{event_type}",
            event_type=event_type,
            severity=alert.severity,
            asset_id=alert.asset_id,
            title=title,
            body=body,
            message={
                "title": {
                    "key": "api.monitoring.alert.title",
                    "params": {"alert": alert.alert_name, "asset": asset_label},
                },
                "body": {"key": body_key, "params": body_params},
            },
            url=url,
            acknowledged=acknowledged,
            recovered=recovered,
            occurred_at=now,
        )
        return True

    def _known_assets(self, asset_ids: Sequence[str]) -> None:
        keys = sorted({key for key in asset_ids if key})
        if not keys:
            return
        known = set(self._session.scalars(select(Asset.id).where(Asset.id.in_(keys))))
        missing = [key for key in keys if key not in known]
        if missing:
            raise ValidationFailed("alert references an asset that is not in inventory")

    @staticmethod
    def _normalize_alert_item(
        labels: Mapping[str, Any],
        annotations: Mapping[str, Any],
        *,
        status: str,
        starts_at: Any,
        ends_at: Any = None,
        fingerprint: Any = None,
        value: Any = None,
    ) -> dict[str, Any]:
        clean_labels = {str(key): str(raw) for key, raw in labels.items()}
        clean_annotations = {str(key): str(raw) for key, raw in annotations.items()}
        asset_id = _uuid(clean_labels.get("asset_id"), "asset_id label")
        alert_name = _text(
            clean_labels.get("alertname"),
            "alertname label",
            max_length=128,
            required=True,
        )
        start = _datetime_arg(starts_at, "startsAt")
        end = _datetime_arg(ends_at, "endsAt") if ends_at else None
        canonical = (
            "resolved" if status == "resolved" else ("pending" if status == "pending" else "firing")
        )
        native_fingerprint = fingerprint if isinstance(fingerprint, str) and fingerprint else None
        if native_fingerprint is not None and not re.fullmatch(
            r"[A-Za-z0-9]{1,64}", native_fingerprint
        ):
            native_fingerprint = None
        return {
            "asset_id": asset_id,
            "alert_name": alert_name,
            "severity": _severity(clean_labels.get("severity")),
            "labels": clean_labels,
            "annotations": clean_annotations,
            "fingerprint": native_fingerprint or _fingerprint(clean_labels),
            "starts_at": start,
            "ends_at": end,
            "state": canonical,
            "summary": (clean_annotations.get("summary") or "")[:1000] or None,
            "description": (clean_annotations.get("description") or "")[:2000] or None,
            "value": str(value)[:200] if value is not None else None,
        }

    def _ingest_one(
        self,
        item: Mapping[str, Any],
        *,
        now: datetime,
        source: str,
        group_key: str | None,
        stats: dict[str, int],
    ) -> None:
        asset_id = item["asset_id"]
        fingerprint = item["fingerprint"]
        starts_at = item["starts_at"]
        state = item["state"]
        alert = self._session.scalar(
            select(MonitoringAlert).where(
                MonitoringAlert.fingerprint == fingerprint,
                MonitoringAlert.starts_at == starts_at,
            )
        )
        latest = self._session.scalar(
            select(func.max(MonitoringAlert.starts_at)).where(
                MonitoringAlert.fingerprint == fingerprint
            )
        )
        if latest is not None and starts_at < as_utc(latest):
            if state == "resolved" and alert is not None and alert.state != "resolved":
                # A late resolution may close its own older cycle, but it never
                # changes the newer active cycle nor resurrects it.
                previous = alert.state
                alert.state = "resolved"
                alert.ends_at = item["ends_at"] or now
                alert.last_seen_at = now
                alert.updated_at = now
                if self._append_event(
                    alert,
                    action="resolved",
                    from_state=previous,
                    to_state="resolved",
                    note="Late resolution for an older alert cycle",
                    source=source,
                    event_key=f"{alert.id}:resolved",
                ):
                    stats["events"] += 1
                    newer_active = self._session.scalar(
                        select(MonitoringAlert.id)
                        .where(
                            MonitoringAlert.fingerprint == fingerprint,
                            MonitoringAlert.state.in_(ACTIVE_ALERT_STATES),
                            MonitoringAlert.starts_at > alert.starts_at,
                        )
                        .limit(1)
                    )
                    if (
                        previous == "firing"
                        and newer_active is None
                        and self._notify(
                            alert,
                            "recovered",
                            now=now,
                            recovered=True,
                            acknowledged=alert.acknowledged_at is not None,
                        )
                    ):
                        stats["notifications"] += 1
                stats["resolved"] += 1
                stats["updated"] += 1
            else:
                stats["ignored"] += 1
            return
        if alert is None:
            alert = MonitoringAlert(
                id=str(uuid4()),
                fingerprint=fingerprint,
                alert_name=item["alert_name"],
                severity=item["severity"],
                asset_id=asset_id,
                group_key=group_key,
                source=source,
                state=state,
                labels=item["labels"],
                annotations=item["annotations"],
                summary=item["summary"],
                description=item["description"],
                starts_at=starts_at,
                ends_at=item["ends_at"] or (now if state == "resolved" else None),
                last_seen_at=now,
                created_at=now,
                updated_at=now,
            )
            self._session.add(alert)
            self._session.flush()
            stats["created"] += 1
            if state == "resolved":
                if self._append_event(
                    alert,
                    action="resolved",
                    from_state=None,
                    to_state="resolved",
                    note="Resolved alert received without an observed firing cycle",
                    source=source,
                    event_key=f"{alert.id}:resolved",
                ):
                    stats["events"] += 1
            else:
                if self._append_event(
                    alert,
                    action="opened",
                    from_state=None,
                    to_state=state,
                    source=source,
                    event_key=f"{alert.id}:opened",
                ):
                    stats["events"] += 1
                    if state == "firing" and self._notify(alert, "firing", now=now):
                        stats["notifications"] += 1
            return
        if state == "resolved":
            if alert.state == "resolved":
                alert.last_seen_at = now
                stats["updated"] += 1
                return
            previous = alert.state
            alert.state = "resolved"
            alert.ends_at = item["ends_at"] or now
            alert.last_seen_at = now
            alert.updated_at = now
            if self._append_event(
                alert,
                action="resolved",
                from_state=previous,
                to_state="resolved",
                source=source,
                event_key=f"{alert.id}:resolved",
            ):
                stats["events"] += 1
                if self._notify(
                    alert,
                    "recovered",
                    now=now,
                    recovered=True,
                    acknowledged=alert.acknowledged_at is not None,
                ):
                    stats["notifications"] += 1
            stats["resolved"] += 1
            stats["updated"] += 1
            return
        if alert.state == "resolved":
            stats["ignored"] += 1
            return
        alert.last_seen_at = now
        alert.updated_at = now
        alert.labels = item["labels"]
        alert.annotations = item["annotations"]
        alert.summary = item["summary"]
        alert.description = item["description"]
        if alert.severity != item["severity"]:
            alert.severity = item["severity"]
        if alert.group_key is None:
            alert.group_key = group_key
        if alert.state == "pending" and state == "firing":
            previous = alert.state
            alert.state = "firing"
            if self._append_event(
                alert,
                action="fired",
                from_state=previous,
                to_state="firing",
                source=source,
                event_key=f"{alert.id}:fired",
            ):
                stats["events"] += 1
                if self._notify(alert, "firing", now=now):
                    stats["notifications"] += 1
        stats["updated"] += 1

    def _ingest_items(
        self,
        items: Sequence[Mapping[str, Any]],
        *,
        now: datetime,
        source: str,
        group_key: str | None = None,
    ) -> dict[str, int]:
        if not items:
            raise ValidationFailed("the payload contains no alerts")
        if len(items) > rules.MAX_ALERTS_PER_INGEST:
            raise ValidationFailed("the payload exceeds the bounded alert count")
        self._known_assets([item["asset_id"] for item in items])
        stats = {
            "received": len(items),
            "created": 0,
            "updated": 0,
            "ignored": 0,
            "events": 0,
            "notifications": 0,
            "resolved": 0,
        }
        for item in items:
            self._ingest_one(item, now=now, source=source, group_key=group_key, stats=stats)
        return stats

    @serialized
    def ingest_alertmanager(
        self, payload: Mapping[str, Any], *, now: datetime | None = None
    ) -> dict[str, int]:
        """Idempotent Alertmanager v4 webhook ingestion; validates all assets first."""
        if not isinstance(payload, Mapping):
            raise ValidationFailed("alertmanager payload must be an object")
        if str(payload.get("version")) != "4":
            raise ValidationFailed("unsupported alertmanager payload version")
        raw_alerts = payload.get("alerts")
        if (
            not isinstance(raw_alerts, list)
            or not 1 <= len(raw_alerts) <= rules.MAX_ALERTS_PER_INGEST
        ):
            raise ValidationFailed("alerts must be a bounded non-empty list")
        group_key = payload.get("groupKey")
        if group_key is not None and (not isinstance(group_key, str) or len(group_key) > 256):
            raise ValidationFailed("groupKey must be at most 256 characters")
        items: list[dict[str, Any]] = []
        for raw in raw_alerts:
            if not isinstance(raw, Mapping):
                raise ValidationFailed("each alert must be an object")
            labels = raw.get("labels")
            annotations = raw.get("annotations") or {}
            if not isinstance(labels, Mapping) or not isinstance(annotations, Mapping):
                raise ValidationFailed("alert labels and annotations must be objects")
            status = raw.get("status")
            if status not in {"firing", "resolved"}:
                raise ValidationFailed("alert status must be firing or resolved")
            items.append(
                self._normalize_alert_item(
                    labels,
                    annotations,
                    status=status,
                    starts_at=raw.get("startsAt"),
                    ends_at=raw.get("endsAt"),
                    fingerprint=raw.get("fingerprint"),
                )
            )
        current = now or self._now()
        stats = self._ingest_items(items, now=current, source="alertmanager", group_key=group_key)
        self._session.commit()
        return stats

    # ----------------------------------------------------------- machine surfaces
    def discovery(self, check_type: str) -> list[dict[str, Any]]:
        """Prometheus HTTP SD entries; computed in memory, never materialized."""
        if check_type not in rules.CHECK_TYPES:
            raise ValidationFailed("unsupported check_type")
        assets = list(
            self._session.scalars(
                select(Asset).order_by(Asset.quick_code).limit(rules.MAX_SD_ASSETS)
            )
        )
        exporters = {
            row.id: row
            for row in self._session.scalars(select(MonitorExporter).limit(rules.MAX_LIMIT))
        }
        entries: list[dict[str, Any]] = []
        for asset in assets:
            config = self._effective(asset)
            if (
                not config["enabled"]
                or not config["targetPresent"]
                or config["checkType"] != check_type
            ):
                continue
            exporter = exporters.get(config.get("exporterId") or "")
            if config.get("exporterId") and (exporter is None or not exporter.enabled):
                continue
            labels = {
                "asset_id": asset.id,
                "asset_name": asset.name,
                "check_type": check_type,
                "module": config.get("module") or rules.DEFAULT_MODULE.get(check_type, ""),
                "interval_seconds": str(config.get("intervalSeconds") or 60),
            }
            if asset.category:
                labels["category"] = asset.category
            if asset.site:
                labels["site"] = asset.site
            if config.get("exporterId"):
                labels["exporter_id"] = str(config["exporterId"])
            if exporter is not None and exporter.address:
                labels["exporter_address"] = exporter.address
            if config.get("snmpAuthRef"):
                labels["auth"] = str(config["snmpAuthRef"])
            entries.append({"targets": [config["target"]], "labels": labels})
        if len(entries) >= rules.MAX_SD_ASSETS:
            log_event(
                logger,
                "monitoring.discovery_truncated",
                limit=rules.MAX_SD_ASSETS,
                check_type=check_type,
            )
        return entries

    def config_metrics(self) -> str:
        """Prometheus exposition of the effective check configuration per asset."""
        assets = list(
            self._session.scalars(
                select(Asset).order_by(Asset.quick_code).limit(rules.MAX_SD_ASSETS)
            )
        )
        lines = [
            "# HELP itsm_monitoring_check_enabled 1 when the asset monitoring check is enabled.",
            "# TYPE itsm_monitoring_check_enabled gauge",
            "# HELP itsm_monitoring_check_duration_preset_seconds "
            "Configured minimum duration preset.",
            "# TYPE itsm_monitoring_check_duration_preset_seconds gauge",
            "# HELP itsm_monitoring_check_interval_seconds Configured check interval in seconds.",
            "# TYPE itsm_monitoring_check_interval_seconds gauge",
            "# HELP itsm_monitoring_check_threshold Configured per-metric threshold.",
            "# TYPE itsm_monitoring_check_threshold gauge",
            "# HELP itsm_monitoring_asset_target_present 1 when the asset has a valid real target.",
            "# TYPE itsm_monitoring_asset_target_present gauge",
            "# HELP itsm_monitoring_build_info Monitoring rule bundle version.",
            "# TYPE itsm_monitoring_build_info gauge",
            f'itsm_monitoring_build_info{{version="{rules.RULE_BUNDLE_VERSION}"}} 1',
        ]
        for asset in assets:
            config = self._effective(asset)
            if not config["enabled"]:
                continue
            asset_label = _prom_label(asset.id)
            check_type = _prom_label(str(config.get("checkType") or ""))
            lines.append(
                f'itsm_monitoring_check_enabled{{asset_id="{asset_label}",'
                f'check_type="{check_type}"}} 1'
            )
            lines.append(
                "itsm_monitoring_check_duration_preset_seconds"
                f'{{asset_id="{asset_label}"}} '
                f"{int(config.get('minimumDurationSeconds') or 0)}"
            )
            lines.append(
                "itsm_monitoring_check_interval_seconds"
                f'{{asset_id="{asset_label}"}} {int(config.get("intervalSeconds") or 60)}'
            )
            lines.append(
                f'itsm_monitoring_asset_target_present{{asset_id="{asset_label}"}} '
                f"{1 if config['targetPresent'] else 0}"
            )
            for metric, pair in sorted((config.get("thresholds") or {}).items()):
                for severity in ("warning", "critical"):
                    value = pair.get(severity)
                    if value is None:
                        continue
                    lines.append(
                        "itsm_monitoring_check_threshold"
                        f'{{asset_id="{asset_label}",metric="{_prom_label(metric)}",'
                        f'severity="{severity}"}} {_metric_number(float(value))}'
                    )
        return "\n".join(lines) + "\n"

    @serialized
    def poll_native_alerts(self, *, now: datetime | None = None) -> dict[str, int]:
        """Poll native Prometheus alerts when Alertmanager is not configured."""
        if self._settings.alertmanager_url:
            return {"skipped": 1}
        current = now or self._now()
        adapter = self._monitor_adapter()
        raw_alerts = adapter.alerts()
        if len(raw_alerts) > rules.MAX_ALERTS_PER_INGEST:
            raise MonitoringUnavailable("prometheus alert count exceeds the bounded limit")
        items: list[dict[str, Any]] = []
        ignored = 0
        for raw in raw_alerts:
            labels = raw.get("labels") or {}
            if not labels.get("asset_id"):
                ignored += 1
                continue
            state = raw.get("state")
            if state not in {"firing", "pending"}:
                ignored += 1
                continue
            try:
                items.append(
                    self._normalize_alert_item(
                        labels,
                        raw.get("annotations") or {},
                        status=state,
                        starts_at=raw.get("activeAt"),
                    )
                )
            except ValidationFailed:
                ignored += 1
        self._known_assets([item["asset_id"] for item in items])
        stats = {
            "received": len(items),
            "created": 0,
            "updated": 0,
            "ignored": ignored,
            "events": 0,
            "notifications": 0,
            "resolved": 0,
        }
        if items:
            merged = self._ingest_items(items, now=current, source="prometheus")
            for key, value in merged.items():
                stats[key] += value
        seen = {(item["fingerprint"], item["starts_at"]) for item in items}
        active = list(
            self._session.scalars(
                select(MonitoringAlert)
                .where(
                    MonitoringAlert.source == "prometheus",
                    MonitoringAlert.state.in_(ACTIVE_ALERT_STATES),
                )
                .limit(1000)
            )
        )
        for alert in active:
            if (alert.fingerprint, as_utc(alert.starts_at)) in seen:
                continue
            previous = alert.state
            alert.state = "resolved"
            alert.ends_at = current
            alert.last_seen_at = current
            alert.updated_at = current
            if self._append_event(
                alert,
                action="resolved",
                from_state=previous,
                to_state="resolved",
                note="Alert is no longer active in Prometheus",
                source="prometheus",
                event_key=f"{alert.id}:resolved",
            ):
                stats["events"] += 1
                if previous == "firing" and self._notify(
                    alert,
                    "recovered",
                    now=current,
                    recovered=True,
                    acknowledged=alert.acknowledged_at is not None,
                ):
                    stats["notifications"] += 1
                stats["resolved"] += 1
        self._session.commit()
        return stats


def _prom_label(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _metric_number(value: float) -> str:
    return f"{value:.6f}".rstrip("0").rstrip(".") or "0"


__all__ = [
    "CONFIG_KEYS",
    "EXPORTER_KEYS",
    "PROFILE_KEYS",
    "SILENCE_KEYS",
    "WINDOW_KEYS",
    "MonitoringService",
]
