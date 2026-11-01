"""Operations dashboard aggregation over canonical authorized sources.

The dashboard is a read projection, never a demo fallback:
- inventory counts and breakdowns come from the canonical ``assets`` table;
- device status, availability and latency come from the existing monitoring
  service and its bounded Prometheus adapter;
- active alerts and lifecycle events come from monitoring tables;
- incidents, maintenance plans and warranties are read from their canonical
  tables with the same scope filters and permissions as their services.

Page-derived totals are never used: every total is its own aggregate query and
detail lists are independently bounded. Missing telemetry is reported as
``unknown``; no outage or uptime value is invented when Prometheus is absent.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.identity.clock import as_utc, utcnow
from itsm.identity.service import IdentityService, Principal, ValidationFailed
from itsm.interventions.models import Incident
from itsm.inventory.models import Asset, AssetHistory
from itsm.maintenance.models import MaintenancePlan
from itsm.monitoring import rules
from itsm.monitoring.models import MonitoringAlert, MonitoringAlertEvent
from itsm.monitoring.service import ACTIVE_ALERT_STATES, MonitoringService
from itsm.workflows.models import Warranty, WarrantyPreference

DEFAULT_WARRANTY_DAYS = 30
MAX_ALERTS = 20
MAX_ROWS = 50
MAX_ACTIVITY = 15
MAX_MAINTENANCE = 10
MAX_WARRANTIES = 10
MAX_INCIDENTS = 10
MAX_ATTENTION = 10
ACTIVE_INCIDENTS = ("open", "in_progress")
_SEVERITIES = ("critical", "warning", "info")
_STATUS_RANK = {"down": 0, "degraded": 1, "unmonitored": 2, "unknown": 3, "up": 4}
_INFRASTRUCTURE = (
    "gateway",
    "router",
    "switch",
    "firewall",
    "server",
    "servidor",
    "reloj",
    "biometric",
    "biometr",
    "ups",
    "nas",
    "storage",
    "almacenamiento",
    "access point",
    "punto de acceso",
)
_ACTION_LABELS = {
    "created": "Activo creado",
    "updated": "Activo actualizado",
    "status_change": "Estado actualizado",
    "quick_code_change": "Código rápido actualizado",
    "archived": "Activo archivado",
    "restored": "Activo restaurado",
    "purged": "Activo eliminado",
    "moved": "Ubicación actualizada",
    "media_updated": "Imagen actualizada",
}


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return as_utc(value).isoformat().replace("+00:00", "Z")


def _date(value: date | None) -> str | None:
    return value.isoformat() if value is not None else None


def _text(value: Any, field: str, *, max_length: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationFailed(
            f"{field} must be text",
            key="api.validation.field_text",
            params={"field": field},
        )
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > max_length:
        raise ValidationFailed(
            f"{field} must be at most {max_length} characters",
            key="api.validation.field_max_length",
            params={"field": field, "limit": max_length},
        )
    return cleaned


def _uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValidationFailed(
            f"{field} must be a UUID",
            key="api.validation.field_uuid",
            params={"field": field},
        )
    try:
        return str(UUID(value.strip()))
    except ValueError as exc:
        raise ValidationFailed(
            f"{field} must be a UUID",
            key="api.validation.field_uuid",
            params={"field": field},
        ) from exc


def _severity(value: str | None) -> str:
    candidate = (value or "").strip().lower()
    return candidate if candidate in _SEVERITIES else "info"


def _infrastructure(row: Mapping[str, Any]) -> bool:
    text = " ".join(str(row.get(key) or "").casefold() for key in ("category", "type", "name"))
    return any(token in text for token in _INFRASTRUCTURE)


class DashboardService:
    """One authorized, bounded read model for the NOC dashboard."""

    def __init__(
        self,
        session: Session,
        identity: IdentityService,
        settings: Settings,
        source: str = "api",
        *,
        monitoring: MonitoringService | None = None,
        now: Any = None,
    ) -> None:
        self._session = session
        self._identity = identity
        self._settings = settings
        self._source = source
        self._monitoring = monitoring or MonitoringService(
            session, settings, identity=identity, source=source
        )
        self._now = now or utcnow

    # ---------------------------------------------------------------- helpers
    def _conditions(self, category: str | None, site_id: str | None) -> list[Any]:
        conditions: list[Any] = [Asset.archived_at.is_(None)]
        if category is not None:
            conditions.append(Asset.category == category)
        if site_id is not None:
            conditions.append(Asset.site_id == site_id)
        return conditions

    def _activation_counts(self, conditions: Sequence[Any]) -> dict[str, int]:
        rows = self._session.execute(
            select(MonitoringAlert.severity, func.count())
            .join(Asset, Asset.id == MonitoringAlert.asset_id)
            .where(
                MonitoringAlert.state.in_(ACTIVE_ALERT_STATES),
                *conditions,
            )
            .group_by(MonitoringAlert.severity)
        )
        counts = {severity: 0 for severity in _SEVERITIES}
        for severity, count in rows:
            key = _severity(severity)
            counts[key] += int(count)
        return counts

    def _active_alerts(self, conditions: Sequence[Any]) -> list[dict[str, Any]]:
        severity_order = case(
            (MonitoringAlert.severity == "critical", 0),
            (MonitoringAlert.severity == "warning", 1),
            else_=2,
        )
        rows = self._session.execute(
            select(MonitoringAlert, Asset)
            .join(Asset, Asset.id == MonitoringAlert.asset_id)
            .where(
                MonitoringAlert.state.in_(ACTIVE_ALERT_STATES),
                *conditions,
            )
            .order_by(severity_order, MonitoringAlert.starts_at.desc())
            .limit(MAX_ALERTS)
        )
        return [
            {
                "id": alert.id,
                "title": alert.alert_name,
                "description": alert.description or alert.summary or "",
                "severity": _severity(alert.severity),
                "assetId": alert.asset_id,
                "assetName": asset.name,
                "assetCode": asset.quick_code,
                "state": alert.state,
                "acknowledged": alert.acknowledged_at is not None,
                "createdAt": _iso(alert.starts_at),
                "acknowledgedAt": _iso(alert.acknowledged_at),
                "target": {"kind": "alert", "id": alert.id},
            }
            for alert, asset in rows
        ]

    def _incidents(self, conditions: Sequence[Any]) -> tuple[list[dict[str, Any]], int]:
        priority_order = case(
            (Incident.priority == "critical", 0),
            (Incident.priority == "high", 1),
            (Incident.priority == "normal", 2),
            else_=3,
        )
        base = (
            select(Incident, Asset)
            .join(Asset, Asset.id == Incident.primary_asset_id)
            .where(Incident.status.in_(ACTIVE_INCIDENTS), *conditions)
        )
        total = self._session.scalar(
            select(func.count())
            .select_from(Incident)
            .join(Asset, Asset.id == Incident.primary_asset_id)
            .where(Incident.status.in_(ACTIVE_INCIDENTS), *conditions)
        )
        rows = self._session.execute(
            base.order_by(priority_order, Incident.opened_on.desc()).limit(MAX_INCIDENTS)
        )
        severity = {"critical": "critical", "high": "warning", "normal": "info", "low": "info"}
        return (
            [
                {
                    "id": incident.id,
                    "title": incident.description,
                    "assetId": incident.primary_asset_id,
                    "assetName": asset.name,
                    "assetCode": asset.quick_code,
                    "severity": severity.get(incident.priority, "info"),
                    "status": incident.status,
                    "openedAt": _date(incident.opened_on),
                    "target": {"kind": "incident", "id": incident.id},
                }
                for incident, asset in rows
            ],
            int(total or 0),
        )

    def _maintenance(self, conditions: Sequence[Any], today: date) -> list[dict[str, Any]]:
        rows = self._session.execute(
            select(MaintenancePlan, Asset)
            .join(Asset, Asset.id == MaintenancePlan.asset_id)
            .where(MaintenancePlan.status != "cancelled", *conditions)
            .order_by(MaintenancePlan.due_on, MaintenancePlan.id)
            .limit(MAX_MAINTENANCE)
        )
        items = []
        for plan, asset in rows:
            if plan.due_on < today:
                state, tone = "overdue", "danger"
            elif plan.due_on <= today + timedelta(days=30):
                state, tone = "upcoming", "warn"
            else:
                state, tone = "pending", "normal"
            items.append(
                {
                    "planId": plan.id,
                    "assetId": plan.asset_id,
                    "assetName": asset.name,
                    "assetCode": asset.quick_code,
                    "label": plan.maintenance_type,
                    "status": state,
                    "statusTone": tone,
                    "dueAt": _date(plan.due_on),
                }
            )
        return items

    def _warranty_days(self) -> int:
        row = self._session.get(WarrantyPreference, "expiring")
        return row.days if row is not None else DEFAULT_WARRANTY_DAYS

    def _warranties(self, conditions: Sequence[Any], today: date) -> list[dict[str, Any]]:
        rows = self._session.execute(
            select(Warranty, Asset).join(Asset, Asset.id == Warranty.asset_id).where(*conditions)
        )
        days = self._warranty_days()
        items: list[dict[str, Any]] = []
        for warranty, asset in rows:
            payload = warranty.payload or {}
            raw = payload.get("expiresOn")
            if not isinstance(raw, str):
                continue
            try:
                expires = date.fromisoformat(raw)
            except ValueError:
                continue
            remaining = (expires - today).days
            if remaining < 0:
                coverage = "expired"
            elif remaining <= days:
                coverage = "expiring"
            else:
                continue
            items.append(
                {
                    "assetId": asset.id,
                    "assetName": asset.name,
                    "assetCode": asset.quick_code,
                    "until": expires.isoformat(),
                    "days": remaining,
                    "coverage": coverage,
                }
            )
        items.sort(key=lambda item: (item["days"], item["assetCode"]))
        return items[:MAX_WARRANTIES]

    def _activity(self, conditions: Sequence[Any]) -> list[dict[str, Any]]:
        history_rows = self._session.execute(
            select(AssetHistory, Asset)
            .join(Asset, Asset.id == AssetHistory.asset_id)
            .where(*conditions)
            .order_by(AssetHistory.created_at.desc(), AssetHistory.sequence.desc())
            .limit(MAX_ACTIVITY)
        )
        events = [
            {
                "id": row.id,
                "at": _iso(row.created_at),
                "_at": as_utc(row.created_at),
                "kind": "inventory",
                "title": _ACTION_LABELS.get(row.action, row.action.replace("_", " ").capitalize()),
                "detail": row.reason
                or (
                    f"{row.status_old} → {row.status_new}"
                    if row.status_old and row.status_new and row.status_old != row.status_new
                    else ""
                ),
                "assetId": asset.id,
                "assetName": asset.name,
                "assetCode": asset.quick_code,
                "target": {"kind": "asset", "id": asset.id},
            }
            for row, asset in history_rows
        ]
        event_rows = self._session.execute(
            select(MonitoringAlertEvent, MonitoringAlert, Asset)
            .join(MonitoringAlert, MonitoringAlert.id == MonitoringAlertEvent.alert_id)
            .join(Asset, Asset.id == MonitoringAlert.asset_id)
            .where(*conditions)
            .order_by(MonitoringAlertEvent.created_at.desc())
            .limit(MAX_ACTIVITY)
        )
        for event, alert, asset in event_rows:
            events.append(
                {
                    "id": event.id,
                    "at": _iso(event.created_at),
                    "_at": as_utc(event.created_at),
                    "kind": "recovery" if event.to_state == "resolved" else "alert",
                    "title": f"{alert.alert_name}: {event.action.replace('_', ' ')}",
                    "detail": event.note or alert.summary or "",
                    "assetId": asset.id,
                    "assetName": asset.name,
                    "assetCode": asset.quick_code,
                    "target": {"kind": "alert", "id": alert.id},
                }
            )
        events.sort(key=lambda item: (item["_at"], item["id"]), reverse=True)
        for item in events:
            item.pop("_at", None)
        return events[:MAX_ACTIVITY]

    def _breakdown(
        self,
        assets: Sequence[Asset],
        key: str,
        statuses: Mapping[str, str],
    ) -> list[dict[str, Any]]:
        groups: dict[str, dict[str, Any]] = {}
        for asset in assets:
            if key == "category":
                identifier = asset.category or "unassigned"
                name = asset.category or "Sin categoría"
            else:
                identifier = asset.site_id or "unassigned"
                name = asset.site or asset.site_id or "Sin sitio"
            group = groups.setdefault(
                identifier,
                {
                    "id": identifier,
                    "label": name,
                    "total": 0,
                    "up": 0,
                    "degraded": 0,
                    "down": 0,
                    "other": 0,
                },
            )
            group["total"] += 1
            status = statuses.get(asset.id, "unknown")
            if status in {"up", "degraded", "down"}:
                group[status] += 1
            else:
                group["other"] += 1
        return sorted(groups.values(), key=lambda item: (-item["total"], item["label"]))

    # ------------------------------------------------------------------ read
    def summary(
        self,
        principal: Principal,
        period: str = "24h",
        category: str | None = None,
        site_id: str | None = None,
    ) -> dict[str, Any]:
        self._identity.authorize(principal, "assets.view", resource="dashboard")
        if period not in rules.PERIOD_PRESETS:
            raise ValidationFailed(
                "period must be one of 24h, 7d or 30d",
                key="api.dashboard.period_allowed",
                params={"allowed": ", ".join(rules.PERIOD_PRESETS)},
            )
        checked_category = _text(category, "category", max_length=64)
        checked_site = _uuid(site_id, "siteId") if site_id is not None else None
        conditions = self._conditions(checked_category, checked_site)
        assets = list(
            self._session.scalars(
                select(Asset).where(*conditions).order_by(Asset.quick_code, Asset.id)
            )
        )
        devices = self._monitoring.dashboard_devices(
            principal,
            period=period,
            category=checked_category,
            site_id=checked_site,
        )
        device_states = {item["assetId"]: item["status"] for item in devices["items"]}
        rows = sorted(
            [item for item in devices["items"] if item["monitored"] or _infrastructure(item)],
            key=lambda item: (
                _STATUS_RANK.get(item["status"], 3),
                0 if _infrastructure(item) else 1,
                -int(item.get("activeAlerts") or 0),
                str(item.get("quickCode") or ""),
            ),
        )[:MAX_ROWS]
        severity_counts = self._activation_counts(conditions)
        alerts = self._active_alerts(conditions)
        incidents, incident_total = self._incidents(conditions)
        today = self._now().date()
        maintenance = self._maintenance(conditions, today)
        warranties = self._warranties(conditions, today)
        distribution = [
            {
                "id": status,
                "label": {
                    "up": "En línea",
                    "degraded": "Degradado",
                    "down": "Fuera de línea",
                    "unmonitored": "Sin monitoreo",
                    "unknown": "Sin datos",
                }[status],
                "count": sum(1 for item in devices["items"] if item["status"] == status),
            }
            for status in ("up", "degraded", "down", "unmonitored", "unknown")
        ]
        counts = {item["id"]: item["count"] for item in distribution}
        unacknowledged = int(
            self._session.scalar(
                select(func.count())
                .select_from(MonitoringAlert)
                .join(Asset, Asset.id == MonitoringAlert.asset_id)
                .where(
                    MonitoringAlert.state.in_(ACTIVE_ALERT_STATES),
                    MonitoringAlert.acknowledged_at.is_(None),
                    *conditions,
                )
            )
            or 0
        )
        attention = [
            {
                "assetId": asset.id,
                "assetName": asset.name,
                "assetCode": asset.quick_code,
                "status": asset.status,
            }
            for asset in assets
            if asset.status in {"maintenance", "retired"}
        ][:MAX_ATTENTION]
        return {
            "generatedAt": _iso(self._now()),
            "period": period,
            "category": checked_category,
            "siteId": checked_site,
            "stats": {
                "total": len(assets),
                "monitored": sum(1 for item in devices["items"] if item["monitored"]),
                "up": counts["up"],
                "degraded": counts["degraded"],
                "down": counts["down"],
                "unmonitored": counts["unmonitored"],
                "unknown": counts["unknown"],
                "criticalAlerts": severity_counts["critical"],
                "unacknowledged": unacknowledged,
                "activeIncidents": incident_total,
            },
            "availability": devices["availability"],
            "latency": devices["latency"],
            "distribution": distribution,
            "severity": [
                {
                    "id": severity,
                    "label": {"critical": "Crítica", "warning": "Alta", "info": "Media"}[severity],
                    "count": severity_counts[severity],
                }
                for severity in _SEVERITIES
            ],
            "byCategory": self._breakdown(assets, "category", device_states),
            "bySite": self._breakdown(assets, "site_id", device_states),
            "activeAlerts": alerts,
            "incidents": incidents,
            "rows": rows,
            "activity": self._activity(conditions),
            "maintenance": maintenance,
            "warranties": warranties,
            "inventory": {
                "total": len(assets),
                "active": len(assets),
                "unassigned": sum(
                    1
                    for asset in assets
                    if not asset.responsible_person_id and not asset.responsible
                ),
                "attention": attention,
            },
        }


__all__ = ["DashboardService"]
