"""Phase 10 dashboard: canonical aggregates, real sources, bounded output.

The service test injects a duck-typed Prometheus boundary; everything else is
the real migrated database, real identity service and real domain services.
The router check uses the real app state only to prove authentication and
validation, not a frontend contract.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.dashboard.api import create_dashboard_router
from itsm.dashboard.service import DashboardService
from itsm.identity.api import install_error_handlers
from itsm.identity.service import IdentityService, ValidationFailed
from itsm.interventions.models import Incident
from itsm.inventory.models import Asset, AssetHistory
from itsm.main import create_app
from itsm.maintenance.models import MaintenancePlan
from itsm.monitoring.models import MonitorAsset, MonitoringAlert
from itsm.monitoring.service import MonitoringService
from itsm.workflows.models import Warranty
from sqlalchemy.orm import Session
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import Catalog, prepare, sign_in_as

NOW = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)
SITE_MAIN = "11111111-1111-4111-8111-111111111111"
SITE_NORTH = "22222222-2222-4222-8222-222222222222"


class FakePrometheus:
    """Window-aware uptime boundary; mirrors the real adapter's return shape."""

    def __init__(self, states: dict[str, dict[str, Any]]) -> None:
        self.states = states

    def current_states(self, assets: list[tuple[str, str]]) -> dict[str, dict[str, Any]]:
        return {
            asset_id: dict(self.states[asset_id])
            for asset_id, _ in assets
            if asset_id in self.states
        }

    def page_availability(self, assets: list[tuple[str, str]], window: Any) -> dict[str, Any]:
        values = {"24h": 99.5, "7d": 98.0, "30d": 97.0}
        return {
            asset_id: {"percent": values[window.preset], "samples": 100}
            for asset_id, _ in assets
            if asset_id in self.states
        }


def _add_asset(
    session: Session,
    *,
    quick_code: str,
    name: str,
    category: str,
    asset_type: str,
    site: str,
    site_id: str,
    ip: str | None,
    status: str = "in_use",
    archived: bool = False,
) -> Asset:
    asset = Asset(
        id=str(uuid4()),
        quick_code=quick_code,
        quick_code_key=quick_code.casefold(),
        name=name,
        category=category,
        type=asset_type,
        site=site,
        site_id=site_id,
        ip=ip,
        status=status,
        created_at=NOW,
        updated_at=NOW,
        archived_at=NOW if archived else None,
    )
    session.add(asset)
    return asset


def _build_dataset(catalog: Catalog) -> dict[str, Any]:
    identifiers: dict[str, Any] = {"up": [], "down": None, "degraded": None, "missing": None}
    with catalog.session() as session:
        for index in range(50):
            asset = _add_asset(
                session,
                quick_code=f"SW-MAT-{index:03d}",
                name=f"Switch Matriz {index:02d}",
                category="Red",
                asset_type="Switch",
                site="Matriz",
                site_id=SITE_MAIN,
                ip=f"10.10.0.{index + 10}",
            )
            identifiers["up"].append(asset.id)
        down = _add_asset(
            session,
            quick_code="SW-MAT-900",
            name="Switch caído",
            category="Red",
            asset_type="Switch",
            site="Matriz",
            site_id=SITE_MAIN,
            ip="10.10.9.1",
        )
        degraded = _add_asset(
            session,
            quick_code="GW-MAT-901",
            name="Gateway degradado",
            category="Red",
            asset_type="Gateway",
            site="Matriz",
            site_id=SITE_MAIN,
            ip="10.10.9.2",
        )
        missing = _add_asset(
            session,
            quick_code="SW-MAT-902",
            name="Switch sin objetivo",
            category="Red",
            asset_type="Switch",
            site="Matriz",
            site_id=SITE_MAIN,
            ip=None,
        )
        server = _add_asset(
            session,
            quick_code="SRV-NOR-001",
            name="Servidor Norte",
            category="Servidores",
            asset_type="Servidor",
            site="Norte",
            site_id=SITE_NORTH,
            ip="10.20.0.10:9100",
        )
        biometric = _add_asset(
            session,
            quick_code="BIO-MAT-001",
            name="Reloj Matriz",
            category="Reloj biométrico",
            asset_type="Reloj",
            site="Matriz",
            site_id=SITE_MAIN,
            ip="10.10.9.3",
        )
        workstation = _add_asset(
            session,
            quick_code="PC-MAT-001",
            name="Equipo de escritorio",
            category="Computadoras",
            asset_type="Workstation",
            site="Matriz",
            site_id=SITE_MAIN,
            ip="10.10.9.4",
        )
        attention = _add_asset(
            session,
            quick_code="SW-MAT-903",
            name="Switch en mantenimiento",
            category="Red",
            asset_type="Switch",
            site="Matriz",
            site_id=SITE_MAIN,
            ip="10.10.9.5",
            status="maintenance",
        )
        archived = _add_asset(
            session,
            quick_code="SW-OLD-001",
            name="Switch archivado",
            category="Red",
            asset_type="Switch",
            site="Matriz",
            site_id=SITE_MAIN,
            ip="10.10.9.6",
            archived=True,
        )
        session.add(
            MonitorAsset(
                asset_id=degraded.id,
                thresholds={"latency": {"warning": 1.0}},
            )
        )
        session.add(
            AssetHistory(
                id=str(uuid4()),
                sequence=1,
                asset_id=down.id,
                action="status_change",
                status_old="in_use",
                status_new="maintenance",
                changes={},
                reason="Revisión programada",
                source="internal",
                created_at=NOW,
            )
        )
        session.add(
            MaintenancePlan(
                id=str(uuid4()),
                asset_id=down.id,
                maintenance_type="preventive",
                interval_months=6,
                tasks=["Revisar puertos"],
                status="active",
                scheduled_on=NOW.date() + timedelta(days=5),
                due_on=NOW.date() + timedelta(days=5),
            )
        )
        session.add(
            Warranty(
                asset_id=degraded.id,
                payload={"expiresOn": (NOW.date() + timedelta(days=10)).isoformat()},
            )
        )
        session.add(
            Incident(
                id=str(uuid4()),
                description="Enlace principal intermitente",
                priority="high",
                status="open",
                primary_asset_id=down.id,
                opened_on=NOW.date(),
                revision=1,
                created_by=catalog.admin().actor_id,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.add(
            Incident(
                id=str(uuid4()),
                description="Incidencia cerrada",
                priority="normal",
                status="closed",
                primary_asset_id=down.id,
                opened_on=NOW.date() - timedelta(days=4),
                closed_at=NOW,
                revision=1,
                created_by=catalog.admin().actor_id,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        common = {
            "source": "prometheus",
            "labels": {},
            "annotations": {},
            "starts_at": NOW - timedelta(hours=1),
            "last_seen_at": NOW,
        }
        session.add(
            MonitoringAlert(
                id=str(uuid4()),
                fingerprint="critical-firing",
                alert_name="Enlace caído",
                severity="critical",
                asset_id=down.id,
                state="firing",
                summary="Sin respuesta",
                description="El enlace no responde",
                **common,
            )
        )
        session.add(
            MonitoringAlert(
                id=str(uuid4()),
                fingerprint="warning-acknowledged",
                alert_name="Latencia alta",
                severity="warning",
                asset_id=degraded.id,
                state="pending",
                acknowledged_at=NOW,
                acknowledged_by="ana.admin",
                **common,
            )
        )
        session.add(
            MonitoringAlert(
                id=str(uuid4()),
                fingerprint="critical-resolved",
                alert_name="Enlace recuperado",
                severity="critical",
                asset_id=down.id,
                state="resolved",
                ends_at=NOW,
                **common,
            )
        )
        session.commit()
        identifiers.update(
            down=down.id,
            degraded=degraded.id,
            missing=missing.id,
            server=server.id,
            biometric=biometric.id,
            workstation=workstation.id,
            attention=attention.id,
            archived=archived.id,
        )
    identifiers["states"] = {}
    for asset_id in identifiers["up"]:
        identifiers["states"][asset_id] = {
            "success": 1.0,
            "latency": 0.01,
            "at": "2026-10-23T09:59:00Z",
        }
    identifiers["states"][identifiers["down"]] = {
        "success": 0.0,
        "latency": 0.5,
        "at": "2026-10-23T09:59:00Z",
    }
    identifiers["states"][identifiers["degraded"]] = {
        "success": 1.0,
        "latency": 2.0,
        "at": "2026-10-23T09:59:00Z",
    }
    identifiers["states"][identifiers["server"]] = {
        "success": 1.0,
        "latency": 0.5,
        "at": "2026-10-23T09:58:00Z",
    }
    identifiers["states"][identifiers["biometric"]] = {
        "success": 1.0,
        "latency": 0.01,
        "at": "2026-10-23T09:57:00Z",
    }
    identifiers["states"][identifiers["attention"]] = {
        "success": 1.0,
        "latency": 0.01,
        "at": "2026-10-23T09:57:00Z",
    }
    return identifiers


@pytest.fixture
def catalog(settings_factory: Any) -> Catalog:
    return prepare(settings_factory, prometheus_url="http://prometheus.test:9090")


def _summary(catalog: Catalog, fake: FakePrometheus) -> dict[str, Any]:
    with catalog.session() as session:
        identity = IdentityService(session, catalog.settings)
        monitoring = MonitoringService(
            session,
            catalog.settings,
            identity=identity,
            adapter=fake,
            now=lambda: NOW,
        )
        service = DashboardService(
            session,
            identity,
            catalog.settings,
            monitoring=monitoring,
            now=lambda: NOW,
        )
        return service.summary(catalog.admin(), period="24h")


def test_summary_aggregates_every_module_from_canonical_sources(catalog: Catalog) -> None:
    dataset = _build_dataset(catalog)
    summary = _summary(catalog, FakePrometheus(dataset["states"]))

    assert set(summary) == {
        "generatedAt",
        "period",
        "category",
        "siteId",
        "stats",
        "availability",
        "latency",
        "distribution",
        "severity",
        "byCategory",
        "bySite",
        "activeAlerts",
        "incidents",
        "rows",
        "activity",
        "maintenance",
        "warranties",
        "inventory",
    }
    assert summary["period"] == "24h"
    stats = summary["stats"]
    assert stats["total"] == 57
    assert stats["monitored"] == 55
    assert stats["up"] == 53
    assert stats["degraded"] == 1
    assert stats["down"] == 1
    assert stats["unknown"] == 1
    assert stats["unmonitored"] == 1
    assert stats["criticalAlerts"] == 1
    assert stats["unacknowledged"] == 1
    assert stats["activeIncidents"] == 1

    assert summary["availability"]["current"] == 99.5
    assert summary["availability"]["configured"] is True
    assert [sample["label"] for sample in summary["availability"]["samples"]] == [
        "24h",
        "7d",
        "30d",
    ]
    assert [sample["value"] for sample in summary["availability"]["samples"]] == [
        99.5,
        98.0,
        97.0,
    ]
    assert summary["availability"]["samplesCount"] > 0
    assert summary["availability"]["lastCheckAt"] == "2026-10-23T09:59:00Z"
    assert summary["latency"]["current"] is not None

    distribution = {item["id"]: item["count"] for item in summary["distribution"]}
    assert distribution == {
        "up": 53,
        "degraded": 1,
        "down": 1,
        "unmonitored": 1,
        "unknown": 1,
    }
    severity = {item["id"]: item["count"] for item in summary["severity"]}
    assert severity == {"critical": 1, "warning": 1, "info": 0}

    assert summary["rows"][0]["assetId"] == dataset["down"]
    assert summary["rows"][0]["status"] == "down"
    assert len(summary["rows"]) == 50
    assert all(row["assetId"] != dataset["archived"] for row in summary["rows"])
    assert all(row["assetId"] != dataset["workstation"] for row in summary["rows"])

    assert summary["activeAlerts"][0]["severity"] == "critical"
    assert summary["activeAlerts"][0]["target"] == {
        "kind": "alert",
        "id": summary["activeAlerts"][0]["id"],
    }
    assert len(summary["activeAlerts"]) == 2
    assert summary["incidents"][0]["id"]
    assert summary["incidents"][0]["target"]["kind"] == "incident"
    assert summary["maintenance"][0]["assetId"] == dataset["down"]
    assert summary["maintenance"][0]["statusTone"] == "warn"
    assert summary["warranties"][0]["assetId"] == dataset["degraded"]
    assert summary["warranties"][0]["days"] == 10
    assert summary["inventory"] == {
        "total": 57,
        "active": 57,
        "unassigned": 57,
        "attention": [
            {
                "assetId": dataset["attention"],
                "assetName": "Switch en mantenimiento",
                "assetCode": "SW-MAT-903",
                "status": "maintenance",
            }
        ],
    }
    assert any(item["assetId"] == dataset["down"] for item in summary["activity"])
    category = next(item for item in summary["byCategory"] if item["id"] == "Red")
    assert category["total"] == 54
    assert category["up"] == 51
    assert category["degraded"] == 1
    assert category["down"] == 1
    assert category["other"] == 1
    site = next(item for item in summary["bySite"] if item["id"] == SITE_MAIN)
    assert site["total"] == 56
    assert site["up"] == 52
    assert site["degraded"] == 1
    assert site["down"] == 1
    assert site["other"] == 2


def test_summary_scopes_filters_and_never_fabricates_page_totals(catalog: Catalog) -> None:
    dataset = _build_dataset(catalog)
    with catalog.session() as session:
        identity = IdentityService(session, catalog.settings)
        monitoring = MonitoringService(
            session,
            catalog.settings,
            identity=identity,
            adapter=FakePrometheus(dataset["states"]),
            now=lambda: NOW,
        )
        service = DashboardService(
            session,
            identity,
            catalog.settings,
            monitoring=monitoring,
            now=lambda: NOW,
        )
        scoped = service.summary(
            catalog.admin(), period="7d", category="Servidores", site_id=SITE_NORTH
        )
        assert scoped["stats"]["total"] == 1
        assert scoped["stats"]["up"] == 1
        assert [row["assetId"] for row in scoped["rows"]] == [dataset["server"]]
        assert [item["label"] for item in scoped["availability"]["samples"]] == [
            "24h",
            "7d",
            "30d",
        ]
        assert scoped["incidents"] == []
        assert scoped["maintenance"] == []
        assert scoped["warranties"] == []

        with pytest.raises(ValidationFailed):
            service.summary(catalog.admin(), period="1h")
        with pytest.raises(ValidationFailed):
            service.summary(catalog.admin(), site_id="not-a-uuid")


def test_unconfigured_prometheus_reports_unknown_without_inventing_outages(
    settings_factory: Any,
) -> None:
    catalog = prepare(settings_factory)
    dataset = _build_dataset(catalog)
    with catalog.session() as session:
        identity = IdentityService(session, catalog.settings)
        service = DashboardService(session, identity, catalog.settings, now=lambda: NOW)
        summary = service.summary(catalog.admin())
        assert summary["availability"]["configured"] is False
        assert summary["availability"]["current"] is None
        assert all(sample["value"] is None for sample in summary["availability"]["samples"])
        assert summary["stats"]["down"] == 0
        assert summary["stats"]["unknown"] == 56
        assert summary["stats"]["unmonitored"] == 1
        assert dataset["down"] not in [
            row["assetId"] for row in summary["rows"] if row["status"] == "down"
        ]


@contextmanager
def _router_client(settings: Settings, catalog: Catalog) -> Iterator[TestClient]:
    app = FastAPI()
    install_error_handlers(app)
    app.state.settings = settings
    app.state.session_factory = catalog.factory()
    app.include_router(create_dashboard_router(), prefix=settings.api_prefix)
    with TestClient(app) as client:
        yield client


def test_dashboard_router_requires_session_and_validates_period(catalog: Catalog) -> None:
    with _router_client(catalog.settings, catalog) as anonymous:
        assert anonymous.get("/api/v1/dashboard").status_code == 401

    with TestClient(create_app(catalog.settings)) as main:
        headers = sign_in_as(main, catalog.settings, ADMIN_USERNAME, ADMIN_PASSWORD)
        cookie = main.cookies.get(catalog.settings.auth_cookie_name)
    assert cookie
    with _router_client(catalog.settings, catalog) as client:
        client.cookies.set(catalog.settings.auth_cookie_name, str(cookie))
        invalid = client.get("/api/v1/dashboard?period=1h")
        assert invalid.status_code == 422, invalid.text
        assert invalid.json()["error"]["code"] == "validation_error"
        # The mutation origin/CSRF guard is covered by workspace tests; this GET
        # proves the authenticated route resolves the canonical service.
        assert headers["Origin"] == catalog.settings.auth_origin
