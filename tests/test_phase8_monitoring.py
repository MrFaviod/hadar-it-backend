"""Focused Phase 8 monitoring coverage: real SQL, real ASGI, real HTTP stubs.

Every test uses the public service, the real error envelope, a migrated SQLite
database and, where HTTP matters, a real local HTTP server. Monitoring reads are
asserted to never materialize configuration rows or write operational events.
"""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.identity.api import create_identity_router, install_error_handlers
from itsm.identity.service import PermissionDenied, ValidationFailed
from itsm.inventory.models import Asset
from itsm.inventory.service import InventoryService
from itsm.monitoring.api import create_monitoring_router
from itsm.monitoring.models import (
    MonitorAsset,
    MonitoringAlert,
    MonitoringAlertEvent,
    MonitorProfile,
)
from itsm.monitoring.projection import summarize_device
from itsm.monitoring.prometheus import (
    MonitoringUnavailable,
    PrometheusAdapter,
    metric_expression,
    range_window,
)
from itsm.monitoring.service import MonitoringService
from pydantic import SecretStr
from sqlalchemy import func, inspect, select
from tests.conftest import BACKEND_ROOT, run_cli, sign_in
from tests.inventory_support import OPERATOR, READER, Catalog, prepare

NOW = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)
DELIVERY_NOW = "itsm_monitoring_check_enabled"


class Clock:
    def __init__(self, value: datetime = NOW):
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, **kwargs: Any) -> datetime:
        self.value += timedelta(**kwargs)
        return self.value


class FakeAdapter:
    """Duck-typed boundary for service tests; real HTTP is exercised separately."""

    def __init__(self) -> None:
        self.fail = False
        self.silence_fail = False
        self.states: dict[str, dict[str, Any]] = {}
        self.uptimes: dict[str, dict[str, Any]] = {}
        self.availabilities: dict[str, dict[str, Any]] = {}
        self.latencies: dict[str, dict[str, Any]] = {}
        self.series: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self.alerts_data: list[dict[str, Any]] = []
        self.created_silences: list[dict[str, Any]] = []
        self.deleted_silences: list[str] = []
        self.silences_data: list[dict[str, Any]] = []

    def _guard(self) -> None:
        if self.fail:
            raise MonitoringUnavailable("source unavailable")

    def current_states(self, assets: list[tuple[str, str]]) -> dict[str, dict[str, Any]]:
        self._guard()
        return {
            asset_id: dict(self.states[asset_id])
            for asset_id, _ in assets
            if asset_id in self.states
        }

    def page_availability(
        self, assets: list[tuple[str, str]], window: Any
    ) -> dict[str, dict[str, Any]]:
        self._guard()
        return {
            asset_id: dict(self.uptimes[asset_id])
            for asset_id, _ in assets
            if asset_id in self.uptimes
        }

    def availability(self, asset_id: str, check_type: str, window: Any) -> dict[str, Any]:
        self._guard()
        return self.availabilities.get(asset_id, {"percent": None, "samples": 0})

    def latency(self, asset_id: str, check_type: str, window: Any) -> dict[str, Any]:
        self._guard()
        return self.latencies.get(asset_id, {"averageMs": None, "p95Ms": None, "currentMs": None})

    def metric_series(
        self, asset_id: str, check_type: str, metric: str, window: Any
    ) -> list[dict[str, Any]] | None:
        self._guard()
        return self.series.get((asset_id, metric))

    def alerts(self) -> list[dict[str, Any]]:
        self._guard()
        return list(self.alerts_data)

    def create_silence(self, **kwargs: Any) -> str:
        if self.fail or self.silence_fail:
            raise MonitoringUnavailable("alertmanager unavailable")
        silence_id = f"am-{len(self.created_silences) + 1}"
        self.created_silences.append({"id": silence_id, **kwargs})
        return silence_id

    def delete_silence(self, silence_id: str) -> None:
        self._guard()
        self.deleted_silences.append(silence_id)

    def silences(self) -> list[dict[str, Any]]:
        self._guard()
        return list(self.silences_data)


@dataclass
class MonitoringHarness:
    catalog: Catalog
    clock: Clock
    adapter: FakeAdapter
    notifier_calls: list[dict[str, Any]] = field(default_factory=list)
    counter: int = 0

    @property
    def settings(self) -> Settings:
        return self.catalog.settings

    @property
    def admin(self):
        return self.catalog.admin()

    @property
    def operator(self):
        return self.catalog.principal(OPERATOR[0])

    @property
    def reader(self):
        return self.catalog.principal(READER[0])

    @classmethod
    def build(cls, settings_factory) -> MonitoringHarness:
        catalog = prepare(settings_factory, prometheus_url="http://prometheus.test:9090")
        catalog.add_user(*READER)
        catalog.add_user(*OPERATOR)
        return cls(catalog=catalog, clock=Clock(), adapter=FakeAdapter())

    def service(
        self,
        session,
        *,
        adapter: FakeAdapter | None = None,
        notifier: bool = True,
        source: str = "rest",
    ) -> MonitoringService:
        return MonitoringService(
            session,
            self.settings,
            source=source,
            adapter=adapter or self.adapter,
            notifier=self.record if notifier else None,
            now=self.clock,
        )

    def record(self, session, settings, **kwargs: Any) -> None:
        self.notifier_calls.append(kwargs)

    def add_asset(
        self,
        name: str = "Server",
        *,
        category: str = "servidores",
        ip: str | None = "10.0.0.5",
        type: str | None = None,
        site: str | None = None,
    ) -> str:
        self.counter += 1
        asset_id = str(uuid4())
        with self.catalog.session() as session:
            session.add(
                Asset(
                    id=asset_id,
                    quick_code=f"TST-{self.counter:04d}",
                    quick_code_key=f"tst-{self.counter:04d}",
                    name=name,
                    category=category,
                    type=type,
                    ip=ip,
                    site=site,
                    status="in_use",
                    created_at=NOW,
                    updated_at=NOW,
                )
            )
            session.commit()
        return asset_id

    def scalar(self, statement) -> Any:
        with self.catalog.session() as session:
            return session.scalar(statement)

    def count(self, model) -> int:
        return int(self.scalar(select(func.count()).select_from(model)) or 0)


@pytest.fixture
def harness(settings_factory) -> MonitoringHarness:
    return MonitoringHarness.build(settings_factory)


def monitoring_app(harness: MonitoringHarness) -> FastAPI:
    """Standalone app: identity plus monitoring routes under the real prefix."""
    app = FastAPI()
    install_error_handlers(app)
    app.state.settings = harness.settings
    app.state.session_factory = harness.catalog.factory()
    api = APIRouter(prefix=harness.settings.api_prefix)
    api.include_router(create_identity_router())
    api.include_router(create_monitoring_router())
    app.include_router(api)
    return app


def test_monitoring_schema_migrates_and_round_trips(harness: MonitoringHarness) -> None:
    with harness.catalog.engine.connect() as connection:
        names = set(inspect(connection).get_table_names())
    assert {
        "monitor_exporters",
        "monitor_profiles",
        "monitor_assets",
        "monitoring_alerts",
        "monitoring_alert_events",
        "monitoring_silences",
        "maintenance_windows",
    } <= names
    current = run_cli(
        ["-m", "alembic", "-c", str(BACKEND_ROOT / "alembic.ini"), "current"],
        harness.settings,
    )
    assert current.returncode == 0, current.stderr

    for args in (
        ["downgrade", "0015_maintenance_reminders"],
        ["upgrade", "head"],
    ):
        result = run_cli(
            ["-m", "alembic", "-c", str(BACKEND_ROOT / "alembic.ini"), *args],
            harness.settings,
        )
        assert result.returncode == 0, result.stderr
    with harness.catalog.engine.connect() as connection:
        names = set(inspect(connection).get_table_names())
    assert "monitoring_alerts" in names


def test_default_profiles_prioritize_infrastructure_without_materializing(
    harness: MonitoringHarness,
) -> None:
    switch = harness.add_asset("Core switch", category="switches", ip="10.0.0.1")
    laptop = harness.add_asset("Notebook", category="notebooks", ip="10.0.0.2")
    assert switch and laptop
    with harness.catalog.session() as session:
        config = harness.service(session).get_config(harness.admin)
    profiles = {profile["category"]: profile for profile in config["profiles"]}
    assert profiles["switches"]["enabled"] is True
    assert profiles["switches"]["checkType"] == "snmp"
    assert profiles["notebooks"]["enabled"] is False
    assert profiles["notebooks"]["checkType"] == "icmp"
    assert config["presets"]["minimumDurations"] == [0, 60, 300, 900]
    assert config["presets"]["intervals"] == [30, 60, 300, 900]
    assert {item["id"] for item in config["presets"]["metrics"]} == {
        "latency",
        "cpu",
        "memory",
        "disk",
        "temperature",
    }
    assert harness.count(MonitorProfile) == 0
    assert harness.count(MonitorAsset) == 0


def test_asset_override_inheritance_clearing_and_validation(
    harness: MonitoringHarness,
) -> None:
    asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9")
    with harness.catalog.session() as session:
        service = harness.service(session)
        disabled = service.update_asset(harness.admin, asset, {"enabled": False})
        assert disabled["config"]["overridden"] == ["enabled"]
        assert service.get_device(harness.admin, asset)["status"] == "unmonitored"

        service.update_asset(harness.admin, asset, {"enabled": None, "target": "10.0.0.9:9100"})
        detail = service.get_device(harness.admin, asset)
        assert detail["config"]["targetPresent"] is True
        assert detail["config"]["checkType"] == "node"
        assert "enabled" not in detail["config"]["overridden"]

        service.update_asset(harness.admin, asset, {"target": None})
    assert harness.count(MonitorAsset) == 0

    invalid = (
        {"intervalSeconds": 45},
        {"minimumDurationSeconds": 120},
        {"miniumDurationSeconds": 60},
        {"target": "http://user:secret@example.test"},
        {"thresholds": {"cpu": {"warning": 90, "critical": 80}}},
    )
    for values in invalid:
        with harness.catalog.session() as session, pytest.raises(ValidationFailed):
            harness.service(session).update_asset(harness.admin, asset, values)
    assert harness.count(MonitorAsset) == 0


def test_profile_update_requires_config_categories_and_changes_defaults(
    harness: MonitoringHarness,
) -> None:
    asset = harness.add_asset("Switch", category="switches", ip="10.0.0.1")
    with harness.catalog.session() as session:
        service = harness.service(session)
        with pytest.raises(PermissionDenied):
            service.update_profile(harness.operator, "switches", {"enabled": False})
        profile = service.update_profile(
            harness.admin,
            "switches",
            {
                "enabled": True,
                "checkType": "icmp",
                "intervalSeconds": 300,
                "minimumDurationSeconds": 0,
                "metrics": ["latency"],
                "thresholds": {"latency": {"warning": 0.2, "critical": 1.0}},
            },
        )
        assert profile["checkType"] == "icmp"
        detail = service.get_device(harness.admin, asset)
        assert detail["config"]["checkType"] == "icmp"
        assert detail["config"]["intervalSeconds"] == 300
        assert detail["config"]["minimumDurationSeconds"] == 0
        assert harness.count(MonitorProfile) == 1
    audit = harness.catalog.audit("monitoring.profile_updated")
    assert audit and audit[-1]["outcome"] == "success"


def test_readers_and_operators_are_denied_without_mutation(
    harness: MonitoringHarness,
) -> None:
    asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9")
    with harness.catalog.session() as session:
        service = harness.service(session)
        with pytest.raises(PermissionDenied):
            service.update_asset(harness.reader, asset, {"enabled": False})
        with pytest.raises(PermissionDenied):
            service.save_exporter(
                harness.operator,
                {"name": "blackbox", "kind": "blackbox", "module": "http_2xx"},
            )
    assert harness.count(MonitorAsset) == 0
    denied = [row for row in harness.catalog.audit() if row["outcome"] == "denied"]
    assert denied


def test_device_states_and_provenance(harness: MonitoringHarness) -> None:
    asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9:9100")
    harness.adapter.states[asset] = {
        "success": None,
        "up": 1.0,
        "latency": 0.02,
        "at": "2026-10-23T10:00:00Z",
    }
    harness.adapter.uptimes[asset] = {"percent": 99.5, "samples": 288}
    harness.adapter.availabilities[asset] = {
        "percent": 99.5,
        "samples": 288,
        "from": "2026-10-22T10:00:00Z",
        "to": "2026-10-23T10:00:00Z",
    }
    harness.adapter.latencies[asset] = {
        "averageMs": 20.0,
        "p95Ms": 35.0,
        "currentMs": 20.0,
    }
    harness.adapter.series[(asset, "cpu")] = [{"at": "2026-10-23T09:55:00Z", "value": 42.0}]
    with harness.catalog.session() as session:
        service = harness.service(session)
        detail = service.get_device(harness.admin, asset)
        assert detail["status"] == "up"
        assert detail["reason"] is None
        assert detail["uptime"]["percent"] == 99.5
        assert detail["latency"]["p95Ms"] == 35.0
        assert detail["checks"][0]["lastCheckAt"] == "2026-10-23T10:00:00Z"
        assert detail["series"][0]["metric"] == "cpu"
        assert detail["provenance"]["period"]["stepSeconds"] >= 60
        assert detail["provenance"]["source"] == "prometheus"

        service.update_asset(
            harness.admin,
            asset,
            {"thresholds": {"cpu": {"warning": 40, "critical": 90}}},
        )
        degraded = service.get_device(harness.admin, asset)
        assert degraded["status"] == "degraded"
        assert degraded["severity"] == "warning"
        harness.adapter.states[asset]["up"] = 0.0
        down = service.get_device(harness.admin, asset)
        assert down["status"] == "down"

        harness.adapter.states[asset]["up"] = None
        harness.adapter.states[asset]["success"] = None
        no_data = service.get_device(harness.admin, asset)
        assert no_data["status"] == "no_data"
        assert no_data["reason"] is None

        harness.adapter.fail = True
        unavailable = service.get_device(harness.admin, asset)
        assert unavailable["status"] == "unavailable"
        assert unavailable["reason"] == "prometheus_unavailable"
        assert unavailable["series"] == []

        listed = service.list_devices(harness.admin, period="24h")
        item = next(row for row in listed["items"] if row["assetId"] == asset)
        assert item["status"] == "unavailable"
        assert item["uptime"] == {"percent": None, "samples": 0}


def test_unconfigured_prometheus_and_missing_target_never_invent_failures(
    settings_factory,
) -> None:
    catalog = prepare(settings_factory)
    harness = MonitoringHarness(catalog=catalog, clock=Clock(), adapter=FakeAdapter())
    harness.catalog.add_user(*READER)
    harness.catalog.add_user(*OPERATOR)
    server = harness.add_asset("Server", category="servidores", ip="10.0.0.9:9100")
    orphan = harness.add_asset("No target", category="servidores", ip=None)
    with harness.catalog.session() as session:
        service = harness.service(session)
        detail = service.get_device(harness.admin, server)
        assert detail["status"] == "unavailable"
        assert detail["reason"] == "prometheus_not_configured"
        missing = service.get_device(harness.admin, orphan)
        assert missing["status"] == "no_data"
        assert missing["reason"] == "target_missing"
    assert harness.count(MonitoringAlert) == 0
    assert harness.count(MonitoringAlertEvent) == 0


def test_real_prometheus_adapter_is_bounded_and_authenticated() -> None:
    with stub_server() as stub:
        asset = str(uuid4())

        def vector(query: str) -> tuple[int, Any, str]:
            return (
                200,
                {
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [
                            {
                                "metric": {"asset_id": asset},
                                "value": [1792759200.0, "1"],
                            }
                        ],
                    },
                },
                "application/json",
            )

        def matrix(query: str) -> tuple[int, Any, str]:
            values = [[1792759200.0 + index * 60, str(index)] for index in range(1000)]
            return (
                200,
                {
                    "status": "success",
                    "data": {
                        "resultType": "matrix",
                        "result": [{"metric": {"asset_id": asset}, "values": values}],
                    },
                },
                "application/json",
            )

        stub.routes[("GET", "/api/v1/query")] = vector
        stub.routes[("GET", "/api/v1/query_range")] = matrix
        settings = Settings(
            _env_file=None,
            environment="test",
            database_url="sqlite://",
            prometheus_url=stub.base_url,
            prometheus_token=SecretStr("prom-token"),
        )
        adapter = PrometheusAdapter(settings)
        window = range_window("24h", now=NOW)
        states = adapter.current_states([(asset, "node")])
        assert states[asset]["up"] == 1.0
        assert states[asset]["at"].endswith("Z")
        points = adapter.metric_series(asset, "node", "cpu", window)
        assert points is not None and 0 < len(points) <= 300
        request = stub.requests[-1]
        assert request["headers"]["authorization"] == "Bearer prom-token"
        assert asset in request["query"]["query"][0]
        assert "[" in request["query"]["query"][0]

        stub.routes[("GET", "/api/v1/query")] = lambda query: (
            500,
            {"status": "error"},
            "application/json",
        )
        with pytest.raises(MonitoringUnavailable):
            adapter.current_states([(asset, "node")])

        stub.routes[("GET", "/api/v1/query")] = lambda query: (
            302,
            {},
            "text/plain",
        )
        with pytest.raises(MonitoringUnavailable):
            adapter.current_states([(asset, "node")])


def test_uptime_is_check_type_scoped_and_sample_weighted(
    harness: MonitoringHarness,
) -> None:
    asset = harness.add_asset("Node", category="servidores", ip="10.0.0.9:9100")
    with stub_server() as stub:
        queries: list[str] = []

        def vector(raw: str) -> tuple[int, Any, str]:
            expression = parse_qs(raw)["query"][0]
            queries.append(expression)
            if "sum_over_time" in expression:
                value = "73.214"
            elif "count_over_time" in expression:
                value = "131"
            else:
                value = "1"
            return (
                200,
                {
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [
                            {
                                "metric": {"asset_id": asset},
                                "value": [1792759200.0, value],
                            }
                        ],
                    },
                },
                "application/json",
            )

        def matrix(raw: str) -> tuple[int, Any, str]:
            return (
                200,
                {
                    "status": "success",
                    "data": {"resultType": "matrix", "result": []},
                },
                "application/json",
            )

        stub.routes[("GET", "/api/v1/query")] = vector
        stub.routes[("GET", "/api/v1/query_range")] = matrix
        settings = Settings(
            _env_file=None,
            environment="test",
            database_url=harness.settings.database_url,
            prometheus_url=stub.base_url,
        )
        adapter = PrometheusAdapter(settings)
        with harness.catalog.session() as session:
            service = harness.service(session, adapter=adapter)  # type: ignore[arg-type]
            detail = service.get_device(harness.admin, asset)
            listed = service.list_devices(harness.admin, period="24h")

    item = next(row for row in listed["items"] if row["assetId"] == asset)
    expected = {"percent": 73.214, "samples": 131}
    assert detail["uptime"] == expected
    assert item["uptime"] == expected
    assert item["status"] == "up"

    uptime_queries = [
        expression
        for expression in queries
        if "sum_over_time" in expression or "count_over_time" in expression
    ]
    assert uptime_queries
    for expression in uptime_queries:
        assert f'asset_id="{asset}"' in expression
        assert 'check_type="node"' in expression
        assert "sum by (asset_id)" in expression
    assert any(
        "sum_over_time" in expression and " / " in expression for expression in uptime_queries
    )
    assert all("avg_over_time(up" not in expression for expression in queries)
    for expression in queries:
        if "up{" in expression:
            assert 'check_type="node"' in expression


def test_alertmanager_silence_adapter_contract() -> None:
    with stub_server() as stub:
        created: list[dict[str, Any]] = []

        def create(query: str) -> tuple[int, Any, str]:
            created.append(json.loads(stub.last_body))
            return 200, {"silenceID": "native-1"}, "application/json"

        stub.routes[("POST", "/api/v2/silences")] = create
        stub.routes[("DELETE", "/api/v2/silence/native-1")] = lambda query: (
            200,
            {},
            "application/json",
        )
        settings = Settings(
            _env_file=None,
            environment="test",
            database_url="sqlite://",
            alertmanager_url=stub.base_url,
            alertmanager_token=SecretStr("am-token"),
        )
        adapter = PrometheusAdapter(settings)
        silence_id = adapter.create_silence(
            matchers=[
                {
                    "name": "asset_id",
                    "value": str(uuid4()),
                    "isRegex": False,
                    "isEqual": True,
                }
            ],
            starts_at=NOW,
            ends_at=NOW + timedelta(hours=1),
            comment="maintenance",
            created_by="itsm-test",
        )
        assert silence_id == "native-1"
        assert created[0]["comment"] == "maintenance"
        assert created[0]["matchers"][0]["name"] == "asset_id"
        assert stub.requests[-1]["headers"]["authorization"] == "Bearer am-token"
        adapter.delete_silence("native-1")
        with pytest.raises(MonitoringUnavailable):
            adapter.delete_silence("../../etc/passwd")
        with pytest.raises(MonitoringUnavailable):
            adapter.create_silence(
                matchers=[],
                starts_at=NOW + timedelta(hours=1),
                ends_at=NOW,
                comment="backwards",
                created_by="itsm-test",
            )


def test_device_list_uptime_is_batched_and_unmonitored_is_never_offline(
    harness: MonitoringHarness,
) -> None:
    server = harness.add_asset("Server", category="servidores", ip="10.0.0.9:9100")
    laptop = harness.add_asset("Laptop", category="notebooks", ip="10.0.0.10")
    harness.adapter.states[server] = {"up": 1.0, "latency": 0.01, "at": "2026-10-23T10:00:00Z"}
    harness.adapter.uptimes[server] = {"percent": 99.0, "samples": 1440}
    with harness.catalog.session() as session:
        payload = harness.service(session).list_devices(harness.admin, period="7d")
    by_id = {item["assetId"]: item for item in payload["items"]}
    assert by_id[server]["status"] == "up"
    assert by_id[server]["uptime"] == {"percent": 99.0, "samples": 1440}
    assert by_id[laptop]["status"] == "unmonitored"
    assert by_id[laptop]["uptime"] == {"percent": None, "samples": 0}
    assert payload["period"] == "7d"


def test_discovery_labels_purge_and_alert_readability(harness: MonitoringHarness) -> None:
    switch = harness.add_asset("Core switch", category="switches", ip="10.0.0.1")
    laptop = harness.add_asset("Laptop", category="notebooks", ip="10.0.0.2")
    with harness.catalog.session() as session:
        service = harness.service(session)
        entries = service.discovery("snmp")
        assert len(entries) == 1
        assert entries[0]["targets"] == ["10.0.0.1"]
        labels = entries[0]["labels"]
        assert labels["asset_id"] == switch
        assert labels["check_type"] == "snmp"
        assert labels["module"] == "if_mib"
        assert labels["interval_seconds"] == "60"
        assert all(entry["labels"]["asset_id"] != laptop for entry in service.discovery("icmp"))

        exporter = service.save_exporter(
            harness.admin,
            {
                "name": "snmp-prod",
                "kind": "snmp",
                "module": "if_mib",
                "address": "snmp-exporter:9116",
            },
        )
        service.update_asset(harness.admin, switch, {"exporterId": exporter["id"]})
        assert service.discovery("snmp")[0]["labels"]["exporter_address"] == "snmp-exporter:9116"
        service.save_exporter(
            harness.admin,
            {
                "id": exporter["id"],
                "name": "snmp-prod",
                "kind": "snmp",
                "module": "if_mib",
                "address": "snmp-exporter:9116",
                "enabled": False,
            },
        )
        assert service.discovery("snmp") == []

        ingested = service.ingest_alertmanager(am_payload(switch, alert_name="SnmpDown"))
        assert ingested["created"] == 1
        alert = service.list_alerts(harness.admin)["items"][0]
        InventoryService(session, harness.settings).purge(harness.admin, switch, confirm=True)
        remaining = service.list_alerts(harness.admin)
        assert remaining["total"] == 1
        readable = service.get_alert(harness.admin, alert["id"])
        assert readable["assetName"] is None
        assert readable["state"] == "firing"
        assert service.discovery("snmp") == []


def test_config_gauges_expose_effective_enabled_values_only(
    harness: MonitoringHarness,
) -> None:
    server = harness.add_asset("Server", category="servidores", ip="10.0.0.9")
    laptop = harness.add_asset("Laptop", category="notebooks", ip="10.0.0.10")
    with harness.catalog.session() as session:
        service = harness.service(session)
        service.update_asset(
            harness.admin,
            server,
            {
                "target": "10.0.0.9:9100",
                "thresholds": {
                    "cpu": {"warning": 70, "critical": 90},
                    "temperature": {"warning": 70, "critical": 85},
                },
            },
        )
        body = service.config_metrics()
    assert f'itsm_monitoring_check_enabled{{asset_id="{server}",check_type="node"}} 1' in body
    assert f'itsm_monitoring_check_duration_preset_seconds{{asset_id="{server}"}} 300' in body
    assert (
        f'itsm_monitoring_check_threshold{{asset_id="{server}",metric="cpu",severity="warning"}} 70'
    ) in body
    assert f'itsm_monitoring_check_threshold{{asset_id="{server}",metric="temperature",' in body
    assert f'itsm_monitoring_check_interval_seconds{{asset_id="{server}"}} 60' in body
    assert laptop not in body
    assert "# TYPE itsm_monitoring_check_enabled gauge" in body
    assert harness.settings.prometheus_url not in body


def test_machine_routes_require_dedicated_tokens(settings_factory) -> None:
    catalog = prepare(
        settings_factory,
        prometheus_url="http://prometheus.test:9090",
        monitoring_discovery_token="discovery-secret",
        monitoring_ingest_token="ingest-secret",
    )
    harness = MonitoringHarness(catalog=catalog, clock=Clock(), adapter=FakeAdapter())
    harness.add_asset("Core switch", category="switches", ip="10.0.0.1")
    app = monitoring_app(harness)
    with TestClient(app) as client:
        missing = client.get("/api/v1/monitoring/discovery?check_type=snmp")
        assert missing.status_code == 401
        wrong = client.get(
            "/api/v1/monitoring/discovery?check_type=snmp",
            headers={"Authorization": "Bearer nope"},
        )
        assert wrong.status_code == 401
        accepted = client.get(
            "/api/v1/monitoring/discovery?check_type=snmp",
            headers={"Authorization": "Bearer discovery-secret"},
        )
        assert accepted.status_code == 200
        assert accepted.json()[0]["labels"]["check_type"] == "snmp"
        invalid = client.get(
            "/api/v1/monitoring/discovery?check_type=shell",
            headers={"Authorization": "Bearer discovery-secret"},
        )
        assert invalid.status_code == 400
        metrics = client.get(
            "/api/v1/monitoring/prometheus-metrics",
            headers={"Authorization": "Bearer discovery-secret"},
        )
        assert metrics.status_code == 200
        assert metrics.headers["content-type"].startswith("text/plain")
        assert "itsm_monitoring_check_enabled" in metrics.text
        webhook = client.post(
            "/api/v1/monitoring/alertmanager",
            json=am_payload("00000000-0000-0000-0000-000000000000"),
        )
        assert webhook.status_code == 401
        wrong_ingest = client.post(
            "/api/v1/monitoring/alertmanager",
            json=am_payload("00000000-0000-0000-0000-000000000000"),
            headers={"Authorization": "Bearer discovery-secret"},
        )
        assert wrong_ingest.status_code == 401

    unset = MonitoringHarness.build(settings_factory)
    with TestClient(monitoring_app(unset)) as client:
        assert client.get("/api/v1/monitoring/prometheus-metrics").status_code == 503


def test_human_routes_use_session_csrf_and_bounded_lists(harness: MonitoringHarness) -> None:
    asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9")
    app = monitoring_app(harness)
    with TestClient(app) as client:
        unauth = client.get("/api/v1/monitoring/devices")
        assert unauth.status_code == 401
        headers = sign_in(client, harness.settings)
        config = client.get("/api/v1/monitoring/config")
        assert config.status_code == 200
        assert config.json()["profiles"]
        listed = client.get("/api/v1/monitoring/devices?limit=10")
        assert listed.status_code == 200
        assert listed.json()["items"][0]["assetId"] == asset
        too_many = client.get("/api/v1/monitoring/devices?limit=500")
        assert too_many.status_code == 422
        missing_csrf = client.patch(f"/api/v1/monitoring/assets/{asset}", json={"enabled": False})
        assert missing_csrf.status_code == 403
        updated = client.patch(
            f"/api/v1/monitoring/assets/{asset}",
            json={"enabled": False},
            headers=headers,
        )
        assert updated.status_code == 200
        assert updated.json()["config"]["enabled"] is False
        detail = client.get(f"/api/v1/monitoring/devices/{asset}?period=30d")
        assert detail.status_code == 200
        assert detail.json()["provenance"]["period"]["preset"] == "30d"
        alerts = client.get("/api/v1/monitoring/alerts")
        assert alerts.status_code == 200
        assert alerts.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}


@pytest.mark.parametrize(
    ("check_type", "metric"),
    [
        *[("node", metric) for metric in ("cpu", "memory", "disk", "temperature")],
        *[("windows", metric) for metric in ("cpu", "memory", "disk")],
    ],
)
def test_every_allowed_metric_builds_a_bounded_selector(check_type: str, metric: str) -> None:
    asset_id = str(uuid4())
    expression = metric_expression(check_type, metric, asset_id)
    assert expression is not None
    assert f'asset_id="{asset_id}"' in expression
    assert "{{" not in expression
    assert expression.count("{") == expression.count("}")


def test_projection_samples_series_without_labels(harness: MonitoringHarness) -> None:
    asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9:9100")
    harness.adapter.states[asset] = {"up": 1.0, "latency": 0.01, "at": "2026-10-23T10:00:00Z"}
    harness.adapter.series[(asset, "cpu")] = [
        {"at": f"2026-10-23T{index % 24:02d}:00:00Z", "value": float(index)}
        for index in range(1000)
    ]
    with harness.catalog.session() as session:
        detail = harness.service(session).get_device(harness.admin, asset)
    summary = summarize_device(detail, include_series=True)
    assert "metrics" not in summary
    assert "labels" not in json.dumps(summary)
    assert summary["series"][0]["points"][0] == {"at": "2026-10-23T00:00:00Z", "value": 0.0}
    assert len(summary["series"][0]["points"]) <= 60
    assert summary["series"][0]["points"][-1]["value"] == 999.0


def test_prometheus_failure_writes_no_device_events(settings_factory) -> None:
    catalog = prepare(settings_factory, prometheus_url="http://127.0.0.1:1")
    harness = MonitoringHarness(catalog=catalog, clock=Clock(), adapter=FakeAdapter())
    harness.adapter.fail = True
    asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9:9100")
    with harness.catalog.session() as session:
        detail = harness.service(session).get_device(harness.admin, asset)
    assert detail["status"] == "unavailable"
    assert detail["reason"] == "prometheus_unavailable"
    assert harness.count(MonitoringAlert) == 0
    assert harness.count(MonitoringAlertEvent) == 0


def am_payload(
    asset_id: str,
    *,
    status: str = "firing",
    starts_at: datetime = NOW,
    ends_at: datetime | None = None,
    fingerprint: str = "fp1",
    severity: str = "critical",
    alert_name: str = "DeviceDown",
    group_key: str = "group-1",
) -> dict[str, Any]:
    return {
        "version": "4",
        "status": status,
        "groupKey": group_key,
        "alerts": [
            {
                "status": status,
                "labels": {
                    "asset_id": asset_id,
                    "alertname": alert_name,
                    "severity": severity,
                },
                "annotations": {"summary": "device is not reachable"},
                "startsAt": starts_at.isoformat().replace("+00:00", "Z"),
                "endsAt": ends_at.isoformat().replace("+00:00", "Z") if ends_at else None,
                "fingerprint": fingerprint,
                "generatorURL": "http://prometheus.test/graph",
            }
        ],
    }


class _StubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:
        return

    def _handle(self) -> None:
        parsed = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.last_body = body.decode(errors="replace")
        self.server.requests.append(
            {
                "method": self.command,
                "path": parsed.path,
                "query": parse_qs(parsed.query),
                "headers": {key.lower(): value for key, value in self.headers.items()},
            }
        )
        handler = self.server.routes.get((self.command, parsed.path))
        if handler is None:
            status, payload, content_type = 404, {"error": "not found"}, "application/json"
        else:
            status, payload, content_type = handler(parsed.query)
        encoded = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    do_GET = _handle
    do_POST = _handle
    do_DELETE = _handle


class StubServer:
    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Any] = {}
        self.requests: list[dict[str, Any]] = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
        self.httpd.routes = self.routes
        self.httpd.requests = self.requests
        self.httpd.last_body = ""
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def last_body(self) -> str:
        return self.httpd.last_body

    @property
    def base_url(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    def start(self) -> StubServer:
        self.thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@contextmanager
def stub_server():
    server = StubServer().start()
    try:
        yield server
    finally:
        server.stop()


def test_m3_normalized_asset_candidate_is_persisted_with_null_inheritance(harness):
    asset = harness.add_asset("M3 switch", category="switches", ip="10.0.0.1")
    with harness.catalog.session() as session:
        service = harness.service(session)
        result = service.update_asset(
            harness.admin,
            asset,
            {
                "checkType": "icmp",
                "metrics": ["latency", "latency"],
                "thresholds": {"latency": {"warning": 0.1234567}},
                "target": " 10.0.0.1 ",
            },
        )
        assert result["config"]["metrics"] == ["latency"]
        assert result["config"]["thresholds"]["latency"]["warning"] == 0.1235
        assert result["config"]["target"] == "10.0.0.1"
    with harness.catalog.session() as session:
        service = harness.service(session)
        result = service.get_device(harness.admin, asset)
        assert result["config"]["metrics"] == ["latency"]
        cleared = service.update_asset(
            harness.admin, asset, {"metrics": None, "thresholds": None, "target": None}
        )
        assert "metrics" not in cleared["config"]["overridden"]
        assert "thresholds" not in cleared["config"]["overridden"]
        assert "target" not in cleared["config"]["overridden"]
