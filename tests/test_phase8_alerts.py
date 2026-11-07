"""Focused Phase 8 alert lifecycle coverage: durable cycles, silences, incidents.

All state transitions go through the public service or ASGI surfaces against a
migrated SQL database. Notification delivery is observed only at the flush-only
seam, so these tests prove the monitoring half of the contract without importing
the notification module.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from itsm.identity.service import Conflict, NotFound, PermissionDenied, ValidationFailed
from itsm.interventions.models import Incident, IncidentAsset
from itsm.interventions.service import InterventionService
from itsm.monitoring.models import (
    MaintenanceWindow,
    MonitoringAlert,
    MonitoringAlertEvent,
    MonitoringSilence,
)
from itsm.monitoring.prometheus import MonitoringUnavailable
from itsm.monitoring.scheduler import sync_from_prometheus
from itsm.monitoring.service import MonitoringService
from sqlalchemy import func, select
from tests.inventory_support import OPERATOR, READER, prepare
from tests.test_phase8_monitoring import (
    NOW,
    Clock,
    FakeAdapter,
    MonitoringHarness,
    am_payload,
    monitoring_app,
    stub_server,
)


def build_harness(settings_factory, **overrides: Any) -> MonitoringHarness:
    catalog = prepare(
        settings_factory,
        prometheus_url="http://prometheus.test:9090",
        **overrides,
    )
    catalog.add_user(*READER)
    catalog.add_user(*OPERATOR)
    return MonitoringHarness(catalog=catalog, clock=Clock(), adapter=FakeAdapter())


@pytest.fixture
def harness(settings_factory) -> MonitoringHarness:
    return build_harness(settings_factory)


@pytest.fixture
def alert_harness(harness: MonitoringHarness) -> tuple[MonitoringHarness, str, dict[str, Any]]:
    asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9")
    with harness.catalog.session() as session:
        stats = harness.service(session).ingest_alertmanager(am_payload(asset))
    assert stats["created"] == 1
    with harness.catalog.session() as session:
        alert = harness.service(session).list_alerts(harness.admin)["items"][0]
    return harness, asset, alert


def test_webhook_is_idempotent_and_ack_never_resolves(
    alert_harness: tuple[MonitoringHarness, str, dict[str, Any]],
) -> None:
    harness, asset, alert = alert_harness
    assert len(harness.notifier_calls) == 1
    call = harness.notifier_calls[0]
    assert call["event_type"] == "firing"
    assert call["severity"] == "critical"
    assert call["alert_id"] == alert["id"]
    assert call["event_key"].startswith(f"{alert['id']}:")
    assert call["url"].endswith(f"/#/supervision/alerta/{alert['id']}")
    assert call["recovered"] is False and call["acknowledged"] is False

    with harness.catalog.session() as session:
        service = harness.service(session)
        repeated = service.ingest_alertmanager(am_payload(asset))
        assert repeated["updated"] == 1
        assert repeated["events"] == 0
        assert service.list_alerts(harness.admin)["total"] == 1
        assert harness.count(MonitoringAlertEvent) == 1
        assert len(harness.notifier_calls) == 1

        acknowledged = service.acknowledge(harness.operator, alert["id"], "reviewing")
        assert acknowledged["state"] == "firing"
        assert acknowledged["acknowledged"] is True
        assert acknowledged["notes"] == "reviewing"
        assert harness.notifier_calls[-1]["event_type"] == "acknowledged"
        assert harness.notifier_calls[-1]["acknowledged"] is True
        delivered = len(harness.notifier_calls)

        service.acknowledge(harness.operator, alert["id"], "still reviewing")
        assert len(harness.notifier_calls) == delivered
        service.ingest_alertmanager(am_payload(asset))
        preserved = service.get_alert(harness.operator, alert["id"])
        assert preserved["state"] == "firing"
        assert preserved["acknowledged"] is True
        assert preserved["notes"] == "reviewing"


def test_recurrence_cycles_and_stale_payloads(
    alert_harness: tuple[MonitoringHarness, str, dict[str, Any]],
) -> None:
    harness, asset, first = alert_harness
    with harness.catalog.session() as session:
        service = harness.service(session)
        service.acknowledge(harness.operator, first["id"])
        resolved = service.ingest_alertmanager(
            am_payload(
                asset,
                status="resolved",
                starts_at=NOW,
                ends_at=NOW + timedelta(minutes=5),
            )
        )
        assert resolved["resolved"] == 1
        cycle_a = service.get_alert(harness.operator, first["id"])
        assert cycle_a["state"] == "resolved"
        assert cycle_a["acknowledged"] is True
        assert harness.notifier_calls[-1]["event_type"] == "recovered"
        assert harness.notifier_calls[-1]["recovered"] is True

        service.ingest_alertmanager(am_payload(asset))
        assert service.get_alert(harness.operator, first["id"])["state"] == "resolved"

        second_stats = service.ingest_alertmanager(
            am_payload(asset, fingerprint="secondcycle", starts_at=NOW + timedelta(hours=1))
        )
        assert second_stats["created"] == 1
        rows = service.list_alerts(harness.admin)
        assert rows["total"] == 2
        second = rows["items"][0]
        assert second["state"] == "firing"

        service.ingest_alertmanager(am_payload(asset))
        assert service.get_alert(harness.operator, second["id"])["state"] == "firing"
        assert service.get_alert(harness.operator, first["id"])["state"] == "resolved"
        service.ingest_alertmanager(
            am_payload(asset, status="resolved", starts_at=NOW, ends_at=NOW + timedelta(minutes=6))
        )
        assert service.get_alert(harness.operator, first["id"])["state"] == "resolved"
        assert service.get_alert(harness.operator, second["id"])["state"] == "firing"
        assert harness.count(MonitoringAlertEvent) == 4


def test_late_resolution_of_superseded_cycle_never_touches_newer_cycle(
    alert_harness: tuple[MonitoringHarness, str, dict[str, Any]],
) -> None:
    harness, asset, _ = alert_harness
    with harness.catalog.session() as session:
        service = harness.service(session)
        service.ingest_alertmanager(
            am_payload(asset, fingerprint="recurring", starts_at=NOW + timedelta(hours=1))
        )
        service.ingest_alertmanager(
            am_payload(asset, fingerprint="recurring", starts_at=NOW + timedelta(hours=2))
        )
        active = service.list_alerts(harness.admin, state="firing")
        assert active["total"] == 3
        before = len(harness.notifier_calls)
        service.ingest_alertmanager(
            am_payload(
                asset,
                status="resolved",
                fingerprint="recurring",
                starts_at=NOW + timedelta(hours=1),
                ends_at=NOW + timedelta(hours=1, minutes=10),
            )
        )
        rows = [
            row
            for row in service.list_alerts(harness.admin)["items"]
            if row["fingerprint"] == "recurring"
        ]
        rows.sort(key=lambda row: row["startsAt"])
        assert [row["state"] for row in rows] == ["resolved", "firing"]
        assert len(harness.notifier_calls) == before


def test_unknown_assets_and_malformed_payloads_write_nothing(
    harness: MonitoringHarness,
) -> None:
    asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9")
    mixed = am_payload(asset)
    mixed["alerts"].append(am_payload(str(uuid4()))["alerts"][0])
    bad_version = am_payload(asset)
    bad_version["version"] = "3"
    missing_name = am_payload(asset)
    missing_name["alerts"][0]["labels"].pop("alertname")
    bad_annotations = am_payload(asset)
    bad_annotations["alerts"][0]["annotations"] = ["nope"]
    too_many = am_payload(asset)
    too_many["alerts"] = [am_payload(asset)["alerts"][0] for _ in range(501)]
    with harness.catalog.session() as session:
        service = harness.service(session)
        for payload in (mixed, bad_version, missing_name, bad_annotations, too_many):
            with pytest.raises(ValidationFailed):
                service.ingest_alertmanager(payload)
    assert harness.count(MonitoringAlert) == 0
    assert harness.count(MonitoringAlertEvent) == 0
    assert harness.notifier_calls == []


def test_acknowledge_silence_and_link_require_assets_edit_and_do_not_mutate(
    alert_harness: tuple[MonitoringHarness, str, dict[str, Any]],
) -> None:
    harness, _, alert = alert_harness
    with harness.catalog.session() as session:
        service = harness.service(session)
        with pytest.raises(PermissionDenied):
            service.acknowledge(harness.reader, alert["id"])
        with pytest.raises(PermissionDenied):
            service.silence(
                harness.reader,
                {
                    "alertId": alert["id"],
                    "endsAt": (NOW + timedelta(minutes=30)).isoformat(),
                    "comment": "reader attempt",
                },
            )
        with pytest.raises(PermissionDenied):
            service.link_incident(harness.reader, alert["id"])
        with pytest.raises(PermissionDenied):
            service.prepare_maintenance(harness.reader, alert["id"])
        untouched = service.get_alert(harness.admin, alert["id"])
        assert untouched["state"] == "firing"
        assert untouched["acknowledged"] is False
        assert untouched["incident"] is None
    assert harness.count(MonitoringSilence) == 0
    assert harness.count(Incident) == 0
    denied = [row for row in harness.catalog.audit() if row["outcome"] == "denied"]
    assert len(denied) >= 4


def test_local_silence_suppresses_notifications_until_expiry(
    alert_harness: tuple[MonitoringHarness, str, dict[str, Any]],
) -> None:
    harness, asset, alert = alert_harness
    with harness.catalog.session() as session:
        service = harness.service(session)
        silence = service.silence(
            harness.operator,
            {
                "assetId": asset,
                "endsAt": (NOW + timedelta(minutes=30)).isoformat(),
                "comment": "planned check",
            },
        )
        assert silence["source"] == "local"
        assert silence["active"] is True
        detail = service.get_alert(harness.operator, alert["id"])
        assert detail["silenced"] is True
        assert detail["state"] == "firing"
        assert len(harness.notifier_calls) == 1

        service.ingest_alertmanager(
            am_payload(asset, fingerprint="silencedcycle", starts_at=NOW + timedelta(minutes=10))
        )
        assert len(harness.notifier_calls) == 1
        silenced = next(
            row
            for row in service.list_alerts(harness.admin)["items"]
            if row["fingerprint"] == "silencedcycle"
        )
        assert silenced["silenced"] is True
        assert silenced["state"] == "firing"

        harness.clock.advance(minutes=60)
        service.ingest_alertmanager(
            am_payload(asset, fingerprint="aftersilence", starts_at=harness.clock())
        )
        assert len(harness.notifier_calls) == 2
        expired = service.get_alert(harness.operator, alert["id"])
        assert expired["silenced"] is False


def test_maintenance_window_suppresses_and_validates(
    alert_harness: tuple[MonitoringHarness, str, dict[str, Any]],
) -> None:
    harness, asset, _ = alert_harness
    with harness.catalog.session() as session:
        service = harness.service(session)
        window = service.save_window(
            harness.operator,
            {
                "name": "Ventana viernes",
                "assetIds": [asset],
                "daysOfWeek": [4],
                "startTime": "09:00",
                "endTime": "11:00",
                "timezone": "UTC",
            },
        )
        assert window["active"] is True
        assert window["nextOccurrence"]["startsAt"].startswith("2026-10-23T09:00")
        before = len(harness.notifier_calls)
        service.ingest_alertmanager(
            am_payload(asset, fingerprint="inwindow", starts_at=NOW + timedelta(minutes=5))
        )
        assert len(harness.notifier_calls) == before
        inside = next(
            row
            for row in service.list_alerts(harness.admin)["items"]
            if row["fingerprint"] == "inwindow"
        )
        assert inside["state"] == "firing"
        assert inside["silenced"] is True

        for values in (
            {"name": "Bad zone", "startTime": "01:00", "endTime": "02:00", "timezone": "Mars/Base"},
            {"name": "Equal", "startTime": "01:00", "endTime": "01:00", "timezone": "UTC"},
            {"name": "Bad day", "daysOfWeek": [9], "startTime": "01:00", "endTime": "02:00"},
        ):
            with pytest.raises(ValidationFailed):
                service.save_window(harness.operator, values)
        with pytest.raises(NotFound):
            service.save_window(
                harness.operator,
                {
                    "name": "Unknown asset",
                    "assetIds": [str(uuid4())],
                    "startTime": "01:00",
                    "endTime": "02:00",
                },
            )
        global_window = service.save_window(
            harness.operator,
            {
                "name": "Global",
                "daysOfWeek": [0, 1, 2, 3, 4, 5, 6],
                "startTime": "00:00",
                "endTime": "00:01",
                "timezone": "UTC",
            },
        )
        assert global_window["assetIds"] == []
    assert harness.settings.api_prefix


def test_incident_creation_link_recovery_and_prepare(
    alert_harness: tuple[MonitoringHarness, str, dict[str, Any]],
) -> None:
    harness, asset, alert = alert_harness
    with harness.catalog.session() as session:
        service = harness.service(session)
        linked = service.link_incident(harness.operator, alert["id"])
        incident = linked["incident"]
        assert incident["status"] == "open"
        assert incident["suggestedClose"] is False
        incident_id = incident["id"]
        row = session.get(Incident, incident_id)
        assert row is not None and row.priority == "critical"
        assert row.primary_asset_id == asset
        assert session.scalar(
            select(func.count())
            .select_from(IncidentAsset)
            .where(IncidentAsset.incident_id == incident_id)
        ) == 0
        events = service.history(harness.operator, alert["id"])
        assert any(event["action"] == "incident_created" for event in events["items"])

        suggestion = service.prepare_maintenance(harness.operator, alert["id"])
        assert suggestion["suggested"]["assetIds"] == [asset]
        assert suggestion["existingWindow"] is None
        assert harness.count(MaintenanceWindow) == 0

        service.ingest_alertmanager(
            am_payload(asset, status="resolved", starts_at=NOW, ends_at=NOW + timedelta(minutes=2))
        )
        recovered = service.get_alert(harness.operator, alert["id"])
        assert recovered["state"] == "resolved"
        assert recovered["incident"]["id"] == incident_id
        assert recovered["incident"]["status"] == "open"
        assert recovered["incident"]["suggestedClose"] is True
        assert session.get(Incident, incident_id).status == "open"

        again = service.link_incident(harness.operator, alert["id"], incident_id)
        assert again["incident"]["id"] == incident_id
        duplicate = service.link_incident(harness.operator, alert["id"])
        assert duplicate["incident"]["id"] == incident_id
        assert harness.count(Incident) == 1
        with pytest.raises(NotFound):
            service.link_incident(
                harness.operator, alert["id"], str(uuid4())
            )


def test_link_to_existing_incident_and_conflicts(
    alert_harness: tuple[MonitoringHarness, str, dict[str, Any]],
) -> None:
    harness, asset, alert = alert_harness
    with harness.catalog.session() as session:
        service = harness.service(session)
        actions = InterventionService(session, harness.settings)
        created = actions.create_incident(
            harness.admin,
            {
                "primaryAssetId": asset,
                "description": "Pre-existing incident",
                "priority": "high",
            },
        )
        linked = service.link_incident(harness.operator, alert["id"], created.id)
        assert linked["incident"]["id"] == created.id
        service.ingest_alertmanager(
            am_payload(asset, fingerprint="secondcycle", starts_at=NOW + timedelta(hours=1))
        )
        other = next(
            row
            for row in service.list_alerts(harness.admin)["items"]
            if row["fingerprint"] == "secondcycle"
        )
        second = service.link_incident(harness.operator, other["id"])
        with pytest.raises(Conflict):
            service.link_incident(harness.operator, other["id"], created.id)
        duplicate = service.link_incident(harness.operator, other["id"])
        assert duplicate["incident"]["id"] == second["incident"]["id"]
        assert second["incident"]["id"] != created.id
        assert harness.count(Incident) == 2


def test_alertmanager_window_silence_sync_is_idempotent_and_pending_on_failure(
    settings_factory,
) -> None:
    harness = build_harness(settings_factory, alertmanager_url="http://am.test:9093")
    asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9")
    values = {
        "name": "Nightly",
        "assetIds": [asset],
        "daysOfWeek": [0, 1, 2, 3, 4, 5, 6],
        "startTime": "00:00",
        "endTime": "23:59",
        "timezone": "UTC",
    }
    with harness.catalog.session() as session:
        service = harness.service(session)
        window = service.save_window(harness.operator, values)
        assert window["alertmanagerSync"] == "synced"
        assert len(harness.adapter.created_silences) == 1
        native_id = harness.adapter.created_silences[0]["id"]
        stats = service.sync_maintenance_windows()
        assert stats["windows"] == 1
        assert len(harness.adapter.created_silences) == 1

        harness.adapter.silence_fail = True
        service.save_window(
            harness.operator,
            {**values, "id": window["id"], "startTime": "00:01", "endTime": "23:58"},
        )
        assert harness.adapter.deleted_silences == [native_id]
        stored = service.list_windows(harness.admin)["items"][0]
        assert stored["alertmanagerSync"] == "pending"
        stats = service.sync_maintenance_windows()
        assert stats["pending"] == 1
        harness.adapter.silence_fail = False
        stats = service.sync_maintenance_windows()
        assert stats["silences"] == 1
        assert len(harness.adapter.created_silences) == 2


def test_native_polling_is_stable_resolves_and_preserves_ack(settings_factory) -> None:
    harness = build_harness(settings_factory)
    asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9")

    def native(state: str = "firing", *, active_at: Any = NOW) -> dict[str, Any]:
        return {
            "labels": {"asset_id": asset, "alertname": "DeviceDown", "severity": "warning"},
            "annotations": {"summary": "probe failed"},
            "state": state,
            "activeAt": active_at if isinstance(active_at, str) else active_at.isoformat(),
            "value": "1",
        }

    harness.adapter.alerts_data = [native()]
    with harness.catalog.session() as session:
        service = harness.service(session)
        first = service.poll_native_alerts()
        assert first["created"] == 1
        assert len(harness.notifier_calls) == 1
        second = service.poll_native_alerts()
        assert second["created"] == 0
        assert len(harness.notifier_calls) == 1
        alert = service.list_alerts(harness.admin)["items"][0]
        service.acknowledge(harness.operator, alert["id"], "on it")

        harness.adapter.alerts_data = []
        resolved = service.poll_native_alerts()
        assert resolved["resolved"] == 1
        detail = service.get_alert(harness.operator, alert["id"])
        assert detail["state"] == "resolved"
        assert detail["acknowledged"] is True
        assert harness.notifier_calls[-1]["event_type"] == "recovered"

        harness.adapter.alerts_data = [native("pending", active_at=NOW + timedelta(hours=1))]
        service.poll_native_alerts()
        pending = next(
            row for row in service.list_alerts(harness.admin)["items"] if row["state"] == "pending"
        )
        before = len(harness.notifier_calls)
        harness.adapter.alerts_data = []
        service.poll_native_alerts()
        assert service.get_alert(harness.operator, pending["id"])["state"] == "resolved"
        assert len(harness.notifier_calls) == before

        harness.adapter.alerts_data = [{"labels": {"alertname": "NoAsset"}, "state": "firing"}]
        stats = service.poll_native_alerts()
        assert stats["ignored"] >= 1

        harness.adapter.alerts_data = [native()]
        service.poll_native_alerts()
        active_before = service.list_alerts(harness.admin, state="firing")["total"]
        harness.adapter.fail = True
        with pytest.raises(MonitoringUnavailable):
            service.poll_native_alerts()
        assert service.list_alerts(harness.admin, state="firing")["total"] == active_before


def test_polling_is_skipped_when_alertmanager_is_configured(settings_factory) -> None:
    harness = build_harness(settings_factory, alertmanager_url="http://am.test:9093")
    harness.add_asset("Server", category="servidores", ip="10.0.0.9")
    with harness.catalog.session() as session:
        stats = harness.service(session).poll_native_alerts()
    assert stats == {"skipped": 1}
    assert harness.notifier_calls == []


def test_notifier_is_flush_only_and_failures_roll_back(harness: MonitoringHarness) -> None:
    asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9")

    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("notification outbox unavailable")

    with harness.catalog.session() as session:
        service = MonitoringService(
            session,
            harness.settings,
            adapter=harness.adapter,
            notifier=boom,
            now=harness.clock,
        )
        with pytest.raises(RuntimeError):
            service.ingest_alertmanager(am_payload(asset))
    assert harness.count(MonitoringAlert) == 0
    assert harness.count(MonitoringAlertEvent) == 0

    with harness.catalog.session() as session:
        silent = MonitoringService(
            session,
            harness.settings,
            adapter=harness.adapter,
            now=harness.clock,
        )
        stats = silent.ingest_alertmanager(am_payload(asset))
        assert stats["created"] == 1
    assert harness.count(MonitoringAlert) == 1
    assert harness.notifier_calls == []


def test_webhook_http_boundaries(settings_factory) -> None:
    harness = build_harness(
        settings_factory,
        monitoring_ingest_token="ingest-secret",
        monitoring_discovery_token="discovery-secret",
    )
    asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9")
    app = monitoring_app(harness)
    with TestClient(app) as client:
        missing = client.post("/api/v1/monitoring/alertmanager", json=am_payload(asset))
        assert missing.status_code == 401
        wrong = client.post(
            "/api/v1/monitoring/alertmanager",
            json=am_payload(asset),
            headers={"Authorization": "Bearer nope"},
        )
        assert wrong.status_code == 401
        malformed = client.post(
            "/api/v1/monitoring/alertmanager",
            content=b"not json",
            headers={
                "Authorization": "Bearer ingest-secret",
                "Content-Type": "application/json",
            },
        )
        assert malformed.status_code == 400
        too_large = client.post(
            "/api/v1/monitoring/alertmanager",
            content=b"{" + b"x" * (1024 * 1024 + 8),
            headers={
                "Authorization": "Bearer ingest-secret",
                "Content-Type": "application/json",
            },
        )
        assert too_large.status_code == 413
        unknown = client.post(
            "/api/v1/monitoring/alertmanager",
            json=am_payload(str(uuid4())),
            headers={"Authorization": "Bearer ingest-secret"},
        )
        assert unknown.status_code == 422
        accepted = client.post(
            "/api/v1/monitoring/alertmanager",
            json=am_payload(asset),
            headers={"Authorization": "Bearer ingest-secret"},
        )
        assert accepted.status_code == 202
        repeated = client.post(
            "/api/v1/monitoring/alertmanager",
            json=am_payload(asset),
            headers={"Authorization": "Bearer ingest-secret"},
        )
        assert repeated.status_code == 202
        assert harness.count(MonitoringAlert) == 1
        assert harness.count(MonitoringAlertEvent) == 1


def test_worker_native_mode_uses_real_http(settings_factory) -> None:
    with stub_server() as stub:
        catalog = prepare(settings_factory, prometheus_url=stub.base_url)
        catalog.add_user(*READER)
        catalog.add_user(*OPERATOR)
        harness = MonitoringHarness(catalog=catalog, clock=Clock(), adapter=FakeAdapter())
        asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9")
        stub.routes[("GET", "/api/v1/alerts")] = lambda query: (
            200,
            {
                "status": "success",
                "data": {
                    "alerts": [
                        {
                            "labels": {
                                "asset_id": asset,
                                "alertname": "DeviceDown",
                                "severity": "critical",
                            },
                            "annotations": {"summary": "probe failed"},
                            "state": "firing",
                            "activeAt": NOW.isoformat().replace("+00:00", "Z"),
                            "value": "1",
                        }
                    ]
                },
            },
            "application/json",
        )
        calls: list[dict[str, Any]] = []
        stats = sync_from_prometheus(
            harness.settings, notifier=lambda session, settings, **kwargs: calls.append(kwargs)
        )
        assert stats["created"] == 1
        assert calls and calls[0]["event_type"] == "firing"
        with harness.catalog.session() as session:
            assert harness.service(session).list_alerts(harness.admin)["total"] == 1
        assert stub.requests[0]["path"] == "/api/v1/alerts"


def test_worker_alertmanager_mode_syncs_windows_and_skips_alert_polling(
    settings_factory,
) -> None:
    with stub_server() as stub:
        catalog = prepare(
            settings_factory,
            prometheus_url=stub.base_url,
            alertmanager_url=stub.base_url,
        )
        catalog.add_user(*READER)
        catalog.add_user(*OPERATOR)
        harness = MonitoringHarness(catalog=catalog, clock=Clock(), adapter=FakeAdapter())
        asset = harness.add_asset("Server", category="servidores", ip="10.0.0.9")
        harness.adapter.silence_fail = True
        with harness.catalog.session() as session:
            harness.service(session).save_window(
                harness.operator,
                {
                    "name": "Nightly",
                    "assetIds": [asset],
                    "daysOfWeek": [0, 1, 2, 3, 4, 5, 6],
                    "startTime": "00:00",
                    "endTime": "23:59",
                    "timezone": "UTC",
                },
            )
        stub.routes[("POST", "/api/v2/silences")] = lambda query: (
            200,
            {"silenceID": "native-worker-1"},
            "application/json",
        )
        stats = sync_from_prometheus(harness.settings)
        assert stats["windows"] == 1
        assert stats["silences"] == 1
        assert all(request["path"] != "/api/v1/alerts" for request in stub.requests)
        assert any(request["path"] == "/api/v2/silences" for request in stub.requests)


def test_worker_degrades_without_raising(settings_factory) -> None:
    catalog = prepare(settings_factory, prometheus_url="http://127.0.0.1:1")
    harness = MonitoringHarness(catalog=catalog, clock=Clock(), adapter=FakeAdapter())
    harness.add_asset("Server", category="servidores", ip="10.0.0.9")
    stats = sync_from_prometheus(harness.settings)
    assert stats == {"unavailable": 1}
