"""Phase 10 independent regressions: S1/S2/S6/S7; C1/C2/C4."""

import pytest
from itsm.dashboard.service import DashboardService
from itsm.identity.service import IdentityService
from itsm.monitoring.service import MonitoringService
from itsm.search.indexer import execute_sync
from tests.inventory_support import prepare
from tests.test_phase10_directory_media import (
    admin_auth,
    create_floor,
    media_client,
    png_bytes,
)
from tests.test_phase10_search import StubEngine, _asset, _catalog, _search


@pytest.mark.parametrize("kind", ["section", "view"])
def test_engine_never_broadens_explicit_kind(settings_factory, kind):
    stub = StubEngine()
    try:
        catalog = _catalog(settings_factory, stub.url)
        _asset(catalog, name="KindIsolationProbe")
        with catalog.session() as session:
            assert execute_sync(session, catalog.settings)["synced"] == 1
        page = _search(catalog, catalog.admin(), "KindIsolationProbe", kinds=[kind])
        assert page["items"] == []
        assert page["total"] == 0
    finally:
        stub.stop()


def test_engine_total_cannot_reveal_denied_assets(settings_factory):
    stub = StubEngine()
    try:
        catalog = _catalog(settings_factory, stub.url)
        _asset(catalog, name="DeniedCountProbe")
        with catalog.session() as session:
            assert execute_sync(session, catalog.settings)["synced"] == 1
            role = IdentityService(session, catalog.settings).create_role(
                catalog.admin(), name="People only regression", permissions=["people.view"]
            )
        actor = catalog.add_user("denied-count", "Denied Count", role.id)
        page = _search(catalog, actor, "DeniedCountProbe", kinds=["asset"])
        assert page["items"] == []
        assert page["total"] == 0
    finally:
        stub.stop()


def test_truncated_floor_plan_cannot_replace_valid_blob(settings_factory, tmp_path):
    catalog = prepare(settings_factory, attachment_storage_path=tmp_path / "blobs")
    with media_client(catalog) as client:
        headers = admin_auth(client, catalog)
        floor = create_floor(client, headers)
        url = "/api/v1/locations/" + floor["id"] + "/plan"
        valid = png_bytes(2, 2)
        assert client.put(url, content=valid, headers=headers).status_code == 200
        rejected = client.put(url, content=valid[:24], headers=headers)
        assert rejected.status_code == 422
        downloaded = client.get(url)
        assert downloaded.status_code == 200
        assert downloaded.content == valid


def test_device_uptime_is_not_installation_average(settings_factory):
    catalog = prepare(settings_factory, prometheus_url="http://unused.invalid")
    down = _asset(catalog, name="Never up")
    up = _asset(catalog, name="Always up", quick_code="SW-002", serial="SW002", ip="10.0.0.2")

    class Metrics:
        def current_states(self, pairs):
            return {
                key: {"success": float(key == up), "latency": 0.01, "at": "2026-10-23T10:00:00Z"}
                for key, _ in pairs
            }

        def page_availability(self, pairs, window):
            return {
                key: {"percent": 100.0 if key == up else 0.0, "samples": 100} for key, _ in pairs
            }

    with catalog.session() as session:
        identity = IdentityService(session, catalog.settings)
        monitoring = MonitoringService(
            session, catalog.settings, identity=identity, adapter=Metrics()
        )
        summary = DashboardService(
            session, identity, catalog.settings, monitoring=monitoring
        ).summary(catalog.admin())
    rows = {row["assetId"]: row for row in summary["rows"]}
    assert summary["availability"]["current"] == 50.0
    assert rows[down]["uptimePct"] == 0.0
    assert rows[up]["uptimePct"] == 100.0
