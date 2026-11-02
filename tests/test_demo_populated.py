"""Public-surface coverage of the populated fictional demonstration.

Every assertion goes through the real API of a marked demo installation, never
through private counters: the dataset must read as an installation in use across
the existing modules, and the guarded reset must regenerate the same shape.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.demo.seed import seed
from itsm.main import create_app
from itsm.release_mode import RELEASE_MODE_ENV
from tests.conftest import run_migrations

API = "/api/v1"
ORIGIN = "http://testserver"
INSTALLER_PASSWORD = "test-only-populated-password"


@dataclass
class Installation:
    settings: Settings
    client: TestClient
    payload: dict[str, Any]

    def auth(self) -> dict[str, str]:
        login = self.client.post(
            f"{API}/auth/login",
            json={"username": "admin", "password": "admin"},
            headers={"Origin": ORIGIN},
        )
        assert login.status_code == 200, login.text
        return {"Origin": ORIGIN, "X-CSRF-Token": str(login.json()["csrfToken"])}

    def get(self, path: str, headers: dict[str, str] | None = None) -> Any:
        response = self.client.get(f"{API}{path}", headers=headers or {})
        assert response.status_code == 200, response.text
        return response.json()


@pytest.fixture(scope="module")
def installation(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Installation]:
    root = tmp_path_factory.mktemp("demo-populated")
    (root / "tasks").mkdir()
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{root / 'demo.db'}",
        task_sqlite_path=root / "tasks" / "huey.db",
        attachment_storage_path=root / "attachments",
        demo_data_directory=root,
        auth_origin=ORIGIN,
        auth_cookie_secure=False,
        log_level="WARNING",
        demo_rate_limit_per_minute=6000,
        demo_rate_limit_burst=6000,
        demo_login_rate_per_minute=1000,
        demo_login_rate_burst=1000,
    )
    assert run_migrations(settings).returncode == 0
    engine = create_engine_from_settings(settings)
    try:
        with create_session_factory(engine)() as session:
            payload = seed(session, settings, "admin", INSTALLER_PASSWORD)
    finally:
        engine.dispose()
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv(RELEASE_MODE_ENV, "demo")
        with TestClient(create_app(settings)) as client:
            yield Installation(settings=settings, client=client, payload=payload)


def test_seeded_installation_reads_as_in_use(installation: Installation) -> None:
    payload = installation.payload
    assert payload["mode"] == "demo"
    assert payload["dataset"] == "fictional-infrastructure-v1"
    assert payload["assets"] >= 12
    assert payload["sites"] == 2
    assert payload["people"] >= 5
    assert payload["relationships"] >= 10
    assert payload["redundancyGroups"] >= 1
    assert payload["incidents"] == 4
    assert payload["maintenancePlans"] == 4
    assert payload["warranties"] >= 4
    assert payload["attachments"] >= 2
    assert payload["alerts"] >= 2
    assert payload["notifications"] >= 2
    assert payload["importOperationId"]
    assert payload["workspaceViews"] == 1

    headers = installation.auth()
    assets = installation.get("/assets?limit=100", headers)
    # The completed import created its rows through the canonical service, so the
    # visible inventory is the seeded set plus the imported ones.
    assert payload["importSummary"]["created"] == 2
    assert assets["total"] == payload["assets"] + 2
    codes = {item["quickCode"] for item in assets["items"]}
    assert {"DEMO-101", "DEMO-102"} <= codes
    categories = {item["category"] for item in assets["items"]}
    assert {"servidores", "switches", "camaras", "virtualizacion", "notebooks"} <= categories
    assert any(item["responsiblePersonId"] for item in assets["items"])
    assert any(not item["responsiblePersonId"] for item in assets["items"])
    assert any(item["status"] == "in_storage" for item in assets["items"])

    plan = installation.get("/map", headers)
    assert len(plan["positions"]) == payload["positions"] >= 4
    assert len(plan["sites"]) == 2


def test_people_relationships_and_redundancy_are_coherent(installation: Installation) -> None:
    headers = installation.auth()
    people = installation.get("/people?limit=100", headers)
    assert people["total"] >= 5
    known = {person["id"] for person in people["items"]}

    assets = installation.get("/assets?limit=100", headers)["items"]
    responsible = {asset["responsiblePersonId"] for asset in assets if asset["responsiblePersonId"]}
    assert responsible <= known

    relations = installation.get("/relationships?limit=100", headers)
    types = {item["typeKey"] for item in relations["items"]}
    assert {"hosted_in", "connected_to", "depends_on"} <= types
    asset_ids = {asset["id"] for asset in assets}
    for relation in relations["items"]:
        assert relation["sourceId"] in asset_ids
        assert relation["targetId"] in asset_ids

    groups = installation.get("/redundancy-groups?limit=100", headers)
    assert groups["total"] == installation.payload["redundancyGroups"]
    modes = {group["mode"] for group in groups["items"]}
    assert "active_passive" in modes
    for group in groups["items"]:
        assert group["memberCount"] >= 2

    graph = installation.get("/infrastructure/graph", headers)
    assert graph["nodes"]


def test_assignment_return_and_transfer_left_structured_history(
    installation: Installation,
) -> None:
    headers = installation.auth()
    assets = installation.get("/assets?limit=100", headers)["items"]
    actions: set[str] = set()
    sources: set[str] = set()
    for asset in assets:
        history = installation.get(f"/assets/{asset['id']}/history?limit=100", headers)
        for entry in history["items"]:
            actions.add(entry["action"])
            sources.add(entry["source"])
    assert {"assigned", "returned", "transferred"} <= actions
    assert sources == {"internal"}


def test_incidents_cover_every_documented_state(installation: Installation) -> None:
    headers = installation.auth()
    incidents = installation.get("/incidents?limit=100", headers)
    assert incidents["total"] == 4
    states = sorted(item["status"] for item in incidents["items"])
    assert states == ["closed", "in_progress", "open", "resolved"]

    active = installation.get("/incidents?active=true&limit=100", headers)
    assert active["total"] == 2
    acknowledged = next(item for item in incidents["items"] if item["status"] == "in_progress")
    detail = installation.get(f"/incidents/{acknowledged['id']}", headers)
    assert [event["action"] for event in detail["events"]] == ["created", "acknowledged"]


def test_maintenance_covers_overdue_upcoming_completed_and_postponed(
    installation: Installation,
) -> None:
    headers = installation.auth()
    plans = installation.get("/maintenance/plans?limit=100", headers)
    # The four seeded plans are visible together with the template-derived
    # virtual rows every canonical asset has.
    assert plans["total"] >= 4
    items = plans["items"]
    today = date.today()
    overdue = [
        item for item in items if item["status"] == "active" and item["lastCompletedOn"] is None
    ]
    assert overdue, items
    assert any(date.fromisoformat(item["dueOn"]) < today for item in overdue)
    assert any(
        item["status"] == "active"
        and item["lastCompletedOn"] is None
        and date.fromisoformat(item["dueOn"]) >= today
        for item in items
    )
    completed = [item for item in items if item["lastCompletedOn"] is not None]
    assert completed and all(item["status"] == "active" for item in completed)
    postponed = [item for item in items if item["status"] == "postponed"]
    assert postponed and date.fromisoformat(postponed[0]["dueOn"]) > today

    templates = installation.get("/maintenance/templates", headers)
    assert templates["items"]


def test_warranties_have_downloadable_local_receipts(installation: Installation) -> None:
    headers = installation.auth()
    warranties = installation.get("/warranties", headers)
    coverage = {item["coverage"] for item in warranties["items"]}
    assert {"current", "expiring", "expired"} <= coverage
    receipt = next(item for item in warranties["items"] if item.get("receiptId"))
    asset_id = receipt["assetId"]

    listed = installation.get(f"/assets/{asset_id}/attachments", headers)
    attachment = next(item for item in listed["items"] if item["id"] == receipt["receiptId"])
    assert attachment["category"] == "receipt"
    download = installation.client.get(
        f"{API}/assets/{asset_id}/attachments/{receipt['receiptId']}/download", headers=headers
    )
    assert download.status_code == 200, download.text
    assert download.headers["content-disposition"].startswith("attachment;")
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "documento ficticio" in download.content.decode("utf-8").lower()

    photos = installation.get(f"/assets/{asset_id}/attachments", headers)["items"]
    assert any(item["category"] in {"photo", "document"} for item in photos)


def test_monitoring_alerts_and_the_internal_inbox_are_populated(
    installation: Installation,
) -> None:
    headers = installation.auth()
    alerts = installation.get("/monitoring/alerts?limit=100", headers)
    assert alerts["total"] >= 3
    states = {item["state"] for item in alerts["items"]}
    assert {"firing", "resolved"} <= states
    assert any(item["acknowledged"] for item in alerts["items"])
    assert any(item["severity"] in {"critical", "warning"} for item in alerts["items"])

    inbox = installation.get("/notifications/inbox?limit=100", headers)
    assert inbox["total"] >= 2
    assert any(item["eventType"] == "recovered" for item in inbox["items"])
    assert any(item["assetId"] for item in inbox["items"])
    config = installation.get("/notifications/config", headers)
    assert config["defaults"]["internalChannelId"]
    channels = config["channels"]
    assert channels and all(channel["kind"] == "internal" for channel in channels)


def test_completed_import_keeps_its_own_receipts(installation: Installation) -> None:
    headers = installation.auth()
    operation_id = installation.payload["importOperationId"]
    operation = installation.get(f"/operations/{operation_id}", headers)
    assert operation["state"] == "complete"
    assert operation["summary"]["created"] >= 2
    created = [row for row in operation["rows"] if row["result"] == "created"]
    assert created and all(row["createdAssetId"] for row in created)
    assets = installation.get("/assets?limit=100", headers)
    known = {asset["id"] for asset in assets["items"]}
    assert {row["createdAssetId"] for row in created} <= known


def test_workspace_view_dashboard_reports_and_qr_are_usable(installation: Installation) -> None:
    headers = installation.auth()
    views = installation.get("/workspace/views", headers)
    assert len(views) == 1
    assert views[0]["route"]
    assert views[0]["snapshot"]

    dashboard = installation.get("/dashboard", headers)
    assert dashboard["inventory"]["total"] == (
        installation.payload["assets"] + installation.payload["importSummary"]["created"]
    )
    assert dashboard["incidents"]
    assert dashboard["maintenance"]
    assert dashboard["warranties"]

    templates = installation.get("/reports/templates", headers)
    assert templates["items"]
    asset = installation.get("/assets?limit=1", headers)["items"][0]
    qr = installation.client.get(f"{API}/reports/assets/{asset['id']}/qr", headers=headers)
    assert qr.status_code == 200, qr.text
    assert "svg" in qr.text.lower()

    jobs = installation.get("/reports/jobs", headers)
    assert jobs["items"] == [], "the demo seeds no report job; rendering needs the worker"


def test_reset_regenerates_the_same_populated_shape(installation: Installation) -> None:
    from itsm.demo.cycle import reset_demo

    headers = installation.auth()
    first = installation.get("/demo/status")
    before = {
        "assets": installation.get("/assets?limit=100", headers)["total"],
        "incidents": installation.get("/incidents?limit=100", headers)["total"],
        "alerts": installation.get("/monitoring/alerts?limit=100", headers)["total"],
        "inbox": installation.get("/notifications/inbox?limit=100", headers)["total"],
        "plans": installation.get("/maintenance/plans?limit=100", headers)["total"],
    }
    listed = [
        item
        for asset in installation.get("/assets?limit=100", headers)["items"]
        for item in installation.get(f"/assets/{asset['id']}/attachments", headers)["items"]
    ]
    assert listed
    stale = listed[0]["id"]

    # The seeded import is a real completed operation with per-row receipts.
    operation_id = installation.payload["importOperationId"]
    imported = installation.get(f"/operations/{operation_id}", headers)
    assert imported["state"] == "complete"
    assert imported["summary"]["created"] == 2
    receipts = {row["createdAssetId"] for row in imported["rows"] if row.get("createdAssetId")}
    assert len(receipts) == 2

    async def reset_under_gate() -> None:
        gate = installation.client.app.state.demo_controller.gate
        await gate.begin_reset()
        try:
            reset_demo(installation.settings, installation.client.app.state.engine)
        finally:
            gate.end_reset()

    installation.client.portal.call(reset_under_gate)
    assert installation.client.get(f"{API}/auth/me").status_code == 401
    second = installation.get("/demo/status")
    assert second["generation"] == first["generation"] + 1
    assert second["resetting"] is False

    headers = installation.auth()
    after = {
        "assets": installation.get("/assets?limit=100", headers)["total"],
        "incidents": installation.get("/incidents?limit=100", headers)["total"],
        "alerts": installation.get("/monitoring/alerts?limit=100", headers)["total"],
        "inbox": installation.get("/notifications/inbox?limit=100", headers)["total"],
        "plans": installation.get("/maintenance/plans?limit=100", headers)["total"],
    }
    assert after == before
    fresh = [
        item
        for asset in installation.get("/assets?limit=100", headers)["items"]
        for item in installation.get(f"/assets/{asset['id']}/attachments", headers)["items"]
    ]
    assert fresh and stale not in {item["id"] for item in fresh}

    # The completed import is regenerated too: the old operation is gone, the
    # imported assets come back with new ids and their own history.
    stale_operation = installation.client.get(f"{API}/operations/{operation_id}", headers=headers)
    assert stale_operation.status_code == 404
    imported_assets = {
        item["quickCode"]: item["id"]
        for item in installation.get("/assets?limit=100", headers)["items"]
    }
    assert {"DEMO-101", "DEMO-102"} <= set(imported_assets)
    assert receipts.isdisjoint(set(imported_assets.values()))
    history = installation.get(f"/assets/{imported_assets['DEMO-101']}/history", headers)
    assert any(entry["action"] == "created" for entry in history["items"])

    # The regenerated import keeps its own public row receipts, with new ids.
    # The import API has no list endpoint, so the new operation is discovered
    # through the public audit read the seed itself produced.
    audit = installation.get("/identity/audit?limit=200", headers)
    approvals = [
        event for event in audit["events"] if event["action"] == "inventory.operation_approved"
    ]
    assert approvals, "the regenerated import records its approval"
    fresh_operation_id = approvals[0]["resource"].removeprefix("operation:")
    assert fresh_operation_id != operation_id
    fresh_operation = installation.get(f"/operations/{fresh_operation_id}", headers)
    assert fresh_operation["state"] == "complete"
    assert fresh_operation["total"] == 2
    assert fresh_operation["summary"]["created"] == 2
    assert [row["result"] for row in fresh_operation["rows"]] == ["created", "created"]
    fresh_receipts = {row["createdAssetId"] for row in fresh_operation["rows"]}
    assert len(fresh_receipts) == 2
    assert fresh_receipts <= set(imported_assets.values())
    assert fresh_receipts.isdisjoint(receipts)


def test_dangerous_environments_leave_the_dataset_unchanged(
    installation: Installation,
) -> None:
    from itsm.demo.cycle import reset_demo
    from itsm.release_identity import DeploymentIdentityError

    headers = installation.auth()
    before = installation.get("/assets?limit=100", headers)["total"]
    database = Path(installation.settings.demo_data_directory) / "demo.db"
    bytes_before = database.read_bytes()

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv(RELEASE_MODE_ENV, "dev")
        with pytest.raises(DeploymentIdentityError):
            reset_demo(installation.settings, installation.client.app.state.engine)

    external = Path(installation.settings.demo_data_directory).parent / "external"
    external.mkdir(exist_ok=True)
    sentinel = external / "keep.txt"
    sentinel.write_text("unchanged", encoding="utf-8")
    previous = installation.settings.attachment_storage_path
    installation.settings.attachment_storage_path = external
    try:
        with pytest.raises(DeploymentIdentityError, match="owned"):
            reset_demo(installation.settings, installation.client.app.state.engine)
    finally:
        installation.settings.attachment_storage_path = previous

    assert database.read_bytes() == bytes_before
    assert sentinel.read_text(encoding="utf-8") == "unchanged"
    assert installation.get("/assets?limit=100", headers)["total"] == before
