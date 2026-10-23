"""A real Huey consumer executes the registered maintenance periodic task."""

from datetime import datetime

from itsm.tasks.runtime import build_runtime
from sqlalchemy import text
from tests.conftest import running_worker
from tests.test_inventory_api import api_values


def test_real_worker_prepares_due_reminders(signed_in_client, tmp_path):
    import time

    client, auth = signed_in_client()
    created = client.post("/api/v1/assets", headers=auth, json=api_values(name="Periodic worker"))
    assert created.status_code == 201, created.text
    asset_id = created.json()["id"]
    plan = client.post(
        "/api/v1/maintenance/plans",
        headers=auth,
        json={
            "assetId": asset_id,
            "maintenanceType": "worker_probe",
            "intervalMonths": 6,
            "dueOn": "2020-01-01",
        },
    )
    assert plan.status_code == 201, plan.text
    plan_id = plan.json()["id"]
    runtime = build_runtime(client.app.state.settings)
    periodic = [
        task
        for task in runtime.huey.read_periodic(datetime(2026, 10, 23, 12, 0))
        if task.name == "maintenance_due_scan"
    ]
    assert len(periodic) == 1
    log_path = tmp_path / "maintenance-worker.log"
    with running_worker(client.app.state.settings, log_path=log_path):
        # Use the scheduler-produced task, not a direct domain function call.
        runtime.huey.enqueue(periodic[0])
        deadline = time.monotonic() + 20
        found = False
        while time.monotonic() < deadline:
            with client.app.state.session_factory() as session:
                found = session.scalar(
                    text(
                        "SELECT id FROM maintenance_reminders "
                        "WHERE plan_id = :id AND stage = 'overdue'"
                    ),
                    {"id": plan_id},
                )
            if found:
                break
            time.sleep(0.1)
        assert found, "registered periodic work did not produce its durable reminder"
        runtime.huey.enqueue(periodic[0])
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if log_path.read_text().count('"event": "maintenance.reminders_prepared"') >= 2:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("second periodic execution was not observed")
    with client.app.state.session_factory() as session:
        count = session.scalar(
            text(
                "SELECT count(*) FROM maintenance_reminders "
                "WHERE plan_id = :id AND stage = 'overdue'"
            ),
            {"id": plan_id},
        )
        assert count == 1
    current = client.get("/api/v1/maintenance/plans/" + plan_id)
    assert current.json()["lastCompletedOn"] is None
    assert current.json()["dueOn"] == "2020-01-01"
