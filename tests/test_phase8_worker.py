"""Real Huey consumer dispatches durable internal notifications without duplicates."""

from __future__ import annotations

import time
from datetime import datetime

from itsm.tasks import create_task_queue
from itsm.tasks.adapter import TaskState
from itsm.tasks.runtime import build_runtime
from sqlalchemy import text
from tests.conftest import running_worker


def test_real_worker_delivers_internal_event_once_and_preserves_read_state(
    signed_in_client, tmp_path
):
    from itsm.notifications.service import record_alert_event

    client, auth = signed_in_client()
    settings = client.app.state.settings
    with client.app.state.session_factory() as session:
        record_alert_event(
            session,
            settings,
            alert_id="worker-alert-cycle",
            event_key="firing:2026-10-23T12:00:00Z",
            event_type="firing",
            severity="critical",
            asset_id=None,
            title="Worker durable alert",
            body="La comprobación requiere atención.",
            url=None,
        )
        session.commit()
    runtime = build_runtime(settings)
    periodic = next(
        task
        for task in runtime.huey.read_periodic(datetime(2026, 10, 23, 12, 0))
        if task.name == "notification_dispatch"
    )
    log_path = tmp_path / "phase8-worker.log"
    with running_worker(settings, log_path=log_path):
        runtime.huey.enqueue(periodic)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            inbox = client.get("/api/v1/notifications/inbox", headers=auth)
            assert inbox.status_code == 200, inbox.text
            items = inbox.json()["items"]
            matches = [item for item in items if item["alertId"] == "worker-alert-cycle"]
            if matches:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("real consumer did not deliver the durable notification")
        notification = matches[0]
        assert notification["unread"] is True
        marked = client.post(f"/api/v1/notifications/inbox/{notification['id']}/read", headers=auth)
        assert marked.status_code == 200, marked.text
        assert marked.json()["unread"] is False
        queue = create_task_queue(settings)
        repeated = queue.submit_notifications()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            state = queue.get_status(repeated.task_id)
            if state and state.state in {TaskState.COMPLETE, TaskState.ERROR}:
                break
            time.sleep(0.1)
        assert state is not None and state.state == TaskState.COMPLETE, state
    with client.app.state.session_factory() as session:
        assert (
            session.scalar(
                text("SELECT count(*) FROM notification_inbox WHERE alert_id = :id"),
                {"id": "worker-alert-cycle"},
            )
            == 1
        )
    inbox = client.get("/api/v1/notifications/inbox", headers=auth).json()["items"]
    assert next(item for item in inbox if item["id"] == notification["id"])["unread"] is False
