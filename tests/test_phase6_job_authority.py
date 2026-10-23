"""Queued job authority: revoked executors/approvers never write and never lie."""

from __future__ import annotations

import time
from typing import Any

from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.identity.service import IdentityService
from tests.conftest import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    running_worker,
    sign_in,
)
from tests.test_inventory_api import create_asset
from tests.test_phase6_workflows import analyze

MACHINE_USERNAME = "agent.jobs"
APPROVER_USERNAME = "omar.approver"
APPROVER_PASSWORD = "approver-password-2026"


def wait_task(
    client: TestClient, task_id: str, states: set[str], timeout: float = 25.0
) -> dict[str, Any]:
    """Poll the public task endpoint until one of ``states`` is reached."""
    deadline = time.monotonic() + timeout
    task: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/tasks/{task_id}")
        assert response.status_code == 200, response.text
        task = response.json()
        if task["state"] in states:
            return task
        time.sleep(0.1)
    raise AssertionError(f"task {task_id} did not reach {sorted(states)}: {task}")


def preview_and_queue(
    client: TestClient,
    auth: dict[str, str],
    data: bytes,
    *,
    queue_auth: dict[str, str] | None = None,
) -> tuple[str, str]:
    """Preview, approve as the signing-in human, then enqueue and return ids."""
    operation = analyze(client, auth, data).json()
    path = f"/api/v1/operations/{operation['id']}"
    approved = client.post(f"{path}/approve", headers=auth)
    assert approved.status_code == 200, approved.text
    queued = client.post(f"{path}/enqueue", headers=queue_auth or auth)
    assert queued.status_code == 202, queued.text
    return operation["id"], queued.json()["jobId"]


def identity_service(settings: Settings) -> tuple[Any, IdentityService]:
    """A direct service/session against the same isolated database."""
    engine = create_engine_from_settings(settings)
    session = create_session_factory(engine)()
    return engine, IdentityService(session, settings)


def create_machine_token(settings: Settings) -> str:
    """Create an operator machine identity and return its one-time bearer token."""
    engine, service = identity_service(settings)
    try:
        admin = service.login(ADMIN_USERNAME, ADMIN_PASSWORD)
        service.create_user(
            admin.principal,
            username=MACHINE_USERNAME,
            name="Jobs agent",
            role_id="operator",
            actor_kind="external_agent",
        )
        return service.issue_machine_credential(MACHINE_USERNAME, label="queued jobs").token
    finally:
        service._session.close()
        engine.dispose()


def revoke_machine_token(settings: Settings) -> int:
    engine, service = identity_service(settings)
    try:
        return service.revoke_machine_credentials(MACHINE_USERNAME)
    finally:
        service._session.close()
        engine.dispose()


def test_queued_job_cannot_write_after_executor_logout(signed_in_client, settings_factory):
    settings = settings_factory()
    client, auth = signed_in_client(settings)
    original = create_asset(client, auth)
    history = client.get(f"/api/v1/assets/{original['id']}/history").json()
    operation_id, job_id = preview_and_queue(client, auth, b"name,serial\nRevoked job,RV-1\n")
    path = f"/api/v1/operations/{operation_id}"

    assert client.post("/api/v1/auth/logout", headers=auth).status_code == 200
    auth = sign_in(client, settings)
    with running_worker(settings):
        task = wait_task(client, job_id, {"error"})
    assert task["error"]

    assert client.get("/api/v1/assets/search").json()["total"] == 1
    assert client.get(f"/api/v1/assets/{original['id']}").json() == original
    assert client.get(f"/api/v1/assets/{original['id']}/history").json() == history
    operation = client.get(path).json()
    assert operation["state"] == "error"
    assert operation["processed"] == 0
    assert operation["summary"] == {"created": 0, "modified": 0, "omitted": 0, "failed": 0}
    assert "result" not in operation["rows"][0]


def test_queued_machine_executor_loses_authority_when_credential_is_revoked(
    signed_in_client, settings_factory
):
    settings = settings_factory()
    client, auth = signed_in_client(settings)
    original = create_asset(client, auth)
    token = create_machine_token(settings)
    machine = {"Authorization": f"Bearer {token}"}
    operation_id, job_id = preview_and_queue(
        client, auth, b"name,serial\nMachine job,MJ-1\n", queue_auth=machine
    )
    path = f"/api/v1/operations/{operation_id}"

    assert revoke_machine_token(settings) == 1
    with running_worker(settings):
        wait_task(client, job_id, {"error"})

    assert client.get(f"/api/v1/assets/{original['id']}").json() == original
    assert client.get("/api/v1/assets/search").json()["total"] == 1
    operation = client.get(path).json()
    assert operation["state"] == "error"
    assert operation["processed"] == 0


def test_queued_job_denies_when_the_approver_loses_authority(signed_in_client, settings_factory):
    settings = settings_factory()
    client, auth = signed_in_client(settings)
    original = create_asset(client, auth)
    engine, service = identity_service(settings)
    try:
        admin = service.login(ADMIN_USERNAME, ADMIN_PASSWORD)
        approver = service.create_user(
            admin.principal,
            username=APPROVER_USERNAME,
            name="Omar Approver",
            role_id="operator",
            password=APPROVER_PASSWORD,
        )
    finally:
        service._session.close()
        engine.dispose()

    operation = analyze(client, auth, b"name,serial\nApprover job,AP-1\n").json()
    path = f"/api/v1/operations/{operation['id']}"
    approver_auth = {
        "X-CSRF-Token": str(
            client.post(
                "/api/v1/auth/login",
                json={"username": APPROVER_USERNAME, "password": APPROVER_PASSWORD},
                headers={"Origin": settings.auth_origin},
            ).json()["csrfToken"]
        ),
        "Origin": settings.auth_origin,
    }
    assert client.post(f"{path}/approve", headers=approver_auth).status_code == 200, "approval"
    auth = sign_in(client, settings)
    queued = client.post(f"{path}/enqueue", headers=auth)
    assert queued.status_code == 202, queued.text

    deactivated = client.patch(
        f"/api/v1/identity/users/{approver.id}/active", json={"active": False}, headers=auth
    )
    assert deactivated.status_code == 200, deactivated.text
    with running_worker(settings):
        wait_task(client, queued.json()["jobId"], {"error"})

    assert client.get(f"/api/v1/assets/{original['id']}").json() == original
    assert client.get("/api/v1/assets/search").json()["total"] == 1
    operation = client.get(path).json()
    assert operation["state"] == "error"
    assert operation["processed"] == 0


def test_stale_queued_task_never_regresses_a_completed_operation(
    signed_in_client, settings_factory
):
    settings = settings_factory()
    client, auth = signed_in_client(settings)
    create_asset(client, auth)
    operation_id, job_id = preview_and_queue(client, auth, b"name,serial\nApplied early,AE-1\n")
    path = f"/api/v1/operations/{operation_id}"

    applied = client.post(f"{path}/execute", headers=auth)
    assert applied.status_code == 200, applied.text
    assert applied.json()["summary"]["created"] == 1
    assert client.post("/api/v1/auth/logout", headers=auth).status_code == 200
    auth = sign_in(client, settings)

    with running_worker(settings):
        task = wait_task(client, job_id, {"error"})
    assert task["error"]

    operation = client.get(path).json()
    assert operation["state"] == "complete"
    assert operation["summary"] == {"created": 1, "modified": 0, "omitted": 0, "failed": 0}
    assert [row["result"] for row in operation["rows"]] == ["created"]
    assert client.get("/api/v1/assets/search").json()["total"] == 2


def test_queued_execution_preserves_the_trusted_source(signed_in_client, settings_factory):
    settings = settings_factory()
    client, auth = signed_in_client(settings)
    operation_id, job_id = preview_and_queue(client, auth, b"name,serial\nSourced job,SC-1\n")

    with running_worker(settings):
        wait_task(client, job_id, {"complete"})

    created = client.get("/api/v1/assets/search").json()
    assert created["total"] == 1
    asset_id = created["items"][0]["id"]
    history = client.get(f"/api/v1/assets/{asset_id}/history").json()
    assert {item["source"] for item in history["items"]} == {"rest"}
    assert client.get(f"/api/v1/operations/{operation_id}").json()["state"] == "complete"
