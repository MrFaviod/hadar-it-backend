"""Expired queued machine credentials cannot mutate inventory or produce reports."""

from datetime import UTC, datetime, timedelta

from itsm.identity.hashing import hash_token
from itsm.identity.models import IdentityCredential
from sqlalchemy import select
from tests.conftest import running_worker
from tests.test_phase6_job_authority import (
    create_machine_token,
    identity_service,
    preview_and_queue,
    wait_task,
)
from tests.test_phase9_reports import (
    RecordingQueue,
    ReportRequest,
    asset_values,
    catalog,  # noqa: F401 - pytest fixture
    reports,
    seed,
)


def expire_token(settings, token):
    engine, identity = identity_service(settings)
    try:
        credential = identity._session.scalar(
            select(IdentityCredential).where(IdentityCredential.token_digest == hash_token(token))
        )
        credential.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        identity._session.commit()
    finally:
        identity._session.close()
        engine.dispose()


def test_expired_machine_worker_writes_nothing(signed_in_client, settings_factory):
    settings = settings_factory()
    client, auth = signed_in_client(settings)
    token = create_machine_token(settings)
    operation_id, job_id = preview_and_queue(
        client, auth, b"name\nExpired job\n", queue_auth={"Authorization": "Bearer " + token}
    )
    expire_token(settings, token)
    with running_worker(settings):
        task = wait_task(client, job_id, {"error"})
    assert task["error"]
    operation = client.get(f"/api/v1/operations/{operation_id}").json()
    assert operation["state"] == "error" and operation["processed"] == 0
    assert operation["summary"] == {"created": 0, "modified": 0, "omitted": 0, "failed": 0}
    assert client.get("/api/v1/assets/search").json()["total"] == 0


def test_expired_machine_report_produces_no_documents(catalog):  # noqa: F811
    principal, token = catalog.add_machine("report.expiry", "Report expiry", "operator")
    seed(catalog, asset_values(quick_code="EXPIRY-REPORT"))
    queue = RecordingQueue()
    service = reports(catalog, queue)
    job = service.generate(
        principal,
        ReportRequest(family="inventory", output="csv"),
        credential_digest=hash_token(token),
    )
    expire_token(catalog.settings, token)
    finished = service.execute(job["id"])
    assert finished["status"] == "failed", finished
    assert finished["documents"] == []
    assert finished["processed"] == 0
