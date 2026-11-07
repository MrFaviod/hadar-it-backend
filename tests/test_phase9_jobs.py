"""Phase 9 durable report jobs: bounded batches, retry and cleanup ordering."""

from __future__ import annotations

import threading
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from itsm.attachments.storage import LocalBlobStorage
from itsm.identity.clock import utcnow
from itsm.identity.hashing import hash_token
from itsm.identity.models import IdentityRolePolicy, IdentitySession
from itsm.identity.service import NotFound, ValidationFailed
from itsm.reports.models import ReportDocument, ReportJob
from itsm.reports.rendering import RenderTimeout
from itsm.reports.schemas import ReportRequest
from itsm.reports.service import ReportService
from sqlalchemy import delete, select, update
from tests.inventory_support import Catalog, asset_values, prepare
from tests.test_phase9_reports import RecordingQueue, reports, seed, session_principal


@pytest.fixture
def catalog(settings_factory: Any, tmp_path: Path) -> Catalog:
    return prepare(
        settings_factory,
        attachment_storage_path=tmp_path / "blobs",
        report_base_url="https://itam.example.com",
        report_retention_days=30,
    )


class FlakyStorage:
    """Blob storage that fails a bounded number of writes/deletes."""

    def __init__(
        self,
        root: Path,
        *,
        put_failures: int = 0,
        delete_failures: int = 0,
    ) -> None:
        self.inner = LocalBlobStorage(root)
        self.put_failures = put_failures
        self.delete_failures = delete_failures

    def put(self, key: str, data: bytes) -> None:
        if self.put_failures:
            self.put_failures -= 1
            raise OSError("simulated write failure")
        self.inner.put(key, data)

    def read(self, key: str, limit: int) -> bytes:
        return self.inner.read(key, limit)

    def delete(self, key: str) -> None:
        if self.delete_failures:
            self.delete_failures -= 1
            raise OSError("simulated delete failure")
        self.inner.delete(key)


def service_with(catalog: Catalog, storage: Any, queue: Any = None) -> ReportService:
    return ReportService(
        catalog.factory(), settings=catalog.settings, storage=storage, task_queue=queue
    )


def test_consolidated_job_enqueues_downloads_and_deduplicates(catalog: Catalog) -> None:
    first = seed(catalog, asset_values(quick_code="JOB-001", name="Servidor Uno"))
    second = seed(catalog, asset_values(quick_code="JOB-002", name="Servidor Dos"))
    queue = RecordingQueue()
    service = reports(catalog, queue)
    principal = session_principal(catalog)
    job = service.generate(principal, ReportRequest(family="inventory", assetIds=[first, second]))
    assert job["status"] == "queued"
    assert job["total"] == 2
    assert job["processed"] == 0
    assert queue.calls == [(job["id"], job["id"])]

    finished = service.execute(job["id"])
    assert finished["status"] == "completed", finished
    assert finished["processed"] == 2
    assert finished["errors"] == []
    assert len(finished["documents"]) == 1
    document = finished["documents"][0]
    assert document["assetId"] is None
    assert document["downloadUrl"] == (f"/api/v1/reports/documents/{document['id']}/download")
    _, data = service.download(principal, document["id"])
    assert data.startswith(b"%PDF-")

    again = service.execute(job["id"])
    assert again["status"] == "completed"
    assert len(again["documents"]) == 1
    with catalog.session() as session:
        count = len(session.execute(select(ReportDocument)).scalars().all())
    assert count == 1


def test_individual_mode_produces_one_document_per_asset(catalog: Catalog) -> None:
    first = seed(catalog, asset_values(quick_code="BATCH-001", name="Portátil Uno"))
    second = seed(catalog, asset_values(quick_code="BATCH-002", name="Portátil Dos"))
    service = reports(catalog)
    principal = session_principal(catalog)
    job = service.generate(
        principal,
        ReportRequest(
            family="inventory",
            assetIds=[first, second],
            mode="individual",
            fields=["id", "quickCode", "name"],
        ),
    )
    finished = service.execute(job["id"])
    assert finished["status"] == "completed", finished
    assert finished["processed"] == 2
    assert {document["assetId"] for document in finished["documents"]} == {first, second}
    assert all(
        document["name"].startswith(("BATCH-001", "BATCH-002"))
        for document in finished["documents"]
    )
    for document in finished["documents"]:
        _, data = service.download(principal, document["id"])
        assert data.startswith(b"%PDF-")


def test_retryable_storage_failure_requeues_without_partial_document(catalog: Catalog) -> None:
    seed(catalog, asset_values(quick_code="RETRY-001"))
    storage = FlakyStorage(catalog.settings.attachment_storage_path, put_failures=1)
    service = service_with(catalog, storage)
    principal = session_principal(catalog)
    job = service.generate(principal, ReportRequest(family="inventory"))
    with pytest.raises(OSError):
        service.execute(job["id"])
    retried = service.job(principal, job["id"])
    assert retried["status"] == "queued"
    assert retried["documents"] == []
    assert any("simulated write failure" in error["message"] for error in retried["errors"])

    finished = service.execute(job["id"])
    assert finished["status"] == "completed", finished
    assert len(finished["documents"]) == 1
    assert finished["documents"][0]["size"] > 0


def test_retryable_renderer_timeout_requeues_once(catalog: Catalog) -> None:
    seed(catalog, asset_values(quick_code="RENDER-001"))
    service = reports(catalog)
    principal = session_principal(catalog)
    job = service.generate(principal, ReportRequest(family="inventory"))
    original_render = service._render

    def fail_once(document: Any) -> bytes:
        raise RenderTimeout("renderer timed out")

    service._render = fail_once
    with pytest.raises(RenderTimeout):
        service.execute(job["id"])
    retried = service.job(principal, job["id"])
    assert retried["status"] == "queued"
    assert retried["documents"] == []
    assert any("renderer timed out" in error["message"] for error in retried["errors"])

    service._render = original_render
    finished = service.execute(job["id"])
    assert finished["status"] == "completed", finished
    assert len(finished["documents"]) == 1


def test_revoked_executor_session_leaves_no_document(catalog: Catalog) -> None:
    seed(catalog, asset_values(quick_code="AUTH-001"))
    service = reports(catalog)
    principal = session_principal(catalog)
    job = service.generate(principal, ReportRequest(family="inventory"))
    with catalog.session() as session:
        session.execute(
            update(IdentitySession)
            .where(IdentitySession.id == principal.session_id)
            .values(revoked_at=utcnow())
        )
        session.commit()
    finished = service.execute(job["id"])
    assert finished["status"] == "failed"
    assert finished["documents"] == []
    assert finished["errors"]
    assert not (
        catalog.settings.attachment_storage_path.exists()
        and list(catalog.settings.attachment_storage_path.iterdir())
    )
    with catalog.session() as session:
        assert session.execute(select(ReportDocument)).first() is None


def test_lost_issuer_permission_fails_the_job(catalog: Catalog) -> None:
    seed(catalog, asset_values(quick_code="AUTH-002"))
    service = reports(catalog)
    principal = session_principal(catalog)
    job = service.generate(principal, ReportRequest(family="inventory"))
    with catalog.session() as session:
        session.execute(
            delete(IdentityRolePolicy).where(
                IdentityRolePolicy.role_id == "admin",
                IdentityRolePolicy.resource == "assets",
                IdentityRolePolicy.operation == "view",
            )
        )
        session.commit()
    finished = service.execute(job["id"])
    assert finished["status"] == "failed"
    assert finished["documents"] == []

    with catalog.session() as session:
        session.add(IdentityRolePolicy(role_id="admin", resource="assets", operation="view"))
        session.commit()
    # The failed job is terminal; a new request would be required to retry.
    assert service.job(principal, job["id"])["status"] == "failed"


def test_job_visibility_is_owner_or_admin(catalog: Catalog) -> None:
    seed(catalog, asset_values(quick_code="OWNER-001"))
    service = reports(catalog)
    principal = session_principal(catalog)
    job = service.generate(principal, ReportRequest(family="inventory"))
    service.execute(job["id"])
    document_id = service.job(principal, job["id"])["documents"][0]["id"]

    reader = catalog.add_user("reader-jobs", "Reader Jobs", "user")
    with pytest.raises(NotFound):
        service.job(reader, job["id"])
    with pytest.raises(NotFound):
        service.download(reader, document_id)
    assert service.jobs(reader)["items"] == []
    assert service.jobs(principal)["items"][0]["id"] == job["id"]
    with pytest.raises(ValidationFailed):
        service.jobs(principal, limit=0)
    with pytest.raises(ValidationFailed):
        service.jobs(principal, limit=101)


def test_enqueue_failure_marks_job_failed(catalog: Catalog) -> None:
    class BrokenQueue:
        def submit_report(self, job_id: str, task_id: str) -> None:
            raise RuntimeError("queue offline")

    seed(catalog, asset_values(quick_code="QUEUE-001"))
    service = reports(catalog, BrokenQueue())
    principal = session_principal(catalog)
    with pytest.raises(RuntimeError, match="queue offline"):
        service.generate(principal, ReportRequest(family="inventory"))
    with catalog.session() as session:
        job = session.execute(select(ReportJob)).scalars().one()
        assert job.status == "failed"


def test_cleanup_tombstones_first_then_retries_blob_delete(catalog: Catalog) -> None:
    seed(catalog, asset_values(quick_code="CLEAN-001"))
    storage = FlakyStorage(catalog.settings.attachment_storage_path, delete_failures=2)
    service = service_with(catalog, storage)
    principal = session_principal(catalog)
    job = service.generate(principal, ReportRequest(family="inventory"))
    service.execute(job["id"])
    document = service.job(principal, job["id"])["documents"][0]
    with catalog.session() as session:
        row = session.get(ReportDocument, document["id"])
        assert row is not None
        key = row.blob_key
        session.execute(
            update(ReportDocument)
            .where(ReportDocument.id == row.id)
            .values(created_at=utcnow() - timedelta(days=31))
        )
        session.commit()

    first = service.cleanup()
    assert first["deleted"] == 0
    assert first["pending"] >= 1
    with catalog.session() as session:
        row = session.get(ReportDocument, document["id"])
        assert row is not None and row.deleted_at is not None
        assert row.delete_error
    # Tombstoned metadata is already invisible even while bytes wait for retry.
    with pytest.raises(NotFound):
        service.download(principal, document["id"])
    assert storage.inner.read(key, 10 * 1024 * 1024).startswith(b"%PDF-")

    second = service.cleanup()
    assert second == {"deleted": 1, "pending": 0}
    with catalog.session() as session:
        assert session.get(ReportDocument, document["id"]) is None
    with pytest.raises(FileNotFoundError):
        storage.inner.read(key, 1024)


def _claim(catalog: Catalog, job_id: str, claimed_at: Any) -> None:
    with catalog.session() as session:
        session.execute(
            update(ReportJob)
            .where(ReportJob.id == job_id)
            .values(status="running", claimed_at=claimed_at)
        )
        session.commit()


def _assert_no_output(catalog: Catalog) -> None:
    assert not (
        catalog.settings.attachment_storage_path.exists()
        and list(catalog.settings.attachment_storage_path.iterdir())
    )
    with catalog.session() as session:
        assert session.execute(select(ReportDocument)).first() is None


def test_duplicate_delivery_of_a_fresh_running_claim_does_nothing(catalog: Catalog) -> None:
    seed(catalog, asset_values(quick_code="CLAIM-001"))
    service = reports(catalog)
    job = service.generate(session_principal(catalog), ReportRequest(family="inventory"))
    _claim(catalog, job["id"], utcnow())

    duplicate = service.execute(job["id"])
    assert duplicate["status"] == "running"
    assert duplicate["documents"] == []
    assert duplicate["errors"] == []
    _assert_no_output(catalog)


def test_stale_running_claim_is_taken_over_once(catalog: Catalog) -> None:
    seed(catalog, asset_values(quick_code="CLAIM-002"))
    service = reports(catalog)
    principal = session_principal(catalog)
    job = service.generate(principal, ReportRequest(family="inventory"))
    _claim(catalog, job["id"], utcnow() - timedelta(hours=1))

    finished = service.execute(job["id"])
    assert finished["status"] == "completed", finished
    assert len(finished["documents"]) == 1
    _, data = service.download(principal, finished["documents"][0]["id"])
    assert data.startswith(b"%PDF-")


def test_concurrent_execute_produces_one_document(catalog: Catalog) -> None:
    seed(catalog, asset_values(quick_code="CLAIM-003"))
    principal = session_principal(catalog)
    job = reports(catalog).generate(principal, ReportRequest(family="inventory"))
    outcomes: list[dict[str, Any]] = []
    failures: list[BaseException] = []
    guard = threading.Lock()
    barrier = threading.Barrier(4)

    def attempt() -> None:
        service = reports(catalog)
        try:
            barrier.wait(timeout=10)
            outcome = service.execute(job["id"])
        except BaseException as exc:  # asserted below, never swallowed
            with guard:
                failures.append(exc)
            return
        with guard:
            outcomes.append(outcome)

    threads = [threading.Thread(target=attempt) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert failures == []
    assert len(outcomes) == 4
    assert {outcome["status"] for outcome in outcomes} <= {"running", "completed"}
    assert any(outcome["status"] == "completed" for outcome in outcomes)
    with catalog.session() as session:
        documents = session.execute(select(ReportDocument)).scalars().all()
    assert len(documents) == 1
    assert len(list(catalog.settings.attachment_storage_path.iterdir())) == 1


def test_machine_job_without_credential_fails_closed(catalog: Catalog) -> None:
    machine, _ = catalog.add_machine("report-machine", "Report machine", "operator")
    seed(catalog, asset_values(quick_code="MACHINE-001"))
    service = reports(catalog)
    job = service.generate(machine, ReportRequest(family="inventory"))

    finished = service.execute(job["id"])
    assert finished["status"] == "failed"
    assert finished["documents"] == []
    assert any("credential" in error["message"] for error in finished["errors"])
    _assert_no_output(catalog)


def test_machine_job_with_current_credential_completes(catalog: Catalog) -> None:
    machine, token = catalog.add_machine("report-machine", "Report machine", "operator")
    seed(catalog, asset_values(quick_code="MACHINE-002"))
    service = reports(catalog)
    job = service.generate(
        machine,
        ReportRequest(family="inventory"),
        credential_digest=hash_token(token),
    )

    finished = service.execute(job["id"])
    assert finished["status"] == "completed", finished
    assert len(finished["documents"]) == 1
    _, data = service.download(machine, finished["documents"][0]["id"])
    assert data.startswith(b"%PDF-")


def test_machine_credential_revoked_before_execution_leaves_no_document(
    catalog: Catalog,
) -> None:
    machine, token = catalog.add_machine("report-machine", "Report machine", "operator")
    seed(catalog, asset_values(quick_code="MACHINE-003"))
    service = reports(catalog)
    job = service.generate(
        machine,
        ReportRequest(family="inventory"),
        credential_digest=hash_token(token),
    )
    catalog.revoke_machine("report-machine")

    finished = service.execute(job["id"])
    assert finished["status"] == "failed"
    assert finished["documents"] == []
    assert any("credential" in error["message"] for error in finished["errors"])
    _assert_no_output(catalog)
