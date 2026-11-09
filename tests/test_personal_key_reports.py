"""Report executors retain live personal-key authority across queue boundaries."""

from datetime import timedelta

import pytest
from itsm.identity.clock import utcnow
from itsm.identity.service import IdentityService
from itsm.reports.schemas import ReportRequest
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import prepare
from tests.test_phase9_reports import RecordingQueue, reports


@pytest.mark.parametrize("loss", [None, "revoke", "expire", "demote"])
def test_personal_report_executor_revalidates_key(settings_factory, tmp_path, monkeypatch, loss):
    catalog = prepare(
        settings_factory,
        attachment_storage_path=tmp_path / "attachments",
        extension_workspace_path=tmp_path / "extension-workspaces",
        extension_data_path=tmp_path / "extension-data",
    )
    try:
        with catalog.session() as session:
            identity = IdentityService(session, catalog.settings)
            owner = identity.login(ADMIN_USERNAME, ADMIN_PASSWORD).principal
            role = identity.create_role(owner, name="Report executor", permissions=["assets.view"])
            user = identity.create_user(
                owner,
                username="report.executor",
                name="Executor",
                role_id=role.id,
                password=ADMIN_PASSWORD,
            )
            executor = identity.login(user.username, ADMIN_PASSWORD).principal
            key = identity.issue_api_key(
                executor,
                label="Report key",
                permissions=["assets.view"],
                expires_at=utcnow() + timedelta(hours=1),
            )
            principal = identity.authenticate_token(key["token"]).principal
        service = reports(catalog, RecordingQueue())
        rendered, stored = [], []

        def render(document):
            rendered.append(1)
            return b"%PDF-1.7\nTest-only bounded renderer\n%%EOF"

        monkeypatch.setattr(service, "_render", render)
        storage = service._storage_backend()
        original_put = storage.put

        def put(*args, **kwargs):
            stored.append(1)
            return original_put(*args, **kwargs)

        monkeypatch.setattr(storage, "put", put)
        monkeypatch.setattr(service, "_storage_backend", lambda: storage)
        job = service.generate(principal, ReportRequest(family="inventory", output="pdf"))
        assert job["status"] == "queued"
        if loss == "expire":
            future = utcnow() + timedelta(hours=2)
            monkeypatch.setattr(
                "itsm.reports.service.IdentityService",
                lambda session, settings: IdentityService(session, settings, now=lambda: future),
            )
        elif loss:
            with catalog.session() as session:
                identity = IdentityService(session, catalog.settings)
                if loss == "revoke":
                    identity.revoke_api_key(executor, key["id"])
                else:
                    identity.update_role(owner, role.id, name="Report executor", permissions=[])
        result = service.execute(job["id"])
        assert result["status"] == ("failed" if loss else "completed")
        public = service.job(owner, job["id"])
        assert public["documents"] == [] if loss else len(public["documents"]) == 1
        assert rendered == ([] if loss else [1])
        assert stored == ([] if loss else [1])
        if loss:
            assert public["processed"] == 0
        else:
            assert service.download(principal, public["documents"][0]["id"])[1].startswith(b"%PDF-")
    finally:
        catalog.engine.dispose()
