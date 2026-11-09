"""Personal credentials cannot regain ambient browser authority."""

from types import SimpleNamespace

import pytest
from itsm.agent_integrations.service import AgentIntegrationService
from itsm.agents.api import _runtime
from itsm.agents.isolation import is_privileged_human, runs_in_isolation
from itsm.identity.service import IdentityService, NotFound, PermissionDenied
from itsm.reports.schemas import ReportRequest
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.test_identity_api_keys import api as _api
from tests.test_identity_api_keys import bearer, issue
from tests.test_phase9_reports import RecordingQueue, reports

api = _api


@pytest.mark.parametrize(
    "authorization", ["", "Bearer", "Bearer ", "Basic invalid", "Bearer invalid"]
)
def test_present_invalid_authorization_never_uses_cookie(api, authorization):
    _catalog, client, headers = api
    before = client.get("/api/v1/assets/search").json()
    denied = {**headers, "Authorization": authorization}
    assert client.get("/api/v1/auth/me", headers=denied).status_code == 401
    assert (
        client.post("/api/v1/assets", json={"name": "Must not exist"}, headers=denied).status_code
        == 401
    )
    assert client.get("/api/v1/assets/search").json() == before
    assert client.get("/api/v1/auth/me").status_code == 200
    assert (
        client.post("/api/v1/assets", json={"name": "Guarded cookie"}, headers=headers).status_code
        == 201
    )


def test_personal_keys_never_select_privileged_runtime(api):
    catalog, client, headers = api
    key = issue(client, headers, permissions=["assets.view"])
    integration = AgentIntegrationService(catalog.settings, catalog.factory())
    privileged_runtime, isolated_runtime = object(), object()
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                settings=catalog.settings,
                session_factory=catalog.factory(),
                agent_runtime=privileged_runtime,
                isolated_runtime=isolated_runtime,
            )
        )
    )
    with catalog.session() as db:
        identity = IdentityService(db, catalog.settings)
        principal = identity.authenticate_token(key["token"]).principal
        browser = identity.login(ADMIN_USERNAME, ADMIN_PASSWORD).principal
        assert not is_privileged_human(db, catalog.settings, principal)
        assert runs_in_isolation(db, catalog.settings, principal)
        assert not integration._privileged_human(db, principal)
        assert is_privileged_human(db, catalog.settings, browser)
        assert not runs_in_isolation(db, catalog.settings, browser)
    assert _runtime(request, principal) is isolated_runtime
    assert _runtime(request, browser) is privileged_runtime


def test_report_owner_boundary_does_not_inherit_key_owner_admin_role(api):
    catalog, client, headers = api
    other = catalog.add_user("report.other", "Report Other", "operator")
    service = reports(catalog, RecordingQueue())
    job = service.generate(other, ReportRequest(family="inventory", output="csv"))
    completed = service.execute(job["id"])
    assert completed["status"] == "completed"
    document_id = completed["documents"][0]["id"]
    key = issue(client, headers, permissions=["assets.view"])
    with catalog.session() as db:
        identity = IdentityService(db, catalog.settings)
        principal = identity.authenticate_token(key["token"]).principal
        browser = identity.login(ADMIN_USERNAME, ADMIN_PASSWORD).principal
    assert service.job(browser, job["id"])["id"] == job["id"]
    assert service.download(browser, document_id)[1]
    assert service.job(other, job["id"])["id"] == job["id"]
    assert service.download(other, document_id)[1]
    administrator = catalog.add_user("report.admin", "Report Admin", "admin")
    assert service.job(administrator, job["id"])["id"] == job["id"]
    with catalog.session() as db:
        IdentityService(db, catalog.settings).update_user(
            browser, administrator.actor_id, role_id="user"
        )
    with pytest.raises(NotFound):
        service.job(administrator, job["id"])
    with pytest.raises(NotFound):
        service.download(administrator, document_id)
    with pytest.raises(NotFound):
        service.job(principal, job["id"])
    with pytest.raises(NotFound):
        service.download(principal, document_id)
    assert client.get(f"/api/v1/reports/jobs/{job['id']}", headers=bearer(key)).status_code == 404
    assert (
        client.get(
            f"/api/v1/reports/documents/{document_id}/download", headers=bearer(key)
        ).status_code
        == 404
    )
    own = service.generate(principal, ReportRequest(family="inventory", output="csv"))
    assert service.execute(own["id"])["status"] == "completed"
    assert service.job(principal, own["id"])["id"] == own["id"]
    client.delete(f"/api/v1/auth/api-keys/{key['id']}", headers=headers)
    with pytest.raises(PermissionDenied):
        service.job(principal, own["id"])
