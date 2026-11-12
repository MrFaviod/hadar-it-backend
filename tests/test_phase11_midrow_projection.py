"""Frozen permission names must never cache executor or approver authority."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from itsm.identity.service import Conflict, IdentityService
from itsm.main import create_app
from itsm.workflows.service import WorkflowService
from tests.test_inventory_api import create_asset
from tests.test_phase6_workflows import analyze


@pytest.mark.parametrize("revoked", ["executor", "approver"])
@pytest.mark.parametrize("failure_path", [False, True])
def test_projection_revalidates_midrow_assignment_revocation(
    signed_in_client, settings_factory, monkeypatch, revoked, failure_path
):
    settings = settings_factory()
    admin, auth = signed_in_client(settings)
    first = create_asset(admin, auth, quick_code="FIRST-MANUAL", name="First original")
    second = create_asset(admin, auth, quick_code="SECOND-MANUAL", name="Second original")
    roles = {}
    users = {}
    for who in ("approver", "executor"):
        role = admin.post(
            "/api/v1/identity/roles",
            json={
                "name": "Midrow " + who,
                "permissions": ["assets.view", "assets.edit", "assets.assign"],
            },
            headers=auth,
        )
        assert role.status_code == 201, role.text
        roles[who] = role.json()["id"]
        user = admin.post(
            "/api/v1/identity/users",
            json={
                "username": "midrow." + who,
                "name": who,
                "roleId": roles[who],
                **(
                    {"password": "midrow-password-2026"}
                    if who == "approver"
                    else {"actorKind": "external_agent", "delegatedById": users["approver"]}
                ),
            },
            headers=auth,
        )
        assert user.status_code == 201, user.text
        users[who] = user.json()["id"]

    with TestClient(create_app(settings)) as executor, TestClient(create_app(settings)) as approver:
        headers = {}
        for who, client in (("executor", executor), ("approver", approver)):
            if who == "executor":
                with admin.app.state.session_factory() as session:
                    token = (
                        IdentityService(session, settings)
                        .issue_machine_credential("midrow.executor")
                        .token
                    )
                client.headers["Authorization"] = "Bearer " + token
                headers[who] = {"Origin": settings.auth_origin}
                continue
            login = client.post(
                "/api/v1/auth/login",
                json={"username": "midrow." + who, "password": "midrow-password-2026"},
                headers={"Origin": settings.auth_origin},
            )
            assert login.status_code == 200, login.text
            headers[who] = {
                "Origin": settings.auth_origin,
                "X-CSRF-Token": login.json()["csrfToken"],
            }
        data = (
            f"id,name,responsible\n{first['id']},First changed,New owner\n"
            f"{second['id']},Second changed,\n"
        ).encode()
        preview = analyze(executor, headers["executor"], data)
        assert preview.status_code == 200, preview.text
        operation = preview.json()
        path = "/api/v1/operations/" + operation["id"]
        assert "responsible" in operation["rows"][0]["values"]
        assert "responsible" not in operation["rows"][1]["values"]
        # An unrelated administrator cannot acquire the private machine proposal.
        denied = admin.post(path + "/approve", headers=auth)
        assert denied.status_code == 404, denied.text
        approved = approver.post(path + "/approve", headers=headers["approver"])
        assert approved.status_code == 200, approved.text
        original = WorkflowService._apply_row

        def apply_then_revoke(service, principal, operation_id, index, permissions):
            if index == 1 and failure_path:
                raise Conflict("independent row failure after revocation")
            result = original(service, principal, operation_id, index, permissions)
            if index == 0:
                frozen = approver.post(
                    path + "/resolve",
                    json={
                        "row": 1,
                        "action": "update",
                        "assetId": second["id"],
                        "values": {"name": "Sneaked"},
                    },
                    headers=headers["approver"],
                )
                assert frozen.status_code == 409, frozen.text
                changed = admin.put(
                    "/api/v1/identity/roles/" + roles[revoked],
                    json={"permissions": ["assets.view", "assets.edit"]},
                    headers=auth,
                )
                assert changed.status_code == 200, changed.text
            return result

        monkeypatch.setattr(WorkflowService, "_apply_row", apply_then_revoke)
        response = executor.post(path + "/execute", headers=headers["executor"])
        assert response.status_code == 403, response.text
        page = approver.get(path).json()
        assert page["processed"] == 1
        assert page["summary"] == {"created": 0, "modified": 1, "omitted": 0, "failed": 0}
        assert page["state"] == "running"
        assert admin.get("/api/v1/assets/" + first["id"]).json()["name"] == "First changed"
        assert admin.get("/api/v1/assets/" + second["id"]).json() == second
        assert "result" not in page["rows"][1]
