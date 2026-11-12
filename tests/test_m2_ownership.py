"""M2 owner frontiers through public services and HTTP, on disposable SQLite."""

import pytest
from itsm.identity.service import IdentityService, NotFound, PermissionDenied
from itsm.workflows.service import WorkflowService
from itsm.workspace.service import WorkspaceService
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, sign_in
from tests.inventory_support import prepare, sign_in_as
from tests.test_phase6_workflows import analyze


@pytest.mark.parametrize("action", ["get", "resolve", "approve", "execute", "enqueue"])
def test_other_human_cannot_access_operation(signed_in_client, settings_factory, action):
    settings = settings_factory()
    client, auth = signed_in_client(settings)
    factory = client.app.state.session_factory
    with factory() as session:
        identity = IdentityService(session, settings)
        admin = identity.login(ADMIN_USERNAME, ADMIN_PASSWORD).principal
        identity.create_user(
            admin,
            username="other.operator",
            name="Other",
            role_id="operator",
            password="machine-identity-password-2026",
        )
    preview = analyze(client, auth, b"name\nPrivate preview\n").json()
    path = f"/api/v1/operations/{preview['id']}"
    assert client.post(f"{path}/approve", headers=auth).status_code == 200
    before = client.get(path).json()
    other_auth = sign_in_as(client, settings, "other.operator")
    response = (
        client.get(path)
        if action == "get"
        else client.post(
            f"{path}/{action}",
            headers=other_auth,
            json={"row": 0, "action": "skip"} if action == "resolve" else None,
        )
    )
    assert response.status_code == 404, response.text
    auth = sign_in(client, settings)
    assert client.get(path).json() == before
    assert client.get("/api/v1/assets/search").json()["total"] == 0
    assert client.post(f"{path}/execute", headers=auth).json()["summary"]["created"] == 1


def test_only_persisted_delegation_allows_human_machine_handoff(settings_factory):
    catalog = prepare(settings_factory)
    replacement = catalog.add_user("replacement.owner", "Replacement", "operator")
    with catalog.session() as session:
        identity = catalog.service(session)
        owner = catalog.admin()
        machine = identity.create_user(
            owner,
            username="delegated.agent",
            name="Agent",
            role_id="operator",
            actor_kind="external_agent",
            delegated_by_id=owner.actor_id,
        )
        stranger = identity.create_user(
            owner,
            username="stranger.agent",
            name="Stranger",
            role_id="operator",
            actor_kind="external_agent",
        )
        actor = identity.resolve_actor(machine.id)
        unrelated = identity.resolve_actor(stranger.id)
        workflows = WorkflowService(session, catalog.settings, identity=identity)
        preview = workflows.analyze(owner, b"name\nHandoff\n", "assets.csv")
        with pytest.raises(NotFound):
            workflows.get(actor, preview["id"])
        workflows.approve(owner, preview["id"])
        with pytest.raises(NotFound):
            workflows.execute(unrelated, preview["id"])
        with pytest.raises(NotFound):
            workflows.resolve(actor, preview["id"], 0, "skip")
        assert workflows.execute(actor, preview["id"])["summary"]["created"] == 1
        # Reverse direction: the persisted human delegator reviews a machine preview.
        prepared = workflows.analyze(actor, b"name\nMachine proposal\n", "assets.csv")
        assert workflows.get(owner, prepared["id"])["state"] == "preview"
        workflows.approve(owner, prepared["id"])
        assert workflows.execute(actor, prepared["id"])["summary"]["created"] == 1
        identity.update_user(
            owner,
            machine.id,
            username="delegated.agent",
            name="Agent",
            role_id="operator",
            actor_kind="external_agent",
            delegated_by_id=replacement.actor_id,
        )
        with pytest.raises(NotFound):
            workflows.get(actor, preview["id"])
    catalog.engine.dispose()


@pytest.mark.parametrize("action", ["update", "delete"])
def test_shared_shortcut_visibility_does_not_grant_mutation(settings_factory, action):
    catalog = prepare(settings_factory)
    other = catalog.add_user("other.admin", "Other admin", "admin")
    with catalog.session() as session:
        service = WorkspaceService(session, catalog.service(session))
        owner = catalog.admin()
        shortcut = service.create_shortcut(
            owner, {"name": "Shared", "url": "https://example.test/", "scope": "shared"}
        )
        assert service.list_shortcuts(other) == [shortcut]
        with pytest.raises(PermissionDenied):
            if action == "update":
                service.update_shortcut(other, shortcut["id"], {"name": "Hijacked"})
            else:
                service.delete_shortcut(other, shortcut["id"])
        assert service.list_shortcuts(owner) == [shortcut]
        assert service.update_shortcut(owner, shortcut["id"], {"name": "Owner"})["name"] == "Owner"
        assert service.delete_shortcut(owner, shortcut["id"])["deleted"]
        assert service.list_shortcuts(other) == []
    catalog.engine.dispose()
