"""Personal keys through the public HTTP contract and canonical authorization."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from itsm.identity.clock import utcnow
from itsm.identity.service import IdentityService, PermissionDenied
from itsm.main import create_app
from tests.conftest import sign_in
from tests.inventory_support import prepare, sign_in_as

KEYS = "/api/v1/auth/api-keys"


@pytest.fixture
def api(settings_factory, tmp_path):
    catalog = prepare(
        settings_factory,
        attachment_storage_path=tmp_path / "attachments",
        extension_workspace_path=tmp_path / "extension-workspaces",
        extension_data_path=tmp_path / "extension-data",
    )
    with TestClient(create_app(catalog.settings)) as client:
        headers = sign_in(client, catalog.settings)
        yield catalog, client, headers
    catalog.engine.dispose()


def issue(client, headers, **values):
    response = client.post(KEYS, json={"label": "External test", **values}, headers=headers)
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def bearer(key):
    return {"Authorization": "Bearer " + key["token"]}


def test_personal_key_lifecycle_and_same_rest_ceiling(api, caplog):
    catalog, client, headers = api
    key = issue(client, headers, permissions=["assets.view"])
    assert key["permissions"] == ["assets.view"]
    assert key["expiresAt"] is not None
    listed = client.get(KEYS)
    assert listed.status_code == 200
    assert listed.headers["cache-control"] == "no-store"
    assert "token" not in listed.json()["items"][0]
    assert key["token"] not in listed.text
    with TestClient(create_app(catalog.settings)) as external:
        assert external.get("/api/v1/assets", headers=bearer(key)).status_code == 200
        assert external.get("/api/v1/auth/me", headers=bearer(key)).json()["permissions"] == [
            "assets.view"
        ]
        assert (
            external.post(
                "/api/v1/assets", json={"name": "Denied"}, headers=bearer(key)
            ).status_code
            == 403
        )
        assert external.get(KEYS, headers=bearer(key)).status_code == 403
        assert (
            external.post(KEYS, json={"label": "Launder"}, headers=bearer(key)).status_code == 403
        )
        assert external.delete(KEYS + "/" + key["id"], headers=bearer(key)).status_code == 403
        assert catalog.asset_count() == 0
        revoked = client.delete(KEYS + "/" + key["id"], headers=headers)
        assert revoked.status_code == 200
        assert revoked.json()["revokedAt"] is not None
        assert external.get("/api/v1/assets", headers=bearer(key)).status_code == 401
    assert key["token"] not in caplog.text


def test_api_key_management_is_owner_only_and_cookie_guarded(api):
    catalog, client, headers = api
    key = issue(client, headers, permissions=[])
    assert client.post(KEYS, json={"label": "No origin"}).status_code == 403
    assert client.delete(KEYS + "/" + key["id"]).status_code == 403
    assert (
        client.post(
            KEYS, json={"label": "No CSRF"}, headers={"Origin": catalog.settings.auth_origin}
        ).status_code
        == 403
    )
    assert (
        client.post(
            KEYS,
            json={"label": "Wrong origin"},
            headers={**headers, "Origin": "https://wrong.invalid"},
        ).status_code
        == 403
    )
    catalog.add_user("other-owner", "Other Owner", "user")
    with TestClient(create_app(catalog.settings)) as other:
        other_headers = sign_in_as(other, catalog.settings, "other-owner")
        assert other.get(KEYS).json() == {"items": []}
        assert other.delete(KEYS + "/" + key["id"], headers=other_headers).status_code == 404
        for injection in (
            {"ownerId": catalog.admin().actor_id},
            {"roleId": "superadmin"},
            {"scopes": ["system.modules"]},
        ):
            assert (
                other.post(
                    KEYS, json={"label": "Injected", **injection}, headers=other_headers
                ).status_code
                == 422
            )
        assert (
            other.post(
                KEYS,
                json={"label": "Escalate", "permissions": ["system.modules"]},
                headers=other_headers,
            ).status_code
            == 403
        )
        assert other.get(KEYS).json() == {"items": []}
    assert len(client.get(KEYS).json()["items"]) == 1
    with TestClient(create_app(catalog.settings)) as external:
        assert external.get("/api/v1/assets", headers=bearer(key)).status_code == 403
        assert external.get("/api/v1/auth/me", headers=bearer(key)).json()["permissions"] == []
    assert client.get(KEYS).json()["items"][0]["revokedAt"] is None


def test_ceiling_is_frozen_and_live_role_changes_apply(api):
    catalog, client, _ = api
    actor = catalog.add_user("limited-owner", "Limited Owner", "user")
    headers = sign_in_as(client, catalog.settings, "limited-owner")
    key = issue(client, headers, expiresAt=None)
    assert set(key["permissions"]) == {"assets.view", "people.view", "agents.providers.personal"}
    assert key["expiresAt"] is None
    with catalog.session() as db:
        IdentityService(db, catalog.settings).update_user(
            catalog.admin(),
            actor.actor_id,
            username=actor.username,
            name=actor.display_name,
            role_id="operator",
            email=None,
            person_id=None,
            actor_kind="human",
            active=True,
        )
    with TestClient(create_app(catalog.settings)) as external:
        assert (
            external.post(
                "/api/v1/assets", json={"name": "Still denied"}, headers=bearer(key)
            ).status_code
            == 403
        )
        assert external.get("/api/v1/assets", headers=bearer(key)).status_code == 200
        catalog.deactivate(actor.username)
        assert external.get("/api/v1/assets", headers=bearer(key)).status_code == 401
    assert catalog.asset_count() == 0


def test_api_key_expiry_validation_and_machine_compatibility(api):
    catalog, client, headers = api
    for invalid in (
        "not-a-date",
        "2020-01-01T00:00:00Z",
        "2099-01-01T00:00:00",
        "2020-01-01T00:00:00+01:00",
    ):
        response = client.post(
            KEYS, json={"label": "Expiry", "expiresAt": invalid}, headers=headers
        )
        assert response.status_code in (400, 422)
    assert client.get(KEYS).json() == {"items": []}
    key = issue(
        client,
        headers,
        permissions=["assets.view"],
        expiresAt=(utcnow() + timedelta(seconds=1)).isoformat(),
    )
    _, token = catalog.add_machine("legacy-machine", "Legacy", "operator")
    with TestClient(create_app(catalog.settings)) as external:
        assert (
            external.get("/api/v1/assets", headers={"Authorization": "Bearer " + token}).status_code
            == 200
        )
        assert (
            external.post(
                "/api/v1/assets",
                json={"name": "Machine asset"},
                headers={"Authorization": "Bearer " + token},
            ).status_code
            == 201
        )
        assert external.get(KEYS, headers={"Authorization": "Bearer " + token}).status_code == 403
        catalog.revoke_machine("legacy-machine")
        assert (
            external.get("/api/v1/assets", headers={"Authorization": "Bearer " + token}).status_code
            == 401
        )
    # Use the domain's clock seam rather than sleeping or modifying persisted rows.
    with catalog.session() as db:
        service = IdentityService(db, catalog.settings, now=lambda: utcnow() + timedelta(minutes=1))
        from itsm.identity.service import AuthenticationFailed

        with pytest.raises(AuthenticationFailed):
            service.authenticate_token(key["token"])


def test_retained_personal_principal_is_revalidated(api):
    catalog, client, headers = api
    key = issue(client, headers, permissions=["assets.view"])
    with catalog.session() as db:
        service = IdentityService(db, catalog.settings)
        principal = service.authenticate_token(key["token"]).principal
        service.authorize(principal, "assets.view")
        assert client.delete(KEYS + "/" + key["id"], headers=headers).status_code == 200
        assert service.effective_permissions(principal) == frozenset()
        with pytest.raises(PermissionDenied):
            service.authorize(principal, "assets.view")


def test_anonymous_private_api_rejected_public_login_data_remains_public(api):
    catalog, _, _ = api
    with TestClient(create_app(catalog.settings)) as anonymous:
        for path in (
            "/auth/me",
            "/auth/api-keys",
            "/identity/state",
            "/assets",
            "/system/status",
            "/extensions",
        ):
            assert anonymous.get("/api/v1" + path).status_code == 401
        assert anonymous.post(KEYS, json={"label": "Anonymous"}).status_code == 401
        for path in (
            "/health/live",
            "/demo/status",
            "/appearance/active",
            "/i18n/locales",
            "/i18n/bundle?locale=es",
        ):
            assert anonymous.get("/api/v1" + path).status_code == 200
        assert (
            anonymous.post(
                "/api/v1/auth/login",
                json={"username": "invalid", "password": "invalid"},
                headers={"Origin": catalog.settings.auth_origin},
            ).status_code
            == 401
        )
