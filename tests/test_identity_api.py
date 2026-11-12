"""HTTP contract: cookie sessions, CSRF, origin checks and identity endpoints."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.identity.api import COOKIE_PATH
from itsm.identity.permissions import PERMISSION_CATALOG
from itsm.main import create_app
from tests.conftest import run_migrations
from tests.identity_support import PASSWORD, Harness

ORIGIN = "http://testserver"
API = "/api/v1"


@pytest.fixture
def env(settings_factory: Callable[..., Settings]) -> Iterator[tuple[TestClient, Harness]]:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    # HTTP services use real UTC; issue fixture credentials on the same clock.
    harness = Harness(
        settings=settings, engine=create_engine_from_settings(settings), clock=datetime.now(UTC)
    )
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
    with TestClient(create_app(settings)) as client:
        try:
            yield client, harness
        finally:
            harness.close()


def login_response(
    client: TestClient,
    username: str = "ana.admin",
    password: str = PASSWORD,
    origin: str | None = ORIGIN,
):
    headers = {} if origin is None else {"Origin": origin}
    return client.post(
        f"{API}/auth/login",
        json={"username": username, "password": password},
        headers=headers,
    )


def login(
    client: TestClient,
    username: str = "ana.admin",
    password: str = PASSWORD,
    origin: str | None = ORIGIN,
) -> dict[str, object]:
    response = login_response(client, username, password, origin)
    assert response.status_code == 200, response.text
    return response.json()


def csrf_headers(token: object) -> dict[str, str]:
    return {"Origin": ORIGIN, "X-CSRF-Token": str(token)}


def test_login_sets_a_hardened_cookie_and_returns_the_identity_envelope(env) -> None:
    client, harness = env
    response = login_response(client)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert harness.scalar("SELECT COUNT(*) FROM identity_sessions") == 1

    cookie = client.cookies.get("itsm_session")
    assert cookie and len(cookie) >= 32
    assert cookie not in str(payload)

    header = response.headers["set-cookie"]
    assert "HttpOnly" in header
    assert "SameSite=strict" in header
    assert f"Path={COOKIE_PATH}" in header
    assert "Secure" not in header  # explicit local HTTP override in test settings

    assert payload["sessionMinutes"] == 480
    assert set(payload["permissions"]) == set(PERMISSION_CATALOG)
    assert payload["csrfToken"] and len(str(payload["csrfToken"])) >= 32
    user = payload["user"]
    assert set(user) == {
        "id",
        "username",
        "name",
        "email",
        "roleId",
        "active",
        "lastAccess",
        "personId",
        "actorKind",
    }
    assert user["username"] == "ana.admin"
    assert user["roleId"] == "superadmin"
    assert "password" not in str(payload).lower()
    assert PASSWORD not in str(payload)


def test_cookie_is_secure_when_the_secure_flag_is_enabled(settings_factory, env) -> None:
    _, _ = env
    hardened = settings_factory(auth_cookie_secure=True)
    applied = run_migrations(hardened)
    assert applied.returncode == 0, applied.stderr
    with TestClient(create_app(hardened)) as secure_client:
        response = secure_client.post(
            f"{API}/auth/login",
            json={"username": "ana.admin", "password": PASSWORD},
            headers={"Origin": ORIGIN},
        )
    assert response.status_code == 200, response.text
    assert "Secure" in response.headers["set-cookie"]


def test_login_requires_the_configured_origin(env) -> None:
    client, harness = env
    for headers in ({}, {"Origin": "http://evil.example"}):
        response = client.post(
            f"{API}/auth/login",
            json={"username": "ana.admin", "password": PASSWORD},
            headers=headers,
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "forbidden"

    assert harness.scalar("SELECT COUNT(*) FROM identity_sessions") == 0


def test_login_rejects_invalid_credentials_generically(env) -> None:
    client, _ = env
    response = client.post(
        f"{API}/auth/login",
        json={"username": "ana.admin", "password": "wrong-password-value"},
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "unauthorized",
            "key": "api.auth.invalid_credentials",
            "params": {},
            "message": "Credenciales inválidas.",
        }
    }
    assert "wrong-password-value" not in response.text
    assert client.cookies.get("itsm_session") is None


def test_login_throttles_after_the_configured_failures(env) -> None:
    client, _ = env
    for _ in range(5):
        failed = client.post(
            f"{API}/auth/login",
            json={"username": "ana.admin", "password": "wrong-password-value"},
            headers={"Origin": ORIGIN},
        )
        assert failed.status_code == 401

    throttled = client.post(
        f"{API}/auth/login",
        json={"username": "ana.admin", "password": PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert throttled.status_code == 429
    assert throttled.headers["retry-after"] == "900"
    assert throttled.json()["error"]["code"] == "too_many_requests"


def test_me_requires_a_session_and_clears_the_cookie_on_401(env) -> None:
    client, _ = env
    unauthenticated = client.get(f"{API}/auth/me")
    assert unauthenticated.status_code == 401
    assert unauthenticated.json()["error"]["code"] == "unauthorized"

    login(client)
    me = client.get(f"{API}/auth/me")
    assert me.status_code == 200
    body = me.json()
    assert body["user"]["username"] == "ana.admin"
    assert set(body["permissions"]) == set(PERMISSION_CATALOG)
    assert body["sessionMinutes"] == 480


def test_invalid_bearer_does_not_clear_a_valid_cookie_session(env) -> None:
    """R2-O1: a failed machine credential is not a reason to drop the visitor's session."""
    client, _ = env
    login(client)
    rejected = client.get(
        f"{API}/auth/me", headers={"Authorization": "Bearer itsm_mk_not-a-real-token"}
    )
    assert rejected.status_code == 401
    assert "set-cookie" not in rejected.headers
    still_signed_in = client.get(f"{API}/auth/me")
    assert still_signed_in.status_code == 200, still_signed_in.text
    assert still_signed_in.json()["user"]["username"] == "ana.admin"


def test_unauthorized_cookie_session_is_still_cleared(env) -> None:
    client, _ = env
    client.cookies.set("itsm_session", "itsm_s_not-a-real-session")
    rejected = client.get(f"{API}/auth/me")
    assert rejected.status_code == 401
    set_cookie = rejected.headers["set-cookie"]
    assert set_cookie.startswith('itsm_session=""')
    assert "Max-Age=0" in set_cookie


def test_logout_requires_origin_and_csrf_and_invalidates_the_session(env) -> None:
    client, harness = env
    payload = login(client)

    no_csrf = client.post(f"{API}/auth/logout", headers={"Origin": ORIGIN})
    assert no_csrf.status_code == 403
    wrong_origin = client.post(
        f"{API}/auth/logout",
        headers={"Origin": "http://evil.example", "X-CSRF-Token": str(payload["csrfToken"])},
    )
    assert wrong_origin.status_code == 403
    assert client.get(f"{API}/auth/me").status_code == 200

    logged_out = client.post(f"{API}/auth/logout", headers=csrf_headers(payload["csrfToken"]))
    assert logged_out.status_code == 200
    assert logged_out.json() == {"status": "ok"}
    assert client.cookies.get("itsm_session") is None
    assert (
        harness.scalar("SELECT COUNT(*) FROM identity_sessions WHERE revoked_at IS NOT NULL") == 1
    )
    assert client.get(f"{API}/auth/me").status_code == 401


def test_cookie_mutations_require_csrf_and_leave_no_side_effect(env) -> None:
    client, harness = env
    payload = login(client)
    body = {
        "username": "rita.reader",
        "name": "Rita",
        "email": "rita@example.test",
        "roleId": "user",
        "password": PASSWORD,
    }

    missing = client.post(f"{API}/identity/users", json=body, headers={"Origin": ORIGIN})
    assert missing.status_code == 403
    wrong = client.post(
        f"{API}/identity/users",
        json=body,
        headers={"Origin": ORIGIN, "X-CSRF-Token": "not-the-token"},
    )
    assert wrong.status_code == 403
    assert harness.scalar("SELECT COUNT(*) FROM identity_identities") == 1

    created = client.post(
        f"{API}/identity/users", json=body, headers=csrf_headers(payload["csrfToken"])
    )
    assert created.status_code == 201, created.text
    assert created.json()["username"] == "rita.reader"
    assert created.json()["active"] is True


def test_state_returns_authorized_subsets_for_every_authenticated_actor(env) -> None:
    client, harness = env
    assert client.get(f"{API}/identity/state").status_code == 401
    admin = login(client)
    created = client.post(
        f"{API}/identity/users",
        json={
            "username": "rita.reader",
            "name": "Rita",
            "roleId": "user",
            "password": PASSWORD,
        },
        headers=csrf_headers(admin["csrfToken"]),
    )
    assert created.status_code == 201

    admin_state = client.get(f"{API}/identity/state").json()
    assert {user["username"] for user in admin_state["users"]} == {"ana.admin", "rita.reader"}
    assert {role["id"] for role in admin_state["roles"]} == {
        "admin",
        "operator",
        "superadmin",
        "user",
    }
    assert admin_state["sessionMinutes"] == 480
    role = next(entry for entry in admin_state["roles"] if entry["id"] == "user")
    assert role["permissions"] == [
        "agents.providers.personal",
        "assets.view",
        "people.view",
    ]
    assert role["builtIn"] is True

    with TestClient(create_app(harness.settings)) as reader_client:
        reader = login(reader_client, "rita.reader")
        state = reader_client.get(f"{API}/identity/state")
    assert state.status_code == 200
    assert state.json() == {"users": [], "roles": [], "sessionMinutes": 480}
    assert reader["permissions"] == [
        "agents.providers.personal",
        "assets.view",
        "people.view",
    ]


def test_user_lifecycle_over_http(env) -> None:
    client, _ = env
    admin = login(client)
    headers = csrf_headers(admin["csrfToken"])
    created = client.post(
        f"{API}/identity/users",
        json={
            "username": "omar.operator",
            "name": "Omar",
            "email": "omar@example.test",
            "roleId": "operator",
            "personId": "person-9",
            "password": PASSWORD,
        },
        headers=headers,
    )
    assert created.status_code == 201
    user_id = created.json()["id"]
    assert created.json()["personId"] == "person-9"

    updated = client.put(
        f"{API}/identity/users/{user_id}",
        json={"name": "Omar Actualizado", "roleId": "user"},
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Omar Actualizado"
    assert updated.json()["roleId"] == "user"

    deactivated = client.patch(
        f"{API}/identity/users/{user_id}/active", json={"active": False}, headers=headers
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["active"] is False

    rejected_login = client.post(
        f"{API}/auth/login",
        json={"username": "omar.operator", "password": PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert rejected_login.status_code == 401

    roles = client.get(f"{API}/identity/state").json()["roles"]
    assert {entry["id"] for entry in roles} == {
        "admin",
        "operator",
        "superadmin",
        "user",
    }


def test_role_endpoints_manage_custom_roles_only(env) -> None:
    client, _ = env
    admin = login(client)
    headers = csrf_headers(admin["csrfToken"])

    created = client.post(
        f"{API}/identity/roles",
        json={"name": "Campo", "permissions": ["assets.view", "people.view"]},
        headers=headers,
    )
    assert created.status_code == 201
    role_id = created.json()["id"]
    assert created.json() == {
        "id": role_id,
        "name": "Campo",
        "permissions": ["assets.view", "people.view"],
        "builtIn": False,
    }

    updated = client.put(
        f"{API}/identity/roles/{role_id}",
        json={"name": "Campo", "permissions": ["assets.edit"]},
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.json()["permissions"] == ["assets.edit"]

    built_in = client.put(
        f"{API}/identity/roles/admin", json={"permissions": ["assets.view"]}, headers=headers
    )
    assert built_in.status_code == 409

    unknown = client.post(
        f"{API}/identity/roles",
        json={"name": "Rota", "permissions": ["assets.destroy"]},
        headers=headers,
    )
    assert unknown.status_code == 422
    assert unknown.json()["error"]["code"] == "validation_error"


def test_settings_and_audit_require_their_permissions(env) -> None:
    client, _ = env
    admin = login(client)
    headers = csrf_headers(admin["csrfToken"])
    created = client.post(
        f"{API}/identity/users",
        json={
            "username": "omar.operator",
            "name": "Omar",
            "roleId": "operator",
            "password": PASSWORD,
        },
        headers=headers,
    )
    assert created.status_code == 201

    settings = client.put(f"{API}/identity/settings", json={"sessionMinutes": 60}, headers=headers)
    assert settings.status_code == 200
    assert settings.json() == {"sessionMinutes": 60}
    assert client.get(f"{API}/identity/state").json()["sessionMinutes"] == 60

    invalid = client.put(f"{API}/identity/settings", json={"sessionMinutes": 2}, headers=headers)
    assert invalid.status_code == 422

    audit = client.get(f"{API}/identity/audit?limit=20")
    assert audit.status_code == 200
    events = audit.json()["events"]
    assert any(event["action"] == "identity.user_created" for event in events)
    assert all(
        set(event)
        == {
            "actorId",
            "actorKind",
            "actorUsername",
            "action",
            "resource",
            "outcome",
            "createdAt",
            "executionId",
            "delegatedBy",
            "authorizationRef",
        }
        for event in events
    )
    assert PASSWORD not in audit.text

    with TestClient(create_app(client.app.state.settings)) as operator_client:
        login(operator_client, "omar.operator")
        denied_settings = operator_client.put(
            f"{API}/identity/settings", json={"sessionMinutes": 30}, headers={}
        )
        assert denied_settings.status_code == 403
        denied_audit = operator_client.get(f"{API}/identity/audit")
        assert denied_audit.status_code == 403


def test_machine_bearer_tokens_authenticate_without_csrf_but_never_administer(env) -> None:
    client, harness = env
    admin = login(client)
    headers = csrf_headers(admin["csrfToken"])
    created = client.post(
        f"{API}/identity/users",
        json={
            "username": "agent.ops",
            "name": "Ops agent",
            "roleId": "operator",
            "actorKind": "internal_agent",
        },
        headers=headers,
    )
    assert created.status_code == 201
    with harness.service() as service:
        credential = service.issue_machine_credential("agent.ops")

    bearer = {"Authorization": f"Bearer {credential.token}"}
    me = client.get(f"{API}/auth/me", headers=bearer)
    assert me.status_code == 200
    assert me.json()["user"]["actorKind"] == "internal_agent"
    assert me.json()["csrfToken"] is None
    assert "users.edit" not in me.json()["permissions"]

    denied = client.post(
        f"{API}/identity/users",
        json={"username": "agent.two", "name": "Two", "roleId": "user"},
        headers=bearer,
    )
    assert denied.status_code == 403
    assert harness.scalar("SELECT COUNT(*) FROM identity_identities") == 2

    tampered = client.get(f"{API}/auth/me", headers={"Authorization": "Bearer itsm_mk_nope"})
    assert tampered.status_code == 401


def test_task_endpoints_require_an_authenticated_actor(env) -> None:
    client, _ = env
    unauthenticated = client.post(f"{API}/tasks/demo", json={"message": "ping"})
    assert unauthenticated.status_code == 401

    session = login(client)
    cookie_only = client.post(f"{API}/tasks/demo", json={"message": "ping"})
    assert cookie_only.status_code == 403
    accepted = client.post(
        f"{API}/tasks/demo",
        json={"message": "ping"},
        headers=csrf_headers(session["csrfToken"]),
    )
    assert accepted.status_code == 202, accepted.text
    task_id = accepted.json()["task_id"]
    assert client.get(f"{API}/tasks/{task_id}").status_code == 200


def test_limited_user_administrator_cannot_escalate_over_http(env) -> None:
    client, harness = env
    admin = login(client)
    manager_role = client.post(
        f"{API}/identity/roles",
        json={
            "name": "Gestor HTTP",
            "permissions": [
                "users.view",
                "users.create",
                "users.edit",
                "assets.view",
                "people.view",
            ],
        },
        headers=csrf_headers(admin["csrfToken"]),
    )
    assert manager_role.status_code == 201, manager_role.text
    created = client.post(
        f"{API}/identity/users",
        json={
            "username": "gestor.http",
            "name": "Gestor HTTP",
            "roleId": manager_role.json()["id"],
            "password": PASSWORD,
        },
        headers=csrf_headers(admin["csrfToken"]),
    )
    assert created.status_code == 201, created.text
    admin_id = harness.sql("SELECT id FROM identity_identities WHERE username = 'ana.admin'")[0][0]

    client.cookies.clear()
    manager = login(client, username="gestor.http")

    escalation = client.post(
        f"{API}/identity/users",
        json={
            "username": "intruso.http",
            "name": "Intruso",
            "roleId": "superadmin",
            "password": PASSWORD,
        },
        headers=csrf_headers(manager["csrfToken"]),
    )
    assert escalation.status_code == 403
    assert harness.scalar("SELECT COUNT(*) FROM identity_identities") == 2

    reset = client.put(
        f"{API}/identity/users/{admin_id}",
        json={"password": "otra-clave-larga-2026"},
        headers=csrf_headers(manager["csrfToken"]),
    )
    assert reset.status_code == 403
    deactivate = client.patch(
        f"{API}/identity/users/{admin_id}/active",
        json={"active": False},
        headers=csrf_headers(manager["csrfToken"]),
    )
    assert deactivate.status_code == 403

    client.cookies.clear()
    login(client, username="ana.admin")  # the administrator password still works


def test_limited_role_manager_cannot_grant_more_than_it_holds_over_http(env) -> None:
    client, harness = env
    admin = login(client)
    manager_role = client.post(
        f"{API}/identity/roles",
        json={"name": "Roles HTTP", "permissions": ["roles.manage", "assets.view"]},
        headers=csrf_headers(admin["csrfToken"]),
    )
    assert manager_role.status_code == 201, manager_role.text
    higher = client.post(
        f"{API}/identity/roles",
        json={"name": "Campo alto", "permissions": ["assets.edit"]},
        headers=csrf_headers(admin["csrfToken"]),
    )
    assert higher.status_code == 201, higher.text
    created = client.post(
        f"{API}/identity/users",
        json={
            "username": "roles.http",
            "name": "Roles HTTP",
            "roleId": manager_role.json()["id"],
            "password": PASSWORD,
        },
        headers=csrf_headers(admin["csrfToken"]),
    )
    assert created.status_code == 201, created.text
    roles_before = harness.scalar("SELECT COUNT(*) FROM identity_roles")

    client.cookies.clear()
    manager = login(client, username="roles.http")
    escalation = client.post(
        f"{API}/identity/roles",
        json={"name": "Escalada HTTP", "permissions": ["assets.edit"]},
        headers=csrf_headers(manager["csrfToken"]),
    )
    assert escalation.status_code == 403
    assert harness.scalar("SELECT COUNT(*) FROM identity_roles") == roles_before

    edit_higher = client.put(
        f"{API}/identity/roles/{higher.json()['id']}",
        json={"permissions": ["assets.view"]},
        headers=csrf_headers(manager["csrfToken"]),
    )
    assert edit_higher.status_code == 403
    assert (
        harness.scalar(
            "SELECT COUNT(*) FROM identity_role_policies WHERE role_id = '"
            + str(higher.json()["id"])
            + "' AND operation = 'edit'"
        )
        == 1
    )
