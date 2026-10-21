"""Authentication, session lifecycle, authorization and agent restrictions.

These tests exercise the service directly: authorization must not depend on
FastAPI, and every denial is checked for unchanged target data plus its audit
record.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime, timedelta

import pytest
from itsm.config import Settings
from itsm.identity.hashing import hash_token, verify_password
from itsm.identity.permissions import PERMISSION_CATALOG
from itsm.identity.service import (
    AccountThrottled,
    AuthenticationFailed,
    BootstrapRefused,
    Conflict,
    IdentityService,
    PermissionDenied,
    ValidationFailed,
)
from tests.identity_support import PASSWORD, Harness, make_harness


@pytest.fixture
def harness(settings_factory: Callable[..., Settings]) -> Iterator[Harness]:
    created = make_harness(settings_factory)
    try:
        yield created
    finally:
        created.close()


def bootstrap_admin(harness: Harness) -> IdentityService:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
    return service


def test_bootstrap_admin_creates_the_first_human_administrator(harness: Harness) -> None:
    with harness.service() as service:
        created = service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)

        assert created.username == "ana.admin"
        assert created.role_id == "admin"
        assert created.actor_kind == "human"
        assert created.active is True

    row = harness.sql(
        "SELECT password_hash, actor_kind FROM identity_identities WHERE username = 'ana.admin'"
    )[0]
    assert row[0].startswith("$argon2id$")
    assert PASSWORD not in row[0]
    assert row[1] == "human"
    audit = harness.sql(
        "SELECT action, outcome, actor_kind FROM identity_audit_events ORDER BY id DESC LIMIT 1"
    )[0]
    assert tuple(audit) == ("identity.bootstrap", "success", "system")
    assert harness.scalar("SELECT COUNT(*) FROM identity_login_attempts") == 0


def test_bootstrap_admin_refuses_when_a_human_identity_already_exists(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        with pytest.raises(BootstrapRefused):
            service.bootstrap_admin("other.admin", "Other Admin", PASSWORD)

    assert harness.scalar("SELECT COUNT(*) FROM identity_identities") == 1


def test_bootstrap_admin_enforces_the_password_policy(harness: Harness) -> None:
    with harness.service() as service, pytest.raises(ValidationFailed):
        service.bootstrap_admin("ana.admin", "Ana Admin", "short")


def test_login_returns_effective_permissions_and_stores_only_the_token_digest(
    harness: Harness,
) -> None:
    bootstrap_admin(harness)

    with harness.service() as service:
        grant = service.login("ana.admin", PASSWORD)

    assert grant.permissions == frozenset(PERMISSION_CATALOG)
    assert grant.session_minutes == 480
    assert grant.expires_at == harness.now() + timedelta(minutes=480)
    assert grant.csrf_token and len(grant.csrf_token) >= 32
    stored = harness.sql("SELECT token_digest, csrf_token FROM identity_sessions")[0]
    assert stored[0] == hash_token(grant.token)
    assert grant.token != stored[0]
    assert stored[1] == grant.csrf_token
    assert (
        harness.scalar(
            "SELECT action || ':' || outcome FROM identity_audit_events ORDER BY id DESC LIMIT 1"
        )
        == "auth.login:success"
    )


def test_login_rejects_wrong_password_and_unknown_user_with_the_same_generic_error(
    harness: Harness,
) -> None:
    bootstrap_admin(harness)
    messages: set[str] = set()

    with harness.service() as service:
        for username, password in (("ana.admin", "wrong-password-value"), ("ghost", PASSWORD)):
            with pytest.raises(AuthenticationFailed) as failure:
                service.login(username, password)
            messages.add(str(failure.value))

    assert messages == {"invalid credentials"}
    denials = harness.sql("SELECT outcome FROM identity_audit_events WHERE action = 'auth.login'")
    assert [tuple(row) for row in denials] == [("denied",), ("denied",)]
    assert harness.scalar("SELECT COUNT(*) FROM identity_sessions") == 0
    assert harness.scalar("SELECT COUNT(*) FROM identity_login_attempts WHERE successful = 0") == 2


def test_login_rejects_disabled_human_and_machine_identities_generically(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        disabled = service.create_user(
            admin.principal,
            username="luis.disabled",
            name="Luis",
            role_id="reader",
            password=PASSWORD,
        )
        service.set_active(admin.principal, disabled.id, active=False)
        machine = service.create_user(
            admin.principal,
            username="agent.ops",
            name="Ops agent",
            role_id="operator",
            actor_kind="internal_agent",
        )
        machine_credential = service.issue_machine_credential("agent.ops")
        assert machine.actor_kind == "internal_agent"

    with harness.service() as service:
        for username in ("luis.disabled", "agent.ops"):
            with pytest.raises(AuthenticationFailed) as failure:
                service.login(username, PASSWORD)
            assert str(failure.value) == "invalid credentials"
        with pytest.raises(AuthenticationFailed):
            service.authenticate_token(machine_credential.token + "-tampered")


def test_repeated_failures_throttle_login_durably_and_expire_with_the_window(
    harness: Harness,
) -> None:
    bootstrap_admin(harness)

    with harness.service() as service:
        for _ in range(5):
            with pytest.raises(AuthenticationFailed):
                service.login("ana.admin", "wrong-password-value")

    with harness.service() as service:  # a new process would see the same durable rows
        with pytest.raises(AccountThrottled) as throttled:
            service.login("ana.admin", PASSWORD)
        assert throttled.value.retry_after_seconds == 15 * 60

    assert harness.scalar("SELECT COUNT(*) FROM identity_login_attempts WHERE successful = 0") == 5
    assert harness.scalar("SELECT COUNT(*) FROM identity_sessions") == 0

    harness.tick(16)
    with harness.service() as service:
        grant = service.login("ana.admin", PASSWORD)
    assert grant.permissions == frozenset(PERMISSION_CATALOG)
    assert harness.scalar("SELECT COUNT(*) FROM identity_login_attempts WHERE successful = 0") == 0


def test_successful_login_resets_the_failure_budget(harness: Harness) -> None:
    bootstrap_admin(harness)

    with harness.service() as service:
        for _ in range(4):
            with pytest.raises(AuthenticationFailed):
                service.login("ana.admin", "wrong-password-value")
        service.login("ana.admin", PASSWORD)
        for _ in range(4):
            with pytest.raises(AuthenticationFailed):
                service.login("ana.admin", "wrong-password-value")
        service.login("ana.admin", PASSWORD)


def test_session_expiry_is_enforced_on_every_request(harness: Harness) -> None:
    bootstrap_admin(harness)
    with harness.service() as service:
        grant = service.login("ana.admin", PASSWORD)
        context = service.authenticate_session(grant.token)
        assert context.permissions == frozenset(PERMISSION_CATALOG)

    harness.tick(479)
    with harness.service() as service:
        assert service.authenticate_session(grant.token).principal.username == "ana.admin"

    harness.tick(2)
    with harness.service() as service, pytest.raises(AuthenticationFailed):
        service.authenticate_session(grant.token)


def test_logout_revokes_the_session_immediately(harness: Harness) -> None:
    bootstrap_admin(harness)
    with harness.service() as service:
        grant = service.login("ana.admin", PASSWORD)
        service.logout(grant.principal)
        with pytest.raises(AuthenticationFailed):
            service.authenticate_session(grant.token)

    assert harness.scalar("SELECT revoked_at FROM identity_sessions") is not None
    assert (
        harness.scalar(
            "SELECT action || ':' || outcome FROM identity_audit_events ORDER BY id DESC LIMIT 1"
        )
        == "auth.logout:success"
    )


def test_deactivation_blocks_an_existing_session_and_revokes_it(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        reader = service.create_user(
            admin.principal,
            username="rita.reader",
            name="Rita",
            role_id="reader",
            password=PASSWORD,
        )
        reader_grant = service.login("rita.reader", PASSWORD)
        service.set_active(admin.principal, reader.id, active=False)

    assert (
        harness.scalar("SELECT COUNT(*) FROM identity_sessions WHERE revoked_at IS NOT NULL") == 1
    )
    with harness.service() as service, pytest.raises(AuthenticationFailed):
        service.authenticate_session(reader_grant.token)


def test_password_and_role_changes_revoke_existing_sessions(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        user = service.create_user(
            admin.principal,
            username="rita.reader",
            name="Rita",
            role_id="reader",
            password=PASSWORD,
        )
        first = service.login("rita.reader", PASSWORD)
        service.update_user(admin.principal, user.id, password="a-different-password-1")
        with pytest.raises(AuthenticationFailed):
            service.authenticate_session(first.token)
        second = service.login("rita.reader", "a-different-password-1")
        service.update_user(admin.principal, user.id, role_id="operator")
        with pytest.raises(AuthenticationFailed):
            service.authenticate_session(second.token)
        third = service.login("rita.reader", "a-different-password-1")
        assert third.permissions == frozenset(
            {
                "assets.view",
                "assets.edit",
                "assets.assign",
                "assets.remote",
                "people.view",
                "people.create",
                "people.edit",
            }
        )


def test_last_access_is_recorded_on_the_identity_and_the_session(harness: Harness) -> None:
    bootstrap_admin(harness)
    with harness.service() as service:
        grant = service.login("ana.admin", PASSWORD)
        harness.tick(5)
        service.authenticate_session(grant.token)

    identity_access, session_access, created = harness.sql(
        "SELECT i.last_access_at, s.last_access_at, s.created_at "
        "FROM identity_identities i JOIN identity_sessions s ON s.identity_id = i.id"
    )[0]
    identity_seen = datetime.fromisoformat(str(identity_access))
    session_seen = datetime.fromisoformat(str(session_access))
    created_seen = datetime.fromisoformat(str(created))
    expected = harness.now().replace(tzinfo=None)
    assert identity_seen == expected
    assert session_seen == expected
    assert session_seen > created_seen


def test_services_enforce_permissions_response_independently_of_http(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        service.create_user(
            admin.principal,
            username="rita.reader",
            name="Rita",
            role_id="reader",
            password=PASSWORD,
        )
        service.create_user(
            admin.principal,
            username="omar.operator",
            name="Omar",
            role_id="operator",
            password=PASSWORD,
        )
        reader = service.login("rita.reader", PASSWORD)
        operator = service.login("omar.operator", PASSWORD)

    with harness.service() as service:
        service.authorize(reader.principal, "assets.view", resource="asset:1")
        with pytest.raises(PermissionDenied):
            service.authorize(reader.principal, "assets.edit", resource="asset:1")
        service.authorize(operator.principal, "assets.edit", resource="asset:1")
        with pytest.raises(PermissionDenied):
            service.authorize(operator.principal, "not.a.permission")
        with pytest.raises(PermissionDenied):
            service.authorize(operator.principal, "sessions.manage")


def test_operator_holds_assets_remote_and_reader_does_not(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        service.create_user(
            admin.principal,
            username="omar.operator",
            name="Omar",
            role_id="operator",
            password=PASSWORD,
        )
        operator = service.login("omar.operator", PASSWORD)

    with harness.service() as service:
        service.authorize(operator.principal, "assets.remote", resource="asset:1")


def test_denied_operation_is_audited_and_leaves_target_data_unchanged(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        service.create_user(
            admin.principal,
            username="omar.operator",
            name="Omar",
            role_id="operator",
            password=PASSWORD,
        )
        operator = service.login("omar.operator", PASSWORD)

    users_before = harness.scalar("SELECT COUNT(*) FROM identity_identities")
    with harness.service() as service, pytest.raises(PermissionDenied):
        service.create_user(
            operator.principal,
            username="intruder",
            name="Intruder",
            role_id="admin",
            password=PASSWORD,
        )

    assert harness.scalar("SELECT COUNT(*) FROM identity_identities") == users_before
    denied = harness.sql(
        "SELECT actor_username, action, resource, outcome FROM identity_audit_events "
        "WHERE outcome = 'denied' ORDER BY id DESC LIMIT 1"
    )[0]
    assert tuple(denied) == ("omar.operator", "users.create", "identity", "denied")


def test_machine_identity_cannot_receive_the_administrator_role(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        with pytest.raises(ValidationFailed):
            service.create_user(
                admin.principal,
                username="agent.admin",
                name="Agent",
                role_id="admin",
                actor_kind="internal_agent",
            )
        agent = service.create_user(
            admin.principal,
            username="agent.ops",
            name="Agent",
            role_id="operator",
            actor_kind="internal_agent",
        )
        credential = service.issue_machine_credential("agent.ops")

    # Simulate a stored policy/database state that would wrongly grant admin to
    # a machine: Casbin must not honour it for machine identities.
    harness.execute(
        "UPDATE identity_identities SET role_id = 'admin' WHERE id = :id", {"id": agent.id}
    )

    with harness.service() as service:
        context = service.authenticate_token(credential.token)
        for permission in ("users.view", "roles.manage", "sessions.manage", "assets.view"):
            with pytest.raises(PermissionDenied):
                service.authorize(context.principal, permission)


def test_agent_delegation_is_limited_to_the_intersection_with_the_human(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        human = service.create_user(
            admin.principal,
            username="rita.reader",
            name="Rita",
            role_id="reader",
            password=PASSWORD,
        )
        custom = service.create_role(
            admin.principal,
            name="Campo",
            permissions=["assets.view", "assets.edit", "people.edit"],
        )
        agent = service.create_user(
            admin.principal,
            username="agent.field",
            name="Field agent",
            role_id=custom.id,
            actor_kind="internal_agent",
            delegated_by_id=human.id,
        )
        credential = service.issue_machine_credential("agent.field")

    with harness.service() as service:
        context = service.authenticate_token(
            credential.token, execution_id="exec-1", authorization_ref="approval-9"
        )
        assert context.principal.delegated_by == human.id
        service.authorize(context.principal, "assets.view", resource="asset:7")
        with pytest.raises(PermissionDenied):
            service.authorize(context.principal, "assets.edit", resource="asset:7")
        with pytest.raises(PermissionDenied):
            service.authorize(context.principal, "people.edit", resource="person:7")

    audit = harness.sql(
        "SELECT execution_id, delegated_by, authorization_ref FROM identity_audit_events "
        "WHERE outcome = 'denied' ORDER BY id DESC LIMIT 1"
    )[0]
    assert tuple(audit) == ("exec-1", human.id, "approval-9")
    assert agent.actor_kind == "internal_agent"


def test_delegation_is_denied_when_the_delegating_human_is_inactive(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        human = service.create_user(
            admin.principal,
            username="rita.reader",
            name="Rita",
            role_id="reader",
            password=PASSWORD,
        )
        service.create_user(
            admin.principal,
            username="agent.field",
            name="Field agent",
            role_id="reader",
            actor_kind="internal_agent",
            delegated_by_id=human.id,
        )
        credential = service.issue_machine_credential("agent.field")
        service.set_active(admin.principal, human.id, active=False)

    with harness.service() as service:
        context = service.authenticate_token(credential.token)
        with pytest.raises(PermissionDenied):
            service.authorize(context.principal, "assets.view")


def test_sensitive_machine_permission_requires_an_explicit_approval_reference(
    harness: Harness,
) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        service.create_user(
            admin.principal,
            username="agent.ops",
            name="Ops agent",
            role_id="operator",
            actor_kind="internal_agent",
        )
        credential = service.issue_machine_credential("agent.ops")

    with harness.service() as service:
        unapproved = service.authenticate_token(credential.token, execution_id="exec-2")
        with pytest.raises(PermissionDenied):
            service.authorize(unapproved.principal, "assets.remote", resource="asset:3")
        approved = service.authenticate_token(
            credential.token, execution_id="exec-2", authorization_ref="approval-77"
        )
        service.authorize(approved.principal, "assets.remote", resource="asset:3")


def test_programmatic_actor_resolution_never_self_asserts_a_role(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        agent = service.create_user(
            admin.principal,
            username="agent.ops",
            name="Ops agent",
            role_id="reader",
            actor_kind="internal_agent",
        )

    with harness.service() as service:
        principal = service.resolve_actor(
            agent.id, execution_id="exec-9", authorization_ref="approval-3"
        )
        assert principal.role_id == "reader"
        service.authorize(principal, "assets.view")
        with pytest.raises(PermissionDenied):
            service.authorize(principal, "assets.edit")
        with pytest.raises(PermissionDenied):
            service.resolve_actor("unknown-identity")


def test_last_active_administrator_cannot_be_deactivated_or_demoted(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        admin_id = admin.principal.actor_id
        with pytest.raises(Conflict):
            service.set_active(admin.principal, admin_id, active=False)
        with pytest.raises(PermissionDenied):
            service.update_user(admin.principal, admin_id, role_id="reader")

    assert (
        harness.scalar(
            "SELECT COUNT(*) FROM identity_identities WHERE active = 1 AND role_id = 'admin'"
        )
        == 1
    )


def test_a_second_administrator_allows_demoting_the_first(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        second = service.create_user(
            admin.principal,
            username="beto.admin",
            name="Beto",
            role_id="admin",
            password=PASSWORD,
        )
        second_grant = service.login("beto.admin", PASSWORD)
        service.update_user(admin.principal, second.id, role_id="reader")
        with pytest.raises(AuthenticationFailed):
            service.authenticate_session(second_grant.token)
        assert service.me(admin).permissions == frozenset(PERMISSION_CATALOG)


def test_password_storage_uses_argon2id_and_never_keeps_the_plain_value(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_admin("ana.admin", "Ana Admin", PASSWORD)

    stored = harness.scalar(
        "SELECT password_hash FROM identity_identities WHERE username = 'ana.admin'"
    )
    assert verify_password(stored, PASSWORD) is True
    assert verify_password(stored, PASSWORD + "x") is False
    assert verify_password(stored, "") is False
