"""Authentication, session lifecycle, authorization and agent restrictions.

These tests exercise the service directly: authorization must not depend on
FastAPI, and every denial is checked for unchanged target data plus its audit
record.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from threading import Barrier

import pytest
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.identity.hashing import hash_password, hash_token, verify_password
from itsm.identity.permissions import PERMISSION_CATALOG
from itsm.identity.service import (
    AccountThrottled,
    AuthenticationFailed,
    BootstrapRefused,
    Conflict,
    IdentityService,
    NotFound,
    PermissionDenied,
    ValidationFailed,
)
from tests.identity_support import PASSWORD, Harness, make_harness

SYSTEM_PERMISSIONS = frozenset(
    {
        "system.view",
        "system.providers",
        "system.modules",
        "system.configure",
        "system.backup",
        "system.update",
    }
)
OWNER_PERMISSIONS = frozenset(PERMISSION_CATALOG) | SYSTEM_PERMISSIONS
ADMIN_PERMISSIONS = OWNER_PERMISSIONS - SYSTEM_PERMISSIONS


@pytest.fixture
def harness(settings_factory: Callable[..., Settings]) -> Iterator[Harness]:
    created = make_harness(settings_factory)
    try:
        yield created
    finally:
        created.close()


def bootstrap_superadmin(harness: Harness) -> IdentityService:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
    return service


def test_bootstrap_superadmin_creates_the_first_human_owner(harness: Harness) -> None:
    with harness.service() as service:
        created = service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)

        assert created.username == "ana.admin"
        assert created.role_id == "superadmin"
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


def test_bootstrap_superadmin_refuses_when_a_human_identity_already_exists(
    harness: Harness,
) -> None:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        with pytest.raises(BootstrapRefused):
            service.bootstrap_superadmin("other.admin", "Other Admin", PASSWORD)

    assert harness.scalar("SELECT COUNT(*) FROM identity_identities") == 1


def test_bootstrap_superadmin_enforces_the_password_policy(harness: Harness) -> None:
    with harness.service() as service, pytest.raises(ValidationFailed):
        service.bootstrap_superadmin("ana.admin", "Ana Admin", "short")


def test_login_returns_effective_permissions_and_stores_only_the_token_digest(
    harness: Harness,
) -> None:
    bootstrap_superadmin(harness)

    with harness.service() as service:
        grant = service.login("ana.admin", PASSWORD)

    assert grant.permissions == frozenset(PERMISSION_CATALOG) | SYSTEM_PERMISSIONS
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
    bootstrap_superadmin(harness)
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
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        disabled = service.create_user(
            admin.principal,
            username="luis.disabled",
            name="Luis",
            role_id="user",
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
    bootstrap_superadmin(harness)

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
    assert grant.permissions == frozenset(PERMISSION_CATALOG) | SYSTEM_PERMISSIONS
    assert harness.scalar("SELECT COUNT(*) FROM identity_login_attempts WHERE successful = 0") == 0


def test_throttle_is_scoped_to_the_client_address_not_only_the_username(
    harness: Harness,
) -> None:
    bootstrap_superadmin(harness)

    with harness.service() as service:
        for _ in range(5):
            with pytest.raises(AuthenticationFailed):
                service.login("ana.admin", "wrong-password-value", client_ip="198.51.100.9")

    with harness.service() as service:  # an attacker from one address cannot lock the owner out
        grant = service.login("ana.admin", PASSWORD, client_ip="203.0.113.7")
    assert grant.principal.username == "ana.admin"

    with harness.service() as service, pytest.raises(AccountThrottled):
        service.login("ana.admin", PASSWORD, client_ip="198.51.100.9")


def test_successful_login_resets_the_failure_budget(harness: Harness) -> None:
    bootstrap_superadmin(harness)

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
    bootstrap_superadmin(harness)
    with harness.service() as service:
        grant = service.login("ana.admin", PASSWORD)
        context = service.authenticate_session(grant.token)
        assert context.permissions == frozenset(PERMISSION_CATALOG) | SYSTEM_PERMISSIONS

    harness.tick(479)
    with harness.service() as service:
        assert service.authenticate_session(grant.token).principal.username == "ana.admin"

    harness.tick(2)
    with harness.service() as service, pytest.raises(AuthenticationFailed):
        service.authenticate_session(grant.token)


def test_logout_revokes_the_session_immediately(harness: Harness) -> None:
    bootstrap_superadmin(harness)
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
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        reader = service.create_user(
            admin.principal,
            username="rita.reader",
            name="Rita",
            role_id="user",
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
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        user = service.create_user(
            admin.principal,
            username="rita.reader",
            name="Rita",
            role_id="user",
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
    bootstrap_superadmin(harness)
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


def test_session_access_writes_are_throttled_within_the_interval(harness: Harness) -> None:
    query = (
        "SELECT i.last_access_at, s.last_access_at "
        "FROM identity_identities i JOIN identity_sessions s ON s.identity_id = i.id"
    )
    bootstrap_superadmin(harness)
    with harness.service() as service:
        grant = service.login("ana.admin", PASSWORD)
    stored = harness.sql(query)[0]

    harness.clock = harness.now() + timedelta(seconds=30)
    with harness.service() as service:
        assert service.authenticate_session(grant.token).principal.username == "ana.admin"

    assert harness.sql(query)[0] == stored

    harness.clock = harness.now() + timedelta(seconds=31)
    with harness.service() as service:
        assert service.authenticate_session(grant.token).principal.username == "ana.admin"

    expected = harness.now().replace(tzinfo=None)
    assert [datetime.fromisoformat(str(value)) for value in harness.sql(query)[0]] == [
        expected,
        expected,
    ]


def test_machine_token_access_writes_are_throttled_within_the_interval(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        machine = service.bootstrap_machine(
            "mcp-operator", "MCP Operator", "external_client", "operator"
        )
    with harness.service() as service:
        credential = service.issue_machine_credential("mcp-operator")
    with harness.service() as service:
        service.authenticate_token(
            credential.token, execution_id="run-1", authorization_ref="ref-1"
        )
    query = f"SELECT last_access_at FROM identity_identities WHERE id = '{machine.id}'"
    stored = harness.sql(query)[0]

    harness.clock = harness.now() + timedelta(seconds=30)
    with harness.service() as service:
        context = service.authenticate_token(
            credential.token, execution_id="run-2", authorization_ref="ref-2"
        )
        assert context.principal.username == "mcp-operator"

    assert harness.sql(query)[0] == stored

    harness.clock = harness.now() + timedelta(seconds=31)
    with harness.service() as service:
        service.authenticate_token(
            credential.token, execution_id="run-3", authorization_ref="ref-3"
        )

    refreshed = harness.sql(query)[0][0]
    assert datetime.fromisoformat(str(refreshed)) == harness.now().replace(tzinfo=None)


def test_services_enforce_permissions_response_independently_of_http(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        service.create_user(
            admin.principal,
            username="rita.reader",
            name="Rita",
            role_id="user",
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
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
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
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
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
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
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
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        human = service.create_user(
            admin.principal,
            username="rita.reader",
            name="Rita",
            role_id="user",
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
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        human = service.create_user(
            admin.principal,
            username="rita.reader",
            name="Rita",
            role_id="user",
            password=PASSWORD,
        )
        service.create_user(
            admin.principal,
            username="agent.field",
            name="Field agent",
            role_id="user",
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
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
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
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        admin = service.login("ana.admin", PASSWORD)
        agent = service.create_user(
            admin.principal,
            username="agent.ops",
            name="Ops agent",
            role_id="user",
            actor_kind="internal_agent",
        )

    with harness.service() as service:
        principal = service.resolve_actor(
            agent.id, execution_id="exec-9", authorization_ref="approval-3"
        )
        assert principal.role_id == "user"
        service.authorize(principal, "assets.view")
        with pytest.raises(PermissionDenied):
            service.authorize(principal, "assets.edit")
        with pytest.raises(PermissionDenied):
            service.resolve_actor("unknown-identity")


def test_last_active_superadmin_cannot_be_deactivated_or_demoted(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        owner = service.login("ana.admin", PASSWORD)
        owner_id = owner.principal.actor_id
        with pytest.raises(Conflict):
            service.set_active(owner.principal, owner_id, active=False)
        with pytest.raises(PermissionDenied):
            service.update_user(owner.principal, owner_id, role_id="admin")

    assert (
        harness.scalar(
            "SELECT COUNT(*) FROM identity_identities WHERE active = 1 AND role_id = 'superadmin'"
        )
        == 1
    )


def test_a_second_superadmin_allows_deactivating_the_first(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        owner = service.login("ana.admin", PASSWORD)
        service.create_user(
            owner.principal,
            username="beto.owner",
            name="Beto",
            role_id="superadmin",
            password=PASSWORD,
        )
        second_grant = service.login("beto.owner", PASSWORD)
        service.set_active(owner.principal, owner.principal.actor_id, active=False)
        with pytest.raises(AuthenticationFailed):
            service.authenticate_session(owner.token)
        assert service.me(second_grant).permissions == OWNER_PERMISSIONS

    assert (
        harness.scalar(
            "SELECT COUNT(*) FROM identity_identities WHERE active = 1 AND role_id = 'superadmin'"
        )
        == 1
    )


def test_password_storage_uses_argon2id_and_never_keeps_the_plain_value(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)

    stored = harness.scalar(
        "SELECT password_hash FROM identity_identities WHERE username = 'ana.admin'"
    )
    assert verify_password(stored, PASSWORD) is True
    assert verify_password(stored, PASSWORD + "x") is False
    assert verify_password(stored, "") is False


def _insert_legacy_admin(harness: Harness, username: str = "legacy.admin") -> str:
    identity_id = "legacy-" + username
    now = harness.now()
    harness.execute(
        "INSERT INTO identity_identities ("
        "id, username, name, actor_kind, active, password_hash, role_id, created_at, updated_at"
        ") VALUES (:id, :username, 'Legacy Admin', 'human', 1, :password, 'admin', :now, :now)",
        {
            "id": identity_id,
            "username": username,
            "password": hash_password(PASSWORD),
            "now": now,
        },
    )
    return identity_id


def test_adopt_superadmin_claims_an_existing_installation_once(harness: Harness) -> None:
    _insert_legacy_admin(harness)

    with harness.service() as service:
        adopted = service.adopt_superadmin("legacy.admin")
        assert adopted.role_id == "superadmin"
        grant = service.login("legacy.admin", PASSWORD)
        assert grant.permissions == OWNER_PERMISSIONS
        with pytest.raises(BootstrapRefused):
            service.adopt_superadmin("legacy.admin")

    assert (
        harness.scalar(
            "SELECT COUNT(*) FROM identity_identities WHERE active = 1 AND role_id = 'superadmin'"
        )
        == 1
    )
    audit = harness.sql(
        "SELECT outcome, actor_kind FROM identity_audit_events "
        "WHERE action = 'identity.superadmin_adopted' ORDER BY id DESC LIMIT 1"
    )[0]
    assert tuple(audit) == ("success", "system")


def test_adopt_superadmin_rejects_unknown_inactive_and_machine_identities(
    harness: Harness,
) -> None:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        owner = service.login("ana.admin", PASSWORD)
        machine = service.create_user(
            owner.principal,
            username="agent.ops",
            name="Agent",
            role_id="operator",
            actor_kind="internal_agent",
        )
        inactive = service.create_user(
            owner.principal,
            username="rita.user",
            name="Rita",
            role_id="user",
            password=PASSWORD,
        )
        service.set_active(owner.principal, inactive.id, active=False)
        with pytest.raises(NotFound):
            service.adopt_superadmin("ghost")
        with pytest.raises(ValidationFailed):
            service.adopt_superadmin(machine.username)
        with pytest.raises(ValidationFailed):
            service.adopt_superadmin(inactive.username)


def test_admin_profile_has_business_authority_but_no_installation_authority(
    harness: Harness,
) -> None:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        owner = service.login("ana.admin", PASSWORD)
        owner_id = owner.principal.actor_id
        owner_hash = harness.scalar(
            "SELECT password_hash FROM identity_identities WHERE username = 'ana.admin'"
        )
        admin = service.create_user(
            owner.principal,
            username="beto.admin",
            name="Beto",
            role_id="admin",
            password=PASSWORD,
        )
        custom = service.create_role(
            owner.principal,
            name="Nodo reservado",
            permissions=["assets.view", "system.view"],
        )
        grant = service.login("beto.admin", PASSWORD)
        assert grant.permissions == ADMIN_PERMISSIONS
        assert not grant.permissions & SYSTEM_PERMISSIONS
        assert "agents.providers.personal" in grant.permissions

        with pytest.raises(PermissionDenied):
            service.create_user(
                grant.principal,
                username="intruder.owner",
                name="Intruder",
                role_id="superadmin",
                password=PASSWORD,
            )
        with pytest.raises(PermissionDenied):
            service.create_role(
                grant.principal,
                name="Fake owner",
                permissions=["assets.view", "system.view"],
            )
        with pytest.raises(PermissionDenied):
            service.update_role(grant.principal, custom.id, permissions=["assets.view"])
        with pytest.raises(PermissionDenied):
            service.update_user(grant.principal, owner_id, role_id="admin")
        with pytest.raises(PermissionDenied):
            service.update_user(grant.principal, owner_id, password="another-password-value")
        with pytest.raises(PermissionDenied):
            service.set_active(grant.principal, owner_id, active=False)
        with pytest.raises(PermissionDenied):
            service.update_user(grant.principal, admin.id, role_id="superadmin")

        service.authorize(grant.principal, "config.integrations", resource="integration:1")
        service.authorize(grant.principal, "assets.purge", resource="asset:1")
        with pytest.raises(PermissionDenied):
            service.authorize(grant.principal, "system.view", resource="system")

    assert harness.scalar("SELECT COUNT(*) FROM identity_identities") == 2
    owner_row = harness.sql(
        "SELECT role_id, active, password_hash FROM identity_identities "
        "WHERE username = 'ana.admin'"
    )[0]
    assert tuple(owner_row) == ("superadmin", 1, owner_hash)
    assert (
        harness.scalar(
            "SELECT COUNT(*) FROM identity_role_policies "
            "WHERE role_id = 'admin' AND resource = 'system'"
        )
        == 0
    )


def test_user_profile_is_read_only_until_a_business_grant_is_assigned(
    harness: Harness,
) -> None:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        owner = service.login("ana.admin", PASSWORD)
        rita = service.create_user(
            owner.principal,
            username="rita.user",
            name="Rita",
            role_id="user",
            password=PASSWORD,
        )
        grant = service.login("rita.user", PASSWORD)
        assert grant.permissions == {
            "assets.view",
            "people.view",
            "agents.providers.personal",
        }
        service.authorize(grant.principal, "assets.view", resource="asset:1")
        service.authorize(grant.principal, "people.view", resource="person:1")
        for denied in ("assets.edit", "users.view", "system.view"):
            with pytest.raises(PermissionDenied):
                service.authorize(grant.principal, denied)

        campo = service.create_role(
            owner.principal,
            name="Campo",
            permissions=["assets.view", "assets.edit"],
        )
        service.update_user(owner.principal, rita.id, role_id=campo.id)

    with harness.service() as service:
        refreshed = service.login("rita.user", PASSWORD)
        assert refreshed.permissions == {"assets.view", "assets.edit"}
        service.authorize(refreshed.principal, "assets.edit", resource="asset:1")
        with pytest.raises(PermissionDenied):
            service.authorize(refreshed.principal, "system.view")


def test_human_custom_role_with_reserved_grants_never_gains_owner_authority(
    harness: Harness,
) -> None:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        owner = service.login("ana.admin", PASSWORD)
        fake = service.create_role(
            owner.principal,
            name="Superadministrador falso",
            permissions=sorted(OWNER_PERMISSIONS),
        )
        user = service.create_user(
            owner.principal,
            username="rita.user",
            name="Rita",
            role_id="user",
            password=PASSWORD,
        )
        with pytest.raises(ValidationFailed):
            service.create_user(
                owner.principal,
                username="fake.owner",
                name="Fake",
                role_id=fake.id,
                password=PASSWORD,
            )
        assert harness.scalar("SELECT COUNT(*) FROM identity_identities") == 2
        harness.execute(
            "UPDATE identity_identities SET role_id = :role WHERE id = :id",
            {"role": fake.id, "id": user.id},
        )
        grant = service.login("rita.user", PASSWORD)
        assert "assets.view" in grant.permissions
        assert not grant.permissions & SYSTEM_PERMISSIONS
        with pytest.raises(PermissionDenied):
            service.authorize(grant.principal, "system.view", resource="system")


def test_machine_reserved_grants_require_a_live_owner_delegator(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        owner = service.login("ana.admin", PASSWORD)
        owner_id = owner.principal.actor_id
        reserved = service.create_role(
            owner.principal,
            name="Nodo sistema",
            permissions=["assets.view", "system.view", "system.backup"],
        )
        with pytest.raises(ValidationFailed):
            service.create_user(
                owner.principal,
                username="agent.undelegated",
                name="Agent",
                role_id=reserved.id,
                actor_kind="internal_agent",
            )
        for administrator in ("admin", "superadmin"):
            with pytest.raises(ValidationFailed):
                service.create_user(
                    owner.principal,
                    username="agent." + administrator,
                    name="Agent",
                    role_id=administrator,
                    actor_kind="internal_agent",
                    delegated_by_id=owner_id,
                )
        agent = service.create_user(
            owner.principal,
            username="agent.owner",
            name="Agent",
            role_id=reserved.id,
            actor_kind="internal_agent",
            delegated_by_id=owner_id,
        )
        credential = service.issue_machine_credential(agent.username)
        assert (
            harness.scalar(
                "SELECT role_owner FROM identity_identities WHERE username = 'agent.owner'"
            )
            == "superadmin"
        )

    with harness.service() as service:
        context = service.authenticate_token(credential.token)
        service.authorize(context.principal, "system.view")
        service.authorize(context.principal, "assets.view", resource="asset:1")

    with harness.service() as service:
        second = service.create_user(
            owner.principal,
            username="beto.owner",
            name="Beto",
            role_id="superadmin",
            password=PASSWORD,
        )
        second_grant = service.login("beto.owner", PASSWORD)
        second_agent = service.create_user(
            second_grant.principal,
            username="agent.second",
            name="Agent",
            role_id=reserved.id,
            actor_kind="internal_agent",
            delegated_by_id=second.id,
        )
        second_credential = service.issue_machine_credential(second_agent.username)

    with harness.service() as service:
        service.update_user(second_grant.principal, owner_id, role_id="admin")
        # The same bearer loses reserved authority as soon as the live
        # delegator stops being the owner, while business grants remain.
        demoted = service.authenticate_token(credential.token)
        with pytest.raises(PermissionDenied):
            service.authorize(demoted.principal, "system.view")
        service.authorize(demoted.principal, "assets.view", resource="asset:1")

        service.update_role(second_grant.principal, reserved.id, permissions=["assets.view"])
        revoked = service.authenticate_token(second_credential.token)
        with pytest.raises(PermissionDenied):
            service.authorize(revoked.principal, "system.view")
        service.authorize(revoked.principal, "assets.view", resource="asset:1")


def test_role_grant_change_applies_to_the_same_machine_bearer(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        owner = service.login("ana.admin", PASSWORD)
        reserved = service.create_role(
            owner.principal,
            name="Nodo sistema",
            permissions=["assets.view", "system.view"],
        )
        machine = service.create_user(
            owner.principal,
            username="agent.cache",
            name="Agent Cache",
            role_id=reserved.id,
            actor_kind="internal_agent",
            delegated_by_id=owner.principal.actor_id,
        )
        credential = service.issue_machine_credential(machine.username)

    with harness.service() as service:
        first = service.authenticate_token(credential.token)
        service.authorize(first.principal, "system.view")

        service.update_role(owner.principal, reserved.id, permissions=["assets.view"])

        # No re-login, credential reissue or process restart: the same bearer
        # token must observe the persisted grant change on its next request.
        second = service.authenticate_token(credential.token)
        with pytest.raises(PermissionDenied):
            service.authorize(second.principal, "system.view")
        service.authorize(second.principal, "assets.view", resource="asset:1")


def _bootstrap_attempt(
    settings: Settings, username: str, barrier: Barrier, results: list[str]
) -> None:
    barrier.wait()
    engine = create_engine_from_settings(settings)
    session = create_session_factory(engine)()
    try:
        IdentityService(session, settings).bootstrap_superadmin(username, username, PASSWORD)
        results.append("created")
    except BootstrapRefused:
        results.append("refused")
    except Exception as exc:  # pragma: no cover - only a regression signal
        results.append(f"{type(exc).__name__}:{exc}")
    finally:
        session.close()
        engine.dispose()


def test_concurrent_first_owner_creation_creates_exactly_one_owner(harness: Harness) -> None:
    barrier = Barrier(2)
    results: list[str] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_bootstrap_attempt, harness.settings, username, barrier, results)
            for username in ("ana.owner", "beto.owner")
        ]
        for future in futures:
            future.result()

    assert sorted(results) == ["created", "refused"]
    assert harness.scalar("SELECT COUNT(*) FROM identity_identities") == 1
    assert (
        harness.scalar(
            "SELECT COUNT(*) FROM identity_identities WHERE active = 1 AND role_id = 'superadmin'"
        )
        == 1
    )


def _deactivate_other(
    settings: Settings,
    principal: object,
    target_id: str,
    barrier: Barrier,
    results: list[str],
) -> None:
    barrier.wait()
    engine = create_engine_from_settings(settings)
    session = create_session_factory(engine)()
    try:
        IdentityService(session, settings).set_active(principal, target_id, active=False)  # type: ignore[arg-type]
        results.append("deactivated")
    except Conflict, PermissionDenied:
        results.append("refused")
    except Exception as exc:  # pragma: no cover - only a regression signal
        results.append(f"{type(exc).__name__}:{exc}")
    finally:
        session.close()
        engine.dispose()


def test_concurrent_owner_deactivation_never_removes_every_owner(harness: Harness) -> None:
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        first = service.login("ana.admin", PASSWORD)
        second_identity = service.create_user(
            first.principal,
            username="beto.owner",
            name="Beto",
            role_id="superadmin",
            password=PASSWORD,
        )
        second = service.login("beto.owner", PASSWORD)
    first_id = first.principal.actor_id
    second_id = second_identity.id

    barrier = Barrier(2)
    results: list[str] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                _deactivate_other, harness.settings, first.principal, second_id, barrier, results
            ),
            pool.submit(
                _deactivate_other, harness.settings, second.principal, first_id, barrier, results
            ),
        ]
        for future in futures:
            future.result()

    assert sorted(results) == ["deactivated", "refused"]
    assert (
        harness.scalar(
            "SELECT COUNT(*) FROM identity_identities WHERE active = 1 AND role_id = 'superadmin'"
        )
        == 1
    )
