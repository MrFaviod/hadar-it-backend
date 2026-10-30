"""Administrative services: users, roles, settings, audit, machine credentials."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from itsm.config import Settings
from itsm.identity.permissions import PERMISSION_CATALOG
from itsm.identity.service import (
    AuthenticationFailed,
    Conflict,
    NotFound,
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


def admin_grant(harness: Harness):
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
        return service.login("ana.admin", PASSWORD)


def test_user_creation_round_trips_the_public_fields(harness: Harness) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        created = service.create_user(
            grant.principal,
            username="Luis.Operador",
            name="Luis Operador",
            email="luis@example.test",
            role_id="operator",
            person_id="person-42",
            password=PASSWORD,
        )
        assert created.username == "luis.operador"
        assert created.name == "Luis Operador"
        assert created.email == "luis@example.test"
        assert created.role_id == "operator"
        assert created.person_id == "person-42"
        assert created.actor_kind == "human"
        assert created.active is True
        assert created.last_access is None

        service.login("luis.operador", PASSWORD)
        refreshed = service.me(grant).user
        assert refreshed.last_access is not None

    access = service.me(grant).user
    assert access.id == grant.principal.actor_id


def test_user_creation_rejects_duplicates_unknown_roles_and_missing_passwords(
    harness: Harness,
) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        service.create_user(
            grant.principal,
            username="rita.reader",
            name="Rita",
            role_id="user",
            password=PASSWORD,
        )
        with pytest.raises(Conflict):
            service.create_user(
                grant.principal,
                username="rita.reader",
                name="Rita",
                role_id="user",
                password=PASSWORD,
            )
        with pytest.raises(ValidationFailed):
            service.create_user(
                grant.principal,
                username="no.role",
                name="No role",
                role_id="missing",
                password=PASSWORD,
            )
        with pytest.raises(ValidationFailed):
            service.create_user(grant.principal, username="no.pass", name="No pass", role_id="user")
        with pytest.raises(ValidationFailed):
            service.create_user(
                grant.principal,
                username="machine.pass",
                name="Machine",
                role_id="user",
                actor_kind="external_agent",
                password=PASSWORD,
            )
        with pytest.raises(ValidationFailed):
            service.create_user(
                grant.principal,
                username="machine.bad-kind",
                name="Machine",
                role_id="user",
                actor_kind="robot",
            )


def test_user_update_leaves_omitted_fields_and_password_unchanged(harness: Harness) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        user = service.create_user(
            grant.principal,
            username="rita.reader",
            name="Rita",
            email="rita@example.test",
            role_id="user",
            password=PASSWORD,
        )
        updated = service.update_user(grant.principal, user.id, name="Rita Actualizada")
        assert updated.name == "Rita Actualizada"
        assert updated.email == "rita@example.test"
        assert updated.role_id == "user"
        # The stored password still works because it was not replaced.
        service.login("rita.reader", PASSWORD)

        updated_again = service.update_user(grant.principal, user.id, username="rita.renombrada")
        assert updated_again.username == "rita.renombrada"
        service.login("rita.renombrada", PASSWORD)
        with pytest.raises(AuthenticationFailed):
            service.login("rita.reader", PASSWORD)


def test_roles_are_created_with_validated_permissions_and_cannot_be_escalated(
    harness: Harness,
) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        role = service.create_role(
            grant.principal, name="Campo", permissions=["people.view", "assets.edit"]
        )
        assert role.built_in is False
        assert role.permissions == ("assets.edit", "people.view")
        with pytest.raises(ValidationFailed):
            service.create_role(grant.principal, name="Rota", permissions=["assets.destroy"])
        with pytest.raises(Conflict):
            service.create_role(grant.principal, name="Campo", permissions=["assets.view"])

        user = service.create_user(
            grant.principal,
            username="campo.uno",
            name="Campo Uno",
            role_id=role.id,
            password=PASSWORD,
        )
        grant_campo = service.login("campo.uno", PASSWORD)
        service.authorize(grant_campo.principal, "assets.edit", resource="asset:1")
        with pytest.raises(PermissionDenied):
            service.authorize(grant_campo.principal, "people.edit", resource="person:1")

    with harness.service() as service:
        updated = service.update_role(grant.principal, role.id, permissions=["assets.view"])
        assert updated.permissions == ("assets.view",)
        # Persisted and reloaded: the removed grant is denied on the next check.
        with pytest.raises(PermissionDenied):
            service.authorize(grant_campo.principal, "assets.edit", resource="asset:1")
        service.authorize(grant_campo.principal, "assets.view", resource="asset:1")
        assert user.role_id == role.id


def test_built_in_roles_are_immutable_and_only_roles_manage_can_edit_roles(
    harness: Harness,
) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        with pytest.raises(Conflict):
            service.update_role(grant.principal, "admin", permissions=["assets.view"])
        with pytest.raises(Conflict):
            service.update_role(grant.principal, "user", name="Usuarios")
        with pytest.raises(NotFound):
            service.update_role(grant.principal, "role-missing", permissions=[])
        service.create_user(
            grant.principal,
            username="rita.reader",
            name="Rita",
            role_id="user",
            password=PASSWORD,
        )
        reader = service.login("rita.reader", PASSWORD)
        with pytest.raises(PermissionDenied):
            service.create_role(reader.principal, name="Intento", permissions=["assets.view"])
        with pytest.raises(PermissionDenied):
            service.catalog(reader.principal)


def test_delegated_administrator_cannot_edit_their_own_role(harness: Harness) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        role = service.create_role(grant.principal, name="Auditor", permissions=["roles.manage"])
        service.create_user(
            grant.principal,
            username="auditor.uno",
            name="Auditor",
            role_id=role.id,
            password=PASSWORD,
        )
        auditor = service.login("auditor.uno", PASSWORD)
        with pytest.raises(PermissionDenied):
            service.update_role(auditor.principal, role.id, permissions=["users.edit"])
        # A role above the auditor's own permissions cannot be edited at all.
        other = service.create_role(grant.principal, name="Otra", permissions=["assets.view"])
        with pytest.raises(PermissionDenied):
            service.update_role(auditor.principal, other.id, permissions=["assets.edit"])
        # An edit that stays inside the auditor's ceiling is still allowed.
        inside = service.create_role(grant.principal, name="Dentro", permissions=["roles.manage"])
        assert service.update_role(
            auditor.principal, inside.id, permissions=["roles.manage"]
        ).permissions == ("roles.manage",)


def test_catalog_lists_the_permission_codes_and_actor_kinds(harness: Harness) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        catalog = service.catalog(grant.principal)
    assert catalog.permissions == PERMISSION_CATALOG
    assert catalog.actor_kinds == (
        "human",
        "internal_agent",
        "external_agent",
        "external_client",
    )


def test_session_minutes_setting_applies_to_new_sessions_and_is_bounded(harness: Harness) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        assert service.update_settings(grant.principal, session_minutes=60) == 60
        with pytest.raises(ValidationFailed):
            service.update_settings(grant.principal, session_minutes=1)
        with pytest.raises(ValidationFailed):
            service.update_settings(grant.principal, session_minutes=5000)
        fresh = service.login("ana.admin", PASSWORD)
        assert fresh.session_minutes == 60
        assert service.state(fresh).session_minutes == 60

    harness.tick(61)
    with harness.service() as service, pytest.raises(AuthenticationFailed):
        service.authenticate_session(fresh.token)

    assert harness.scalar("SELECT session_minutes FROM identity_security_settings") == 60


def test_settings_require_sessions_manage(harness: Harness) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        service.create_user(
            grant.principal,
            username="omar.operator",
            name="Omar",
            role_id="operator",
            password=PASSWORD,
        )
        operator = service.login("omar.operator", PASSWORD)
        with pytest.raises(PermissionDenied):
            service.update_settings(operator.principal, session_minutes=60)
    assert harness.scalar("SELECT session_minutes FROM identity_security_settings") == 480


def test_state_returns_authorized_subsets_for_any_authenticated_actor(harness: Harness) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        service.create_user(
            grant.principal,
            username="rita.reader",
            name="Rita",
            role_id="user",
            password=PASSWORD,
        )
        service.create_user(
            grant.principal,
            username="omar.operator",
            name="Omar",
            role_id="operator",
            password=PASSWORD,
        )
        reader = service.login("rita.reader", PASSWORD)
        reader_state = service.state(reader)
        assert reader_state.users == ()
        assert reader_state.roles == ()
        assert reader_state.session_minutes == 480

        admin_state = service.state(grant)
        assert {user.username for user in admin_state.users} == {
            "ana.admin",
            "omar.operator",
            "rita.reader",
        }
        assert {role.id for role in admin_state.roles} == {
            "admin",
            "operator",
            "superadmin",
            "user",
        }

        roles_only = service.create_role(
            grant.principal, name="Gestor", permissions=["roles.manage"]
        )
        service.create_user(
            grant.principal,
            username="gestor.uno",
            name="Gestor",
            role_id=roles_only.id,
            password=PASSWORD,
        )
        gestor = service.login("gestor.uno", PASSWORD)
        gestor_state = service.state(gestor)
        assert gestor_state.users == ()
        assert {role.id for role in gestor_state.roles} == {
            "admin",
            "operator",
            "superadmin",
            "user",
            roles_only.id,
        }


def test_machine_state_never_exposes_identity_administration(harness: Harness) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        service.create_user(
            grant.principal,
            username="agent.ops",
            name="Ops agent",
            role_id="user",
            actor_kind="internal_agent",
        )
        credential = service.issue_machine_credential("agent.ops")
    with harness.service() as service:
        context = service.authenticate_token(credential.token)
        state = service.state(context)
    assert (state.users, state.roles) == ((), ())


def test_audit_listing_requires_sessions_manage_and_never_leaks_secrets(harness: Harness) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        service.create_user(
            grant.principal,
            username="omar.operator",
            name="Omar",
            role_id="operator",
            password=PASSWORD,
        )
        operator = service.login("omar.operator", PASSWORD)
        with pytest.raises(AuthenticationFailed):
            service.login("omar.operator", "wrong-password-value")
        with pytest.raises(PermissionDenied):
            service.list_audit(operator.principal)
        events = service.list_audit(grant.principal, limit=100)

    assert any(event.action == "identity.user_created" for event in events)
    assert any(event.action == "auth.login" and event.outcome == "success" for event in events)
    assert any(event.action == "auth.login" and event.outcome == "denied" for event in events)
    serialized = repr(events)
    assert PASSWORD not in serialized
    assert grant.token not in serialized
    assert "argon2" not in serialized
    assert len(service.list_audit(grant.principal, limit=2)) == 2


def test_machine_credentials_are_hashed_at_rest_and_revocable(harness: Harness) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        service.create_user(
            grant.principal,
            username="agent.ops",
            name="Ops agent",
            role_id="operator",
            actor_kind="external_agent",
        )
        credential = service.issue_machine_credential("agent.ops", label="nightly")
        assert credential.token.startswith("itsm_mk_")
        with pytest.raises(ValidationFailed):
            service.issue_machine_credential("ana.admin")

    stored = harness.scalar("SELECT token_digest FROM identity_credentials")
    assert credential.token not in str(stored)
    assert len(str(stored)) == 64
    with harness.service() as service:
        context = service.authenticate_token(credential.token)
        assert context.principal.kind == "external_agent"

    with harness.service() as service:
        assert service.revoke_machine_credentials("agent.ops") == 1
        with pytest.raises(AuthenticationFailed):
            service.authenticate_token(credential.token)
        assert service.revoke_machine_credentials("agent.ops") == 0


def test_audit_records_outcomes_without_mutating_denied_targets(harness: Harness) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        role = service.create_role(grant.principal, name="Campo", permissions=["assets.view"])
        service.create_user(
            grant.principal, username="campo.uno", name="Campo", role_id=role.id, password=PASSWORD
        )
        campo = service.login("campo.uno", PASSWORD)
        before = harness.scalar("SELECT COUNT(*) FROM identity_roles")
        with pytest.raises(PermissionDenied):
            service.create_role(campo.principal, name="Escalada", permissions=["users.edit"])
        after = harness.scalar("SELECT COUNT(*) FROM identity_roles")
        assert before == after
        denied = [
            event
            for event in service.list_audit(grant.principal)
            if event.action == "roles.manage" and event.outcome == "denied"
        ]

    assert len(denied) == 1
    assert denied[0].actor_username == "campo.uno"


def test_limited_user_manager_cannot_create_an_administrator_or_reset_its_password(
    harness: Harness,
) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        manager_role = service.create_role(
            grant.principal,
            name="Gestor de usuarios",
            permissions=[
                "users.view",
                "users.create",
                "users.edit",
                "assets.view",
                "people.view",
            ],
        )
        service.create_user(
            grant.principal,
            username="gestor.uno",
            name="Gestor Uno",
            role_id=manager_role.id,
            password=PASSWORD,
        )
        manager = service.login("gestor.uno", PASSWORD)
        admin_id = str(
            harness.sql("SELECT id FROM identity_identities WHERE username = 'ana.admin'")[0][0]
        )
        sessions_before = harness.scalar(
            "SELECT COUNT(*) FROM identity_sessions WHERE revoked_at IS NULL"
        )

        with pytest.raises(PermissionDenied):
            service.create_user(
                manager.principal,
                username="intruso.admin",
                name="Intruso",
                role_id="admin",
                password=PASSWORD,
            )
        with pytest.raises(PermissionDenied):
            service.update_user(manager.principal, admin_id, password="otra-clave-larga-2026")
        with pytest.raises(PermissionDenied):
            service.set_active(manager.principal, admin_id, active=False)

    assert harness.scalar("SELECT COUNT(*) FROM identity_identities") == 2
    assert (
        harness.scalar("SELECT COUNT(*) FROM identity_sessions WHERE revoked_at IS NULL")
        == sessions_before
    )
    with harness.service() as service:
        # The administrator password and status are untouched.
        assert service.login("ana.admin", PASSWORD).permissions
        admin_state = harness.sql(
            "SELECT active FROM identity_identities WHERE username = 'ana.admin'"
        )[0][0]
        assert admin_state in (True, 1)
    denied = [
        event
        for event in harness.sql("SELECT action, outcome FROM identity_audit_events ORDER BY id")
        if event[1] == "denied"
    ]
    assert ("identity.user_created", "denied") in denied
    assert ("identity.user_updated", "denied") in denied


def test_limited_user_manager_can_administer_permissions_it_holds(harness: Harness) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        manager_role = service.create_role(
            grant.principal,
            name="Gestor de usuarios",
            permissions=[
                "users.view",
                "users.create",
                "users.edit",
                "assets.view",
                "people.view",
                # The built-in user profile now carries the personal-provider
                # right, so assigning it needs it inside the manager's ceiling.
                "agents.providers.personal",
            ],
        )
        service.create_user(
            grant.principal,
            username="gestor.dos",
            name="Gestor Dos",
            role_id=manager_role.id,
            password=PASSWORD,
        )
        manager = service.login("gestor.dos", PASSWORD)

        created = service.create_user(
            manager.principal,
            username="rita.user",
            name="Rita",
            role_id="user",
            password=PASSWORD,
        )
        assert created.role_id == "user"

        with pytest.raises(PermissionDenied):
            service.create_user(
                manager.principal,
                username="op.uno",
                name="Operador",
                role_id="operator",
                password=PASSWORD,
            )

        renamed = service.update_user(manager.principal, created.id, name="Rita Lector")
        assert renamed.name == "Rita Lector"

        reset = service.update_user(
            manager.principal, created.id, password="nueva-clave-larga-2026"
        )
        assert reset.id == created.id

        own = service.update_user(
            manager.principal, manager.principal.actor_id, name="Gestor Dos B"
        )
        assert own.name == "Gestor Dos B"


def test_limited_role_manager_cannot_grant_or_edit_beyond_its_own_permissions(
    harness: Harness,
) -> None:
    grant = admin_grant(harness)
    with harness.service() as service:
        manager_role = service.create_role(
            grant.principal,
            name="Gestor de roles",
            permissions=["roles.manage", "assets.view"],
        )
        service.create_user(
            grant.principal,
            username="roles.uno",
            name="Roles Uno",
            role_id=manager_role.id,
            password=PASSWORD,
        )
        manager = service.login("roles.uno", PASSWORD)
        roles_before = harness.scalar("SELECT COUNT(*) FROM identity_roles")

        with pytest.raises(PermissionDenied):
            service.create_role(manager.principal, name="Escalada", permissions=["assets.edit"])
        assert harness.scalar("SELECT COUNT(*) FROM identity_roles") == roles_before

        higher = service.create_role(
            grant.principal, name="Campo alto", permissions=["assets.edit", "assets.view"]
        )
        with pytest.raises(PermissionDenied):
            service.update_role(manager.principal, higher.id, permissions=["assets.view"])
        assert (
            harness.scalar(
                "SELECT COUNT(*) FROM identity_role_policies WHERE role_id = '"
                + higher.id
                + "' AND operation = 'edit'"
            )
            == 1
        )

        allowed = service.create_role(manager.principal, name="Dentro", permissions=["assets.view"])
        assert allowed.permissions == ("assets.view",)
        assert service.update_role(
            manager.principal, allowed.id, permissions=["assets.view", "roles.manage"]
        ).permissions == ("assets.view", "roles.manage")
