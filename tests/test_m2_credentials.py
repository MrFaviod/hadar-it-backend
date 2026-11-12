"""Bounded machine credentials and honest local operator attribution."""

import json
from datetime import timedelta

import pytest
from itsm.identity.service import AuthenticationFailed
from tests.identity_support import PASSWORD, make_harness
from tests.test_identity_cli import bootstrap_args, migrated, run_identity_cli, service


def test_machine_credential_expires_at_exact_boundary_and_rotation_revokes_old(settings_factory):
    harness = make_harness(settings_factory)
    try:
        with harness.service() as identity:
            owner = identity.bootstrap_superadmin("ana.admin", "Ana", PASSWORD)
            identity.bootstrap_machine(
                "expiry.agent", "Agent", "external_agent", "operator", delegated_by="ana.admin"
            )
            first = identity.issue_machine_credential("expiry.agent")
            assert identity.authenticate_token(first.token).principal.delegated_by == owner.id
        harness.clock += timedelta(days=90) - timedelta(microseconds=1)
        with harness.service() as identity:
            identity.authenticate_token(first.token)
        harness.clock += timedelta(microseconds=1)
        with harness.service() as identity:
            with pytest.raises(AuthenticationFailed):
                identity.authenticate_token(first.token)
            second = identity.issue_machine_credential("expiry.agent")
            rotated = identity.issue_machine_credential("expiry.agent", rotate=True)
            with pytest.raises(AuthenticationFailed):
                identity.authenticate_token(second.token)
            assert identity.authenticate_token(rotated.token).principal.username == "expiry.agent"
            assert identity.revoke_machine_credentials("expiry.agent") == 1
            with pytest.raises(AuthenticationFailed):
                identity.authenticate_token(rotated.token)
    finally:
        harness.close()


def test_cli_rotation_and_local_audit_preserve_first_bootstrap(settings_factory):
    settings = migrated(settings_factory)
    bootstrap = run_identity_cli(
        bootstrap_args(), settings, extra_env={"ITSM_BOOTSTRAP_PASSWORD": PASSWORD}
    )
    assert bootstrap.returncode == 0 and bootstrap.stderr == ""
    created = run_identity_cli(
        [
            "create-machine-identity",
            "--username",
            "cli.agent",
            "--name",
            "Agent",
            "--actor-kind",
            "external_agent",
            "--role",
            "operator",
            "--delegated-by",
            "ana.admin",
        ],
        settings,
    )
    assert created.returncode == 0 and created.stderr == "", created.stderr
    first = json.loads(created.stdout)
    rotated = run_identity_cli(["rotate-machine-token", "--username", "cli.agent"], settings)
    assert rotated.returncode == 0 and rotated.stderr == "", rotated.stderr
    second = json.loads(rotated.stdout)
    assert second["action"] == "rotate-machine-token"
    assert second["expiresAt"] and second["credentialId"]
    assert second["token"] != first["token"]
    assert rotated.stdout.count(second["token"]) == 1
    identity = service(settings)
    try:
        with pytest.raises(AuthenticationFailed):
            identity.authenticate_token(first["token"])
        identity.authenticate_token(second["token"])
        owner = identity.login("ana.admin", PASSWORD).principal
        events = identity.list_audit(owner, limit=200)
        local = [
            event
            for event in events
            if event.action
            in {
                "identity.bootstrap",
                "identity.bootstrap_machine",
                "identity.credential_issued",
                "identity.credential_rotated",
            }
        ]
        assert len(local) == 4
        assert all(
            event.actor_kind == "local_operator"
            and event.actor_id is None
            and event.actor_username is None
            for event in local
        )
        assert any(
            event.delegated_by == owner.actor_id
            for event in local
            if event.action == "identity.bootstrap_machine"
        )
        revoked = run_identity_cli(["revoke-machine-token", "--username", "cli.agent"], settings)
        assert revoked.returncode == 0 and revoked.stderr == ""
        assert json.loads(revoked.stdout) == {
            "status": "revoked",
            "action": "revoke-machine-token",
            "username": "cli.agent",
            "revoked": 1,
        }
        event = identity.list_audit(owner, limit=1)[0]
        assert event.actor_kind == "local_operator" and event.actor_id is None
        assert event.actor_username is None
    finally:
        identity._session.close()


def test_machine_expiry_migration_preserves_legacy_token_for_bounded_grace(settings_factory):
    from datetime import UTC, datetime

    from itsm.database import create_engine_from_settings
    from itsm.identity.hashing import hash_token
    from sqlalchemy import text
    from tests.conftest import run_cli, run_migrations

    settings = settings_factory()

    def migrate(*args):
        result = run_cli(["-m", "alembic", *args], settings)
        assert result.returncode == 0, result.stderr
        return result

    migrate("upgrade", "0044_personal_api_keys")
    engine = create_engine_from_settings(settings)
    now = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO identity_identities (id,username,name,actor_kind,"
                "active,role_id,created_at,updated_at) VALUES ('legacy-agent','legacy.agent',"
                "'Legacy','external_agent',1,'operator',:now,:now)"
            ),
            {"now": now},
        )
        connection.execute(
            text(
                "INSERT INTO identity_credentials "
                "(id,identity_id,token_digest,created_at) VALUES ('legacy-token','legacy-agent',"
                ":digest,:now)"
            ),
            {"digest": hash_token("isolated-legacy-test-token"), "now": now},
        )
    before = datetime.now(UTC)
    result = run_migrations(settings)
    assert result.returncode == 0, result.stderr
    identity = service(settings)
    try:
        identity.authenticate_token("isolated-legacy-test-token")
        # Public authentication must stop at the new persisted boundary.
        with engine.connect() as connection:
            expiry = connection.execute(
                text("SELECT expires_at FROM identity_credentials")
            ).scalar_one()
        expiry = datetime.fromisoformat(str(expiry)).replace(tzinfo=UTC)
        assert before + timedelta(days=90) <= expiry <= datetime.now(UTC) + timedelta(days=90)
        identity._now = lambda: expiry
        with pytest.raises(AuthenticationFailed):
            identity.authenticate_token("isolated-legacy-test-token")
    finally:
        identity._session.close()
    migrate("downgrade", "0044_personal_api_keys")
    with engine.connect() as connection:
        assert connection.execute(
            text("SELECT token_digest FROM identity_credentials")
        ).scalar_one() == hash_token("isolated-legacy-test-token")
    migrate("upgrade", "head")
    engine.dispose()
