"""Native extension notices preserve inbox ownership and live permission checks."""

from __future__ import annotations

import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from itsm.database import create_engine_from_settings
from itsm.extensions.notifications import enqueue_extension_notice
from itsm.identity.models import Identity, IdentityRolePolicy
from itsm.identity.service import IdentityService, NotFound, Principal, ValidationFailed
from itsm.notifications.models import NotificationEvent, NotificationInbox
from itsm.notifications.service import NotificationService
from tests.conftest import ADMIN_USERNAME, bootstrap_superadmin, run_migrations


@pytest.fixture
def notice_context(settings_factory):
    settings = settings_factory()
    migrated = run_migrations(settings)
    assert migrated.returncode == 0, migrated.stderr
    bootstrap_superadmin(settings)
    engine = create_engine_from_settings(settings)
    with Session(engine) as session:
        owner = session.scalars(select(Identity).where(Identity.username == ADMIN_USERNAME)).one()
        principal = Principal(
            actor_id=owner.id,
            kind="human",
            username=owner.username,
            display_name=owner.name,
            role_id=owner.role_id,
        )
        identity = IdentityService(session, settings)
        operator = identity.create_user(
            principal,
            username="notice-operator",
            name="Notice operator",
            role_id="operator",
            password="extension-notice-password-2026",
        )
        reader = identity.create_user(
            principal,
            username="notice-reader",
            name="Notice reader",
            role_id="user",
            password="extension-notice-password-2026",
        )
        yield settings, session, principal, operator.id, reader.id
    engine.dispose()


def send(context, **changes):
    settings, session, principal, operator_id, reader_id = context
    arguments = {
        "module_id": "notice-example",
        "module_permissions": {"assets.edit"},
        "principal": principal,
        "recipient_ids": [operator_id, reader_id],
        "key": "record-17:2026-10-28",
        "title": "Registro próximo a vencer",
        "body": "El registro vence en siete días.",
        "permission": "assets.edit",
        "url": "#/extensiones/notice-example/records",
    }
    arguments.update(changes)
    return enqueue_extension_notice(session, settings, **arguments)


def test_notice_is_deduplicated_per_authorized_recipient(notice_context):
    settings, session, _principal, operator_id, reader_id = notice_context
    first = send(notice_context)
    session.commit()
    second = send(notice_context)
    session.commit()
    assert first == {"created": 1, "skipped": 1}
    assert second == {"created": 0, "skipped": 2}
    inbox = session.scalars(select(NotificationInbox)).all()
    assert [(row.recipient_id, row.title, row.required_permission) for row in inbox] == [
        (operator_id, "Registro próximo a vencer", "assets.edit")
    ]
    assert reader_id not in {row.recipient_id for row in inbox}
    recipient = session.get(Identity, operator_id)
    principal = IdentityService(session, settings)._principal(recipient)
    visible = NotificationService(session, settings).list_inbox(principal)
    assert visible["total"] == 1
    assert visible["items"][0]["title"] == "Registro próximo a vencer"


def test_revoked_extension_notice_access_hides_content_and_refuses_mark_read(notice_context):
    settings, session, _principal, operator_id, _reader_id = notice_context
    send(notice_context)
    session.commit()
    notice = session.scalars(select(NotificationInbox)).one()
    recipient = session.get(Identity, operator_id)
    principal = IdentityService(session, settings)._principal(recipient)
    session.execute(
        delete(IdentityRolePolicy).where(
            IdentityRolePolicy.role_id == "operator",
            IdentityRolePolicy.resource == "assets",
            IdentityRolePolicy.operation == "edit",
        )
    )
    session.commit()
    service = NotificationService(session, settings)
    assert service.list_inbox(principal) == {"items": [], "total": 0, "limit": 50, "offset": 0}
    with pytest.raises(NotFound):
        service.mark_read(principal, notice.id)
    session.refresh(notice)
    assert notice.read_at is None


def test_undeclared_notice_permission_and_external_url_leave_no_rows(notice_context):
    _settings, session, *_rest = notice_context
    with pytest.raises(ValidationFailed):
        send(notice_context, permission="assets.purge")
    with pytest.raises(ValidationFailed):
        send(notice_context, url="https://external.example/collect")
    assert session.scalars(select(NotificationEvent)).all() == []
    assert session.scalars(select(NotificationInbox)).all() == []


def test_denied_notice_does_not_commit_previous_business_writes(notice_context):
    settings, session, _principal, _operator_id, reader_id = notice_context
    send(notice_context)
    reader = IdentityService(session, settings).resolve_actor(reader_id)
    from itsm.identity.service import PermissionDenied

    with pytest.raises(PermissionDenied):
        send(notice_context, principal=reader, key="reader-denied")
    session.rollback()
    assert session.scalars(select(NotificationEvent)).all() == []
    assert session.scalars(select(NotificationInbox)).all() == []


def test_periodic_worker_delivers_once_and_disable_preserves_data(notice_context):
    """A real generated package reaches the native inbox through the worker entry."""
    import json
    from datetime import timedelta
    from functools import partial

    from itsm.database import create_session_factory
    from itsm.extensions.host import ExtensionHostService
    from itsm.extensions.scheduler import process_extension_schedules
    from itsm.extensions.sdk.generator import generate_package
    from itsm.extensions.sdk.package import build_package
    from itsm.extensions.validator import ContainerValidator
    from itsm.identity.permissions import PERMISSION_CODES

    settings, session, principal, _operator_id, reader_id = notice_context
    validator = ContainerValidator(core_permissions=PERMISSION_CODES)
    if not validator.available():
        pytest.skip("fixed extension validator image unavailable")
    factory = create_session_factory(session.get_bind())
    host = ExtensionHostService(
        settings, factory, notify=partial(enqueue_extension_notice, settings=settings),
    )
    generated = generate_package(
        extension_id="scheduled-records", name="Registros periódicos",
        description="Avisos nativos periódicos con estado persistido.",
        known_core_permissions=PERMISSION_CODES,
    )
    files = dict(generated.files)
    manifest = dict(generated.manifest)
    permission = manifest["permissions"][1]["code"]
    manifest["schedules"] = [{
        "name": "record_notice", "handler": "record_notice", "intervalSeconds": 60,
        "permission": permission,
    }]
    files["extension.json"] = json.dumps(manifest)
    files["backend.py"] += '''

def record_notice(context):
    old = context.store.get("records", "scheduled")
    context.store.put("records", "scheduled", {"title": "Periodic record", "status": "active"},
                      0 if old is None else old["version"])
    context.notify(recipient_ids=[context.principal.actor_id, "READER_ID"],
                   key="record:expiry:2026-10-28", title="Registro próximo a vencer",
                   body="Revisa el registro antes de su vencimiento.",
                   permission="NOTICE_PERMISSION", url="#/extensiones/scheduled-records/records")

_register_records = register
def register(sdk):
    _register_records(sdk)
    sdk.schedule("record_notice", record_notice)
'''.replace("READER_ID", reader_id).replace("NOTICE_PERMISSION", permission)
    files["tests/test_backend.py"] = files["tests/test_backend.py"].replace(
        'raise AssertionError("this example declares no schedules")',
        'assert name == "record_notice" and callable(handler)',
    )
    built = build_package(files, known_core_permissions=PERMISSION_CODES)
    report = validator.validate(built.data, digest=built.digest)
    assert report["status"] == "passed", json.dumps(report, indent=2)
    candidate = host.submit_candidate(principal, built.data)
    host.record_validation_report(candidate["id"], report, expected_version=candidate["revision"])
    # Explicit persisted-human approval in isolated fixture, not model authority.
    host.approve_candidate(principal, candidate["id"], digest=built.digest, expected_version=None)
    first_due = host.list_schedules()[0].next_due_at
    assert process_extension_schedules(settings, first_due)["succeeded"] == 1
    second_due = host.list_schedules()[0].next_due_at
    assert process_extension_schedules(settings, second_due)["succeeded"] == 1
    session.expire_all()
    notices = session.scalars(select(NotificationInbox)).all()
    assert [(row.recipient_id, row.required_permission) for row in notices] == [(principal.actor_id, permission)]
    assert host.invoke(principal, "scheduled-records", "list_records", {})["total"] == 1
    installed = host.discovery(principal)["items"][0]
    host.set_enabled(principal, "scheduled-records", enabled=False, expected_version=installed["revision"])
    assert process_extension_schedules(settings, second_due + timedelta(minutes=2))["claimed"] == 0
    host.set_enabled(principal, "scheduled-records", enabled=True, expected_version=installed["revision"] + 1)
    assert host.invoke(principal, "scheduled-records", "list_records", {})["items"][0]["title"] == "Periodic record"
