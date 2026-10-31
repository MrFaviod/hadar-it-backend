"""The core-call ledger belongs to one principal, not just to one module.

A stored capability response is a canonical core response: whoever replays the
key receives it.  The ledger is therefore keyed by
``(extension_id, principal actor id, call_key)`` and a replay re-authorizes the
permission the original call needed, so a second identity, or a principal whose
permission was revoked, cannot read someone else's stored asset view.
"""

# ruff: noqa: F811 - the `env` fixture is imported and also named in signatures.

from __future__ import annotations

from typing import Any

import pytest
from itsm.extensions.host import ExtensionHostService  # noqa: F401 - parity
from itsm.identity.service import IdentityService, PermissionDenied
from sqlalchemy import text
from tests.inventory_support import asset_values
from tests.test_extension_runtime_support import (  # noqa: F401 - fixtures
    MODULE_ID,
    READ,
    WRITE,
    build_package,
    env,
    probe_manifest,
)


def extension_principal(
    env, permissions: list[str], *, username: str, role_name: str
) -> tuple[Any, str]:
    """Create a real role/user pair and resolve the principal it stands for."""
    with env.factory() as session:
        identity = IdentityService(session, env.settings)
        role = identity.create_role(env.owner, name=role_name, permissions=permissions)
        user = identity.create_user(
            env.owner,
            username=username,
            name="Extension principal",
            role_id=role.id,
            password="Extension-Principal-Pass-123",
        )
        return identity.resolve_actor(user.id), role.id


def test_idempotency_key_does_not_replay_across_principals(env) -> None:
    """R3-F2: another principal cannot replay a key and read the stored response."""
    env.install(build_package(probe_manifest(capabilities=["assets.write"])))
    values = asset_values(quick_code="EXT-REPLAY-001", serial="EXT-REPLAY-001")
    owner_result = env.invoke(
        "probe_asset_create", {"values": values, "idempotency_key": "shared-key-1"}
    )
    assert owner_result["quickCode"] == "EXT-REPLAY-001"
    reader, _role = extension_principal(
        env, [READ, WRITE], username="ext.reader", role_name="Extension reader"
    )
    # The reader holds the module permission but no core inventory permission, so
    # its own call with the same key is refused: no stored response is handed out.
    with pytest.raises(PermissionDenied):
        env.invoke(
            "probe_asset_create",
            {"values": values, "idempotency_key": "shared-key-1"},
            actor=reader,
        )
    with env.factory() as session:
        created = session.execute(
            text("SELECT COUNT(*) FROM assets WHERE quick_code = 'EXT-REPLAY-001'")
        ).scalar_one()
        ledger = session.execute(
            text(
                "SELECT COUNT(*) FROM extension_core_calls "
                "WHERE extension_id = :id AND response_json <> ''"
            ),
            {"id": MODULE_ID},
        ).scalar_one()
    assert created == 1
    assert ledger == 1


def test_idempotency_replay_reauthorizes_the_caller(env) -> None:
    """R3-F2: a replay re-checks the core permission the first call needed."""
    env.install(build_package(probe_manifest(capabilities=["assets.write"])))
    values = asset_values(quick_code="EXT-REPLAY-002", serial="EXT-REPLAY-002")
    editor, role_id = extension_principal(
        env,
        [READ, WRITE, "assets.edit", "assets.assign"],
        username="ext.editor",
        role_name="Extension editor",
    )
    first = env.invoke(
        "probe_asset_create",
        {"values": values, "idempotency_key": "editor-key"},
        actor=editor,
    )
    assert first["quickCode"] == "EXT-REPLAY-002"
    with env.factory() as session:
        IdentityService(session, env.settings).update_role(
            env.owner, role_id, permissions=[READ, WRITE]
        )
    with pytest.raises(PermissionDenied):
        env.invoke(
            "probe_asset_create",
            {"values": values, "idempotency_key": "editor-key"},
            actor=editor,
        )


def test_a_second_principal_gets_its_own_ledger_row(env) -> None:
    """Triangulation: scoping the key must not break a legitimate second caller.

    The editor's own key and request are reserved under its own principal, so the
    same key used by a different principal is a separate reservation rather than
    a spurious ``idempotency_conflict``.
    """
    env.install(build_package(probe_manifest(capabilities=["assets.write"])))
    editor, _role = extension_principal(
        env,
        [READ, WRITE, "assets.edit", "assets.assign"],
        username="ext.editor.two",
        role_name="Extension editor two",
    )
    owner_values = asset_values(quick_code="EXT-REPLAY-003", serial="EXT-REPLAY-003")
    editor_values = asset_values(quick_code="EXT-REPLAY-004", serial="EXT-REPLAY-004")
    owner_result = env.invoke(
        "probe_asset_create", {"values": owner_values, "idempotency_key": "shared-key-2"}
    )
    editor_result = env.invoke(
        "probe_asset_create",
        {"values": editor_values, "idempotency_key": "shared-key-2"},
        actor=editor,
    )
    assert owner_result["quickCode"] == "EXT-REPLAY-003"
    assert editor_result["quickCode"] == "EXT-REPLAY-004"
    with env.factory() as session:
        rows = session.execute(
            text(
                "SELECT COUNT(DISTINCT principal_id) FROM extension_core_calls "
                "WHERE extension_id = :id AND call_key = 'shared-key-2'"
            ),
            {"id": MODULE_ID},
        ).scalar_one()
    assert rows == 2
