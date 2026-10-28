"""Persistence helpers shared by the host service and identity authority.

Only this module reads extension permission rows for authorization.  It has no
module-global cache: every check uses the caller's SQLAlchemy session, so a
revoked or newly installed grant is visible immediately and isolated test/app
instances never leak permission state into each other.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from itsm.extensions.models import (
    ExtensionEvent,
    ExtensionModule,
    ExtensionPermission,
    ExtensionVersion,
)


def get_module(session: Session, extension_id: str) -> ExtensionModule | None:
    return session.get(ExtensionModule, extension_id)


def get_version(session: Session, extension_id: str, version: str) -> ExtensionVersion | None:
    return session.execute(
        select(ExtensionVersion).where(
            ExtensionVersion.extension_id == extension_id,
            ExtensionVersion.version == version,
        )
    ).scalar_one_or_none()


def get_active_version(session: Session, module: ExtensionModule) -> ExtensionVersion | None:
    if module.active_version is None:
        return None
    return get_version(session, module.id, module.active_version)


def permission_owner(session: Session, code: str) -> str | None:
    row = session.execute(
        select(ExtensionPermission).where(ExtensionPermission.code == code)
    ).scalar_one_or_none()
    return None if row is None else row.extension_id


def extension_permission_exists(session: Session, code: str) -> bool:
    return (
        session.execute(
            select(ExtensionPermission.id).where(ExtensionPermission.code == code)
        ).first()
        is not None
    )


def registered_permission_codes(session: Session) -> tuple[str, ...]:
    rows = session.execute(
        select(ExtensionPermission.code).order_by(ExtensionPermission.code)
    ).scalars()
    return tuple(rows)


def register_extension_permission(
    session: Session,
    *,
    extension_id: str,
    code: str,
    label: str,
    description: str,
) -> bool:
    """Insert or refresh one namespaced code; returns True when newly created."""
    row = session.execute(
        select(ExtensionPermission).where(ExtensionPermission.code == code)
    ).scalar_one_or_none()
    if row is not None:
        if row.extension_id != extension_id:
            raise ValueError(f"permission {code} belongs to another extension")
        row.label = label
        row.description = description
        session.flush()
        return False
    session.add(
        ExtensionPermission(
            extension_id=extension_id,
            code=code,
            label=label,
            description=description,
        )
    )
    session.flush()
    return True


def record_event(
    session: Session,
    *,
    extension_id: str,
    action: str,
    actor_id: str | None,
    detail: Mapping[str, Any],
) -> ExtensionEvent:
    event = ExtensionEvent(
        extension_id=extension_id,
        action=action,
        actor_id=actor_id,
        detail_json=json.dumps(detail, sort_keys=True, separators=(",", ":")),
    )
    session.add(event)
    session.flush()
    return event
