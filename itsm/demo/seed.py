"""Create a coherent fictional dataset using the same services as the API.

The installation gets exactly two kinds of identity:

* one internal Superadmin owner, whose password is generated here and discarded
  immediately. It exists only because the identity model refuses to run without
  a Superadmin; no visitor can ever log in as it;
* the published demonstration accounts (``admin/admin`` as the demo
  administrator, the operator CLI account and ``demo.operator``), all created
  with the demo-only password waiver.

The business dataset itself lives in :mod:`itsm.demo.populated` and is shared by
the public demonstration and development mode; only the credentials, the
installation marker and the synthetic node monitoring differ.
"""

from __future__ import annotations

import secrets

from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.demo.populated import populate
from itsm.demo.restrictions import (
    INTERNAL_OWNER_USERNAME,
    VISITOR_PASSWORD,
    VISITOR_USERNAME,
    visitor_password_waiver,
)
from itsm.demo.state import DemoInstallation
from itsm.identity.clock import utcnow
from itsm.identity.permissions import ROLE_ADMIN, ROLE_OPERATOR
from itsm.identity.service import IdentityService, Principal
from itsm.inventory.service import InventoryService
from itsm.release_mode import capabilities_for

DATASET = "fictional-infrastructure-v1"


def seed(
    session: Session, settings: Settings, username: str, password: str, *, development: bool = False
) -> dict:
    if development:
        # Reuse fictional business data, never demo credentials or password exemptions.
        identity = IdentityService(session, settings)
        identity.bootstrap_superadmin(username, "Administrador de desarrollo", password)
        principal = identity.login(username, password).principal
        identity.create_user(
            principal,
            username="dev.operator",
            name="Operadora de desarrollo",
            role_id=ROLE_OPERATOR,
            password=password,
        )
    else:
        principal = _demo_principal(session, settings, username, password)
    identity = IdentityService(session, settings)
    dataset = populate(session, settings, identity, principal)
    if not development and settings.demo_data_directory is not None:
        _configure_node_checks(session, settings, identity, principal)
    return {
        "mode": "dev" if development else "demo",
        "dataset": DATASET,
        **dataset,
        "externalNotifications": "blocked",
        "visitorUsername": None if development else VISITOR_USERNAME,
        "visitorRole": None if development else ROLE_ADMIN,
        "operatorUsername": username,
    }


def _demo_principal(
    session: Session, settings: Settings, username: str, password: str
) -> Principal:
    session.add(DemoInstallation(id=1, dataset=DATASET, created_at=utcnow()))
    session.commit()  # Safety marker precedes every service commit, including partial failures.
    identity = IdentityService(
        session,
        settings,
        password_waiver=visitor_password_waiver(capabilities_for("demo")),
    )
    owner_secret = secrets.token_urlsafe(48)
    identity.bootstrap_superadmin(
        INTERNAL_OWNER_USERNAME,
        "Propietario interno de la instalación",
        owner_secret,
    )
    # The owner exists to satisfy the last-Superadmin invariant and to authorise
    # the accounts below. Its secret stays in this frame: it is never printed,
    # returned, logged or persisted anywhere, so the account is unusable.
    owner = identity.login(INTERNAL_OWNER_USERNAME, owner_secret).principal
    del owner_secret
    identity.create_user(
        owner,
        username=VISITOR_USERNAME,
        name="Administrador de demostración",
        role_id=ROLE_ADMIN,
        password=VISITOR_PASSWORD,
    )
    if username != VISITOR_USERNAME:
        identity.create_user(
            owner,
            username=username,
            name="Responsable de demostración",
            role_id=ROLE_ADMIN,
            password=password,
        )
    identity.create_user(
        owner,
        username="demo.operator",
        name="Operadora de demostración",
        role_id=ROLE_OPERATOR,
        password=password,
    )
    # The dataset is authored by the demonstration administrator so the demo
    # history never points at the internal owner.
    return identity.login(VISITOR_USERNAME, VISITOR_PASSWORD).principal


def _configure_node_checks(
    session: Session,
    settings: Settings,
    identity: IdentityService,
    principal: Principal,
) -> None:
    """First generation of a demo installation monitors its own servers."""
    from itsm.demo.telemetry import NODE_METRICS, NODE_THRESHOLDS, node_assets
    from itsm.monitoring.service import MonitoringService

    inventory = InventoryService(session, settings, identity=identity, source="internal")
    monitoring = MonitoringService(session, settings, identity=identity, source="internal")
    for asset in node_assets(inventory, principal):
        monitoring.update_asset(
            principal,
            asset.id,
            {
                "enabled": True,
                "checkType": "node",
                "target": "backend:8000",
                "intervalSeconds": 30,
                "minimumDurationSeconds": 60,
                "metrics": list(NODE_METRICS),
                "thresholds": NODE_THRESHOLDS,
            },
        )
