"""Phase 9 private QR reports and independently authorized public links."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from itsm.identity.models import IdentityRolePolicy
from itsm.identity.service import IdentityService, NotFound, PermissionDenied, ValidationFailed
from itsm.inventory.service import InventoryService
from itsm.reports.models import ReportShare
from itsm.reports.schemas import ASSET_FIELDS
from sqlalchemy import delete, select, update
from tests.inventory_support import Catalog, asset_values, prepare
from tests.test_phase9_reports import reports, seed


@pytest.fixture
def catalog(settings_factory: Any, tmp_path: Path) -> Catalog:
    return prepare(
        settings_factory,
        attachment_storage_path=tmp_path / "blobs",
        report_base_url="https://itam.example.com",
    )


def test_qr_uses_permanent_uuid_and_never_the_quick_code(catalog: Catalog) -> None:
    asset_id = seed(catalog, asset_values(quick_code="QR-001", name="Equipo QR"))
    service = reports(catalog)
    admin = catalog.admin()
    first = service.qr(admin, asset_id)
    assert first["assetId"] == asset_id
    assert first["url"] == f"https://itam.example.com/#/reporte/{asset_id}"
    assert first["svg"].lstrip().startswith("<svg")
    assert first["share"] is None

    with catalog.session() as session:
        inventory = InventoryService(
            session,
            catalog.settings,
            identity=IdentityService(session, catalog.settings),
            source="internal",
        )
        inventory.update(
            admin,
            asset_id,
            {"quick_code": "QR-RENAMED", "category": "Nueva", "site": "Nueva Sede"},
        )
    second = service.qr(admin, asset_id)
    assert second["url"] == first["url"]
    assert second["svg"] == first["svg"]

    report = service.asset_report(admin, asset_id)
    assert report["asset"]["id"] == asset_id
    assert report["asset"]["quickCode"] == "QR-RENAMED"
    assert report["fields"] == list(ASSET_FIELDS)
    assert report["qr"]["url"] == first["url"]
    assert "description" not in report["asset"]


def test_private_report_requires_assets_view(catalog: Catalog) -> None:
    asset_id = seed(catalog, asset_values(quick_code="PRIV-001"))
    reader = catalog.add_user("reader-priv", "Reader Priv", "user")
    # Readers can hold assets.view; a share is a separate capability regardless.
    assert reports(catalog).asset_report(reader, asset_id)["asset"]["id"] == asset_id
    with pytest.raises(PermissionDenied):
        reports(catalog).create_share(reader, asset_id, ["name"])


def test_share_token_is_hashed_and_projection_is_explicit(catalog: Catalog) -> None:
    asset_id = seed(catalog, asset_values(quick_code="PUB-001", name="Equipo Público"))
    service = reports(catalog)
    admin = catalog.admin()
    share = service.create_share(admin, asset_id, ["id", "quickCode", "name"], expires_in_days=7)
    assert set(share) == {"id", "url", "fields", "expiresAt"}
    assert share["url"].startswith(f"https://itam.example.com/#/reporte/{asset_id}/publico?share=")
    token = share["url"].split("share=", 1)[1]
    assert len(token) >= 32
    with catalog.session() as session:
        row = session.get(ReportShare, share["id"])
        assert row is not None
        assert row.token_hash == hashlib.sha256(token.encode()).hexdigest()
        assert token not in json.dumps(dict(row.__dict__), default=str)

    public = service.public_report(token)
    assert set(public) == {"asset", "fields", "expiresAt"}
    assert public["asset"] == {
        "id": asset_id,
        "quickCode": "PUB-001",
        "name": "Equipo Público",
    }
    assert public["fields"] == ["id", "quickCode", "name"]

    hint = service.qr(admin, asset_id)["share"]
    assert hint is not None and hint["id"] == share["id"]
    assert hint["fields"] == share["fields"]
    assert hint["expiresAt"] == share["expiresAt"]
    assert "url" not in hint
    assert token not in json.dumps(hint)

    with raises_not_found():
        service.public_report("x" * 43)


def raises_not_found():
    return pytest.raises(NotFound)


def test_public_link_survives_asset_changes_but_shows_current_values(catalog: Catalog) -> None:
    asset_id = seed(catalog, asset_values(quick_code="MOVE-001", name="Antes"))
    service = reports(catalog)
    admin = catalog.admin()
    share = service.create_share(admin, asset_id, ["name"])
    token = share["url"].split("share=", 1)[1]
    with catalog.session() as session:
        InventoryService(
            session,
            catalog.settings,
            identity=IdentityService(session, catalog.settings),
            source="internal",
        ).update(admin, asset_id, {"name": "Después", "site": "Otra sede"})
    public = service.public_report(token)
    assert public["asset"] == {"name": "Después"}
    assert "site" not in public["asset"]
    assert public["fields"] == ["name"]


def test_disallowed_public_fields_and_expiry_bounds(catalog: Catalog) -> None:
    asset_id = seed(catalog, asset_values(quick_code="BAD-001"))
    service = reports(catalog)
    admin = catalog.admin()
    for fields in (["ip"], ["serial"], ["responsible"], ["technical"], []):
        with pytest.raises(ValidationFailed):
            service.create_share(admin, asset_id, fields)
    with pytest.raises(ValidationFailed):
        service.create_share(admin, asset_id, ["name"], expires_in_days=0)
    with pytest.raises(ValidationFailed):
        service.create_share(admin, asset_id, ["name"], expires_in_days=366)
    with catalog.session() as session:
        assert session.execute(select(ReportShare)).first() is None


def test_revoke_and_expiry_deny_public_access(catalog: Catalog) -> None:
    asset_id = seed(catalog, asset_values(quick_code="REV-001"))
    service = reports(catalog)
    admin = catalog.admin()
    share = service.create_share(admin, asset_id, ["quickCode"])
    token = share["url"].split("share=", 1)[1]
    assert service.revoke_share(admin, share["id"])["revoked"] is True
    assert service.revoke_share(admin, share["id"])["revoked"] is True
    with pytest.raises(NotFound):
        service.public_report(token)
    with catalog.session() as session:
        row = session.get(ReportShare, share["id"])
        assert row is not None and row.revoked_at is not None

    second = service.create_share(admin, asset_id, ["quickCode"])
    second_token = second["url"].split("share=", 1)[1]
    with catalog.session() as session:
        session.execute(
            update(ReportShare)
            .where(ReportShare.id == second["id"])
            .values(expires_at=row.created_at - timedelta(seconds=1))
        )
        session.commit()
    with pytest.raises(NotFound):
        service.public_report(second_token)


def test_revocation_requires_the_independent_share_permission(catalog: Catalog) -> None:
    asset_id = seed(catalog, asset_values(quick_code="PERM-001"))
    service = reports(catalog)
    admin = catalog.admin()
    reader = catalog.add_user("reader-revoke", "Reader Revoke", "user")
    share = service.create_share(admin, asset_id, ["name"])
    with pytest.raises(PermissionDenied):
        service.revoke_share(reader, share["id"])
    token = share["url"].split("share=", 1)[1]
    assert service.public_report(token)["asset"] == {"name": asset_values()["name"]}

    # The public link keeps working only while its issuer still holds the
    # independent capability; losing it turns the link into a generic 404.
    with catalog.session() as session:
        session.execute(
            delete(IdentityRolePolicy).where(
                IdentityRolePolicy.role_id == "superadmin",
                IdentityRolePolicy.resource == "reports",
                IdentityRolePolicy.operation == "share",
            )
        )
        session.commit()
    with pytest.raises(NotFound):
        service.public_report(token)
    with catalog.session() as session:
        session.add(IdentityRolePolicy(role_id="superadmin", resource="reports", operation="share"))
        session.commit()
    assert service.public_report(token)["asset"] == {"name": asset_values()["name"]}
