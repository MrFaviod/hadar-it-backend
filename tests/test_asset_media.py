"""Bounded raster media for the two asset image roles (service and validator)."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

import pytest
from itsm.identity.service import NotFound, PermissionDenied, ValidationFailed
from itsm.inventory.media import (
    MAX_IMAGE_BYTES,
    MEDIA_ROLES,
    is_camera_category,
    validate_image,
    validate_role,
)
from itsm.inventory.service import InventoryService
from sqlalchemy import text
from tests.conftest import ADMIN_USERNAME
from tests.inventory_support import MACHINE, Catalog, prepare

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
GIF = b"GIF89a" + b"\x00" * 32
WEBP = b"RIFF" + b"\x24\x00\x00\x00" + b"WEBPVP8 " + b"\x00" * 24


@pytest.fixture
def catalog(settings_factory: Any) -> Catalog:
    return prepare(settings_factory)


@pytest.fixture
def inventory(catalog: Catalog) -> Iterator[InventoryService]:
    with catalog.session() as session:
        yield InventoryService(session, catalog.settings)


def image_rows(catalog: Catalog) -> int:
    with catalog.engine.connect() as connection:
        return int(connection.execute(text("SELECT COUNT(*) FROM asset_media")).scalar_one())


def add_asset(catalog: Catalog, **overrides: Any) -> Mapping[str, Any]:
    with catalog.session() as session:
        view = InventoryService(session, catalog.settings).create(
            catalog.admin(), {"name": "Activo de prueba", **overrides}
        )
    return view.as_payload()


@pytest.mark.parametrize(
    ("data", "content_type"),
    [
        (PNG, "image/png"),
        (JPEG, "image/jpeg"),
        (GIF, "image/gif"),
        (WEBP, "image/webp"),
    ],
)
def test_validated_rasters_are_accepted(data: bytes, content_type: str) -> None:
    upload = validate_image(role="photo", category=None, data=data)

    assert upload.content_type == content_type
    assert upload.data == data
    assert upload.size == len(data)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>",
        b"<?php system($_GET['c']); ?>",
        b"data:image/png;base64,iVBORw0KGgo=",
        b"<html><body>hola</body></html>",
        b"not an image at all",
        PNG + b"\x00" * (MAX_IMAGE_BYTES),
    ],
)
def test_non_raster_and_oversized_input_is_rejected(data: bytes) -> None:
    with pytest.raises(ValidationFailed):
        validate_image(role="photo", category=None, data=data)


def test_validation_rejects_non_bytes_input() -> None:
    for candidate in ("/etc/passwd", "http://example.com/x.png", None, 42):
        with pytest.raises(ValidationFailed):
            validate_image(role="photo", category=None, data=candidate)


def test_roles_are_limited_to_photo_and_fov_and_fov_needs_a_camera() -> None:
    assert MEDIA_ROLES == ("photo", "fov")
    assert validate_role("photo") == "photo"
    assert validate_role("fov") == "fov"
    assert is_camera_category("Cámara IP") is True
    assert is_camera_category("cámara de seguridad") is True
    assert is_camera_category("CAMARA CCTV") is True
    assert is_camera_category("Red") is False
    assert is_camera_category(None) is False

    assert validate_image(role="fov", category="Cámara IP", data=JPEG).content_type == "image/jpeg"
    with pytest.raises(ValidationFailed):
        validate_image(role="fov", category="Red", data=JPEG)
    with pytest.raises(ValidationFailed):
        validate_image(role="fov", category=None, data=JPEG)
    for role in ("FOV", "../photo", "photo/../../etc/passwd", "avatar", ""):
        with pytest.raises(ValidationFailed):
            validate_role(role)


def test_images_stay_separate_per_role_and_are_urls_in_the_dto(
    catalog: Catalog,
    inventory: Iterator[InventoryService],
) -> None:
    created = add_asset(catalog, category="Cámara IP", type="Cámara")

    inventory.set_image(catalog.admin(), created["id"], "photo", PNG)
    inventory.set_image(catalog.admin(), created["id"], "fov", JPEG)

    view = inventory.get(catalog.admin(), created["id"])
    payload = view.as_payload()
    assert set(payload["images"]) == {"photo", "fov"}
    assert payload["images"]["photo"] == f"/api/v1/assets/{created['id']}/images/photo"
    assert payload["images"]["fov"] == f"/api/v1/assets/{created['id']}/images/fov"
    assert "data" not in payload

    photo = inventory.image(catalog.admin(), created["id"], "photo")
    fov = inventory.image(catalog.admin(), created["id"], "fov")
    assert photo.data == PNG
    assert photo.content_type == "image/png"
    assert fov.data == JPEG
    assert fov.content_type == "image/jpeg"
    assert image_rows(catalog) == 2


def test_replacing_a_role_keeps_one_row_and_removal_is_audited(
    catalog: Catalog,
    inventory: Iterator[InventoryService],
) -> None:
    created = add_asset(catalog)

    inventory.set_image(catalog.admin(), created["id"], "photo", PNG)
    inventory.set_image(catalog.admin(), created["id"], "photo", JPEG)

    assert image_rows(catalog) == 1
    assert inventory.image(catalog.admin(), created["id"], "photo").data == JPEG

    inventory.remove_image(catalog.admin(), created["id"], "photo")

    assert image_rows(catalog) == 0
    assert inventory.get(catalog.admin(), created["id"]).images == {}
    with pytest.raises(NotFound):
        inventory.image(catalog.admin(), created["id"], "photo")
    with pytest.raises(NotFound):
        inventory.remove_image(catalog.admin(), created["id"], "photo")

    actions = [event["action"] for event in catalog.audit()]
    assert actions.count("inventory.asset_image_updated") == 2
    assert actions.count("inventory.asset_image_removed") == 1


def test_read_only_identities_can_view_but_not_change_images(
    catalog: Catalog,
    inventory: Iterator[InventoryService],
) -> None:
    catalog.add_user("reader-user", "Reader User", "user")
    _principal, _token = catalog.add_machine(*MACHINE, role_id="user")
    created = add_asset(catalog)
    inventory.set_image(catalog.admin(), created["id"], "photo", PNG)

    reader = catalog.principal("reader-user")
    machine = catalog.principal(MACHINE[0])

    assert inventory.image(reader, created["id"], "photo").data == PNG
    assert inventory.image(machine, created["id"], "photo").data == PNG
    for actor in (reader, machine):
        with pytest.raises(PermissionDenied):
            inventory.set_image(actor, created["id"], "photo", PNG)
        with pytest.raises(PermissionDenied):
            inventory.remove_image(actor, created["id"], "photo")

    assert inventory.image(catalog.admin(), created["id"], "photo").data == PNG


def test_fov_is_rejected_for_a_non_camera_asset_and_leaves_no_row(
    catalog: Catalog,
    inventory: Iterator[InventoryService],
) -> None:
    created = add_asset(catalog, category="Red", type="Switch")

    with pytest.raises(ValidationFailed):
        inventory.set_image(catalog.admin(), created["id"], "fov", JPEG)

    assert image_rows(catalog) == 0
    assert inventory.get(catalog.admin(), created["id"]).images == {}


def test_invalid_bytes_are_rejected_before_any_write(
    catalog: Catalog,
    inventory: Iterator[InventoryService],
) -> None:
    created = add_asset(catalog)

    with pytest.raises(ValidationFailed):
        inventory.set_image(catalog.admin(), created["id"], "photo", b"<svg/>")

    assert image_rows(catalog) == 0
    assert inventory.get(catalog.admin(), created["id"]).images == {}
    assert catalog.audit("inventory.asset_image_updated") == []


def test_unknown_asset_and_role_are_not_found_or_rejected(
    catalog: Catalog,
    inventory: Iterator[InventoryService],
) -> None:
    with pytest.raises(NotFound):
        inventory.set_image(catalog.admin(), "00000000-0000-0000-0000-000000000000", "photo", PNG)

    created = add_asset(catalog)
    with pytest.raises(NotFound):
        inventory.image(catalog.admin(), created["id"], "fov")
    with pytest.raises(ValidationFailed):
        inventory.image(catalog.admin(), created["id"], "avatar")


def test_catalog_admin_identity_is_recorded_on_media_writes(
    catalog: Catalog,
    inventory: Iterator[InventoryService],
) -> None:
    created = add_asset(catalog)

    inventory.set_image(catalog.admin(), created["id"], "photo", PNG)

    with catalog.engine.connect() as connection:
        row = connection.execute(text("SELECT updated_by, size FROM asset_media")).one()
    assert row[0] == ADMIN_USERNAME
    assert row[1] == len(PNG)


def test_permanent_purge_deletes_media_rows(
    catalog: Catalog,
    inventory: Iterator[InventoryService],
) -> None:
    created = add_asset(catalog)
    inventory.set_image(catalog.admin(), created["id"], "photo", PNG)
    inventory.archive(catalog.admin(), created["id"])

    inventory.purge(catalog.admin(), created["id"], confirm=True)

    assert image_rows(catalog) == 0
