"""Floor-plan media REST and bounded raster validation."""

from __future__ import annotations

import io
import struct
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.directory.api import create_directory_router
from itsm.directory.media import (
    MAX_PLAN_BYTES,
    MAX_PLAN_DIMENSION,
    image_dimensions,
    plan_reference,
    validate_plan,
)
from itsm.directory.media_api import create_directory_media_router
from itsm.identity.api import create_identity_router, install_error_handlers
from itsm.identity.service import ValidationFailed
from PIL import Image
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import MACHINE_PASSWORD, READER, Catalog, prepare, sign_in_as

SettingsFactory = Callable[..., Settings]


@pytest.fixture
def catalog(settings_factory: SettingsFactory, tmp_path) -> Catalog:
    return prepare(settings_factory, attachment_storage_path=tmp_path / "attachments")


def _chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def png_bytes(width: int, height: int) -> bytes:
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    rows = b"".join(b"\x00" + b"\x00\x00\x00\x00" * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(rows))
        + _chunk(b"IEND", b"")
    )


def jpeg_bytes(width: int, height: int) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (width, height)).save(output, format="JPEG")
    return output.getvalue()


def webp_bytes(width: int, height: int) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (width, height)).save(output, format="WEBP")
    return output.getvalue()


@contextmanager
def media_client(catalog: Catalog) -> Iterator[TestClient]:
    """The media router with the real directory/auth services.

    ``create_app`` composition is owned by the main integration; this focused
    test mounts the two directory routers on the same API prefix so the media
    resource is exercised through HTTP without duplicating every module.
    """
    app = FastAPI()
    app.state.settings = catalog.settings
    app.state.session_factory = catalog.factory()
    install_error_handlers(app)
    api = APIRouter(prefix=catalog.settings.api_prefix)
    api.include_router(create_identity_router())
    api.include_router(create_directory_router())
    api.include_router(create_directory_media_router())
    app.include_router(api)
    with TestClient(app) as test_client:
        yield test_client


def admin_auth(test_client: TestClient, catalog: Catalog) -> dict[str, str]:
    return sign_in_as(test_client, catalog.settings, ADMIN_USERNAME, ADMIN_PASSWORD)


def create_location(test_client: TestClient, auth: dict[str, str], **values: Any) -> dict[str, Any]:
    response = test_client.post("/api/v1/locations", json=values, headers=auth)
    assert response.status_code == 201, response.text
    return response.json()


def create_floor(test_client: TestClient, auth: dict[str, str]) -> dict[str, Any]:
    site = create_location(test_client, auth, level="site", name="Example Site")
    building = create_location(
        test_client, auth, level="building", name="Edificio A", parentId=site["id"]
    )
    return create_location(test_client, auth, level="floor", name="Piso 1", parentId=building["id"])


def test_plan_round_trip_publishes_only_opaque_metadata(
    catalog: Catalog,
) -> None:
    with media_client(catalog) as test_client:
        auth = admin_auth(test_client, catalog)
        floor = create_floor(test_client, auth)
        plan = png_bytes(100, 50)

        missing = test_client.get(f"/api/v1/locations/{floor['id']}/plan/meta", headers=auth)
        assert missing.status_code == 404
        assert missing.json() == {"error": {"code": "not_found", "message": "plan not found"}}

        uploaded = test_client.put(
            f"/api/v1/locations/{floor['id']}/plan",
            content=plan,
            headers={**auth, "Content-Type": "image/jpeg"},
        )
        assert uploaded.status_code == 200, uploaded.text
        body = uploaded.json()
        assert set(body) == {
            "locationId",
            "planRef",
            "planPage",
            "contentType",
            "width",
            "height",
            "size",
            "planUrl",
        }
        assert (body["width"], body["height"], body["size"]) == (100, 50, len(plan))
        assert body["contentType"] == "image/png"
        assert body["planPage"] == "100x50"
        assert body["planUrl"] == f"/locations/{floor['id']}/plan"
        reference = body["planRef"]
        assert reference.startswith("plan-") and len(reference) == 37
        assert "/" not in reference and "\\" not in reference and "://" not in reference

        located = test_client.get(f"/api/v1/locations/{floor['id']}", headers=auth)
        assert located.status_code == 200
        assert located.json()["planRef"] == reference
        assert located.json()["planPage"] == "100x50"

        image = test_client.get(f"/api/v1/locations/{floor['id']}/plan", headers=auth)
        assert image.status_code == 200
        assert image.content == plan
        assert image.headers["content-type"] == "image/png"
        assert image.headers["x-plan-width"] == "100"
        assert image.headers["x-plan-height"] == "50"
        assert image.headers["x-content-type-options"] == "nosniff"
        assert image.headers["cache-control"] == "no-store"

        again = test_client.get(f"/api/v1/locations/{floor['id']}/plan/meta", headers=auth)
        assert again.json() == body

        replacement = png_bytes(40, 80)
        updated = test_client.put(
            f"/api/v1/locations/{floor['id']}/plan", content=replacement, headers=auth
        )
        assert updated.status_code == 200, updated.text
        assert (updated.json()["width"], updated.json()["height"]) == (40, 80)
        assert updated.json()["planPage"] == "40x80"
        assert (
            test_client.get(f"/api/v1/locations/{floor['id']}/plan", headers=auth).content
            == replacement
        )

        deleted = test_client.delete(f"/api/v1/locations/{floor['id']}/plan", headers=auth)
        assert deleted.status_code == 204, deleted.text
        assert (
            test_client.get(f"/api/v1/locations/{floor['id']}/plan", headers=auth).status_code
            == 404
        )
        cleared = test_client.get(f"/api/v1/locations/{floor['id']}", headers=auth).json()
        assert (cleared["planRef"], cleared["planPage"]) == (None, None)
        assert (
            test_client.delete(f"/api/v1/locations/{floor['id']}/plan", headers=auth).status_code
            == 204
        )


def test_rejected_uploads_leave_the_previous_plan_untouched(catalog: Catalog) -> None:
    with media_client(catalog) as test_client:
        auth = admin_auth(test_client, catalog)
        floor = create_floor(test_client, auth)
        original = png_bytes(20, 20)
        path = f"/api/v1/locations/{floor['id']}/plan"
        assert test_client.put(path, content=original, headers=auth).status_code == 200

        cases = [
            (
                b"<svg xmlns='http://www.w3.org/2000/svg'></svg>",
                "plan image must be a PNG, JPEG or WebP file",
            ),
            (b"GIF89a" + b"0" * 32, "plan image must be a PNG, JPEG or WebP file"),
            (b"not an image", "plan image must be a PNG, JPEG or WebP file"),
            (b"", "plan image is empty"),
            (
                b"\x89PNG\r\n\x1a\n" + b"\x00" * 8,
                "plan image dimensions could not be read",
            ),
        ]
        for payload, message in cases:
            rejected = test_client.put(path, content=payload, headers=auth)
            assert rejected.status_code == 422, rejected.text
            assert rejected.json() == {"error": {"code": "validation_error", "message": message}}
            assert test_client.get(path, headers=auth).content == original

        too_large = b"\x89PNG\r\n\x1a\n" + b"0" * (MAX_PLAN_BYTES - 7)
        rejected = test_client.put(path, content=too_large, headers=auth)
        assert rejected.status_code == 422
        assert "at most 5 MiB" in rejected.json()["error"]["message"]
        assert test_client.get(path, headers=auth).content == original

        too_wide = png_bytes(MAX_PLAN_DIMENSION + 1, 1)
        rejected = test_client.put(path, content=too_wide, headers=auth)
        assert rejected.status_code == 422
        assert "8192 pixels" in rejected.json()["error"]["message"]
        assert test_client.get(path, headers=auth).content == original


def test_plan_resource_requires_a_floor_and_the_configuration_permission(
    catalog: Catalog,
) -> None:
    with media_client(catalog) as test_client:
        auth = admin_auth(test_client, catalog)
        site = create_location(test_client, auth, level="site", name="Example Site")
        plan = png_bytes(10, 10)
        not_floor = test_client.put(
            f"/api/v1/locations/{site['id']}/plan", content=plan, headers=auth
        )
        assert not_floor.status_code == 422
        assert not_floor.json()["error"]["message"] == (
            "floor plans are only stored on a floor location"
        )

        unknown = "0f8c5f1e-0000-4000-8000-000000000000"
        assert test_client.get(f"/api/v1/locations/{unknown}/plan", headers=auth).status_code == 404
        assert (
            test_client.put(
                f"/api/v1/locations/{unknown}/plan", content=plan, headers=auth
            ).status_code
            == 404
        )

        floor = create_location(
            test_client,
            auth,
            level="building",
            name="Edificio A",
            parentId=site["id"],
        )
        floor = create_location(
            test_client, auth, level="floor", name="Piso 1", parentId=floor["id"]
        )
        assert (
            test_client.put(
                f"/api/v1/locations/{floor['id']}/plan", content=plan, headers=auth
            ).status_code
            == 200
        )

        catalog.add_user(*READER)
        with media_client(catalog) as reader:
            reader_auth = sign_in_as(reader, catalog.settings, READER[0], MACHINE_PASSWORD)
            assert (
                reader.get(f"/api/v1/locations/{floor['id']}/plan", headers=reader_auth).status_code
                == 200
            )
            denied = reader.put(
                f"/api/v1/locations/{floor['id']}/plan",
                content=png_bytes(3, 3),
                headers=reader_auth,
            )
            assert denied.status_code == 403
            assert (
                reader.delete(
                    f"/api/v1/locations/{floor['id']}/plan", headers=reader_auth
                ).status_code
                == 403
            )
            no_csrf = reader.put(
                f"/api/v1/locations/{floor['id']}/plan",
                content=png_bytes(3, 3),
                headers={"Origin": catalog.settings.auth_origin},
            )
            assert no_csrf.status_code == 403
        stored = test_client.get(f"/api/v1/locations/{floor['id']}/plan", headers=auth)
        assert stored.content == plan

        with TestClient(_media_application(catalog)) as second:
            second_auth = admin_auth(second, catalog)
            assert (
                second.get(f"/api/v1/locations/{floor['id']}/plan", headers=second_auth).content
                == plan
            )


def _media_application(catalog: Catalog) -> FastAPI:
    app = FastAPI()
    app.state.settings = catalog.settings
    app.state.session_factory = catalog.factory()
    install_error_handlers(app)
    api = APIRouter(prefix=catalog.settings.api_prefix)
    api.include_router(create_identity_router())
    api.include_router(create_directory_router())
    api.include_router(create_directory_media_router())
    app.include_router(api)
    return app


def test_plan_validator_reads_dimensions_without_trusting_the_declared_type() -> None:
    for image, content_type, dimensions in (
        (png_bytes(12, 7), "image/png", (12, 7)),
        (jpeg_bytes(31, 9), "image/jpeg", (31, 9)),
        (webp_bytes(55, 21), "image/webp", (55, 21)),
    ):
        checked = validate_plan(image)
        assert (checked.content_type, checked.width, checked.height) == (
            content_type,
            dimensions[0],
            dimensions[1],
        )
        assert image_dimensions(image, content_type) == dimensions

    with pytest.raises(ValidationFailed, match="PNG, JPEG or WebP"):
        validate_plan(b"GIF89a" + b"0" * 32)
    with pytest.raises(ValidationFailed, match="dimensions could not be read"):
        validate_plan(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)
    assert plan_reference("location-id") == plan_reference("location-id")
    assert plan_reference("a/b").startswith("plan-")
    assert "/" not in plan_reference("a/b")
