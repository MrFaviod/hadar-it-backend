"""Bounded floor-plan media for directory locations.

A floor owns at most one raster plan. Bytes are validated before any write and
kept in the existing opaque blob storage; the database only stores a small
opaque reference and the image dimensions. The endpoint never interprets a
client path, URL or declared content type, and no plan is exposed without the
same authorization used by the directory (``assets.view`` to read,
``config.sites`` to write).
"""

from __future__ import annotations

import hashlib
import io
import struct
from contextlib import suppress
from dataclasses import dataclass
from typing import Final

from PIL import Image, UnidentifiedImageError
from sqlalchemy.orm import Session

from itsm.attachments.service import StorageUnavailable
from itsm.attachments.storage import LocalBlobStorage
from itsm.config import Settings
from itsm.directory.service import PLAN_PAGE_MAX, DirectoryService
from itsm.identity.service import IdentityService, NotFound, Principal, ValidationFailed
from itsm.inventory.media import detect_image_type

MAX_PLAN_BYTES: Final[int] = 5 * 1024 * 1024
MAX_PLAN_DIMENSION: Final[int] = 8192
MAX_PLAN_PIXELS: Final[int] = 25_000_000
PLAN_CONTENT_TYPES: Final[tuple[str, ...]] = ("image/png", "image/jpeg", "image/webp")
PLAN_STORAGE_DIR: Final[str] = "directory-plans"

# JPEG Start Of Frame markers carrying the image dimensions.
_JPEG_SOF: Final[frozenset[int]] = frozenset(
    {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
)


@dataclass(frozen=True)
class PlanImage:
    """One validated raster plan, ready for storage or transport."""

    content_type: str
    data: bytes
    width: int
    height: int

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass(frozen=True)
class PlanView:
    """The public plan metadata; never a filesystem path or bearer URL."""

    location_id: str
    plan_ref: str | None
    plan_page: str | None
    content_type: str
    width: int
    height: int
    size: int

    def as_payload(self) -> dict[str, str | int | None]:
        return {
            "locationId": self.location_id,
            "planRef": self.plan_ref,
            "planPage": self.plan_page,
            "contentType": self.content_type,
            "width": self.width,
            "height": self.height,
            "size": self.size,
            "planUrl": f"/locations/{self.location_id}/plan",
        }


def plan_reference(location_id: str, key: str | None = None) -> str:
    """Opaque stable plan identifier; it is never a path or a URL."""
    digest = key or hashlib.sha256(location_id.encode("utf-8")).hexdigest()[:32]
    return "plan-" + digest


def _png_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 24 or data[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def _jpeg_dimensions(data: bytes) -> tuple[int, int] | None:
    index = 2
    while index + 4 <= len(data):
        if data[index] != 0xFF:
            index += 1
            continue
        marker = data[index + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            index += 2
            continue
        if marker == 0xDA:
            return None
        length = struct.unpack(">H", data[index + 2 : index + 4])[0]
        if length < 2 or index + 2 + length > len(data):
            return None
        if marker in _JPEG_SOF:
            if length < 7:
                return None
            height, width = struct.unpack(">HH", data[index + 5 : index + 9])
            return width, height
        index += 2 + length
    return None


def _webp_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 30:
        return None
    chunk = data[12:16]
    if chunk == b"VP8X":
        width = 1 + int.from_bytes(data[24:27], "little")
        height = 1 + int.from_bytes(data[27:30], "little")
        return width, height
    if chunk == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
        width = int.from_bytes(data[26:28], "little") & 0x3FFF
        height = int.from_bytes(data[28:30], "little") & 0x3FFF
        return width, height
    if chunk == b"VP8L" and data[20] == 0x2F and len(data) >= 25:
        bits = data[21:25]
        width = 1 + (((bits[1] & 0x3F) << 8) | bits[0])
        height = 1 + (((bits[3] & 0x0F) << 10) | (bits[2] << 2) | ((bits[1] & 0xC0) >> 6))
        return width, height
    return None


def image_dimensions(data: bytes, content_type: str) -> tuple[int, int] | None:
    """Read dimensions from the bytes; no external decoder or metadata service."""
    if content_type == "image/png":
        return _png_dimensions(data)
    if content_type == "image/jpeg":
        return _jpeg_dimensions(data)
    if content_type == "image/webp":
        return _webp_dimensions(data)
    return None


def validate_plan(data: object) -> PlanImage:
    """Validate one plan upload before any storage write."""
    if not isinstance(data, bytes | bytearray | memoryview):
        raise ValidationFailed("plan must be binary image data")
    payload = bytes(data)
    if not payload:
        raise ValidationFailed("plan image is empty")
    if len(payload) > MAX_PLAN_BYTES:
        raise ValidationFailed(f"plan image must be at most {MAX_PLAN_BYTES // (1024 * 1024)} MiB")
    content_type = detect_image_type(payload)
    if content_type not in PLAN_CONTENT_TYPES:
        raise ValidationFailed("plan image must be a PNG, JPEG or WebP file")
    dimensions = image_dimensions(payload, content_type)
    if dimensions is None:
        raise ValidationFailed("plan image dimensions could not be read")
    width, height = dimensions
    if width < 1 or height < 1:
        raise ValidationFailed("plan image dimensions are invalid")
    if width > MAX_PLAN_DIMENSION or height > MAX_PLAN_DIMENSION:
        raise ValidationFailed(f"plan image sides must be at most {MAX_PLAN_DIMENSION} pixels")
    if width * height > MAX_PLAN_PIXELS:
        raise ValidationFailed("plan image has too many pixels")
    try:
        with Image.open(io.BytesIO(payload)) as image:
            if (
                image.format
                != {"image/png": "PNG", "image/jpeg": "JPEG", "image/webp": "WEBP"}[content_type]
            ):
                raise ValidationFailed("plan image content does not match its type")
            if getattr(image, "n_frames", 1) != 1:
                raise ValidationFailed("plan image must contain one frame")
            image.load()
    except UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError:
        raise ValidationFailed("plan image is not a valid image") from None
    return PlanImage(content_type=content_type, data=payload, width=width, height=height)


class DirectoryMediaService:
    """One floor plan per location, stored outside the relational database."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        identity: IdentityService | None = None,
        storage: LocalBlobStorage | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._identity = identity or IdentityService(session, settings)
        self._directory = DirectoryService(session, settings, identity=self._identity)
        self._storage = storage or LocalBlobStorage(
            settings.attachment_storage_path / PLAN_STORAGE_DIR
        )

    @staticmethod
    def _key(location_id: str) -> str:
        return hashlib.sha256(location_id.encode("utf-8")).hexdigest()[:32]

    def _read_raw(self, key: str) -> bytes | None:
        try:
            return self._storage.read(key, MAX_PLAN_BYTES)
        except FileNotFoundError:
            return None
        except OSError:
            raise StorageUnavailable() from None

    def _write_raw(self, key: str, data: bytes) -> None:
        try:
            self._storage.put(key, data)
        except FileExistsError:
            raise StorageUnavailable() from None
        except OSError:
            raise StorageUnavailable() from None

    def _replace_raw(self, key: str, data: bytes | None) -> None:
        try:
            self._storage.delete(key)
        except FileNotFoundError:
            pass
        except OSError:
            raise StorageUnavailable() from None
        if data is not None:
            self._write_raw(key, data)

    def _location(self, principal: Principal, location_id: str, *, write: bool):
        view = self._directory.get_location(principal, location_id)
        if view.level != "floor":
            raise ValidationFailed("floor plans are only stored on a floor location")
        if write:
            self._identity.authorize(principal, "config.sites", resource=f"location:{view.id}")
        return view

    def _stored_image(self, key: str) -> PlanImage | None:
        data = self._read_raw(key)
        if data is None:
            return None
        try:
            return validate_plan(data)
        except ValidationFailed:
            # Storage holds something that is not a valid plan. Do not return
            # arbitrary bytes to the browser or claim metadata for them.
            raise StorageUnavailable() from None

    def read(self, principal: Principal, location_id: str) -> PlanImage:
        """Authorized raster bytes for one floor plan."""
        self._location(principal, location_id, write=False)
        image = self._stored_image(self._key(location_id))
        if image is None:
            raise NotFound("plan not found")
        return image

    def meta(self, principal: Principal, location_id: str) -> PlanView:
        """Authorized metadata for one floor plan."""
        view = self._location(principal, location_id, write=False)
        image = self._stored_image(self._key(location_id))
        if image is None:
            raise NotFound("plan not found")
        return PlanView(
            location_id=location_id,
            plan_ref=view.plan_ref,
            plan_page=view.plan_page,
            content_type=image.content_type,
            width=image.width,
            height=image.height,
            size=image.size,
        )

    def upload(self, principal: Principal, location_id: str, data: object) -> PlanView:
        """Validate bytes, store them, then publish the opaque reference."""
        view = self._location(principal, location_id, write=True)
        image = validate_plan(data)
        key = self._key(location_id)
        previous = self._read_raw(key)
        self._replace_raw(key, image.data)
        page = f"{image.width}x{image.height}"
        if len(page) > PLAN_PAGE_MAX:
            self._replace_raw(key, previous)
            raise ValidationFailed("plan dimensions do not fit the plan page field")
        marker = plan_reference(location_id, key)
        try:
            if view.plan_ref != marker or view.plan_page != page:
                view = self._directory.update_location(
                    principal,
                    location_id,
                    {"plan_ref": marker, "plan_page": page},
                    source="rest",
                    notes="Floor plan image uploaded",
                )
        except BaseException:
            with suppress(StorageUnavailable):
                self._replace_raw(key, previous)
            raise
        return PlanView(
            location_id=location_id,
            plan_ref=view.plan_ref,
            plan_page=view.plan_page,
            content_type=image.content_type,
            width=image.width,
            height=image.height,
            size=image.size,
        )

    def delete(self, principal: Principal, location_id: str) -> None:
        """Remove the stored plan and its server-owned reference."""
        view = self._location(principal, location_id, write=True)
        key = self._key(location_id)
        try:
            self._storage.delete(key)
        except FileNotFoundError:
            pass
        except OSError:
            raise StorageUnavailable() from None
        marker = plan_reference(location_id, key)
        if view.plan_ref == marker:
            self._directory.update_location(
                principal,
                location_id,
                {"plan_ref": None, "plan_page": None},
                source="rest",
                notes="Floor plan image removed",
            )


__all__ = [
    "MAX_PLAN_BYTES",
    "MAX_PLAN_DIMENSION",
    "MAX_PLAN_PIXELS",
    "PLAN_CONTENT_TYPES",
    "DirectoryMediaService",
    "PlanImage",
    "PlanView",
    "image_dimensions",
    "plan_reference",
    "validate_plan",
]
