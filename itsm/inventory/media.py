"""Bounded raster-image validation for asset media.

Only a signature-checked raster image is accepted. The declared transport
``Content-Type`` is never trusted and never echoed back: the bytes decide the
stored type. SVG, script-bearing documents, data URLs and remote fetches are
structurally impossible here because no text, URL or path is ever interpreted.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Any, Final

from itsm.identity.service import ValidationFailed

MAX_IMAGE_BYTES: Final[int] = 1024 * 1024
MEDIA_ROLES: Final[tuple[str, ...]] = ("photo", "fov")
PHOTO_ROLE: Final[str] = MEDIA_ROLES[0]
FOV_ROLE: Final[str] = MEDIA_ROLES[1]
CONTENT_TYPES: Final[tuple[str, ...]] = ("image/png", "image/jpeg", "image/webp", "image/gif")
CAMERA_CATEGORY_PREFIXES: Final[tuple[str, ...]] = ("camera", "camara", "cctv", "ipcam")


@dataclass(frozen=True)
class ImageUpload:
    """One validated image, ready for storage."""

    content_type: str
    data: bytes
    size: int


def detect_image_type(data: bytes) -> str | None:
    """Return the raster content type from magic bytes, or ``None``."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _category_key(category: str | None) -> str:
    if not isinstance(category, str):
        return ""
    decomposed = unicodedata.normalize("NFKD", category.strip().casefold())
    return "".join(character for character in decomposed if not unicodedata.combining(character))


def is_camera_category(category: str | None) -> bool:
    """Whether a free-text category names a camera (accent/case insensitive)."""
    return _category_key(category).startswith(CAMERA_CATEGORY_PREFIXES)


def validate_role(role: Any) -> str:
    """Accept only the two documented image roles."""
    if role not in MEDIA_ROLES:
        raise ValidationFailed("image role must be one of: " + ", ".join(MEDIA_ROLES))
    return role


def validate_image(*, role: Any, category: str | None, data: Any) -> ImageUpload:
    """Validate one upload; every rejection happens before any write."""
    checked_role = validate_role(role)
    if not isinstance(data, bytes | bytearray | memoryview):
        raise ValidationFailed("image must be binary data")
    payload = bytes(data)
    if not payload:
        raise ValidationFailed("image is empty")
    if len(payload) > MAX_IMAGE_BYTES:
        raise ValidationFailed(f"image must be at most {MAX_IMAGE_BYTES // 1024} KiB")
    content_type = detect_image_type(payload)
    if content_type is None:
        raise ValidationFailed("image must be a PNG, JPEG, WebP or GIF file")
    if checked_role == FOV_ROLE and not is_camera_category(category):
        raise ValidationFailed("fov image requires a camera category")
    return ImageUpload(content_type=content_type, data=payload, size=len(payload))
