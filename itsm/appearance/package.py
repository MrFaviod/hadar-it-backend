"""Portable appearance ZIP packages and strict graphic-resource validation.

Every byte is validated in memory before it can reach SQL or blob storage.
ZIPs are bounded by entry count, compressed size, expanded size and
compression ratio; names must be exactly ``preset.json`` plus one resource per
graphic key, so traversal, duplicates, encrypted entries and unsupported
compression never reach a stored location. Nothing is ever extracted to the
filesystem: accepted bytes go to opaque ``BlobStorage`` keys.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import re
import struct
import zipfile
from dataclasses import dataclass
from typing import Any, Callable

from defusedxml import ElementTree as DefusedElementTree
from PIL import Image, UnidentifiedImageError

from itsm.appearance.schemas import GRAPHIC_KEYS, PresetPayload
from itsm.identity.service import ValidationFailed

MAX_ZIP_BYTES = 24 * 1024 * 1024
MAX_ENTRIES = 40
MAX_ENTRY_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 24 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_COMPRESSION_RATIO = 1000
MAX_LOGO_BYTES = 2 * 1024 * 1024
MAX_FAVICON_BYTES = 512 * 1024
MAX_SVG_BYTES = MAX_LOGO_BYTES
MAX_IMAGE_PIXELS = 16_777_216
MAX_IMAGE_EDGE = 4096
MAX_ICO_FRAMES = 64
MAX_ICO_EDGE = 256

FORMAT = "asset-manager-appearance"
FORMAT_VERSION = 1

CONTENT_TYPES = {
    "svg": "image/svg+xml",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
    "ico": "image/x-icon",
}
EXTENSIONS = {
    "image/svg+xml": "svg",
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
    "image/x-icon": "ico",
}
ALLOWED_TYPES = {
    "logo": frozenset({"image/svg+xml", "image/png", "image/jpeg", "image/webp"}),
    "logoDark": frozenset({"image/svg+xml", "image/png", "image/jpeg", "image/webp"}),
    "logoCompact": frozenset({"image/svg+xml", "image/png", "image/jpeg", "image/webp"}),
    "favicon": frozenset({"image/svg+xml", "image/png", "image/x-icon"}),
}
MAX_BYTES_BY_KIND = {
    "logo": MAX_LOGO_BYTES,
    "logoDark": MAX_LOGO_BYTES,
    "logoCompact": MAX_LOGO_BYTES,
    "favicon": MAX_FAVICON_BYTES,
}
_SVG_NS = "http://www.w3.org/2000/svg"
_DENIED_SVG_TAGS = frozenset(
    {
        "script",
        "foreignobject",
        "iframe",
        "object",
        "embed",
        "audio",
        "video",
        "canvas",
        "image",
        "feimage",
        "handler",
        "listener",
        "a",
        "style",
        "animate",
        "animatemotion",
        "animatetransform",
        "set",
        "discard",
    }
)
_DENIED_SVG_ATTRS = frozenset(
    {
        "src",
        "data",
        "action",
        "formaction",
        "poster",
        "xml:base",
        "base",
        "background",
    }
)
_URL_IN_VALUE = re.compile(r"url\(\s*['\"]?([^)'\"]*)", re.IGNORECASE)
_ENTRY_NAME = re.compile(
    r"^resources/(logo|logoDark|logoCompact|favicon)\.(svg|png|jpg|jpeg|webp|ico)$"
)
_DATA_URL = re.compile(r"^data:", re.IGNORECASE)


@dataclass(frozen=True)
class ImportedResource:
    key: str
    name: str
    content_type: str
    data: bytes


@dataclass(frozen=True)
class ImportedPackage:
    preset: dict[str, Any]
    resources: tuple[ImportedResource, ...]


def canonical_content_type(value: str) -> str:
    normalized = value.strip().lower()
    aliases = {
        "image/jpg": "image/jpeg",
        "image/vnd.microsoft.icon": "image/x-icon",
        "image/ico": "image/x-icon",
    }
    return aliases.get(normalized, normalized)


def data_url(content_type: str, data: bytes) -> str:
    encoded = base64.b64encode(data).decode("ascii")
    return f"data:{content_type};base64,{encoded}"


def parse_data_url(value: str) -> tuple[str, bytes] | None:
    """Return ``(content_type, bytes)`` for a strict base64 image data URL."""
    if not _DATA_URL.match(value):
        return None
    header, separator, payload = value[5:].partition(",")
    if not separator:
        raise ValidationFailed("graphic data URL is incomplete")
    parts = [part.strip().lower() for part in header.split(";") if part.strip()]
    if not parts or "base64" not in parts[1:]:
        raise ValidationFailed("graphic data URLs must be base64 encoded")
    content_type = canonical_content_type(parts[0])
    if content_type not in EXTENSIONS:
        raise ValidationFailed("graphic data URL type is not supported")
    try:
        data = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        raise ValidationFailed("graphic data URL is not valid base64") from None
    return content_type, data


def _svg_namespace(tag: str) -> tuple[str, str]:
    if tag.startswith("{"):
        namespace, _, local = tag[1:].partition("}")
        return namespace, local
    return "", tag


def _check_svg_style(value: str) -> None:
    lowered = value.lower()
    if any(
        marker in lowered
        for marker in (
            "@import",
            "expression(",
            "javascript:",
            "vbscript:",
            "behavior:",
            "-moz-binding",
            "data:text/html",
        )
    ):
        raise ValidationFailed("SVG style contains active or external content")
    for match in _URL_IN_VALUE.finditer(value):
        target = match.group(1).strip()
        if target and not target.startswith("#"):
            raise ValidationFailed("SVG styles may only reference local fragments")


def validate_svg(data: bytes) -> None:
    """Reject scripts, external references, entities and active SVG content."""
    if not data or len(data) > MAX_LOGO_BYTES:
        raise ValidationFailed("SVG resource must contain at most 2 MiB")
    lowered = data.lower()
    if (
        b"<!doctype" in lowered
        or b"<!entity" in lowered
        or b"<?xml-stylesheet" in lowered
    ):
        raise ValidationFailed("SVG resource must not declare entities or external styles")
    try:
        root = DefusedElementTree.fromstring(data)
    except Exception:
        raise ValidationFailed("SVG resource is not valid XML") from None
    namespace, local = _svg_namespace(root.tag)
    if local.lower() != "svg" or namespace not in {"", _SVG_NS}:
        raise ValidationFailed("graphic resource is not an SVG document")
    for element in root.iter():
        namespace, local = _svg_namespace(element.tag)
        if namespace not in {"", _SVG_NS, "http://www.w3.org/1999/xlink"}:
            raise ValidationFailed("SVG resource uses an unsupported namespace")
        tag = local.lower()
        if tag in _DENIED_SVG_TAGS:
            raise ValidationFailed(f"SVG element {tag} is not allowed")
        for attribute, value in element.attrib.items():
            attr_namespace, attr_name = _svg_namespace(attribute)
            name = attr_name.lower()
            if attr_namespace and attr_namespace != "http://www.w3.org/1999/xlink":
                raise ValidationFailed("SVG attribute namespace is not allowed")
            if name.startswith("on") or name in _DENIED_SVG_ATTRS:
                raise ValidationFailed("SVG resource contains an active attribute")
            text = str(value).strip()
            lowered_value = text.lower()
            if name == "href":
                if text and not text.startswith("#"):
                    raise ValidationFailed("SVG references must stay inside the document")
                continue
            if any(marker in lowered_value for marker in ("javascript:", "vbscript:")):
                raise ValidationFailed("SVG resource contains a script URL")
            if name == "style":
                _check_svg_style(text)
            elif "url(" in lowered_value:
                _check_svg_style(text)


def _validate_ico(data: bytes) -> tuple[int, int]:
    if len(data) < 6:
        raise ValidationFailed("ICO resource is incomplete")
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    if reserved != 0 or kind != 1 or not 1 <= count <= MAX_ICO_FRAMES:
        raise ValidationFailed("favicon is not a valid ICO file")
    directory_end = 6 + count * 16
    if directory_end > len(data):
        raise ValidationFailed("ICO directory is truncated")
    maximum = 0
    for index in range(count):
        offset = 6 + index * 16
        width, height, colors, reserved_byte, planes, bits, size, start = struct.unpack_from(
            "<BBBBHHII", data, offset
        )
        edge = max(width or 256, height or 256)
        if edge > MAX_ICO_EDGE:
            raise ValidationFailed("ICO frame is larger than 256 pixels")
        if reserved_byte != 0 or size < 1 or start < directory_end or start + size > len(data):
            raise ValidationFailed("ICO directory entry is invalid")
        maximum = max(maximum, edge)
    return maximum, maximum


def _validate_raster(
    data: bytes, content_type: str, maximum_bytes: int
) -> tuple[int, int]:
    if not data or len(data) > maximum_bytes:
        raise ValidationFailed(
            f"graphic resource must contain at most {maximum_bytes // 1024} KiB"
        )
    expected_format = {
        "image/png": "PNG",
        "image/jpeg": "JPEG",
        "image/webp": "WEBP",
        "image/x-icon": "ICO",
    }[content_type]
    try:
        with Image.open(io.BytesIO(data)) as image:
            if image.format != expected_format:
                raise ValidationFailed("graphic resource content does not match its type")
            frames = getattr(image, "n_frames", 1)
            if (
                isinstance(frames, bool)
                or not isinstance(frames, int)
                or not 1 <= frames <= MAX_ICO_FRAMES
            ):
                raise ValidationFailed("graphic resource has too many frames")
            total_pixels = 0
            width = height = 0
            for frame in range(frames):
                image.seek(frame)
                frame_width, frame_height = image.size
                edge = MAX_ICO_EDGE if content_type == "image/x-icon" else MAX_IMAGE_EDGE
                if (
                    frame_width < 1
                    or frame_height < 1
                    or frame_width > edge
                    or frame_height > edge
                ):
                    raise ValidationFailed("graphic resource dimensions are not allowed")
                total_pixels += frame_width * frame_height
                if total_pixels > MAX_IMAGE_PIXELS:
                    raise ValidationFailed("graphic resource expands to too many pixels")
                image.load()
                width = max(width, frame_width)
                height = max(height, frame_height)
            return width, height
    except ValidationFailed:
        raise
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        raise ValidationFailed("graphic resource is not a valid image") from None


def validate_resource(
    kind: str, content_type: str, data: bytes
) -> tuple[str, int | None, int | None]:
    """Validate one graphic for a preset key; returns canonical type and size."""
    if kind not in ALLOWED_TYPES:
        raise ValidationFailed("unknown graphic resource key")
    normalized = canonical_content_type(content_type)
    if normalized not in ALLOWED_TYPES[kind]:
        raise ValidationFailed(f"{kind} does not accept the {normalized} type")
    if normalized == "image/svg+xml":
        validate_svg(data)
        if len(data) > MAX_BYTES_BY_KIND[kind]:
            raise ValidationFailed("SVG resource is too large")
        return normalized, None, None
    if normalized == "image/x-icon":
        width, height = _validate_ico(data)
        _validate_raster(data, normalized, MAX_BYTES_BY_KIND[kind])
        return normalized, width, height
    width, height = _validate_raster(data, normalized, MAX_BYTES_BY_KIND[kind])
    return normalized, width, height


def _safe_entry_name(name: str) -> None:
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        raise ValidationFailed("ZIP contains an invalid resource name")
    parts = name.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValidationFailed("ZIP contains a traversal resource name")


def _declared_entry_count(data: bytes) -> int | None:
    """Read the EOCD entry count before ``zipfile`` materializes the directory."""
    start = max(0, len(data) - 65_557)
    end = data.rfind(b"PK\x05\x06", start)
    if end < 0 or end + 12 > len(data):
        return None
    count = struct.unpack_from("<H", data, end + 10)[0]
    return None if count == 0xFFFF else count


def _verify_local_header(archive: bytes, info: zipfile.ZipInfo) -> None:
    offset = info.header_offset
    if offset + 30 > len(archive) or archive[offset : offset + 4] != b"PK\x03\x04":
        raise ValidationFailed("ZIP local entry is damaged")
    name_length, extra_length = struct.unpack_from("<HH", archive, offset + 26)
    name_start = offset + 30
    name_end = name_start + name_length
    if name_end > len(archive):
        raise ValidationFailed("ZIP local entry name is truncated")
    try:
        local_name = archive[name_start:name_end].decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise ValidationFailed("ZIP local entry name is invalid") from None
    if local_name != info.filename:
        raise ValidationFailed("ZIP entry names are inconsistent")


def _resource_entry_name(key: str, content_type: str) -> str:
    extension = EXTENSIONS[canonical_content_type(content_type)]
    return f"resources/{key}.{extension}"


def read_package(data: bytes) -> ImportedPackage:
    """Parse and validate a complete appearance ZIP without writing anything."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_ZIP_BYTES:
        raise ValidationFailed("ZIP must contain at most 24 MiB")
    declared = _declared_entry_count(data)
    if declared is None or declared > MAX_ENTRIES:
        raise ValidationFailed("ZIP contains too many entries")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if not 1 <= len(infos) <= MAX_ENTRIES:
                raise ValidationFailed("ZIP contains too many entries")
            names: set[str] = set()
            total_expanded = 0
            for info in infos:
                if info.is_dir():
                    raise ValidationFailed("ZIP must not contain directories")
                _safe_entry_name(info.filename)
                _verify_local_header(data, info)
                if info.flag_bits & 0x1:
                    raise ValidationFailed("ZIP must not contain encrypted entries")
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise ValidationFailed("ZIP compression method is not supported")
                if info.file_size > MAX_ENTRY_BYTES or info.compress_size > MAX_ENTRY_BYTES:
                    raise ValidationFailed("ZIP entry is too large")
                if (
                    info.file_size > 1024 * 1024
                    and info.compress_size > 0
                    and info.file_size > info.compress_size * MAX_COMPRESSION_RATIO
                ):
                    raise ValidationFailed("ZIP entry compression ratio is not allowed")
                total_expanded += info.file_size
                if total_expanded > MAX_TOTAL_BYTES:
                    raise ValidationFailed("ZIP expands beyond the allowed size")
                folded = info.filename.casefold()
                if folded in names:
                    raise ValidationFailed("ZIP contains duplicate entries")
                names.add(folded)
            if not any(info.filename == "preset.json" for info in infos):
                raise ValidationFailed("ZIP does not contain preset.json")
            manifest_info = archive.getinfo("preset.json")
            if manifest_info.file_size > MAX_MANIFEST_BYTES:
                raise ValidationFailed("preset.json is too large")
            try:
                manifest = json.loads(archive.read(manifest_info).decode("utf-8"))
            except (UnicodeError, ValueError):
                raise ValidationFailed("preset.json is not valid JSON") from None
            if not isinstance(manifest, dict) or set(manifest) != {
                "format",
                "version",
                "preset",
                "resources",
            }:
                raise ValidationFailed("appearance manifest is invalid")
            if manifest.get("format") != FORMAT or manifest.get("version") != FORMAT_VERSION:
                raise ValidationFailed("appearance package format or version is incompatible")
            try:
                preset = PresetPayload.model_validate(manifest.get("preset"))
            except Exception:
                raise ValidationFailed("appearance preset is invalid") from None
            resources = manifest.get("resources")
            if not isinstance(resources, list) or len(resources) > len(GRAPHIC_KEYS):
                raise ValidationFailed("appearance resource index is invalid")
            by_key: dict[str, dict[str, Any]] = {}
            for entry in resources:
                if not isinstance(entry, dict) or set(entry) != {"key", "name", "type"}:
                    raise ValidationFailed("appearance resource entry is invalid")
                key = entry.get("key")
                name = entry.get("name")
                content_type = entry.get("type")
                if not isinstance(key, str) or key not in GRAPHIC_KEYS:
                    raise ValidationFailed("appearance resource key is invalid")
                if key in by_key:
                    raise ValidationFailed("appearance resource key is duplicated")
                if not isinstance(name, str) or not isinstance(content_type, str):
                    raise ValidationFailed("appearance resource metadata is invalid")
                if _ENTRY_NAME.fullmatch(name) is None:
                    raise ValidationFailed("appearance resource path is not allowed")
                canonical = canonical_content_type(content_type)
                if canonical not in ALLOWED_TYPES[key]:
                    raise ValidationFailed("appearance resource type is not allowed")
                if name != _resource_entry_name(key, canonical):
                    raise ValidationFailed("appearance resource path does not match its key")
                if name.casefold() not in names:
                    raise ValidationFailed("appearance resource file is missing")
                by_key[key] = {"name": name, "type": canonical}
            document = preset.model_dump()
            loaded: list[ImportedResource] = []
            for key in GRAPHIC_KEYS:
                reference = document["branding"].get(key) or ""
                entry = by_key.get(key)
                if not reference:
                    if entry is not None:
                        raise ValidationFailed("unused appearance resource is not allowed")
                    continue
                if entry is None:
                    raise ValidationFailed("appearance preset references a missing resource")
                if reference != entry["name"]:
                    raise ValidationFailed("appearance preset resource path is inconsistent")
                info = archive.getinfo(entry["name"])
                try:
                    payload = archive.read(info)
                except (zipfile.BadZipFile, OSError, RuntimeError):
                    raise ValidationFailed("ZIP entry failed integrity validation") from None
                content_type, _, _ = validate_resource(key, entry["type"], payload)
                document["branding"][key] = data_url(content_type, payload)
                loaded.append(
                    ImportedResource(
                        key=key,
                        name=entry["name"],
                        content_type=content_type,
                        data=payload,
                    )
                )
            expected = {"preset.json", *(entry["name"] for entry in by_key.values())}
            if {info.filename for info in infos} != expected:
                raise ValidationFailed("ZIP contains unexpected entries")
            return ImportedPackage(preset=document, resources=tuple(loaded))
    except zipfile.BadZipFile:
        raise ValidationFailed("ZIP is damaged or is not a ZIP file") from None


def write_package(
    preset: dict[str, Any],
    resolver: Callable[[str, str], tuple[str, bytes] | None],
) -> bytes:
    """Build a real self-contained ZIP; ``resolver(key, reference)`` returns bytes."""
    try:
        validated = PresetPayload.model_validate(preset).model_dump()
    except Exception as exc:
        raise ValidationFailed(f"appearance preset is invalid: {exc}") from None
    document = dict(validated)
    resources: list[dict[str, str]] = []
    files: list[tuple[str, bytes]] = []
    for key in GRAPHIC_KEYS:
        reference = document["branding"].get(key) or ""
        if not reference:
            continue
        resolved = resolver(key, reference)
        if resolved is None:
            raise ValidationFailed(f"the {key} graphic is not available for export")
        content_type, payload = resolved
        content_type, _, _ = validate_resource(key, content_type, payload)
        name = _resource_entry_name(key, content_type)
        document["branding"][key] = name
        resources.append({"key": key, "name": name, "type": content_type})
        files.append((name, payload))
    manifest = {
        "format": FORMAT,
        "version": FORMAT_VERSION,
        "preset": document,
        "resources": resources,
    }
    import json

    encoded_manifest = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded_manifest) > MAX_MANIFEST_BYTES:
        raise ValidationFailed("appearance manifest is too large")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in [("preset.json", encoded_manifest), *files]:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, payload)
    return output.getvalue()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
