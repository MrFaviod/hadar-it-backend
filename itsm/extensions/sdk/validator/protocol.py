"""Bounded stdin protocol between the host and the fixed validator container.

Only the candidate archive and this header travel over stdin. The header names
the digest the host already computed, the known core permissions and the same
package limits the host applies. There are no mounts, environment variables,
network endpoints or command arguments for candidate data.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

PROTOCOL_VERSION = 1
MAGIC = b"ITSMSDK1"
MAX_HEADER_BYTES = 65536
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024
MAX_EXPANDED_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 200
MAX_FILE_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 256 * 1024
MAX_FRAME_BYTES = len(MAGIC) + 4 + MAX_HEADER_BYTES + MAX_ARCHIVE_BYTES
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CORE_CODE = re.compile(r"^[a-z][a-z0-9]*(?:\.[a-z0-9_]+)+$")

DEFAULT_LIMITS = {
    "archiveBytes": MAX_ARCHIVE_BYTES,
    "expandedBytes": MAX_EXPANDED_BYTES,
    "entries": MAX_ENTRIES,
    "fileBytes": MAX_FILE_BYTES,
    "outputBytes": MAX_OUTPUT_BYTES,
}


class ProtocolError(ValueError):
    """The stdin frame is not a valid bounded validator request."""


@dataclass(frozen=True)
class Frame:
    archive: bytes
    digest: str
    known_core_permissions: tuple[str, ...]
    limits: Mapping[str, int]


def build_frame(
    archive: bytes,
    *,
    digest: str,
    known_core_permissions: Sequence[str],
    limits: Mapping[str, int] | None = None,
) -> bytes:
    """Serialize one request. The host calls this and writes stdout to stdin."""
    if not isinstance(archive, bytes):
        raise ProtocolError("archive must be bytes")
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise ProtocolError("archive exceeds the 4 MiB package limit")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise ProtocolError("digest must be a lowercase SHA-256 hex value")
    if hashlib.sha256(archive).hexdigest() != digest:
        raise ProtocolError("digest does not match the archive bytes")
    core = _core_permissions(known_core_permissions)
    resolved = _limits(limits or DEFAULT_LIMITS)
    header = {
        "protocolVersion": PROTOCOL_VERSION,
        "sdkVersion": 2,
        "digest": digest,
        "archiveBytes": len(archive),
        "knownCorePermissions": list(core),
        "limits": resolved,
    }
    encoded = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_HEADER_BYTES:
        raise ProtocolError("header exceeds the 64 KiB protocol limit")
    return MAGIC + len(encoded).to_bytes(4, "big") + encoded + archive


def parse_frame(payload: bytes) -> Frame:
    """Parse one request without trusting lengths or the declared digest."""
    if not isinstance(payload, bytes):
        raise ProtocolError("frame must be bytes")
    if len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError("frame exceeds the bounded protocol limit")
    if not payload.startswith(MAGIC):
        raise ProtocolError("frame magic is invalid")
    offset = len(MAGIC)
    if len(payload) < offset + 4:
        raise ProtocolError("frame header length is missing")
    header_bytes = int.from_bytes(payload[offset : offset + 4], "big")
    offset += 4
    if header_bytes < 2 or header_bytes > MAX_HEADER_BYTES:
        raise ProtocolError("frame header length is out of bounds")
    if len(payload) < offset + header_bytes:
        raise ProtocolError("frame header is truncated")
    raw_header = payload[offset : offset + header_bytes]
    archive = payload[offset + header_bytes :]
    try:
        header = json.loads(raw_header.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("frame header is not UTF-8 JSON") from exc
    if not isinstance(header, dict):
        raise ProtocolError("frame header must be a JSON object")
    if header.get("protocolVersion") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    if header.get("sdkVersion") != 2:
        raise ProtocolError("unsupported SDK version")
    digest = header.get("digest")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise ProtocolError("frame digest is invalid")
    declared_bytes = header.get("archiveBytes")
    if not isinstance(declared_bytes, int) or isinstance(declared_bytes, bool):
        raise ProtocolError("archiveBytes must be an integer")
    if declared_bytes != len(archive):
        raise ProtocolError("archive length does not match the header")
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise ProtocolError("archive exceeds the 4 MiB package limit")
    core = _core_permissions(header.get("knownCorePermissions"))
    limits = _limits(header.get("limits"))
    if hashlib.sha256(archive).hexdigest() != digest:
        raise ProtocolError("archive bytes do not match the declared digest")
    return Frame(
        archive=archive,
        digest=digest,
        known_core_permissions=core,
        limits=limits,
    )


def _core_permissions(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or len(values) > 200:
        raise ProtocolError("knownCorePermissions must be a bounded list")
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or len(value) > 96 or not _CORE_CODE.fullmatch(value):
            raise ProtocolError("known core permission is invalid")
        if value in seen:
            raise ProtocolError("known core permission is duplicated")
        seen.add(value)
        result.append(value)
    return tuple(sorted(result))


def _limits(values: Any) -> dict[str, int]:
    if not isinstance(values, Mapping):
        raise ProtocolError("limits must be a mapping")
    allowed = set(DEFAULT_LIMITS)
    if set(values) != allowed:
        raise ProtocolError("limits must contain exactly the fixed fields")
    resolved: dict[str, int] = {}
    for name, maximum in DEFAULT_LIMITS.items():
        value = values[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ProtocolError(f"limit {name} must be a positive integer")
        if value > maximum:
            raise ProtocolError(f"limit {name} exceeds the server maximum")
        resolved[name] = value
    return resolved
