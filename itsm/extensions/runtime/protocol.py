"""Stdlib-only framing shared by the extension runner and its host.

The runner is started as ``python -I -S -B runner.py`` so nothing outside this
package is importable inside the sandbox.  It therefore owns its own small
protocol types instead of importing the host exception hierarchy.
"""

from __future__ import annotations

import json
from typing import Any

PROTOCOL_VERSION = 1
MAX_LINE_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 1024 * 1024


class ModuleError(Exception):
    """A stable, closed error code the host can translate back to HTTP."""

    code = "handler_failed"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class StoreConflict(ModuleError):
    code = "store_conflict"


class StoreValidation(ModuleError):
    code = "store_validation"


class CapabilityDenied(ModuleError):
    code = "capability_denied"


def dumps(message: dict[str, Any]) -> bytes:
    """Serialize one protocol line with bounded UTF-8 output."""
    payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_LINE_BYTES:
        raise ModuleError("protocol message exceeds the line limit", code="output_limit")
    return payload + b"\n"


def loads(line: bytes) -> dict[str, Any]:
    """Parse one protocol line, rejecting oversized or non-object frames."""
    if len(line) > MAX_LINE_BYTES:
        raise ModuleError("protocol message exceeds the line limit", code="output_limit")
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        raise ModuleError("protocol message is not JSON", code="protocol_error") from None
    if not isinstance(message, dict):
        raise ModuleError("protocol message must be an object", code="protocol_error")
    return message
