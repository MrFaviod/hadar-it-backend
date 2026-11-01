"""The shared error envelope: ``{"error": {code, message, key, params}}``."""

from __future__ import annotations

from typing import Any


def error_payload(
    code: str,
    message: str,
    *,
    key: str | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the envelope; ``key``/``params`` are additive and optional.

    A payload without ``key`` keeps the legacy English ``message`` that domain
    error sites still produce (T4 converts those sites). With a key, ``message``
    is already localized for the request locale.
    """
    error: dict[str, Any] = {"code": code, "message": message}
    if key is not None:
        error["key"] = key
        error["params"] = dict(params or {})
    return {"error": error}
