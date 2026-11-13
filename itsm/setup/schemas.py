"""Wire models for the setup service.

Only the sanitized status allowlist, the one-time claim request and the setup
session envelope live here. Nothing in this module can carry a stored hash, a
database URL or any other secret.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, SecretStr

#: Fields ``GET /api/setup/v1/status`` may return. The setup service never
#: probes the backend, so a missing API is not reported here as a new install.
SANITIZED_STATUS_FIELDS: tuple[str, ...] = (
    "state",
    "mode",
    "release_mode",
    "setup_enabled",
    "claim_available",
    "backend",
    "version",
    "instance_id",
)

#: Substrings that must never appear in the anonymous status payload.
FORBIDDEN_STATUS_TOKENS: tuple[str, ...] = (
    "password",
    "secret",
    "credential",
    "ciphertext",
    "api_key",
    "token",
    "dsn",
)


class SanitizedStatus(BaseModel):
    """Anonymous installation status; no secret and no probe of the API."""

    state: str
    mode: Literal["dev", "prod"]
    release_mode: Literal["dev", "prod"]
    setup_enabled: bool
    claim_available: bool
    backend: Literal["unknown"]
    version: str
    instance_id: str | None = None


class ClaimRequest(BaseModel):
    """One-time claim or recovery credential supplied in the request body."""

    credential: SecretStr = Field(min_length=1, max_length=512)


class ClaimResponse(BaseModel):
    """The claim result: state plus the CSRF value for later session mutations."""

    state: str
    mode: Literal["dev", "prod"]
    release_mode: Literal["dev", "prod"]
    csrf_token: str


class SessionResponse(BaseModel):
    """Sanitized setup session envelope; never exposes the cookie or a digest."""

    state: str
    mode: Literal["dev", "prod"]
    release_mode: Literal["dev", "prod"]
    checks: list[str] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    """Stable, sanitized error shape."""

    error: str
