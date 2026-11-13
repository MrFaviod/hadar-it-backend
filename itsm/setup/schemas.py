"""Wire models for the setup service.

Only the sanitized status allowlist, the one-time claim request and the setup
session envelope live here. Nothing in this module can carry a stored hash, a
database URL or any other secret.
"""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, BaseModel, Field, SecretStr, model_validator

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
    "checks",
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
    checks: dict[str, str] = Field(default_factory=dict)


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
    # Returned only to a valid session cookie so a reloaded wizard can resume;
    # it is never part of the anonymous status or the journal.
    csrf_token: str = ""


class ErrorResponse(BaseModel):
    """Stable, sanitized error shape."""

    error: str


class AiConfigureRequest(BaseModel):
    """Provider endpoint, model and one credential supplied by the operator.

    The credential is either the raw key or the name of an operator-bound
    environment reference (``ITSM_AI_SECRET_DESTINATIONS``); exactly one.
    """

    base_url: str = Field(min_length=1, max_length=500)
    model: str = Field(min_length=1, max_length=200)
    api_key: SecretStr | None = Field(default=None, max_length=2048)
    credential_reference: str | None = Field(
        default=None,
        max_length=128,
        validation_alias=AliasChoices("credential_reference", "credential"),
    )

    @model_validator(mode="after")
    def _one_credential(self) -> AiConfigureRequest:
        if self.api_key is not None and self.credential_reference is not None:
            raise ValueError("supply either api_key or credential_reference")
        return self


class AiReceipt(BaseModel):
    """Sanitized provider result; never a key, ciphertext, URL path or header."""

    status: Literal["configured", "pending"]
    provider: str | None = None
    model: str | None = None
    tool: str | None = None
    latency_ms: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    pending: bool = False
    reason: str | None = None
    checked_at: str | None = None
    deferred_at: str | None = None


class AiConfigureResponse(BaseModel):
    """Result of ``POST /api/setup/v1/ai`` or ``/ai/defer``."""

    state: str
    ai: AiReceipt
    discovered_models: int | None = None


class AssistantAskRequest(BaseModel):
    """One bounded question for the read-only bootstrap assistant."""

    question: str = Field(min_length=1, max_length=500)


class AssistantAnswerResponse(BaseModel):
    """A bounded answer plus the tools that actually executed for it."""

    answer: str
    tools: list[str] = Field(default_factory=list)
    latency_ms: int = 0
