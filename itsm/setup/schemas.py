"""Wire models for the setup service.

Only the sanitized status allowlist, the one-time claim request and the setup
session envelope live here. Nothing in this module can carry a stored hash, a
database URL or any other secret.
"""

from __future__ import annotations

from typing import Any, Literal

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


class StorageCheckRequest(BaseModel):
    """One candidate database URL; treated as a secret so it is never logged."""

    database_url: SecretStr = Field(min_length=1, max_length=2048)


class StorageProbe(BaseModel):
    """Sanitized result of a candidate database probe; never the URL or a password."""

    reachable: bool
    engine: str | None = None
    version: str | None = None
    status: Literal["empty", "ours", "foreign", "unreachable"]
    identity: str | None = None
    adoptable: bool = False
    guidance: str | None = None


class StorageSummary(BaseModel):
    """What ``apply_storage`` actually did, with no secret in it."""

    engine: str
    version: str | None = None
    status: Literal["empty", "ours"]
    identity: str | None = None
    config_source: Literal["installation", "external"]
    migrated: bool = True
    identity_claimed: bool = True


class StorageApplyResponse(BaseModel):
    """Result of ``POST /api/setup/v1/storage``."""

    state: str
    storage: StorageSummary


class OwnerRequest(BaseModel):
    """The first human owner; the password is only ever handed to the hasher."""

    username: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=120)
    email: str | None = Field(default=None, max_length=254)
    password: SecretStr = Field(min_length=1, max_length=256)


class OwnerReceipt(BaseModel):
    """Public owner fields; never an email digest, hash or password."""

    username: str
    display_name: str


class OwnerResponse(BaseModel):
    """Result of ``POST /api/setup/v1/owner``."""

    state: str
    owner: OwnerReceipt
    ai: Literal["transferred", "pending"]


class ConfigurationStartResponse(BaseModel):
    """Result of ``POST /api/setup/v1/configuration``."""

    state: str
    mode: str


class ConfigurationSectionRequest(BaseModel):
    """One section proposal; ``confirm`` is the human confirmation bit."""

    values: dict[str, Any] = Field(default_factory=dict)
    action: Literal["apply", "postpone", "accept_risk", "declare"] = "apply"
    confirm: bool = False


class ConfigurationSectionResponse(BaseModel):
    """Effective value, diff preview or applied receipt for one section."""

    section: str
    status: str
    required: bool
    postponable: bool
    current: dict[str, Any] | None = None
    proposed: dict[str, Any] | None = None
    changes: list[dict[str, Any]] | None = None
    env_override: list[str] | None = None
    receipt: dict[str, Any] | None = None
    actions: list[str] | None = None
    preview_only: bool | None = None
    currentUnavailable: bool | None = None


class ConfigurationOverview(BaseModel):
    """Every section plus the contract checklist built from stored receipts."""

    state: str
    mode: str
    sections: list[dict[str, Any]]
    checklist: list[dict[str, Any]]
    blocking: list[str]
    acceptedRisk: list[str]


class VerificationResponse(BaseModel):
    """The observed checklist that decides ``configuring`` -> ``verifying``."""

    state: str
    ready: bool
    mode: str
    checklist: list[dict[str, Any]]
    blocking: list[str]
    acceptedRisk: list[str]
