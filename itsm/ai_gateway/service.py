"""Run-scoped OpenAI-compatible managed gateway.

The gateway is an explicitly bounded admission layer, not an arbitrary proxy:

* a lease is issued only by trusted server code for an existing pending run
  reservation, and binds actor, run, funding, provider, model and engine;
* every call reserves a defensible context + output bound before any paid
  forward, using the run reservation as parent so the original quota day wins;
* only fixed ``/chat/completions`` and ``/models`` routes exist, with an
  explicit unsupported response for ``/responses``;
* upstream credentials, URLs and identity never come from the request;
* accounting uses provider-reported totals only. Missing or untrustworthy usage
  leaves the hold unresolved instead of inventing zero or releasing budget.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import re
import secrets
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from itsm.agent_integrations.providers import (
    CredentialInvalid,
    CredentialUnavailable,
    ProviderEndpointError,
    ProviderModelSelection,
    ProviderNetworkPolicy,
    credential_storage_available,
    personal_endpoint_policy,
    provider_http_client,
    seal_credential,
    unseal_credential,
    validate_provider_endpoint,
)
from itsm.ai_gateway.models import (
    CLAIMED,
    IN_FLIGHT,
    TERMINAL_CALL_STATES,
    UNRESOLVED,
    AiGatewayCall,
    AiGatewayLease,
)
from itsm.config import Settings
from itsm.identity.clock import as_utc, utcnow

logger = logging.getLogger(__name__)

MAX_REQUEST_BYTES = 2 * 1024 * 1024
#: Encoded (base64) budget a lease may declare for non-text content parts.
MAX_ATTACHMENT_BYTES = 4 * 1024 * 1024
_ALLOWED_INPUT_MODALITIES = frozenset({"image", "file"})
_ALLOWED_IMAGE_MEDIA = frozenset({"image/png", "image/jpeg", "image/webp", "image/gif"})
_MAX_CONTENT_PARTS = 256
_DATA_URL = re.compile(
    r"^data:(?P<mime>[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*);base64,(?P<data>[A-Za-z0-9+/=]*)$"
)
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_EVENT_BYTES = 1024 * 1024
MAX_ERROR_BYTES = 64 * 1024
MAX_CONTEXT_TOKENS = 10_000_000
MAX_OUTPUT_TOKENS = 1_000_000
MAX_TTL_SECONDS = 86_400
DEFAULT_TTL_SECONDS = 3600
MAX_IDEMPOTENCY_KEY = 200

ALLOWED_FUNDING = ("company", "personal")
ALLOWED_PROVIDER_SCOPES = ("global", "personal")

_ALLOWED_FIELDS = frozenset(
    {
        "model",
        "messages",
        "max_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "top_k",
        "stop",
        "stream",
        "stream_options",
        "n",
        "seed",
        "presence_penalty",
        "frequency_penalty",
        "logit_bias",
        "user",
        "response_format",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
    }
)
_ALLOWED_MESSAGE_FIELDS = frozenset({"role", "content", "name", "tool_calls", "tool_call_id"})
_ALLOWED_ROLES = frozenset({"system", "developer", "user", "assistant", "tool"})
_ALLOWED_TOOL_CHOICES = frozenset({"none", "auto", "required"})
_ALLOWED_RESPONSE_FORMATS = frozenset({"text", "json_object", "json_schema"})


class GatewayError(Exception):
    """A structured gateway refusal that is safe to return to the caller."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 400,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.headers = dict(headers or {})


class GatewayDenied(GatewayError):
    def __init__(
        self, code: str = "invalid_lease", message: str = "A valid lease is required"
    ) -> None:
        super().__init__(code, message, status_code=401, headers={"WWW-Authenticate": "Bearer"})


class GatewayRejected(GatewayError):
    def __init__(self, code: str, message: str, *, status_code: int = 400) -> None:
        super().__init__(code, message, status_code=status_code)


class GatewayConflict(GatewayError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, status_code=409)


class GatewayQuotaError(GatewayError):
    def __init__(
        self,
        message: str,
        *,
        remaining_tokens: int = 0,
        period_day: str | None = None,
    ) -> None:
        super().__init__("quota_exceeded", message, status_code=429)
        self.remaining_tokens = remaining_tokens
        self.period_day = period_day


class GatewayUpstreamError(GatewayError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, status_code=502)


class GatewayUnavailable(GatewayError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, status_code=503)


@dataclass(frozen=True)
class IssuedLease:
    lease_id: str
    bearer_token: str
    run_id: str
    model: str
    expires_at: datetime
    context_tokens: int
    output_tokens: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "leaseId": self.lease_id,
            "token": self.bearer_token,
            "runId": self.run_id,
            "model": self.model,
            "expiresAt": self.expires_at.isoformat(),
            "contextTokens": self.context_tokens,
            "outputTokens": self.output_tokens,
        }


@dataclass(frozen=True)
class LeaseContext:
    lease_id: str
    actor_id: str
    run_id: str
    parent_reservation_id: str
    funding: str
    provider_id: str
    provider_scope: str
    provider_name: str
    model: str
    engine: str
    context_tokens: int
    output_tokens: int
    expires_at: datetime
    input_modalities: tuple[str, ...] = ()
    attachment_bytes: int = 0


@dataclass
class GatewayResult:
    status_code: int
    body: bytes = b""
    media_type: str = "application/json"
    stream: AsyncIterator[bytes] | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class _PreparedChat:
    payload: dict[str, Any]
    stream: bool
    reserved_tokens: int


def error_payload(
    code: str,
    message: str,
    *,
    error_type: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {
        "code": code,
        "message": message,
        "type": error_type or code,
    }
    if extra:
        error.update(extra)
    return {"error": error}


def _json_result(
    status_code: int,
    code: str,
    message: str,
    *,
    error_type: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> GatewayResult:
    payload = error_payload(code, message, error_type=error_type, extra=extra)
    return GatewayResult(
        status_code=status_code,
        body=json.dumps(payload).encode("utf-8"),
        media_type="application/json",
    )


def _token_count(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value.is_integer() and value >= 0:
        return int(value)
    return None


def usage_evidence(usage: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Map provider usage to canonical ledger evidence without double counting.

    OpenAI-compatible totals are authoritative and their prompt/completion
    counts already include cached and reasoning tokens respectively, so those
    components are reported as included rather than added again.
    """

    if not isinstance(usage, Mapping):
        return None

    prompt = _token_count(usage.get("prompt_tokens"))
    completion = _token_count(usage.get("completion_tokens"))
    reported_total = _token_count(usage.get("total_tokens"))
    if reported_total is not None:
        total = reported_total
        total_source = "provider"
    elif prompt is not None and completion is not None:
        total = prompt + completion
        total_source = "derived"
    else:
        return None

    cache_read: int | None = None
    prompt_details = usage.get("prompt_tokens_details")
    if isinstance(prompt_details, Mapping):
        cache_read = _token_count(prompt_details.get("cached_tokens"))
    if cache_read is None:
        cache_read = _token_count(usage.get("cache_read_input_tokens"))

    reasoning: int | None = None
    completion_details = usage.get("completion_tokens_details")
    if isinstance(completion_details, Mapping):
        reasoning = _token_count(completion_details.get("reasoning_tokens"))
    if reasoning is None:
        reasoning = _token_count(usage.get("reasoning_tokens"))

    evidence: dict[str, Any] = {
        "totalTokens": total,
        "precision": "measured",
        "source": "provider",
        "totalSource": total_source,
        "cacheIncludedInInput": True,
        "reasoningIncludedInOutput": True,
    }
    if prompt is not None:
        evidence["inputTokens"] = prompt
    if completion is not None:
        evidence["outputTokens"] = completion
    if cache_read is not None:
        evidence["cacheReadTokens"] = cache_read
    if reasoning is not None:
        evidence["reasoningTokens"] = reasoning
    return evidence


class _UsageScanner:
    """Incremental SSE scanner that keeps only the last usage object."""

    def __init__(self) -> None:
        self._buffer = b""
        self._skip = False
        self._usage: dict[str, Any] | None = None

    def feed(self, chunk: bytes) -> None:
        if self._skip:
            return
        self._buffer += chunk
        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)
            self._line(line)

    def _line(self, raw: bytes) -> None:
        line = raw.strip()
        if not line:
            self._skip = False
            return
        if self._skip or line.startswith(b":"):
            return
        if line.startswith(b"data:"):
            data = line[5:].strip()
        elif line.startswith(b"event:"):
            return
        else:
            return
        if data == b"[DONE]":
            return
        if len(data) > MAX_EVENT_BYTES:
            self._skip = True
            return
        try:
            event = json.loads(data)
        except ValueError, UnicodeDecodeError:
            return
        if not isinstance(event, Mapping):
            return
        usage = event.get("usage")
        if isinstance(usage, Mapping):
            self._usage = dict(usage)

    def evidence(self) -> dict[str, Any] | None:
        if self._buffer:
            self._line(self._buffer)
            self._buffer = b""
        return usage_evidence(self._usage)


def _parse_json_usage(body: bytes) -> dict[str, Any] | None:
    try:
        document = json.loads(body)
    except ValueError, UnicodeDecodeError:
        return None
    if not isinstance(document, Mapping):
        return None
    usage = document.get("usage")
    return usage_evidence(usage if isinstance(usage, Mapping) else None)


async def _read_limited(response: httpx.Response, limit: int) -> tuple[bytes, bool]:
    """Read at most ``limit`` bytes without trusting upstream length headers."""

    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > limit:
            return bytes(body), True
        body.extend(chunk)
    return bytes(body), False


class AiGatewayService:
    """Issues run leases and forwards bounded calls through the guarded client."""

    def __init__(
        self,
        settings: Settings,
        session_factory: sessionmaker[Session],
        usage_service: Any,
        *,
        now: Callable[[], datetime] | None = None,
        client_factory: Callable[..., httpx.AsyncClient] | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._usage = usage_service
        self._now = now or utcnow
        self._client_factory = client_factory or provider_http_client

    @contextmanager
    def _session(self) -> Any:
        session = self._session_factory()
        try:
            yield session
        finally:
            session.close()

    def _now_utc(self) -> datetime:
        return as_utc(self._now())

    def capability(self) -> dict[str, Any]:
        return {
            "mode": "managed",
            "enforcement": "admission_only",
            "strict": False,
            "reason": (
                "Budget admission, model/provider pinning and output caps are enforced per "
                "call. The declared context bound is an operator/upstream contract, not "
                "independently verified, and strict whole-engine enforcement also requires "
                "network isolation that prevents the native engine from reaching providers "
                "outside this gateway."
            ),
            "routePrefix": f"{self._settings.api_prefix.rstrip('/')}/agent/gateway/v1",
            "routes": ["/chat/completions", "/models"],
            "unsupportedRoutes": ["/responses"],
            "credentialStorage": credential_storage_available(self._settings),
            "contextBound": "operator_declared",
            "streamUsage": "include_usage_required",
            "requestBodyLimitBytes": MAX_REQUEST_BYTES,
            "attachmentBytesLimit": MAX_ATTACHMENT_BYTES,
            "responseBodyLimitBytes": MAX_RESPONSE_BYTES,
            "streamBodyLimitBytes": MAX_STREAM_BYTES,
        }

    def issue_lease(
        self,
        *,
        actor_id: str,
        funding: str,
        parent_reservation_id: str,
        selection: ProviderModelSelection,
        provider_id: str,
        provider_scope: str,
        provider_name: str,
        model: str,
        engine: str,
        run_id: str,
        context_tokens: int,
        output_tokens: int,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        input_modalities: Sequence[str] = (),
        attachment_bytes: int = 0,
    ) -> IssuedLease:
        modalities = _input_modalities(input_modalities)
        attachment_bytes = _attachment_bytes(attachment_bytes, modalities)
        actor_id = _bounded_text(actor_id, "actor id", 36)
        run_id = _bounded_text(run_id, "run id", 64)
        parent_reservation_id = _bounded_text(parent_reservation_id, "parent reservation id", 36)
        provider_id = _bounded_text(provider_id, "provider id", 64)
        provider_name = _bounded_text(provider_name, "provider name", 200)
        model = _bounded_text(model, "model", 200)
        engine = _bounded_text(engine, "engine", 64)
        if funding not in ALLOWED_FUNDING:
            raise GatewayRejected("invalid_funding", "Funding must be company or personal")
        if provider_scope not in ALLOWED_PROVIDER_SCOPES:
            raise GatewayRejected(
                "invalid_provider_scope", "Provider scope must be global or personal"
            )
        if provider_scope == "personal" and funding != "personal":
            raise GatewayRejected(
                "funding_scope_mismatch",
                "A personal provider can only be funded from the personal balance",
            )
        if not isinstance(selection, ProviderModelSelection):
            raise GatewayRejected(
                "invalid_selection", "A server-resolved provider selection is required"
            )
        if selection.model != model:
            raise GatewayRejected(
                "model_mismatch", "The provider selection and lease model must match"
            )
        _bounded_text(selection.base_url, "provider base URL", 2048)
        _secret_text(selection.api_key, "provider API key")
        if not isinstance(selection.allow_private, bool | ProviderNetworkPolicy):
            raise GatewayRejected(
                "invalid_selection",
                "allow_private must be a boolean or a network policy",
            )
        policy = None
        if provider_scope == "personal":
            # The deployment allowlist is the only authority for private personal
            # destinations: a selection cannot widen it.
            policy = personal_endpoint_policy(self._settings)
            if selection.allow_private is True:
                raise GatewayRejected(
                    "invalid_selection",
                    "A personal provider selection cannot allow private connections",
                )
        context_tokens = _positive_int(context_tokens, "context tokens", MAX_CONTEXT_TOKENS)
        output_tokens = _positive_int(output_tokens, "output tokens", MAX_OUTPUT_TOKENS)
        ttl_seconds = _positive_int(ttl_seconds, "lease TTL", MAX_TTL_SECONDS)
        self._endpoint(selection.base_url, provider_scope, at_issue=True, policy=policy)
        self._require_parent(
            actor_id=actor_id,
            funding=funding,
            run_id=run_id,
            parent_reservation_id=parent_reservation_id,
            provider_id=provider_id,
            provider_scope=provider_scope,
            provider_name=provider_name,
            model=model,
            engine=engine,
        )

        snapshot = json.dumps(
            {
                "base_url": selection.base_url,
                "model": selection.model,
                "api_key": selection.api_key,
                "allow_private": selection.allow_private is True,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        try:
            ciphertext = seal_credential(self._settings, snapshot)
        except CredentialUnavailable as exc:
            raise GatewayUnavailable(
                "credential_storage_unavailable",
                "Provider credential storage is not configured",
            ) from exc

        now = self._now_utc()
        expires_at = now + timedelta(seconds=ttl_seconds)
        bearer_token = secrets.token_urlsafe(48)
        lease_id = str(uuid4())
        lease = AiGatewayLease(
            id=lease_id,
            token_hash=_token_hash(bearer_token),
            actor_id=actor_id,
            run_id=run_id,
            parent_reservation_id=parent_reservation_id,
            funding=funding,
            provider_id=provider_id,
            provider_scope=provider_scope,
            provider_name=provider_name,
            model=model,
            engine=engine,
            context_tokens=context_tokens,
            output_tokens=output_tokens,
            input_modalities=",".join(modalities),
            attachment_bytes=attachment_bytes,
            selection_ciphertext=ciphertext,
            allow_private=selection.allow_private is True,
            created_at=now,
            expires_at=expires_at,
        )
        with self._session() as db:
            db.add(lease)
            try:
                db.commit()
            except IntegrityError as exc:
                db.rollback()
                raise GatewayUnavailable(
                    "lease_persistence_failed", "The lease could not be persisted"
                ) from exc
        return IssuedLease(
            lease_id=lease_id,
            bearer_token=bearer_token,
            run_id=run_id,
            model=model,
            expires_at=expires_at,
            context_tokens=context_tokens,
            output_tokens=output_tokens,
        )

    def revoke(self, lease_id: str) -> bool:
        """Revoke a lease. Revocation stops new calls; it never refunds budget."""

        if not isinstance(lease_id, str) or not lease_id:
            return False
        with self._session() as db:
            lease = db.get(AiGatewayLease, lease_id)
            if lease is None:
                return False
            if lease.revoked_at is None:
                lease.revoked_at = self._now_utc()
                db.commit()
            return True

    def authenticate(self, token: str) -> LeaseContext:
        if not isinstance(token, str) or not token or len(token) > 512:
            raise GatewayDenied("invalid_lease", "A valid lease is required")
        digest = _token_hash(token)
        with self._session() as db:
            lease = db.scalar(select(AiGatewayLease).where(AiGatewayLease.token_hash == digest))
            if lease is None:
                raise GatewayDenied("invalid_lease", "A valid lease is required")
            if lease.revoked_at is not None:
                raise GatewayDenied("revoked_lease", "This lease has been revoked")
            if as_utc(lease.expires_at) <= self._now_utc():
                raise GatewayDenied("expired_lease", "This lease has expired")
            return _lease_context(lease)

    def models(self, context: LeaseContext) -> dict[str, Any]:
        return {
            "object": "list",
            "data": [
                {
                    "id": context.model,
                    "object": "model",
                    "created": 0,
                    "owned_by": "itsm-ai-gateway",
                }
            ],
        }

    async def chat(
        self,
        context: LeaseContext,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str | None = None,
    ) -> GatewayResult:
        selection, endpoint, context = self._authorized_selection(context)
        prepared = self._prepare(context, payload)
        _validate_idempotency_key(idempotency_key)
        client = self._client(selection)
        try:
            call_id = self._claim(context, idempotency_key)
        except GatewayError:
            await client.aclose()
            raise

        try:
            grant = self._reserve(context, prepared, call_id)
        except GatewayQuotaError:
            self._delete_claim(call_id)
            await client.aclose()
            raise
        except Exception as exc:
            self._abandon_claim(call_id)
            await client.aclose()
            raise GatewayUnavailable(
                "quota_unavailable", "The quota ledger is unavailable"
            ) from exc

        if getattr(grant, "replayed", False):
            await client.aclose()
            raise GatewayConflict(
                "duplicate_dispatch",
                "A reservation for this call already exists; duplicate dispatch is refused",
            )

        reservation_id = str(grant.reservation_id)
        try:
            self._mark_in_flight(call_id, reservation_id)
        except Exception as exc:
            self._finalize(call_id, reservation_id, None)
            await client.aclose()
            raise GatewayUnavailable(
                "gateway_state_unavailable", "The gateway could not record the call"
            ) from exc

        if prepared.stream:
            return await self._stream(
                client=client,
                endpoint=endpoint,
                selection=selection,
                prepared=prepared,
                call_id=call_id,
                reservation_id=reservation_id,
            )
        return await self._complete(
            client=client,
            endpoint=endpoint,
            selection=selection,
            prepared=prepared,
            call_id=call_id,
            reservation_id=reservation_id,
        )

    def _authorized_selection(
        self, context: LeaseContext
    ) -> tuple[ProviderModelSelection, str, LeaseContext]:
        with self._session() as db:
            lease = db.get(AiGatewayLease, context.lease_id)
            if lease is None:
                raise GatewayDenied("invalid_lease", "A valid lease is required")
            if lease.revoked_at is not None:
                raise GatewayDenied("revoked_lease", "This lease has been revoked")
            if as_utc(lease.expires_at) <= self._now_utc():
                raise GatewayDenied("expired_lease", "This lease has expired")
            try:
                snapshot = json.loads(unseal_credential(self._settings, lease.selection_ciphertext))
            except (CredentialUnavailable, CredentialInvalid, ValueError, TypeError) as exc:
                raise GatewayUnavailable(
                    "credential_unavailable", "The provider credential is unavailable"
                ) from exc
            verified = _lease_context(lease)
        if not isinstance(snapshot, Mapping):
            raise GatewayUnavailable(
                "credential_unavailable", "The provider credential is unavailable"
            )
        base_url = snapshot.get("base_url")
        model = snapshot.get("model")
        api_key = snapshot.get("api_key")
        allow_private = snapshot.get("allow_private")
        if not isinstance(base_url, str) or not isinstance(api_key, str):
            raise GatewayUnavailable(
                "credential_unavailable", "The provider credential is unavailable"
            )
        if model != verified.model or not isinstance(allow_private, bool):
            raise GatewayUnavailable(
                "credential_unavailable", "The provider credential is unavailable"
            )
        if verified.provider_scope == "personal" and allow_private:
            raise GatewayUnavailable(
                "credential_unavailable",
                "A personal provider lease cannot allow private connections",
            )
        policy = None
        if verified.provider_scope == "personal":
            # Re-derived from current settings on every forward: the lease carries
            # no private-network authority of its own.
            policy = personal_endpoint_policy(self._settings)
        endpoint = self._endpoint(base_url, verified.provider_scope, at_issue=False, policy=policy)
        return (
            ProviderModelSelection(
                base_url=base_url,
                model=model,
                api_key=api_key,
                allow_private=policy if policy is not None else allow_private,
            ),
            endpoint,
            verified,
        )

    def _client(self, selection: ProviderModelSelection) -> httpx.AsyncClient:
        try:
            return self._client_factory(allow_private=selection.allow_private)
        except Exception as exc:
            raise GatewayUnavailable(
                "client_unavailable", "The guarded provider client is unavailable"
            ) from exc

    def _require_parent(
        self,
        *,
        actor_id: str,
        funding: str,
        run_id: str,
        parent_reservation_id: str,
        provider_id: str,
        provider_scope: str,
        provider_name: str,
        model: str,
        engine: str,
    ) -> None:
        try:
            items = self._usage.pending(run_id=run_id, user_id=actor_id, limit=500)
        except Exception as exc:
            raise GatewayUnavailable(
                "quota_unavailable", "The quota ledger is unavailable"
            ) from exc
        if not isinstance(items, list):
            raise GatewayUnavailable("quota_unavailable", "The quota ledger is unavailable")
        parent = next(
            (
                item
                for item in items
                if isinstance(item, Mapping) and item.get("reservationId") == parent_reservation_id
            ),
            None,
        )
        if parent is None or parent.get("state") != "pending":
            raise GatewayConflict(
                "parent_reservation_unavailable",
                "The run reservation is not pending for this actor and run",
            )
        expected = {
            "userId": actor_id,
            "funding": funding,
            "runId": run_id,
            "providerId": provider_id,
            "providerScope": provider_scope,
            "providerName": provider_name,
            "model": model,
            "engine": engine,
        }
        for key, value in expected.items():
            if parent.get(key) != value:
                raise GatewayRejected(
                    "parent_reservation_mismatch",
                    f"The run reservation does not match the lease ({key})",
                )

    def _reserve(self, context: LeaseContext, prepared: _PreparedChat, call_id: str) -> Any:
        try:
            return self._usage.reserve(
                context.actor_id,
                funding=context.funding,
                reserved_tokens=prepared.reserved_tokens,
                provider_id=context.provider_id,
                provider_scope=context.provider_scope,
                provider_name=context.provider_name,
                model=context.model,
                engine=context.engine,
                run_id=context.run_id,
                parent_reservation_id=context.parent_reservation_id,
                idempotency_key=f"gateway:{call_id}",
            )
        except Exception as exc:
            if getattr(type(exc), "code", None) == "quota_exceeded":
                remaining = getattr(exc, "remaining_tokens", 0)
                raise GatewayQuotaError(
                    "The daily AI usage quota is exhausted",
                    remaining_tokens=remaining if isinstance(remaining, int) else 0,
                    period_day=getattr(exc, "period_day", None),
                ) from exc
            raise

    def _claim(self, context: LeaseContext, idempotency_key: str | None) -> str:
        now = self._now_utc()
        call_id = str(uuid4())
        call = AiGatewayCall(
            id=call_id,
            lease_id=context.lease_id,
            actor_id=context.actor_id,
            run_id=context.run_id,
            idempotency_hash=(
                hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
                if idempotency_key is not None
                else None
            ),
            state=CLAIMED,
            created_at=now,
            updated_at=now,
        )
        with self._session() as db:
            db.add(call)
            try:
                db.commit()
            except IntegrityError as exc:
                db.rollback()
                raise GatewayConflict(
                    "duplicate_request",
                    "This idempotency key has already been used; replay is not supported",
                ) from exc
        return call_id

    def _delete_claim(self, call_id: str) -> None:
        with self._session() as db:
            call = db.get(AiGatewayCall, call_id)
            if call is not None and call.state == CLAIMED:
                db.delete(call)
                db.commit()

    def _abandon_claim(self, call_id: str) -> None:
        try:
            with self._session() as db:
                call = db.get(AiGatewayCall, call_id)
                if call is None or call.state in TERMINAL_CALL_STATES:
                    return
                call.state = UNRESOLVED
                call.precision = "unavailable"
                call.source = "none"
                call.completed_at = self._now_utc()
                call.updated_at = self._now_utc()
                db.commit()
        except Exception:
            logger.warning("Gateway could not persist an abandoned claim")

    def _mark_in_flight(self, call_id: str, reservation_id: str) -> None:
        with self._session() as db:
            call = db.get(AiGatewayCall, call_id)
            if call is None:
                raise LookupError("gateway call disappeared")
            call.reservation_id = reservation_id
            call.state = IN_FLIGHT
            call.updated_at = self._now_utc()
            db.commit()

    async def _complete(
        self,
        *,
        client: httpx.AsyncClient,
        endpoint: str,
        selection: ProviderModelSelection,
        prepared: _PreparedChat,
        call_id: str,
        reservation_id: str,
    ) -> GatewayResult:
        url = f"{endpoint}/chat/completions"
        try:
            try:
                request = client.build_request(
                    "POST",
                    url,
                    json=prepared.payload,
                    headers=_upstream_headers(selection.api_key, stream=False),
                )
                response = await client.send(request, stream=True)
            except Exception as exc:
                self._finalize(call_id, reservation_id, None)
                raise GatewayUpstreamError(
                    "upstream_unavailable", "The configured provider could not be reached"
                ) from exc
            try:
                if response.status_code >= 300:
                    if response.status_code >= 400:
                        try:
                            body, truncated = await _read_limited(response, MAX_ERROR_BYTES)
                        except httpx.HTTPError:
                            body, truncated = b"", True
                        self._finalize(call_id, reservation_id, None)
                        return _upstream_error(response.status_code, b"" if truncated else body)
                    self._finalize(call_id, reservation_id, None)
                    return _json_result(
                        502,
                        "upstream_redirect",
                        "The provider returned a redirect, which the gateway does not follow",
                    )
                try:
                    body, truncated = await _read_limited(response, MAX_RESPONSE_BYTES)
                except httpx.HTTPError as exc:
                    self._finalize(call_id, reservation_id, None)
                    raise GatewayUpstreamError(
                        "upstream_unavailable", "The provider response could not be read"
                    ) from exc
                if truncated:
                    self._finalize(call_id, reservation_id, None)
                    return _json_result(
                        502,
                        "upstream_response_too_large",
                        "The provider response exceeded the gateway limit",
                    )
                self._finalize(call_id, reservation_id, _parse_json_usage(body))
                media_type = (
                    response.headers.get("content-type", "application/json").split(";")[0].strip()
                    or "application/json"
                )
                return GatewayResult(
                    status_code=200,
                    body=body,
                    media_type=media_type,
                )
            finally:
                await response.aclose()
        finally:
            await client.aclose()

    async def _stream(
        self,
        *,
        client: httpx.AsyncClient,
        endpoint: str,
        selection: ProviderModelSelection,
        prepared: _PreparedChat,
        call_id: str,
        reservation_id: str,
    ) -> GatewayResult:
        url = f"{endpoint}/chat/completions"
        try:
            request = client.build_request(
                "POST",
                url,
                json=prepared.payload,
                headers=_upstream_headers(selection.api_key, stream=True),
            )
            response = await client.send(request, stream=True)
        except Exception as exc:
            await client.aclose()
            self._finalize(call_id, reservation_id, None)
            raise GatewayUpstreamError(
                "upstream_unavailable", "The configured provider could not be reached"
            ) from exc

        if response.status_code >= 300:
            if response.status_code >= 400:
                try:
                    body, truncated = await _read_limited(response, MAX_ERROR_BYTES)
                except httpx.HTTPError:
                    body, truncated = b"", True
                finally:
                    await response.aclose()
                    await client.aclose()
                self._finalize(call_id, reservation_id, None)
                return _upstream_error(response.status_code, b"" if truncated else body)
            await response.aclose()
            await client.aclose()
            self._finalize(call_id, reservation_id, None)
            return _json_result(
                502,
                "upstream_redirect",
                "The provider returned a redirect, which the gateway does not follow",
            )

        return GatewayResult(
            status_code=200,
            media_type="text/event-stream",
            stream=self._relay(
                response=response,
                client=client,
                call_id=call_id,
                reservation_id=reservation_id,
            ),
        )

    async def _relay(
        self,
        *,
        response: httpx.Response,
        client: httpx.AsyncClient,
        call_id: str,
        reservation_id: str,
    ) -> AsyncIterator[bytes]:
        scanner = _UsageScanner()
        total_bytes = 0
        truncated = False
        try:
            try:
                async for chunk in response.aiter_bytes():
                    total_bytes += len(chunk)
                    if total_bytes > MAX_STREAM_BYTES:
                        truncated = True
                        break
                    scanner.feed(chunk)
                    yield chunk
            except httpx.HTTPError:
                pass
        finally:
            try:
                await response.aclose()
            finally:
                try:
                    await client.aclose()
                finally:
                    self._finalize(
                        call_id, reservation_id, None if truncated else scanner.evidence()
                    )

    def _finalize(
        self,
        call_id: str,
        reservation_id: str,
        evidence: Mapping[str, Any] | None,
    ) -> None:
        document = (
            dict(evidence)
            if evidence is not None
            else {
                "precision": "unavailable",
                "source": "none",
            }
        )
        try:
            with self._session() as db:
                call = db.get(AiGatewayCall, call_id)
                if call is None or call.state in TERMINAL_CALL_STATES:
                    return
            try:
                result = self._usage.settle(reservation_id, document)
            except Exception:
                logger.warning("Quota settlement failed; keeping the hold unresolved")
                state, tokens, precision, source = UNRESOLVED, None, "unavailable", "none"
            else:
                state = str(getattr(result, "state", UNRESOLVED))
                if state not in TERMINAL_CALL_STATES:
                    state = UNRESOLVED
                tokens = getattr(result, "tokens", None)
                precision = getattr(result, "precision", "unavailable")
                source = getattr(result, "source", "none")
            try:
                with self._session() as db:
                    call = db.get(AiGatewayCall, call_id)
                    if call is None or call.state in TERMINAL_CALL_STATES:
                        return
                    now = self._now_utc()
                    call.state = state
                    call.total_tokens = (
                        tokens if isinstance(tokens, int) and not isinstance(tokens, bool) else None
                    )
                    call.precision = precision if isinstance(precision, str) else "unavailable"
                    call.source = source if isinstance(source, str) else "none"
                    call.completed_at = now
                    call.updated_at = now
                    db.commit()
            except Exception:
                logger.warning("Gateway call accounting could not be persisted")
        except Exception:
            logger.warning("Gateway accounting state is unavailable; the hold remains")

    def _endpoint(
        self,
        base_url: str,
        scope: str,
        *,
        at_issue: bool,
        policy: ProviderNetworkPolicy | None = None,
    ) -> str:
        try:
            return validate_provider_endpoint(base_url, scope=scope, policy=policy)
        except ProviderEndpointError as exc:
            if at_issue:
                raise GatewayRejected("invalid_provider_endpoint", str(exc)) from exc
            raise GatewayUnavailable("provider_endpoint_invalid", str(exc)) from exc

    def _prepare(self, context: LeaseContext, payload: Mapping[str, Any]) -> _PreparedChat:
        if not isinstance(payload, Mapping):
            raise GatewayRejected("invalid_request", "Request body must be a JSON object")
        body = dict(payload)
        unknown = set(body) - _ALLOWED_FIELDS
        if unknown:
            raise GatewayRejected(
                "unsupported_parameter", f"Unsupported request field: {sorted(unknown)[0]}"
            )
        requested_model = body.get("model", context.model)
        if requested_model != context.model:
            raise GatewayRejected(
                "invalid_model", "The requested model is not authorized by this lease"
            )
        body["model"] = context.model
        if "n" in body:
            n = body["n"]
            if isinstance(n, bool) or not isinstance(n, int) or n != 1:
                raise GatewayRejected("unsupported_parameter", "Only n=1 is supported")
        _validate_messages(
            body.get("messages"),
            context.input_modalities,
            context.attachment_bytes,
        )
        if "tools" in body:
            _validate_tools(body["tools"])
        if "tool_choice" in body:
            _validate_tool_choice(body["tool_choice"])
        if "parallel_tool_calls" in body and not isinstance(body["parallel_tool_calls"], bool):
            raise GatewayRejected("invalid_request", "parallel_tool_calls must be a boolean")
        if "response_format" in body:
            _validate_response_format(body["response_format"])
        _validate_numbers(body)
        _validate_stop(body)
        if "user" in body:
            _bounded_text(body["user"], "user", 200)
        if "seed" in body:
            _non_negative_int(body["seed"], "seed", 2**31 - 1)
        if "logit_bias" in body:
            bias = body["logit_bias"]
            if not isinstance(bias, Mapping) or any(
                not isinstance(value, (int, float)) or isinstance(value, bool)
                for value in bias.values()
            ):
                raise GatewayRejected("invalid_request", "logit_bias must map tokens to numbers")

        stream = body.get("stream", False)
        if not isinstance(stream, bool):
            raise GatewayRejected("invalid_request", "stream must be a boolean")
        options: dict[str, Any] = {}
        if "stream_options" in body:
            raw_options = body["stream_options"]
            if not isinstance(raw_options, Mapping):
                raise GatewayRejected("invalid_request", "stream_options must be an object")
            unknown_options = set(raw_options) - {"include_usage"}
            if unknown_options:
                raise GatewayRejected(
                    "unsupported_parameter",
                    f"Unsupported stream option: {sorted(unknown_options)[0]}",
                )
            if "include_usage" in raw_options and not isinstance(
                raw_options["include_usage"], bool
            ):
                raise GatewayRejected(
                    "invalid_request", "stream_options.include_usage must be a boolean"
                )
            options = dict(raw_options)
        if stream:
            options["include_usage"] = True
            body["stream_options"] = options

        provided = [key for key in ("max_tokens", "max_completion_tokens") if key in body]
        for key in provided:
            try:
                _positive_int(body[key], key, MAX_OUTPUT_TOKENS)
            except GatewayRejected as exc:
                raise GatewayRejected(
                    "invalid_output_limit",
                    f"{key} must be between 1 and {MAX_OUTPUT_TOKENS}",
                ) from exc
        if len(provided) == 2 and body["max_tokens"] != body["max_completion_tokens"]:
            raise GatewayRejected(
                "conflicting_output_limit",
                "max_tokens and max_completion_tokens must agree when both are present",
            )
        if provided:
            cap = (
                body["max_completion_tokens"]
                if "max_completion_tokens" in body
                else body["max_tokens"]
            )
            if cap > context.output_tokens:
                raise GatewayRejected(
                    "output_bound_exceeded",
                    "The requested output limit exceeds the lease output bound",
                )
        else:
            cap = context.output_tokens
            body["max_tokens"] = cap

        return _PreparedChat(
            payload=body,
            stream=stream,
            reserved_tokens=max(
                context.context_tokens,
                _input_estimate(body),
            )
            + cap,
        )


def _lease_context(lease: AiGatewayLease) -> LeaseContext:
    return LeaseContext(
        lease_id=lease.id,
        actor_id=lease.actor_id,
        run_id=lease.run_id,
        parent_reservation_id=lease.parent_reservation_id,
        funding=lease.funding,
        provider_id=lease.provider_id,
        provider_scope=lease.provider_scope,
        provider_name=lease.provider_name,
        model=lease.model,
        engine=lease.engine,
        context_tokens=lease.context_tokens,
        output_tokens=lease.output_tokens,
        expires_at=as_utc(lease.expires_at),
        input_modalities=_input_modalities(
            [item for item in (lease.input_modalities or "").split(",") if item]
        ),
        attachment_bytes=int(lease.attachment_bytes or 0),
    )


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _bounded_text(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str):
        raise GatewayRejected("invalid_request", f"{name} must be a string")
    if not value or len(value) > limit or value != value.strip():
        raise GatewayRejected("invalid_request", f"{name} is invalid")
    if any(ord(character) < 32 for character in value):
        raise GatewayRejected("invalid_request", f"{name} contains control characters")
    return value


def _secret_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise GatewayRejected("invalid_selection", f"{name} is invalid")
    if any(ord(character) < 32 for character in value):
        raise GatewayRejected("invalid_selection", f"{name} contains control characters")
    return value


def _positive_int(value: Any, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise GatewayRejected("invalid_request", f"{name} must be between 1 and {maximum}")
    return value


def _non_negative_int(value: Any, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise GatewayRejected("invalid_request", f"{name} is out of range")
    return value


def _validate_idempotency_key(value: str | None) -> None:
    if value is None:
        return
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > MAX_IDEMPOTENCY_KEY
        or any(ord(character) < 32 for character in value)
    ):
        raise GatewayRejected("invalid_idempotency_key", "Idempotency-Key is invalid")


def _input_modalities(value: Any) -> tuple[str, ...]:
    """Only the documented non-text kinds, bounded and duplicate free."""

    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or isinstance(value, (str, bytes)):
        raise GatewayRejected("invalid_selection", "input modalities must be a list")
    bounded: list[str] = []
    for item in value:
        if not isinstance(item, str) or item not in _ALLOWED_INPUT_MODALITIES:
            raise GatewayRejected(
                "invalid_selection", "input modalities are limited to image and file"
            )
        if item not in bounded:
            bounded.append(item)
    if len(bounded) > len(_ALLOWED_INPUT_MODALITIES):
        raise GatewayRejected("invalid_selection", "input modalities exceed the limit")
    return tuple(bounded)


def _attachment_bytes(value: Any, modalities: Sequence[str]) -> int:
    """Encoded byte budget for attachment parts; zero unless a kind is declared."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GatewayRejected("invalid_selection", "attachment bytes must be a positive integer")
    if value > MAX_ATTACHMENT_BYTES:
        raise GatewayRejected("invalid_selection", "attachment bytes exceed the limit")
    if value and not modalities:
        raise GatewayRejected(
            "invalid_selection", "attachment bytes require a declared input modality"
        )
    return int(value)


def _input_estimate(body: Mapping[str, Any]) -> int:
    """Validated binary bodies use existing modality estimates, not base64 bytes.

    Preserve all other fields (including history/tools/schemas). This is not a
    universal provider token bound; byte admission and output caps still apply.
    """
    from copy import deepcopy

    from itsm.agent_integrations.attachments import binary_input_estimate

    accounting = deepcopy(body)
    attachment_tokens = 0
    for message in accounting["messages"]:
        if not isinstance(message.get("content"), list):
            continue
        for part in message["content"]:
            if part["type"] == "image_url":
                match = _DATA_URL.match(part["image_url"]["url"])
                attachment_tokens += binary_input_estimate(
                    base64.b64decode(match.group("data")), "image"
                )
                part["image_url"]["url"] = ""
            elif part["type"] == "file":
                document = part["file"]
                data = document["file_data"]
                match = _DATA_URL.match(data) if data.startswith("data:") else None
                mime = match.group("mime") if match else ""
                filename = document.get("filename", "").lower()
                if mime.startswith("text/") or (not mime and filename.endswith((".txt", ".csv"))):
                    # Text files cannot disguise a long textual input as binary.
                    attachment_tokens += len(
                        base64.b64decode(match.group("data") if match else data)
                    )
                else:
                    attachment_tokens += binary_input_estimate(
                        base64.b64decode(match.group("data") if match else data), "file"
                    )
                document["file_data"] = ""
    return (
        len(json.dumps(accounting, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        + attachment_tokens
    )


def _part_size(encoded: str) -> int:
    """Validate base64 and return its encoded size, the lease's budget unit."""

    try:
        base64.b64decode(encoded, validate=True)
    except binascii.Error, ValueError:
        raise GatewayRejected("unsupported_content", "Content part is not valid base64") from None
    return len(encoded)


def _image_part(part: Mapping[str, Any], budget: list[int]) -> None:
    """Admit one inline image; remote URLs are always refused."""

    if set(part) != {"type", "image_url"}:
        raise GatewayRejected("unsupported_content", "Unsupported image content part")
    image = part.get("image_url")
    if not isinstance(image, Mapping) or set(image) - {"url", "detail"}:
        raise GatewayRejected("unsupported_content", "Unsupported image content part")
    if "detail" in image and image["detail"] not in {"auto", "low", "high"}:
        raise GatewayRejected("unsupported_content", "Unsupported image detail")
    url = image.get("url")
    if not isinstance(url, str) or not url:
        raise GatewayRejected("unsupported_content", "image_url.url must be a string")
    if not url.startswith("data:"):
        raise GatewayRejected(
            "unsupported_content",
            "Only inline data: image URLs are accepted; remote URLs are refused",
        )
    match = _DATA_URL.match(url)
    if match is None or match.group("mime") not in _ALLOWED_IMAGE_MEDIA:
        raise GatewayRejected("unsupported_content", "Unsupported image media type")
    budget[0] += _part_size(match.group("data"))


def _file_part(part: Mapping[str, Any], budget: list[int]) -> None:
    """Admit one inline document; a path, URL or bare name is refused."""

    if set(part) != {"type", "file"}:
        raise GatewayRejected("unsupported_content", "Unsupported file content part")
    document = part.get("file")
    if not isinstance(document, Mapping) or set(document) - {"filename", "file_data"}:
        raise GatewayRejected("unsupported_content", "Unsupported file content part")
    filename = document.get("filename")
    if filename is not None and (
        not isinstance(filename, str) or not filename or len(filename) > 180
    ):
        raise GatewayRejected("unsupported_content", "file.filename is invalid")
    file_data = document.get("file_data")
    if not isinstance(file_data, str) or not file_data:
        raise GatewayRejected("unsupported_content", "file.file_data must be inline base64")
    if file_data.startswith("data:"):
        match = _DATA_URL.match(file_data)
        if match is None:
            raise GatewayRejected("unsupported_content", "Unsupported file data URL")
        mime = match.group("mime")
        if mime != "application/pdf" and not mime.startswith("text/"):
            raise GatewayRejected("unsupported_content", "Unsupported file media type")
        budget[0] += _part_size(match.group("data"))
        return
    if not isinstance(filename, str) or not filename.lower().endswith((".pdf", ".txt", ".csv")):
        raise GatewayRejected(
            "unsupported_content",
            "Bare base64 file data requires a supported filename",
        )
    budget[0] += _part_size(file_data)


def _validate_messages(
    messages: Any,
    modalities: Sequence[str] = (),
    attachment_bytes: int = 0,
) -> None:
    if not isinstance(messages, list) or not messages:
        raise GatewayRejected("invalid_message", "messages must be a non-empty list")
    if len(messages) > 256:
        raise GatewayRejected("invalid_message", "Too many messages")
    for message in messages:
        if not isinstance(message, Mapping):
            raise GatewayRejected("invalid_message", "Each message must be an object")
        unknown = set(message) - _ALLOWED_MESSAGE_FIELDS
        if unknown:
            raise GatewayRejected(
                "unsupported_parameter", f"Unsupported message field: {sorted(unknown)[0]}"
            )
        role = message.get("role")
        if role not in _ALLOWED_ROLES:
            raise GatewayRejected("invalid_message", "Unsupported message role")
        content = message.get("content")
        if isinstance(content, str):
            pass
        elif isinstance(content, list):
            if len(content) > _MAX_CONTENT_PARTS:
                raise GatewayRejected("invalid_message", "Too many content parts")
            budget = [0]
            for part in content:
                if isinstance(part, Mapping) and part.get("type") == "text":
                    if not isinstance(part.get("text"), str) or set(part) - {"type", "text"}:
                        raise GatewayRejected(
                            "unsupported_content", "Unsupported text content part"
                        )
                    continue
                if not isinstance(part, Mapping):
                    raise GatewayRejected("unsupported_content", "Unsupported content part")
                kind = part.get("type")
                if kind == "image_url" and "image" in modalities:
                    _image_part(part, budget)
                    continue
                if kind == "file" and "file" in modalities:
                    _file_part(part, budget)
                    continue
                if kind in {"image_url", "file"}:
                    raise GatewayRejected(
                        "unsupported_content",
                        "This lease does not admit this content part kind",
                    )
                raise GatewayRejected(
                    "unsupported_content",
                    "Only text, image and file content parts are supported",
                )
            if budget[0] > attachment_bytes:
                raise GatewayRejected(
                    "unsupported_content", "Attachment content exceeds the lease byte budget"
                )
        elif content is not None:
            raise GatewayRejected("unsupported_content", "Unsupported message content")
        if role == "tool":
            tool_call_id = message.get("tool_call_id")
            if not isinstance(tool_call_id, str) or not tool_call_id.strip():
                raise GatewayRejected("invalid_message", "Tool messages require a tool_call_id")
        if "tool_calls" in message:
            _validate_tool_calls(message["tool_calls"])
        if "name" in message and (
            not isinstance(message["name"], str) or not message["name"].strip()
        ):
            raise GatewayRejected("invalid_message", "Message name is invalid")


def _validate_tool_calls(tool_calls: Any) -> None:
    if not isinstance(tool_calls, list) or len(tool_calls) > 128:
        raise GatewayRejected("invalid_message", "tool_calls is invalid")
    for call in tool_calls:
        if not isinstance(call, Mapping):
            raise GatewayRejected("invalid_message", "tool_calls entries must be objects")
        if set(call) - {"id", "type", "function", "index"}:
            raise GatewayRejected("invalid_message", "Unsupported tool_call field")
        if call.get("type") != "function":
            raise GatewayRejected("unsupported_tool", "Only function tools are supported")
        function = call.get("function")
        if not isinstance(function, Mapping) or set(function) - {"name", "arguments"}:
            raise GatewayRejected("invalid_message", "tool_call function is invalid")
        if not isinstance(function.get("name"), str) or not isinstance(
            function.get("arguments"), str
        ):
            raise GatewayRejected("invalid_message", "tool_call function is invalid")


def _validate_tools(tools: Any) -> None:
    if not isinstance(tools, list) or len(tools) > 64:
        raise GatewayRejected("unsupported_tool", "tools is invalid")
    for tool in tools:
        if not isinstance(tool, Mapping) or set(tool) - {"type", "function"}:
            raise GatewayRejected("unsupported_tool", "Only function tools are supported")
        if tool.get("type") != "function":
            raise GatewayRejected("unsupported_tool", "Only function tools are supported")
        function = tool.get("function")
        if not isinstance(function, Mapping):
            raise GatewayRejected("unsupported_tool", "Function tool definition is invalid")
        unknown = set(function) - {"name", "description", "parameters", "strict"}
        if unknown:
            raise GatewayRejected(
                "unsupported_parameter", f"Unsupported function field: {sorted(unknown)[0]}"
            )
        name = function.get("name")
        if not isinstance(name, str) or not name.strip() or len(name) > 64:
            raise GatewayRejected("unsupported_tool", "Function tool name is invalid")
        description = function.get("description")
        if description is not None and (
            not isinstance(description, str) or len(description) > 1024
        ):
            raise GatewayRejected("unsupported_tool", "Function tool description is invalid")
        if not isinstance(function.get("parameters"), Mapping):
            raise GatewayRejected("unsupported_tool", "Function tool parameters are required")
        if "strict" in function and not isinstance(function["strict"], bool):
            raise GatewayRejected("unsupported_tool", "Function tool strict must be a boolean")


def _validate_tool_choice(choice: Any) -> None:
    if isinstance(choice, str):
        if choice not in _ALLOWED_TOOL_CHOICES:
            raise GatewayRejected("unsupported_parameter", "Unsupported tool_choice")
        return
    if not isinstance(choice, Mapping) or set(choice) != {"type", "function"}:
        raise GatewayRejected("unsupported_parameter", "Unsupported tool_choice")
    if choice.get("type") != "function":
        raise GatewayRejected("unsupported_parameter", "Unsupported tool_choice")
    function = choice.get("function")
    if (
        not isinstance(function, Mapping)
        or set(function) != {"name"}
        or not isinstance(function.get("name"), str)
        or not function["name"].strip()
    ):
        raise GatewayRejected("unsupported_parameter", "Unsupported tool_choice")


def _validate_response_format(response_format: Any) -> None:
    if not isinstance(response_format, Mapping):
        raise GatewayRejected("invalid_request", "response_format must be an object")
    kind = response_format.get("type")
    if kind not in _ALLOWED_RESPONSE_FORMATS:
        raise GatewayRejected("unsupported_parameter", "Unsupported response_format")
    if kind == "json_schema":
        if set(response_format) != {"type", "json_schema"} or not isinstance(
            response_format.get("json_schema"), Mapping
        ):
            raise GatewayRejected("invalid_request", "json_schema response_format is invalid")
    elif set(response_format) != {"type"}:
        raise GatewayRejected("unsupported_parameter", "Unsupported response_format field")


def _validate_numbers(body: dict[str, Any]) -> None:
    ranges = {
        "temperature": (0.0, 2.0),
        "top_p": (0.0, 1.0),
        "presence_penalty": (-2.0, 2.0),
        "frequency_penalty": (-2.0, 2.0),
    }
    for key, (low, high) in ranges.items():
        if key not in body:
            continue
        value = body[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not low <= value <= high
        ):
            raise GatewayRejected(
                "invalid_request", f"{key} must be a number between {low} and {high}"
            )
    if "top_k" in body:
        _non_negative_int(body["top_k"], "top_k", 2000)


def _validate_stop(body: dict[str, Any]) -> None:
    if "stop" not in body:
        return
    stop = body["stop"]
    if isinstance(stop, str):
        if not stop:
            raise GatewayRejected("invalid_request", "stop must not be empty")
        return
    if (
        not isinstance(stop, list)
        or len(stop) > 4
        or not all(isinstance(item, str) and item for item in stop)
    ):
        raise GatewayRejected("invalid_request", "stop must be a string or up to four strings")


def _upstream_headers(api_key: str, *, stream: bool) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream" if stream else "application/json",
        "User-Agent": "itsm-ai-gateway/1",
    }


def _upstream_error(status_code: int, body: bytes) -> GatewayResult:
    try:
        parsed = json.loads(body[:MAX_ERROR_BYTES])
    except ValueError, UnicodeDecodeError:
        parsed = None
    if isinstance(parsed, Mapping) and isinstance(parsed.get("error"), (Mapping, str)):
        return GatewayResult(
            status_code=status_code,
            body=json.dumps(parsed).encode("utf-8"),
            media_type="application/json",
        )
    return _json_result(
        status_code,
        "upstream_error",
        "The provider rejected the request",
        extra={"status": status_code},
    )


__all__ = [
    "MAX_ATTACHMENT_BYTES",
    "MAX_REQUEST_BYTES",
    "MAX_RESPONSE_BYTES",
    "MAX_STREAM_BYTES",
    "AiGatewayService",
    "GatewayConflict",
    "GatewayDenied",
    "GatewayError",
    "GatewayQuotaError",
    "GatewayRejected",
    "GatewayResult",
    "GatewayUnavailable",
    "GatewayUpstreamError",
    "IssuedLease",
    "LeaseContext",
    "error_payload",
    "usage_evidence",
]
