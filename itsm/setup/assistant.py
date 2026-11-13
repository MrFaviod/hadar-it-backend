"""Read-only bootstrap assistant for the pre-database setup step.

The assistant is deliberately small. It can call :func:`get_setup_status`,
which returns the same sanitized state the anonymous status endpoint exposes,
and it may search the bundled project documentation through
:class:`itsm.project_context.ProjectContextService`. It has no database, no
domain data, no mutation and no persistent history: every run builds a new
agent from a server-resolved provider selection and is discarded afterwards.

Provider transport is the same guarded stack the API uses:
:func:`itsm.agent_integrations.providers.build_provider_model` over
:func:`~itsm.agent_integrations.providers.provider_http_client` with the
personal :class:`~itsm.agent_integrations.providers.ProviderNetworkPolicy`.
The setup process never generates a credential key; it only seals a key the
operator already supplied through ``ITSM_AI_CREDENTIAL_KEYS``.

A model answer is not proof of tool calling: a provider can complete a text
reply without ever dispatching a tool. The probe therefore reports success only
when the tool function itself ran during the turn.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic_ai import Agent, ModelSettings, UsageLimits
from pydantic_ai.exceptions import ModelAPIError, ModelHTTPError, UsageLimitExceeded

from itsm.agent_integrations.providers import (
    CredentialInvalid,
    CredentialUnavailable,
    ProviderAddressBlocked,
    ProviderEndpointError,
    ProviderModelSelection,
    ProviderNetworkPolicy,
    build_provider_model,
    credential_storage_available,
    discover_provider_models,
    ensure_endpoint_allowed,
    primary_fingerprint,
    provider_http_client,
    seal_credential,
    unseal_credential,
    validate_provider_endpoint,
)
from itsm.config import Settings, parse_personal_private_endpoints
from itsm.project_context import ProjectContextError, ProjectContextService
from itsm.setup.store import SetupSettings

TOOL_GET_SETUP_STATUS = "get_setup_status"
TOOL_SEARCH_PROJECT_DOCS = "search_project_docs"

PROBE_QUESTION = (
    "Call get_setup_status now and answer with the installation state it returns, in one "
    "short sentence."
)
PROBE_REQUEST_LIMIT = 3
PROBE_TOOL_CALLS_LIMIT = 2
PROBE_OUTPUT_TOKENS = 256
PROBE_TIMEOUT_SECONDS = 20.0

ASK_REQUEST_LIMIT = 4
ASK_TOOL_CALLS_LIMIT = 4
ASK_OUTPUT_TOKENS = 600
ASK_TIMEOUT_SECONDS = 30.0
MAX_QUESTION = 500
MAX_ANSWER = 2_000
MAX_TOOL_RESULT = 4_000

DIAGNOSTIC_PROVIDER_UNREACHABLE = "provider_unreachable"
DIAGNOSTIC_MODEL_WITHOUT_TOOLS = "model_without_tools"
DIAGNOSTIC_ENDPOINT_FORBIDDEN = "endpoint_forbidden"
DIAGNOSTIC_CREDENTIAL_MISSING = "credential_missing"
DIAGNOSTIC_CREDENTIAL_KEY_MISSING = "credential_key_missing"
DIAGNOSTIC_AUTH_FAILED = "auth_failed"
DIAGNOSTIC_TOOL_NOT_CALLED = "tool_not_called"

_PROBE_SYSTEM_PROMPT = (
    "You are the bootstrap assistant of a new installation. You have read-only setup "
    "tools. Call the tool you are asked to call; never invent an installation state."
)
_ASK_SYSTEM_PROMPT = (
    "You are the bootstrap assistant of a new installation. Answer only from the "
    "read-only setup tools and the bundled documentation. Never ask for or repeat "
    "credentials. Keep the answer under 120 words."
)

_DISCOVERY_DIAGNOSTICS: Mapping[str, str] = {
    "unauthorized": DIAGNOSTIC_AUTH_FAILED,
    "blocked_address": DIAGNOSTIC_ENDPOINT_FORBIDDEN,
    "timeout": DIAGNOSTIC_PROVIDER_UNREACHABLE,
    "unreachable": DIAGNOSTIC_PROVIDER_UNREACHABLE,
    "redirect": DIAGNOSTIC_PROVIDER_UNREACHABLE,
    "invalid_response": DIAGNOSTIC_PROVIDER_UNREACHABLE,
}

_docs_service: ProjectContextService | None = None


class AssistantError(Exception):
    """A closed, sanitized diagnostic for one provider or assistant operation."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class AssistantAnswer:
    """One bounded assistant turn; ``tools`` lists what actually executed."""

    answer: str
    tools: tuple[str, ...]
    latency_ms: int
    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass(frozen=True)
class ToolProbe:
    """Result of the verification turn: discovery count plus the tool evidence."""

    answer: str
    tools: tuple[str, ...]
    latency_ms: int
    discovered_models: int
    input_tokens: int | None
    output_tokens: int | None

    @property
    def tool_called(self) -> bool:
        return TOOL_GET_SETUP_STATUS in self.tools


def provider_settings(settings: SetupSettings) -> Settings:
    """Build the canonical ``Settings`` shape without opening a database.

    ``Settings`` only parses configuration; no engine is created and the
    database URL is an explicit inert SQLite path. The credential ring and the
    private-endpoint allowlist come from the setup process environment, exactly
    as the API process will receive them after bootstrap.
    """

    return Settings(
        database_url="sqlite://",
        ai_credential_keys=settings.ai_credential_keys,
        ai_credential_key=settings.ai_credential_key,
        ai_personal_private_endpoints=settings.ai_personal_private_endpoints,
    )


def endpoint_policy(settings: SetupSettings) -> ProviderNetworkPolicy:
    """The deployment allowlist for a personal provider, as configured."""

    return ProviderNetworkPolicy(
        allowlist=parse_personal_private_endpoints(settings.ai_personal_private_endpoints)
    )


def normalize_endpoint(base_url: str, policy: ProviderNetworkPolicy) -> str:
    """Validate shape, scheme and destination before any request is attempted."""

    try:
        normalized = validate_provider_endpoint(base_url, scope="personal", policy=policy)
        ensure_endpoint_allowed(normalized, policy)
    except (ProviderEndpointError, OSError) as exc:
        raise AssistantError(DIAGNOSTIC_ENDPOINT_FORBIDDEN) from exc
    return normalized


def seal_provider_key(settings: SetupSettings, api_key: str) -> str:
    """Seal a provider credential with the operator key ring, or fail closed."""

    try:
        return seal_credential(provider_settings(settings), api_key)
    except CredentialUnavailable as exc:
        raise AssistantError(DIAGNOSTIC_CREDENTIAL_KEY_MISSING) from exc


def unseal_provider_key(settings: SetupSettings, ciphertext: str) -> str:
    """Read back a stored provider credential for one assistant run."""

    try:
        return unseal_credential(provider_settings(settings), ciphertext)
    except (CredentialInvalid, CredentialUnavailable) as exc:
        raise AssistantError(DIAGNOSTIC_CREDENTIAL_MISSING) from exc


def storage_available(settings: SetupSettings) -> bool:
    return credential_storage_available(provider_settings(settings))


def key_fingerprint(settings: SetupSettings) -> str | None:
    return primary_fingerprint(provider_settings(settings))


def provider_host(normalized_base_url: str) -> str:
    """The sanitized provider host for a receipt; never userinfo or a path."""

    return urlsplit(normalized_base_url).hostname or ""


def _search_project_docs(query: str) -> str:
    """Search the bundled documentation; bounded and free of any domain data."""

    global _docs_service
    try:
        if _docs_service is None:
            _docs_service = ProjectContextService()
        result = _docs_service.search_project_docs(query[:200], limit=3)
    except ProjectContextError, OSError:
        return json.dumps({"error": "docs_unavailable"})
    payload = {
        "query": result.query,
        "total": result.total,
        "matches": [
            {"path": match.path, "section": match.section, "snippet": match.snippet}
            for match in result.matches
        ],
    }
    return json.dumps(payload, ensure_ascii=False)[:MAX_TOOL_RESULT]


class BootstrapAssistant:
    """One bounded, history-free assistant turn over read-only tools."""

    def __init__(
        self,
        model: object,
        *,
        status_reader: Callable[[], Mapping[str, Any]],
        timeout: float,
        request_limit: int,
        tool_calls_limit: int,
        output_tokens: int,
        system_prompt: str,
    ) -> None:
        self._model = model
        self._status_reader = status_reader
        self._timeout = timeout
        self._request_limit = request_limit
        self._tool_calls_limit = tool_calls_limit
        self._output_tokens = output_tokens
        self._system_prompt = system_prompt

    def _agent(self, called: list[str]) -> Agent[None, str]:
        def get_setup_status() -> str:
            """Read the sanitized installation status: state, mode and pending items."""

            called.append(TOOL_GET_SETUP_STATUS)
            return json.dumps(dict(self._status_reader()), sort_keys=True)[:MAX_TOOL_RESULT]

        def search_project_docs(query: str) -> str:
            """Search the bundled product documentation for setup and operations facts."""

            called.append(TOOL_SEARCH_PROJECT_DOCS)
            return _search_project_docs(query)

        return Agent(
            self._model,
            output_type=str,
            tools=[get_setup_status, search_project_docs],
            system_prompt=self._system_prompt,
        )

    async def run(self, prompt: str) -> AssistantAnswer:
        called: list[str] = []
        agent = self._agent(called)
        limits = UsageLimits(
            request_limit=self._request_limit,
            tool_calls_limit=self._tool_calls_limit,
            output_tokens_limit=self._output_tokens,
        )
        started = time.perf_counter()
        try:
            result = await asyncio.wait_for(
                agent.run(
                    prompt[:MAX_QUESTION],
                    usage_limits=limits,
                    model_settings=ModelSettings(
                        max_tokens=self._output_tokens,
                        temperature=0,
                    ),
                ),
                timeout=self._timeout,
            )
        except AssistantError:
            raise
        except Exception as exc:
            raise AssistantError(diagnostic_for(exc)) from exc
        usage = result.usage
        return AssistantAnswer(
            answer=str(result.output).strip()[:MAX_ANSWER],
            tools=tuple(called),
            latency_ms=int((time.perf_counter() - started) * 1000),
            input_tokens=usage.input_tokens or None,
            output_tokens=usage.output_tokens or None,
        )


def _blocked_destination(exc: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, ProviderAddressBlocked):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


def _mentions_tools(body: object) -> bool:
    try:
        text = json.dumps(body, default=str).lower()
    except TypeError, ValueError:
        text = str(body).lower()
    return "tool" in text or "function" in text


def diagnostic_for(exc: BaseException) -> str:
    """Map an exception to one closed diagnostic; never echo upstream text."""

    if isinstance(exc, AssistantError):
        return exc.code
    if isinstance(exc, TimeoutError):
        return DIAGNOSTIC_PROVIDER_UNREACHABLE
    if _blocked_destination(exc):
        return DIAGNOSTIC_ENDPOINT_FORBIDDEN
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, ModelHTTPError):
            if current.status_code in {401, 403}:
                return DIAGNOSTIC_AUTH_FAILED
            if current.status_code in {400, 404, 405, 422} and _mentions_tools(current.body):
                return DIAGNOSTIC_MODEL_WITHOUT_TOOLS
            return DIAGNOSTIC_PROVIDER_UNREACHABLE
        if isinstance(current, (httpx.HTTPError, OSError)):
            return DIAGNOSTIC_PROVIDER_UNREACHABLE
        if isinstance(current, (UsageLimitExceeded, ModelAPIError)):
            return DIAGNOSTIC_TOOL_NOT_CALLED
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return DIAGNOSTIC_PROVIDER_UNREACHABLE


async def _with_client(
    selection: ProviderModelSelection,
    policy: ProviderNetworkPolicy,
    timeout: float,
    operation: Callable[[Any], Any],
) -> Any:
    client = provider_http_client(policy=policy, timeout=timeout)
    try:
        model = build_provider_model(selection, http_client=client)
        return await operation(model)
    finally:
        await client.aclose()


async def probe_provider(
    *,
    settings: SetupSettings,
    base_url: str,
    model: str,
    api_key: str,
    status_reader: Callable[[], Mapping[str, Any]],
    timeout: float = PROBE_TIMEOUT_SECONDS,
) -> ToolProbe:
    """Discover the model list, then prove one real ``get_setup_status`` call."""

    policy = endpoint_policy(settings)
    discovery = await discover_provider_models(
        base_url,
        api_key,
        allow_private=policy,
        timeout=min(timeout, 10.0),
    )
    if discovery.code != "ok":
        raise AssistantError(
            _DISCOVERY_DIAGNOSTICS.get(discovery.code, DIAGNOSTIC_PROVIDER_UNREACHABLE)
        )
    if not discovery.models:
        raise AssistantError(DIAGNOSTIC_PROVIDER_UNREACHABLE)

    selection = ProviderModelSelection(
        base_url=base_url,
        model=model,
        api_key=api_key,
        allow_private=policy,
    )

    async def run(model_object: Any) -> AssistantAnswer:
        assistant = BootstrapAssistant(
            model_object,
            status_reader=status_reader,
            timeout=timeout,
            request_limit=PROBE_REQUEST_LIMIT,
            tool_calls_limit=PROBE_TOOL_CALLS_LIMIT,
            output_tokens=PROBE_OUTPUT_TOKENS,
            system_prompt=_PROBE_SYSTEM_PROMPT,
        )
        answer = await assistant.run(PROBE_QUESTION)
        if TOOL_GET_SETUP_STATUS not in answer.tools:
            raise AssistantError(DIAGNOSTIC_TOOL_NOT_CALLED)
        return answer

    answer = await _with_client(selection, policy, timeout, run)
    return ToolProbe(
        answer=answer.answer,
        tools=answer.tools,
        latency_ms=answer.latency_ms,
        discovered_models=discovery.count,
        input_tokens=answer.input_tokens,
        output_tokens=answer.output_tokens,
    )


async def ask_provider(
    *,
    settings: SetupSettings,
    base_url: str,
    model: str,
    api_key: str,
    question: str,
    status_reader: Callable[[], Mapping[str, Any]],
    timeout: float = ASK_TIMEOUT_SECONDS,
) -> AssistantAnswer:
    """One bounded question answered from the read-only tools; no history kept."""

    policy = endpoint_policy(settings)
    selection = ProviderModelSelection(
        base_url=base_url,
        model=model,
        api_key=api_key,
        allow_private=policy,
    )

    async def run(model_object: Any) -> AssistantAnswer:
        assistant = BootstrapAssistant(
            model_object,
            status_reader=status_reader,
            timeout=timeout,
            request_limit=ASK_REQUEST_LIMIT,
            tool_calls_limit=ASK_TOOL_CALLS_LIMIT,
            output_tokens=ASK_OUTPUT_TOKENS,
            system_prompt=_ASK_SYSTEM_PROMPT,
        )
        return await assistant.run(question)

    return await _with_client(selection, policy, timeout, run)


__all__ = [
    "DIAGNOSTIC_AUTH_FAILED",
    "DIAGNOSTIC_CREDENTIAL_KEY_MISSING",
    "DIAGNOSTIC_CREDENTIAL_MISSING",
    "DIAGNOSTIC_ENDPOINT_FORBIDDEN",
    "DIAGNOSTIC_MODEL_WITHOUT_TOOLS",
    "DIAGNOSTIC_PROVIDER_UNREACHABLE",
    "DIAGNOSTIC_TOOL_NOT_CALLED",
    "TOOL_GET_SETUP_STATUS",
    "TOOL_SEARCH_PROJECT_DOCS",
    "AssistantAnswer",
    "AssistantError",
    "BootstrapAssistant",
    "ToolProbe",
    "ask_provider",
    "diagnostic_for",
    "endpoint_policy",
    "key_fingerprint",
    "normalize_endpoint",
    "probe_provider",
    "provider_host",
    "provider_settings",
    "seal_provider_key",
    "storage_available",
    "unseal_provider_key",
]
