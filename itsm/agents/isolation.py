"""Isolated Pydantic AI execution for ordinary human roles.

Only an active persisted human ``admin`` or ``superadmin`` may run the agent in
the API process. Every other human runs inference inside a hardened container
owned by a separate host broker; the API keeps the canonical tool inventory and
executes tool calls under the requesting principal, so container compromise does
not grant business authorization.

The broker is the only component with container authority. This module never
accepts an image, command, mount, network or principal from a model or browser
message: the broker derives them from its own server-side configuration, and a
tool call can only name one of the canonical tools advertised by the API.

Wire formats are deliberately strict (``extra="forbid"``) and bounded. The API
side is a synchronous client because the conversational runtime it replaces is
synchronous and already runs in a worker thread.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final, Literal
from uuid import UUID

from itsm.agent_integrations.attachments import ChatAttachmentInput
from itsm.agent_integrations.providers import ProviderModelSelection
from itsm.agents import locales as agent_locales
from itsm.agents.runtime import (
    AgentDeps,
    AgentUnavailable,
    AgentUsage,
    ChatReply,
    ChatRequest,
    build_toolset,
)
from itsm.ai_usage import QuotaExceeded
from itsm.config import Settings
from itsm.identity.permissions import HUMAN_ACTOR_KIND, ROLE_ADMIN, ROLE_SUPERADMIN
from itsm.identity.service import IdentityService, Principal
from itsm.system.providers import effective_selection
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from pydantic.alias_generators import to_camel
from pydantic_ai import RunContext
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.toolsets.function import FunctionToolset, FunctionToolsetTool
from pydantic_ai.usage import RunUsage
from sqlalchemy.orm import Session

logger = logging.getLogger("itsm.agent.isolation")

PRIVILEGED_ROLES: Final[frozenset[str]] = frozenset({ROLE_ADMIN, ROLE_SUPERADMIN})

_RUN_TIMEOUT_SECONDS: Final[int] = 180
#: Bounded protocol frame. Enough for one message's base64 attachments (at most
#: four files of the documented chat ceiling) plus tools and instructions.
_MAX_MESSAGE_BYTES: Final[int] = 8 * 1024 * 1024
_MAX_TOOL_RESULT_BYTES: Final[int] = 48 * 1024
_MAX_TOOLS: Final[int] = 100
_UNAVAILABLE: Final[str] = "the isolated agent runtime is unavailable"


class IsolationUnavailable(Exception):
    """The authenticated broker or its bounded protocol cannot serve the turn."""


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        alias_generator=to_camel,
        populate_by_name=True,
    )


class ProviderSpec(_Strict):
    """Server-resolved inference destination; the only URL in the protocol."""

    kind: Literal["openai", "anthropic", "openai-compatible"]
    model: str = Field(min_length=1, max_length=200)
    base_url: str | None = Field(default=None, max_length=2048)
    api_key: str | None = Field(default=None, max_length=8192)
    allow_private: bool = False
    # Deployment-authorized private destinations travel as data: the broker only
    # relays them, and the worker re-applies the same resolution policy.
    private_allowlist: list[str] = Field(default_factory=list, max_length=64)

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized.startswith(("http://", "https://")):
            raise ValueError("provider baseUrl must use http or https")
        return normalized


class HistoryMessage(_Strict):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=8000)


class RunAttachment(_Strict):
    """One stored attachment relayed to the worker as base64 bytes, never a URL."""

    filename: str = Field(min_length=1, max_length=180)
    media_type: str = Field(min_length=1, max_length=120)
    kind: Literal["image", "file", "text"]
    data: str = Field(min_length=1, max_length=6_000_000)


class ToolSchema(_Strict):
    name: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_]*$")
    description: str = Field(default="", max_length=4000)
    parameters: dict[str, Any] = Field(default_factory=dict)


class RunStart(_Strict):
    """One bounded inference request the broker may launch a container for."""

    type: Literal["run.start"] = "run.start"
    run_id: str = Field(min_length=36, max_length=36)
    user_id: str = Field(min_length=36, max_length=36)
    timeout_seconds: int = Field(default=_RUN_TIMEOUT_SECONDS, ge=1, le=900)
    provider: ProviderSpec
    instructions: str = Field(max_length=12000)
    prompt: str = Field(default="", max_length=20000)
    attachments: list[RunAttachment] = Field(default_factory=list, max_length=4)
    history: list[HistoryMessage] = Field(default_factory=list, max_length=50)
    tools: list[ToolSchema] = Field(default_factory=list, max_length=_MAX_TOOLS)
    max_steps: int = Field(default=8, ge=1, le=20)
    max_output_tokens: int = Field(default=1024, ge=1, le=8192)
    token_limit: int | None = Field(default=None, ge=0, le=1_000_000)
    quota_enabled: bool = False
    context_token_bound: int | None = Field(default=None, ge=1, le=100_000_000)

    @field_validator("run_id", "user_id")
    @classmethod
    def _validate_uuid(cls, value: str) -> str:
        try:
            UUID(value)
        except ValueError:
            raise ValueError("identifier must be a UUID") from None
        return value

    @model_validator(mode="after")
    def _require_content(self) -> RunStart:
        if not self.prompt.strip() and not self.attachments:
            raise ValueError("prompt or at least one attachment is required")
        return self


class WorkerReady(_Strict):
    type: Literal["ready"] = "ready"


class WorkerUsage(_Strict):
    type: Literal["usage"] = "usage"
    input_tokens: int = Field(default=0, ge=0, le=10_000_000)
    output_tokens: int = Field(default=0, ge=0, le=10_000_000)


class WorkerQuotaCall(_Strict):
    type: Literal["quota.call"] = "quota.call"
    call_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    phase: Literal["reserve", "settle"]
    evidence: dict[str, Any] | None = None


class QuotaResult(_Strict):
    type: Literal["quota.result"] = "quota.result"
    call_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    ok: bool


class WorkerToolCall(_Strict):
    type: Literal["tool.call"] = "tool.call"
    call_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    name: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict[str, Any] = Field(default_factory=dict)


class WorkerFinal(_Strict):
    type: Literal["final"] = "final"
    message: str = Field(min_length=1, max_length=20000)


class WorkerError(_Strict):
    type: Literal["error"] = "error"
    code: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    message: str = Field(default="", max_length=1000)


class ToolResult(_Strict):
    type: Literal["tool.result"] = "tool.result"
    call_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    ok: bool
    result: dict[str, Any] = Field(default_factory=dict)


def is_privileged_human(db: Session, settings: Settings, principal: Principal) -> bool:
    """True only for a currently persisted, active human admin/superadmin.

    The transport principal is never trusted for the role itself: the persisted
    identity is reloaded and a deactivated or downgraded account loses access on
    its next request, even with an existing authenticated browser session.
    """
    # A bearer ceiling never delegates the owner's ambient runtime privilege.
    if principal.kind != HUMAN_ACTOR_KIND or principal.api_key_id or principal.scopes:
        return False
    actor = IdentityService(db, settings).resolve_actor(principal.actor_id)
    return actor.kind == HUMAN_ACTOR_KIND and actor.role_id in PRIVILEGED_ROLES


def _uuid_text(value: str | None, label: str) -> str:
    if value is None:
        raise IsolationUnavailable(f"{label} is not available")
    try:
        UUID(value)
    except ValueError:
        raise IsolationUnavailable(f"{label} is not a valid identifier") from None
    return value


def _json_line(payload: BaseModel) -> str:
    return payload.model_dump_json(by_alias=True, exclude_none=True)


def _bounded_json(payload: Any, limit: int) -> bool:
    try:
        return len(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")) <= limit
    except TypeError, ValueError:
        return False


def _history(request: ChatRequest) -> list[HistoryMessage]:
    return [HistoryMessage(role=turn.role, content=turn.content) for turn in request.conversation]


def _provider_spec(
    settings: Settings,
    session_factory: Callable[[], Session],
    provider_selection: ProviderModelSelection | None,
) -> ProviderSpec:
    if provider_selection is not None:
        policy = provider_selection.allow_private
        return ProviderSpec(
            kind="openai-compatible",
            model=provider_selection.model,
            base_url=provider_selection.base_url,
            api_key=provider_selection.api_key,
            allow_private=policy is True,
            private_allowlist=[entry.describe() for entry in getattr(policy, "allowlist", ())],
        )
    with session_factory() as db:
        selection = effective_selection(db, settings)
    if selection is None:
        raise AgentUnavailable()
    if selection.provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY")
        base_url = settings.agent_openai_base_url
    elif selection.provider == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")
        base_url = None
    else:
        raise AgentUnavailable()
    if not api_key:
        raise AgentUnavailable()
    return ProviderSpec(
        kind=selection.provider,
        model=selection.model,
        base_url=base_url,
        api_key=api_key,
    )


@dataclass(frozen=True)
class _PreparedTools:
    toolset: FunctionToolset[AgentDeps]
    context: RunContext[AgentDeps]
    tools: dict[str, Any]
    schemas: list[ToolSchema]


def _attachment_spec(item: ChatAttachmentInput) -> RunAttachment:
    """Relay stored bytes as base64; no path, URL or digest leaves this process."""

    import base64

    return RunAttachment(
        filename=item.filename,
        media_type=item.media_type,
        kind=item.kind,
        data=base64.b64encode(item.data).decode("ascii"),
    )


def _never_model(messages: Any, info: Any) -> Any:  # pragma: no cover - never called
    raise IsolationUnavailable(_UNAVAILABLE)


class IsolatedRuntime:
    """Broker-backed runtime with the same envelope as :class:`AgentRuntime`."""

    def __init__(
        self,
        settings: Settings,
        session_factory: Callable[[], Session],
        *,
        system: Any = None,
        connect: Callable[..., Any] | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._system = system
        self._connect = connect

    @property
    def configured(self) -> bool:
        return bool(self._settings.ai_broker_url and self._settings.ai_broker_token)

    async def aclose(self) -> None:
        """Parity with ``AgentRuntime``; the broker owns all transport cleanup."""

    def chat(
        self,
        principal: Principal,
        request: ChatRequest,
        *,
        credential_digest: str | None = None,
        provider_selection: ProviderModelSelection | None = None,
        locale: str | None = None,
    ) -> ChatReply:
        reply, _ = self.chat_with_usage(
            principal,
            request,
            credential_digest=credential_digest,
            provider_selection=provider_selection,
            locale=locale,
        )
        return reply

    def chat_with_usage(
        self,
        principal: Principal,
        request: ChatRequest,
        *,
        credential_digest: str | None = None,
        usage: AgentUsage | None = None,
        token_limit: int | None = None,
        provider_selection: ProviderModelSelection | None = None,
        quota: Any = None,
        locale: str | None = None,
    ) -> tuple[ChatReply, AgentUsage]:
        if not self.configured:
            raise IsolationUnavailable(_UNAVAILABLE)
        provider = _provider_spec(self._settings, self._session_factory, provider_selection)
        deps = AgentDeps(
            settings=self._settings,
            session_factory=self._session_factory,
            principal=principal,
            credential_digest=credential_digest,
            system=self._system,
            locale=locale,
        )
        prepared = self._prepare_tools(deps, locale)
        prompt = request.message
        if request.assetId:
            marker = f"Activo seleccionado: {request.assetId}"
            prompt = f"{prompt}\n\n{marker}" if prompt else marker
        start = RunStart(
            run_id=(quota.reservation.run_id if quota is not None else str(uuid.uuid4())),
            user_id=_uuid_text(principal.actor_id, "principal"),
            timeout_seconds=_run_timeout(self._settings),
            provider=provider,
            instructions=agent_locales.instructions(locale),
            prompt=prompt,
            attachments=[_attachment_spec(item) for item in request.attachments],
            history=_history(request),
            tools=prepared.schemas,
            max_steps=self._settings.agent_max_steps,
            max_output_tokens=self._settings.agent_max_output_tokens,
            token_limit=token_limit,
            quota_enabled=quota is not None,
            context_token_bound=self._settings.agent_context_token_bound,
        )
        measured = self._exchange(start, prepared, deps, quota=quota)
        tokens = usage if usage is not None else AgentUsage()
        tokens.input_tokens = measured[0]
        tokens.output_tokens = measured[1]
        message = measured[2].strip() or "No pude completar la solicitud."
        return (
            ChatReply(
                message=message[:4000],
                actions=deps.actions,
                results=deps.results,
                approvalPending=deps.approval_pending,
            ),
            tokens,
        )

    def _prepare_tools(self, deps: AgentDeps, locale: str | None = None) -> _PreparedTools:
        toolset = build_toolset(locale)
        context: RunContext[AgentDeps] = RunContext(
            deps=deps,
            model=FunctionModel(_never_model, model_name="itsm-toolset"),
            usage=RunUsage(),
        )
        tools = asyncio.run(toolset.get_tools(context))
        schemas: list[ToolSchema] = []
        for name, tool in tools.items():
            definition = tool.tool_def
            parameters = definition.parameters_json_schema
            if not isinstance(parameters, dict):
                raise IsolationUnavailable(_UNAVAILABLE)
            schema = ToolSchema(
                name=name,
                description=definition.description or "",
                parameters=parameters,
            )
            if not _bounded_json(schema.parameters, _MAX_TOOL_RESULT_BYTES):
                raise IsolationUnavailable(_UNAVAILABLE)
            schemas.append(schema)
        if len(schemas) > _MAX_TOOLS:
            raise IsolationUnavailable(_UNAVAILABLE)
        return _PreparedTools(toolset=toolset, context=context, tools=tools, schemas=schemas)

    def _exchange(
        self,
        start: RunStart,
        prepared: _PreparedTools,
        deps: AgentDeps,
        *,
        quota: Any = None,
    ) -> tuple[int, int, str]:
        from websockets.sync.client import connect

        connector = self._connect or connect
        url = self._settings.ai_broker_url
        token = self._settings.ai_broker_token
        if url is None or token is None:
            raise IsolationUnavailable(_UNAVAILABLE)
        deadline = _run_timeout(self._settings) + 10
        input_tokens = 0
        output_tokens = 0
        quota_calls: dict[str, str] = {}
        try:
            with connector(
                url,
                additional_headers={"Authorization": f"Bearer {token.get_secret_value()}"},
                open_timeout=min(10, deadline),
                close_timeout=2,
                max_size=_MAX_MESSAGE_BYTES,
                compression=None,
                proxy=None,
            ) as socket:
                socket.send(_json_line(start))
                while True:
                    raw = socket.recv(timeout=deadline)
                    if isinstance(raw, bytes):
                        raise IsolationUnavailable(_UNAVAILABLE)
                    if len(raw.encode("utf-8")) > _MAX_MESSAGE_BYTES:
                        raise IsolationUnavailable(_UNAVAILABLE)
                    message = _worker_message(raw)
                    if isinstance(message, WorkerReady):
                        continue
                    if isinstance(message, WorkerUsage):
                        input_tokens += message.input_tokens
                        output_tokens += message.output_tokens
                        continue
                    if isinstance(message, WorkerQuotaCall):
                        if quota is None:
                            raise IsolationUnavailable(_UNAVAILABLE)
                        if message.phase == "reserve":
                            if (
                                message.call_id in quota_calls
                                or len(quota_calls) >= start.max_steps
                            ):
                                raise IsolationUnavailable(_UNAVAILABLE)
                            try:
                                identifier = quota.before_call(
                                    (self._settings.agent_context_token_bound or 0)
                                    + self._settings.agent_max_output_tokens
                                )
                            except Exception as exc:
                                if not isinstance(exc, QuotaExceeded):
                                    raise
                                socket.send(
                                    _json_line(QuotaResult(call_id=message.call_id, ok=False))
                                )
                                raise
                            quota_calls[message.call_id] = identifier
                        else:
                            identifier = quota_calls.get(message.call_id)
                            if identifier is None or message.evidence is None:
                                raise IsolationUnavailable(_UNAVAILABLE)
                            quota.after_call(identifier, message.evidence)
                        socket.send(_json_line(QuotaResult(call_id=message.call_id, ok=True)))
                        continue
                    if isinstance(message, WorkerToolCall):
                        socket.send(_json_line(self._tool_result(message, prepared)))
                        continue
                    if isinstance(message, WorkerFinal):
                        return input_tokens, output_tokens, message.message
                    if isinstance(message, WorkerError):
                        raise IsolationUnavailable(_UNAVAILABLE)
                    raise IsolationUnavailable(_UNAVAILABLE)
        except QuotaExceeded:
            raise
        except IsolationUnavailable:
            raise
        except TimeoutError, OSError:
            raise IsolationUnavailable(_UNAVAILABLE) from None
        except Exception:
            logger.warning("isolated agent transport failed")
            raise IsolationUnavailable(_UNAVAILABLE) from None

    def _tool_result(self, call: WorkerToolCall, prepared: _PreparedTools) -> ToolResult:
        tool = prepared.tools.get(call.name)
        if tool is None:
            return ToolResult(call_id=call.call_id, ok=False)
        schema = getattr(tool.tool_def, "parameters_json_schema", None)
        allowed = set(schema.get("properties", {})) if isinstance(schema, dict) else set()
        if not set(call.arguments).issubset(allowed):
            return ToolResult(call_id=call.call_id, ok=False)
        if not _bounded_json(call.arguments, _MAX_TOOL_RESULT_BYTES):
            return ToolResult(call_id=call.call_id, ok=False)
        if not isinstance(tool, FunctionToolsetTool):  # defensive: canonical builder only
            return ToolResult(call_id=call.call_id, ok=False)
        try:
            arguments = tool.args_validator.validate_python(
                call.arguments, context=prepared.context.validation_context
            )
        except ValidationError:
            return ToolResult(call_id=call.call_id, ok=False)
        try:
            result = asyncio.run(
                prepared.toolset.call_tool(call.name, arguments, prepared.context, tool)
            )
        except Exception:
            logger.warning("isolated agent tool failed")
            return ToolResult(call_id=call.call_id, ok=False)
        if not isinstance(result, dict):
            result = {"ok": False}
        if not _bounded_json(result, _MAX_TOOL_RESULT_BYTES):
            result = {"ok": False}
        return ToolResult(
            call_id=call.call_id,
            ok=bool(result.get("ok")),
            result=result,
        )


def _worker_message(raw: str) -> Any:
    try:
        payload = json.loads(raw)
    except TypeError, ValueError:
        raise IsolationUnavailable(_UNAVAILABLE) from None
    if not isinstance(payload, dict):
        raise IsolationUnavailable(_UNAVAILABLE)
    kind = payload.get("type")
    model = {
        "ready": WorkerReady,
        "usage": WorkerUsage,
        "tool.call": WorkerToolCall,
        "quota.call": WorkerQuotaCall,
        "final": WorkerFinal,
        "error": WorkerError,
    }.get(kind)
    if model is None:
        raise IsolationUnavailable(_UNAVAILABLE)
    try:
        return model.model_validate(payload)
    except ValidationError:
        raise IsolationUnavailable(_UNAVAILABLE) from None


def _run_timeout(settings: Settings) -> int:
    return max(1, min(int(settings.agent_run_timeout_seconds), 900))


def runs_in_isolation(db: Session, settings: Settings, principal: Principal) -> bool:
    """Ordinary human roles must use the broker; privileged humans stay in-process."""
    return not is_privileged_human(db, settings, principal)


__all__ = [
    "PRIVILEGED_ROLES",
    "IsolatedRuntime",
    "IsolationUnavailable",
    "ProviderSpec",
    "RunStart",
    "ToolResult",
    "WorkerError",
    "WorkerFinal",
    "WorkerReady",
    "WorkerToolCall",
    "WorkerUsage",
    "is_privileged_human",
    "runs_in_isolation",
]
