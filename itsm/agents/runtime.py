"""Conversational inventory assistant built on a real Pydantic AI agent.

The agent is deliberately narrow: five typed inventory tools over the canonical
service, a server-configured provider/model and bounded steps, history, input
and output. It has no shell, SQL, filesystem or HTTP tool, and untrusted chat
text cannot grant permissions or supply a principal.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Literal

from itsm.config import Settings
from itsm.identity.service import (
    Conflict,
    IdentityError,
    NotFound,
    PermissionDenied,
    Principal,
    ValidationFailed,
)
from itsm.inventory.service import (
    AssetView,
    BatchResult,
    InventoryPage,
    InventoryService,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic_ai import Agent, RunContext
from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    TextPart,
    UserPromptPart,
)
from pydantic_ai.models import Model
from pydantic_ai.settings import ModelSettings
from pydantic_ai.usage import UsageLimits
from sqlalchemy.orm import Session

logger = logging.getLogger("itsm.agent")

TOOL_NAMES: tuple[str, ...] = (
    "search_assets",
    "get_asset",
    "create_asset",
    "update_asset",
    "batch_update_assets",
)
MAX_RESULTS = 50

INSTRUCTIONS = """\
Sos el asistente de inventario del ITSM. Respondés en español, de forma breve y factual.

Reglas:
- Usá solamente las herramientas de inventario disponibles; no inventes activos,
  identificadores, sitios ni responsables.
- Si falta el activo o un dato necesario para modificar algo, preguntá cuál es;
  nunca elijas un activo por suposición.
- El código rápido (quickCode) identifica al activo pero puede cambiar; el id
  permanente nunca cambia.
- No afirmes permisos que no ejercitaste: si una herramienta devuelve un error de
  permiso, explicalo sin inventar alternativas.
- No menciones detalles internos de configuración, tokens ni rutas del servidor.
"""


class AgentUnavailable(Exception):
    """No provider/model configuration is available for the agent."""


class ConversationTurn(BaseModel):
    """Client-supplied history; only human turns are accepted."""

    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=8000)


class ChatRequest(BaseModel):
    """Bounded browser request; no model, tools, principal or permissions."""

    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=8000)
    conversation: list[ConversationTurn] = Field(default_factory=list, max_length=50)
    assetId: str | None = Field(default=None, max_length=36)

    @field_validator("assetId")
    @classmethod
    def _validate_asset_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            from uuid import UUID

            UUID(value)
        except ValueError:
            raise ValueError("assetId must be a UUID") from None
        return value


class ChatAction(BaseModel):
    """One executed (or refused) tool call, compact enough for the chat UI."""

    tool: str
    status: Literal["completed", "failed", "denied"]
    assetIds: list[str] = Field(default_factory=list)


class ChatReply(BaseModel):
    """Stable chat envelope announced to the frontend."""

    message: str
    actions: list[ChatAction] = Field(default_factory=list)
    results: list[dict[str, Any]] = Field(default_factory=list)
    approvalPending: bool = False


@dataclass
class AgentDeps:
    """Trusted execution context: the principal comes from the transport."""

    settings: Settings
    session_factory: Callable[[], Session]
    principal: Principal
    actions: list[ChatAction] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)


class BatchUpdateArg(BaseModel):
    """Narrow typed input for the batch tool."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str
    name: str | None = None
    quick_code: str | None = None
    category: str | None = None
    type: str | None = None
    brand: str | None = None
    model: str | None = None
    serial: str | None = None
    ip: str | None = None
    site: str | None = None
    location: str | None = None
    responsible: str | None = None
    status: str | None = None
    description: str | None = None


@contextmanager
def _service(deps: AgentDeps) -> Iterator[InventoryService]:
    session = deps.session_factory()
    try:
        yield InventoryService(session, deps.settings)
    finally:
        session.close()


def _record(
    deps: AgentDeps,
    tool: str,
    status: Literal["completed", "failed", "denied"],
    views: tuple[AssetView, ...] = (),
) -> None:
    deps.actions.append(ChatAction(tool=tool, status=status, assetIds=[view.id for view in views]))
    for view in views:
        if len(deps.results) < MAX_RESULTS:
            deps.results.append(view.as_payload())


def _failure(
    deps: AgentDeps, tool: str, status: Literal["failed", "denied"], message: str
) -> dict[str, Any]:
    _record(deps, tool, status)
    return {"ok": False, "message": message}


def _execute(
    deps: AgentDeps,
    tool: str,
    operation: Callable[[InventoryService], Any],
) -> dict[str, Any]:
    """Run one tool through the canonical service and record a compact action."""
    try:
        with _service(deps) as inventory:
            result = operation(inventory)
    except PermissionDenied:
        return _failure(deps, tool, "denied", "La identidad no tiene permiso para esta operación.")
    except Conflict as exc:
        return _failure(deps, tool, "failed", str(exc))
    except NotFound as exc:
        return _failure(deps, tool, "failed", str(exc))
    except ValidationFailed as exc:
        return _failure(deps, tool, "failed", str(exc))
    except IdentityError as exc:  # pragma: no cover - defensive, still factual
        logger.warning("agent tool identity error", exc_info=exc)
        return _failure(deps, tool, "failed", "La operación no pudo completarse.")

    if isinstance(result, AssetView):
        _record(deps, tool, "completed", (result,))
        return {"ok": True, "asset": result.as_payload()}
    if isinstance(result, InventoryPage):
        _record(deps, tool, "completed", result.items)
        return {
            "ok": True,
            "total": result.total,
            "items": [item.as_payload() for item in result.items],
        }
    if isinstance(result, BatchResult):
        _record(deps, tool, "completed", result.created + result.updated)
        return {
            "ok": True,
            "created": [item.as_payload() for item in result.created],
            "updated": [item.as_payload() for item in result.updated],
        }
    return {"ok": True, "result": result}


def _register_tools(agent: Agent[AgentDeps, str]) -> None:
    @agent.tool
    def search_assets(
        ctx: RunContext[AgentDeps],
        query: str | None = None,
        category: str | None = None,
        site: str | None = None,
        status: str | None = None,
        quick_code: str | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        """Buscar activos por texto, categoría, sede, estado o código rápido."""
        return _execute(
            ctx.deps,
            "search_assets",
            lambda inventory: inventory.search(
                ctx.deps.principal,
                query=query,
                category=category,
                site=site,
                status=status,
                quick_code=quick_code,
                limit=limit,
            ),
        )

    @agent.tool
    def get_asset(ctx: RunContext[AgentDeps], asset_id: str) -> dict[str, Any]:
        """Consultar el detalle de un activo por su id permanente."""
        return _execute(
            ctx.deps,
            "get_asset",
            lambda inventory: inventory.get(ctx.deps.principal, asset_id),
        )

    @agent.tool
    def create_asset(
        ctx: RunContext[AgentDeps],
        name: str,
        quick_code: str | None = None,
        category: str | None = None,
        type: str | None = None,
        brand: str | None = None,
        model: str | None = None,
        serial: str | None = None,
        ip: str | None = None,
        site: str | None = None,
        location: str | None = None,
        responsible: str | None = None,
        status: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Registrar un activo nuevo con los datos que aportó la persona."""
        values = {
            "name": name,
            "quick_code": quick_code,
            "category": category,
            "type": type,
            "brand": brand,
            "model": model,
            "serial": serial,
            "ip": ip,
            "site": site,
            "location": location,
            "responsible": responsible,
            "status": status,
            "description": description,
        }
        return _execute(
            ctx.deps,
            "create_asset",
            lambda inventory: inventory.create(
                ctx.deps.principal,
                {key: value for key, value in values.items() if value is not None},
            ),
        )

    @agent.tool
    def update_asset(
        ctx: RunContext[AgentDeps],
        asset_id: str,
        name: str | None = None,
        quick_code: str | None = None,
        category: str | None = None,
        type: str | None = None,
        brand: str | None = None,
        model: str | None = None,
        serial: str | None = None,
        ip: str | None = None,
        site: str | None = None,
        location: str | None = None,
        responsible: str | None = None,
        status: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Actualizar campos concretos de un activo existente; nunca su id."""
        values = {
            "name": name,
            "quick_code": quick_code,
            "category": category,
            "type": type,
            "brand": brand,
            "model": model,
            "serial": serial,
            "ip": ip,
            "site": site,
            "location": location,
            "responsible": responsible,
            "status": status,
            "description": description,
        }
        changes = {key: value for key, value in values.items() if value is not None}
        return _execute(
            ctx.deps,
            "update_asset",
            lambda inventory: inventory.update(ctx.deps.principal, asset_id, changes),
        )

    @agent.tool
    def batch_update_assets(
        ctx: RunContext[AgentDeps], updates: list[BatchUpdateArg]
    ) -> dict[str, Any]:
        """Actualizar varios activos en una sola operación atómica y acotada."""
        changes = []
        for item in updates:
            payload = item.model_dump(exclude_none=True)
            asset_id = payload.pop("asset_id")
            changes.append({"id": asset_id, **payload})
        return _execute(
            ctx.deps,
            "batch_update_assets",
            lambda inventory: inventory.batch(ctx.deps.principal, update=changes),
        )


def resolve_model(settings: Settings) -> Model:
    """Build the configured provider/model; credentials come from the environment."""
    provider_name, _, model_name = settings.agent_model.partition(":")
    if provider_name == "openai":
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.providers.openai import OpenAIProvider

        provider = OpenAIProvider(base_url=settings.agent_openai_base_url)
        return OpenAIChatModel(model_name, provider=provider)
    if provider_name == "anthropic":
        from pydantic_ai.models.anthropic import AnthropicModel
        from pydantic_ai.providers.anthropic import AnthropicProvider

        return AnthropicModel(model_name, provider=AnthropicProvider())
    raise AgentUnavailable()


def _history(conversation: list[ConversationTurn]) -> list[ModelMessage]:
    history: list[ModelMessage] = []
    for turn in conversation:
        if turn.role == "user":
            history.append(ModelRequest(parts=[UserPromptPart(content=turn.content)]))
        else:
            history.append(ModelResponse(parts=[TextPart(content=turn.content)]))
    return history


class AgentRuntime:
    """Lazily built agent bound to one settings snapshot and session factory."""

    def __init__(
        self,
        settings: Settings,
        session_factory: Callable[[], Session],
        *,
        model: Model | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._model = model
        self._agent: Agent[AgentDeps, str] | None = None

    @property
    def configured(self) -> bool:
        return self._model is not None or bool(self._settings.agent_model)

    def _build(self) -> Agent[AgentDeps, str]:
        model = self._model
        if model is None:
            if not self._settings.agent_model:
                raise AgentUnavailable()
            try:
                model = resolve_model(self._settings)
            except AgentUnavailable:
                raise
            except Exception as exc:  # provider construction must stay explicit
                logger.warning("agent model could not be configured: %s", type(exc).__name__)
                raise AgentUnavailable() from None
        agent: Agent[AgentDeps, str] = Agent(
            model,
            deps_type=AgentDeps,
            output_type=str,
            instructions=INSTRUCTIONS,
            retries=1,
            model_settings=ModelSettings(max_tokens=self._settings.agent_max_output_tokens),
        )
        _register_tools(agent)
        return agent

    def _ensure(self) -> Agent[AgentDeps, str]:
        if self._agent is None:
            self._agent = self._build()
        return self._agent

    def chat(self, principal: Principal, request: ChatRequest) -> ChatReply:
        """Run one bounded turn; tool authorization happens per operation."""
        agent = self._ensure()
        deps = AgentDeps(
            settings=self._settings,
            session_factory=self._session_factory,
            principal=principal,
        )
        prompt = request.message
        if request.assetId:
            prompt = f"{prompt}\n\nActivo seleccionado: {request.assetId}"
        result = agent.run_sync(
            prompt,
            deps=deps,
            message_history=_history(request.conversation),
            usage_limits=UsageLimits(
                request_limit=self._settings.agent_max_steps,
                tool_calls_limit=self._settings.agent_max_steps * 4,
            ),
        )
        message = result.output.strip() or "No pude completar la solicitud."
        return ChatReply(
            message=message[:4000],
            actions=deps.actions,
            results=deps.results,
            approvalPending=False,
        )


__all__ = [
    "TOOL_NAMES",
    "AgentDeps",
    "AgentRuntime",
    "AgentUnavailable",
    "BatchUpdateArg",
    "ChatAction",
    "ChatReply",
    "ChatRequest",
    "ConversationTurn",
    "resolve_model",
]
