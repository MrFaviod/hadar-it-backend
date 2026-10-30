"""Conversational inventory assistant built on a real Pydantic AI agent.

The agent is deliberately narrow: typed inventory, directory and relationship
tools over the canonical services, a server-configured provider/model and
bounded steps, history, input and output. It has no shell, SQL, filesystem or
HTTP tool, and untrusted chat text cannot grant permissions, supply a principal,
forge history metadata or choose a service source.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Literal, cast

from itsm.agent_integrations.attachments import ChatAttachmentInput
from itsm.agent_integrations.providers import (
    ProviderModelSelection,
    build_provider_model,
)
from itsm.agent_integrations.providers import (
    provider_http_client as build_provider_http_client,
)
from itsm.config import Settings
from itsm.directory.service import DirectoryService
from itsm.extensions.tools import (
    EXTENSION_TOOL_NAMES,
    dispatch_extension_tool,
    register_agent_extension_tools,
)
from itsm.identity.service import (
    Conflict,
    IdentityError,
    IdentityService,
    NotFound,
    PermissionDenied,
    Principal,
    ValidationFailed,
)
from itsm.inventory.catalog import InventoryCatalog
from itsm.inventory.organization import moment
from itsm.inventory.projection import history_payload, project, validate_fields
from itsm.inventory.service import (
    AssetView,
    BatchResult,
    InventoryPage,
    InventoryService,
)
from itsm.operations import tools as operations_tools
from itsm.redundancy.service import RedundancyService
from itsm.relationships.service import RelationshipService
from itsm.reports.schemas import ReportRequest
from itsm.system.tools import SYSTEM_TOOL_NAMES
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
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
from pydantic_ai.toolsets.function import FunctionToolset
from pydantic_ai.usage import RunUsage, UsageLimits
from sqlalchemy.orm import Session

logger = logging.getLogger("itsm.agent")

TOOL_NAMES: tuple[str, ...] = (
    "search_assets",
    "get_asset",
    "create_asset",
    "update_asset",
    "batch_update_assets",
    "clone_asset",
    "archive_asset",
    "restore_asset",
    "retire_asset",
    "get_asset_history",
    "get_inventory_config",
    "search_locations",
    "search_people",
    "assign_asset",
    "return_asset",
    "transfer_asset",
    "get_asset_relations",
    "create_relationship",
    "remove_relationship",
    "move_host",
    "get_asset_map",
    "list_redundancy_groups",
    "get_redundancy_group",
    "save_redundancy_group",
    "prepare_inventory_import",
    "preview_bulk_operation",
    "get_inventory_operation",
    "resolve_import_conflict",
    "apply_inventory_operation",
    "search_maintenance",
    "complete_maintenance",
    "record_intervention",
    "create_incident",
    "link_incident_assets",
    "get_technical_history",
    "prepare_incident_resolution",
    "confirm_incident_resolution",
    "search_incidents",
    "get_asset_availability",
    "investigate_outage",
    "get_asset_metrics",
    "list_active_alerts",
    "link_alert_incident",
    "acknowledge_alert",
    "prepare_monitoring_maintenance",
    "list_report_templates",
    "prepare_report",
    "generate_report",
    "report_job_status",
    "report_documents",
    "generate_labels",
    "get_operational_summary",
    "search_everything",
    "query_relationships",
    "list_saved_views",
    *SYSTEM_TOOL_NAMES,
) + EXTENSION_TOOL_NAMES

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
- Los mantenimientos y las intervenciones se registran con las herramientas técnicas;
  completar un mantenimiento recalcula su próximo vencimiento.
- Preparar una resolución de incidente no lo resuelve: solo la confirmación con el
  token preparado y la autoridad vigente lo cambia de estado.
- Las métricas proceden de Prometheus; indicá el período y distinguí sin datos,
  sin supervisión y servicio no disponible de una caída confirmada.
- Reconocer una alerta no la resuelve y una recuperación no cierra su incidente.
- Preparar mantenimiento solo propone una ventana; no cambia la supervisión.
- Los reportes y etiquetas usan plantillas y filtros estructurados; nunca generes HTML,
  rutas de servidor ni comandos. Preparar no genera un archivo; generar devuelve un
  trabajo pendiente y solo su estado final confirma los documentos disponibles.
- El resumen operativo y la búsqueda global respetan el período, el motor y los permisos
  vigentes; no supongas que una coincidencia existe si la herramienta no la devuelve.
- Las relaciones se consultan desde un activo concreto o de forma paginada; no recorras
  todo el grafo para responder por un solo equipo.
Para desarrollar funciones nuevas, primero consulta extension_sdk_index y las referencias del SDK.
Trabaja solo en los archivos del espacio independiente mediante extension_workspace_*; valida
el paquete exacto en el contenedor aislado y remítelo a revisión humana. Nunca apruebes ni
instales el paquete tú mismo, ni modifiques el núcleo. Explica los permisos y la ejecución
nativa de confianza. Para módulos instalados, descubre extension_list/extension_operations
y usa extension_invoke con sus parámetros declarados y los permisos vigentes.
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

    message: str = Field(default="", max_length=8000)
    conversation: list[ConversationTurn] = Field(default_factory=list, max_length=50)
    assetId: str | None = Field(default=None, max_length=36)
    attachments: list[ChatAttachmentInput] = Field(default_factory=list, max_length=4)

    @model_validator(mode="after")
    def _require_content(self) -> ChatRequest:
        if not self.message.strip() and not self.attachments:
            raise ValueError("message or at least one attachment is required")
        return self

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
class AgentUsage:
    """Directly measured provider tokens for one runtime call (never estimated)."""

    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class AgentDeps:
    """Trusted execution context: the principal comes from the transport."""

    settings: Settings
    session_factory: Callable[[], Session]
    principal: Principal
    credential_digest: str | None = None
    actions: list[ChatAction] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    system: Any = None
    extensions: Any = None
    extension_development: Any = None
    approval_pending: bool = False


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
    cost: str | float | None = None
    technical: dict[str, Any] | None = None
    site_id: str | None = None
    location_id: str | None = None
    responsible_person_id: str | None = None
    position_x: str | None = None
    position_y: str | None = None


@contextmanager
def _service(deps: AgentDeps) -> Iterator[InventoryService]:
    session = deps.session_factory()
    try:
        yield InventoryService(session, deps.settings, source="agent")
    finally:
        session.close()


@contextmanager
def _directory(deps: AgentDeps) -> Iterator[DirectoryService]:
    session = deps.session_factory()
    try:
        yield DirectoryService(
            session, deps.settings, identity=IdentityService(session, deps.settings)
        )
    finally:
        session.close()


@contextmanager
def _relations(deps: AgentDeps) -> Iterator[RelationshipService]:
    session = deps.session_factory()
    try:
        yield RelationshipService(
            session,
            deps.settings,
            identity=IdentityService(session, deps.settings),
            source="agent",
        )
    finally:
        session.close()


@contextmanager
def _redundancy(deps: AgentDeps) -> Iterator[RedundancyService]:
    session = deps.session_factory()
    try:
        yield RedundancyService(
            session,
            deps.settings,
            identity=IdentityService(session, deps.settings),
            source="agent",
        )
    finally:
        session.close()


@contextmanager
def _maintenance(deps: AgentDeps) -> Iterator[Any]:
    """Open the canonical preventive service for one tool operation."""
    from itsm.maintenance.service import MaintenanceService

    session = deps.session_factory()
    try:
        yield MaintenanceService(
            session,
            deps.settings,
            identity=IdentityService(session, deps.settings),
            source="agent",
        )
    finally:
        session.close()


@contextmanager
def _interventions(deps: AgentDeps) -> Iterator[Any]:
    """Open the canonical intervention/incident service for one tool operation."""
    from itsm.interventions.service import InterventionService

    session = deps.session_factory()
    try:
        yield InterventionService(
            session,
            deps.settings,
            identity=IdentityService(session, deps.settings),
            source="agent",
        )
    finally:
        session.close()


def _system(deps: AgentDeps) -> Any:
    """Use the application's canonical system service, or build the same boundary."""
    if deps.system is not None:
        return deps.system
    from itsm.system.service import SystemService

    return SystemService(deps.settings, deps.session_factory)


def _system_collect(
    deps: AgentDeps,
    tool: str,
    operation: Callable[[Any], dict[str, Any]],
) -> dict[str, Any]:
    """Run one typed system operation through the canonical service and record it."""
    try:
        payload = operation(_system(deps))
    except IdentityError as exc:
        return _failed(deps, tool, exc)
    _record(deps, tool, "completed")
    if len(deps.results) < MAX_RESULTS:
        deps.results.append(payload)
    return {"ok": True, **payload}


def _extension_collect(deps: AgentDeps, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Use the same SDK boundary as HTTP/MCP, including isolated proxy calls."""
    from itsm.extensions.host import ExtensionHostError

    if deps.extensions is None or deps.extension_development is None:
        from itsm.extensions.composition import create_extension_services

        deps.extensions, deps.extension_development = create_extension_services(
            deps.settings, deps.session_factory
        )
    try:
        payload = dispatch_extension_tool(
            name,
            arguments,
            principal=deps.principal,
            host=deps.extensions,
            development=deps.extension_development,
        )
    except IdentityError as exc:
        return _failed(deps, name, exc)
    except ExtensionHostError as exc:
        return _failure(deps, name, "failed", str(exc))
    _record(deps, name, "completed")
    if (
        name == "extension_workspace_submit"
        and payload.get("state") == "pending"
        and isinstance(payload.get("id"), str)
    ):
        deps.approval_pending = True
        if len(deps.results) < MAX_RESULTS:
            deps.results.append(
                {
                    "type": "extension_review",
                    "candidateId": payload["id"],
                    "extensionId": payload["extensionId"],
                    "digest": payload["digest"],
                    "version": payload["version"],
                }
            )
    return {"ok": True, **payload}


@contextmanager
def _monitoring(deps: AgentDeps) -> Iterator[Any]:
    """Open the canonical monitoring service with the current trusted principal."""
    from itsm.monitoring.service import MonitoringService
    from itsm.notifications.service import record_alert_event

    with deps.session_factory() as session:
        yield MonitoringService(
            session,
            deps.settings,
            identity=IdentityService(session, deps.settings),
            source="agent",
            notifier=record_alert_event,
        )


def _bounded_page(limit: int, offset: int) -> tuple[int, int]:
    """Clamp one tool page so a model cannot request unbounded rows."""
    return max(1, min(int(limit), MAX_RESULTS)), max(0, int(offset))


def _operational(
    deps: AgentDeps,
    tool: str,
    operation: Callable[[Session, IdentityService], dict[str, Any]],
) -> dict[str, Any]:
    """Run one shared operational query under the current trusted principal."""

    def call() -> dict[str, Any]:
        with deps.session_factory() as session:
            return operation(session, IdentityService(session, deps.settings))

    return _collect(deps, tool, call)


def _page_payload(page: Any) -> dict[str, Any]:
    return {
        "total": page.total,
        "limit": page.limit,
        "offset": page.offset,
        "items": [item.as_payload() for item in page.items],
    }


def _bounded_ids(values: list[str] | None, label: str) -> list[str] | None:
    if values is None:
        return None
    if len(values) > MAX_RESULTS:
        raise ValidationFailed(f"{label} must contain at most {MAX_RESULTS} ids")
    return list(values)


def _optional_iso_date(value: str | None, label: str) -> date | None:
    """Parse one optional tool date string; the maintenance service requires real dates."""
    if value is None:
        return None
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(value)
    except TypeError, ValueError:
        raise ValidationFailed(f"{label} must be an ISO date (YYYY-MM-DD)") from None


class RedundancyMemberArg(BaseModel):
    """One member of a group; the asset id must be an existing permanent UUID."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1, max_length=36)
    role: str | None = None
    share: Any = None


class InterventionPartArg(BaseModel):
    """One consumed part; money uses canonical decimal strings."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    quantity: int
    unit_cost: str | None = None


def _record(
    deps: AgentDeps,
    tool: str,
    status: Literal["completed", "failed", "denied"],
    views: tuple[AssetView, ...] = (),
    fields: list[str] | None = None,
) -> None:
    deps.actions.append(ChatAction(tool=tool, status=status, assetIds=[view.id for view in views]))
    for view in views:
        if len(deps.results) < MAX_RESULTS:
            deps.results.append(project(view, fields))


def _failure(
    deps: AgentDeps, tool: str, status: Literal["failed", "denied"], message: str
) -> dict[str, Any]:
    _record(deps, tool, status)
    return {"ok": False, "message": message}


def _failed(deps: AgentDeps, tool: str, exc: Exception) -> dict[str, Any]:
    """Map one service error to a compact, factual tool failure."""
    if isinstance(exc, PermissionDenied):
        return _failure(deps, tool, "denied", "La identidad no tiene permiso para esta operación.")
    if isinstance(exc, Conflict):
        return _failure(deps, tool, "failed", str(exc))
    if isinstance(exc, NotFound):
        return _failure(deps, tool, "failed", str(exc))
    if isinstance(exc, ValidationFailed):
        return _failure(deps, tool, "failed", str(exc))
    logger.warning("agent tool identity error", exc_info=exc)
    return _failure(deps, tool, "failed", "La operación no pudo completarse.")


def _collect(
    deps: AgentDeps,
    tool: str,
    operation: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Run a query or write that renders its own compact payload."""
    try:
        payload = operation()
    except IdentityError as exc:
        return _failed(deps, tool, exc)
    _record(deps, tool, "completed")
    if len(deps.results) < MAX_RESULTS:
        deps.results.append(payload)
    return {"ok": True, **payload}


def _execute(
    deps: AgentDeps,
    tool: str,
    operation: Callable[[InventoryService], Any],
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Run one tool through the canonical service and record a compact action."""
    try:
        validate_fields(fields)
        with _service(deps) as inventory:
            result = operation(inventory)
    except IdentityError as exc:
        return _failed(deps, tool, exc)

    if isinstance(result, AssetView):
        _record(deps, tool, "completed", (result,), fields)
        return {"ok": True, "asset": project(result, fields)}
    if isinstance(result, InventoryPage):
        _record(deps, tool, "completed", result.items, fields)
        return {
            "ok": True,
            "total": result.total,
            "items": [project(item, fields) for item in result.items],
        }
    if isinstance(result, BatchResult):
        _record(deps, tool, "completed", result.created + result.updated, fields)
        return {
            "ok": True,
            "created": [project(item, fields) for item in result.created],
            "updated": [project(item, fields) for item in result.updated],
        }
    return {"ok": True, "result": result}


def build_toolset() -> FunctionToolset[AgentDeps]:
    """Canonical typed tool inventory shared by the agent and the isolated proxy.

    Every execution path must use this builder; it is the single source of the
    tools the model can see and therefore the single authorization surface.
    """
    toolset: FunctionToolset[AgentDeps] = FunctionToolset()

    @toolset.tool
    def search_assets(
        ctx: RunContext[AgentDeps],
        query: str | None = None,
        category: str | None = None,
        site: str | None = None,
        status: str | None = None,
        quick_code: str | None = None,
        limit: int = 10,
        archived: bool | None = None,
        fields: list[str] | None = None,
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
                archived=archived,
            ),
            fields,
        )

    @toolset.tool
    def get_asset(
        ctx: RunContext[AgentDeps], asset_id: str, fields: list[str] | None = None
    ) -> dict[str, Any]:
        """Consultar el detalle de un activo por su id permanente."""
        return _execute(
            ctx.deps,
            "get_asset",
            lambda inventory: inventory.get(ctx.deps.principal, asset_id),
            fields,
        )

    @toolset.tool
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
        cost: str | float | None = None,
        technical: dict[str, Any] | None = None,
        site_id: str | None = None,
        location_id: str | None = None,
        responsible_person_id: str | None = None,
        position_x: str | None = None,
        position_y: str | None = None,
        fields: list[str] | None = None,
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
            "cost": cost,
            "technical": technical,
            "site_id": site_id,
            "location_id": location_id,
            "responsible_person_id": responsible_person_id,
            "position_x": position_x,
            "position_y": position_y,
        }
        return _execute(
            ctx.deps,
            "create_asset",
            lambda inventory: inventory.create(
                ctx.deps.principal,
                {key: value for key, value in values.items() if value is not None},
            ),
            fields,
        )

    @toolset.tool
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
        cost: str | float | None = None,
        technical: dict[str, Any] | None = None,
        site_id: str | None = None,
        location_id: str | None = None,
        responsible_person_id: str | None = None,
        position_x: str | None = None,
        position_y: str | None = None,
        fields: list[str] | None = None,
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
            "cost": cost,
            "technical": technical,
            "site_id": site_id,
            "location_id": location_id,
            "responsible_person_id": responsible_person_id,
            "position_x": position_x,
            "position_y": position_y,
        }
        changes = {key: value for key, value in values.items() if value is not None}
        return _execute(
            ctx.deps,
            "update_asset",
            lambda inventory: inventory.update(ctx.deps.principal, asset_id, changes),
            fields,
        )

    @toolset.tool
    def batch_update_assets(
        ctx: RunContext[AgentDeps], updates: list[BatchUpdateArg], fields: list[str] | None = None
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
            fields,
        )

    @toolset.tool
    def clone_asset(
        ctx: RunContext[AgentDeps],
        asset_id: str,
        name: str | None = None,
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Duplicar con UUID nuevo, sin heredar el archivado ni las imágenes."""
        return _execute(
            ctx.deps,
            "clone_asset",
            lambda service: service.clone(
                ctx.deps.principal, asset_id, {"name": name} if name else None
            ),
            fields,
        )

    @toolset.tool
    def archive_asset(
        ctx: RunContext[AgentDeps], asset_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """Archivar sin cambiar estado, responsable ni ubicación."""
        return _execute(
            ctx.deps,
            "archive_asset",
            lambda service: service.archive(ctx.deps.principal, asset_id, reason=reason),
        )

    @toolset.tool
    def restore_asset(ctx: RunContext[AgentDeps], asset_id: str) -> dict[str, Any]:
        """Restaurar un activo archivado, sin alterar sus otros datos."""
        return _execute(
            ctx.deps, "restore_asset", lambda service: service.restore(ctx.deps.principal, asset_id)
        )

    @toolset.tool
    def retire_asset(ctx: RunContext[AgentDeps], asset_id: str, reason: str) -> dict[str, Any]:
        """Dar de baja con motivo y controles de transición y asignación."""
        return _execute(
            ctx.deps,
            "retire_asset",
            lambda service: service.retire(ctx.deps.principal, asset_id, reason=reason),
        )

    @toolset.tool
    def get_asset_history(
        ctx: RunContext[AgentDeps], asset_id: str, limit: int = 20, offset: int = 0
    ) -> dict[str, Any]:
        """Consultar historial acotado por UUID permanente, con origen y fecha efectiva."""
        return _execute(
            ctx.deps,
            "get_asset_history",
            lambda service: history_payload(
                service.history(ctx.deps.principal, asset_id, limit=limit, offset=offset)
            ),
        )

    @toolset.tool
    def get_inventory_config(ctx: RunContext[AgentDeps]) -> dict[str, Any]:
        """Consultar formularios, campos, estados y reglas configurados."""
        return _execute(
            ctx.deps,
            "get_inventory_config",
            lambda service: InventoryCatalog(service._session, ctx.deps.settings).get(
                ctx.deps.principal
            ),
        )

    @toolset.tool
    def search_locations(
        ctx: RunContext[AgentDeps],
        query: str | None = None,
        level: str | None = None,
        parent_id: str | None = None,
        active: bool | None = True,
        tree: bool = False,
        depth: int = 2,
        max_nodes: int = 50,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Buscar sedes, edificios, pisos o salas; con tree=True devuelve la jerarquía acotada."""

        def operation() -> dict[str, Any]:
            with _directory(ctx.deps) as directory:
                if tree:
                    built = directory.location_tree(
                        ctx.deps.principal, root_id=parent_id, depth=depth, max_nodes=max_nodes
                    )
                    return {
                        "routes": [node.location.as_payload() for node in built.roots],
                        "nodeCount": built.node_count,
                        "depth": built.depth,
                        "truncated": built.truncated,
                    }
                page = directory.list_locations(
                    ctx.deps.principal,
                    query=query,
                    level=level,
                    parent_id=parent_id,
                    active=active,
                    limit=limit,
                    offset=offset,
                )
                return {
                    "total": page.total,
                    "limit": page.limit,
                    "offset": page.offset,
                    "items": [item.as_payload() for item in page.items],
                }

        return _collect(ctx.deps, "search_locations", operation)

    @toolset.tool
    def search_people(
        ctx: RunContext[AgentDeps],
        query: str | None = None,
        status: str | None = None,
        department_id: str | None = None,
        site_id: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Buscar personas responsables por texto, estado, departamento o sede."""

        def operation() -> dict[str, Any]:
            with _directory(ctx.deps) as directory:
                page = directory.list_people(
                    ctx.deps.principal,
                    query=query,
                    status=status,
                    department_id=department_id,
                    site_id=site_id,
                    limit=limit,
                    offset=offset,
                )
            return {
                "total": page.total,
                "limit": page.limit,
                "offset": page.offset,
                "items": [item.as_payload() for item in page.items],
            }

        return _collect(ctx.deps, "search_people", operation)

    @toolset.tool
    def assign_asset(
        ctx: RunContext[AgentDeps],
        asset_id: str,
        person_id: str,
        reason: str | None = None,
        notes: str | None = None,
        effective_at: str | None = None,
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Asignar un activo a una persona activa del directorio."""
        return _execute(
            ctx.deps,
            "assign_asset",
            lambda service: service.assign_responsible(
                ctx.deps.principal,
                asset_id,
                person_id,
                reason=reason,
                notes=notes,
                effective_at=moment(effective_at),
            ),
            fields,
        )

    @toolset.tool
    def return_asset(
        ctx: RunContext[AgentDeps],
        asset_id: str,
        reason: str,
        notes: str | None = None,
        effective_at: str | None = None,
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Registrar la devolución del activo y liberar el responsable."""
        return _execute(
            ctx.deps,
            "return_asset",
            lambda service: service.return_responsible(
                ctx.deps.principal,
                asset_id,
                reason=reason,
                notes=notes,
                effective_at=moment(effective_at),
            ),
            fields,
        )

    @toolset.tool
    def transfer_asset(
        ctx: RunContext[AgentDeps],
        asset_id: str,
        reason: str,
        site_id: str | None = None,
        location_id: str | None = None,
        notes: str | None = None,
        effective_at: str | None = None,
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Transferir el activo a otra sede o ubicación sin cambiar su id."""
        return _execute(
            ctx.deps,
            "transfer_asset",
            lambda service: service.transfer(
                ctx.deps.principal,
                asset_id,
                site_id=site_id,
                location_id=location_id,
                reason=reason,
                notes=notes,
                effective_at=moment(effective_at),
            ),
            fields,
        )

    @toolset.tool
    def get_asset_relations(
        ctx: RunContext[AgentDeps],
        asset_ids: list[str],
        type_key: str | None = None,
        direction: str = "both",
        limit: int = 20,
    ) -> dict[str, Any]:
        """Consultar en una sola operación las relaciones de varios activos."""

        def operation() -> dict[str, Any]:
            with _relations(ctx.deps) as relationships:
                page = relationships.list(
                    ctx.deps.principal,
                    asset_ids=asset_ids,
                    type_key=type_key,
                    direction=direction,
                    limit=limit,
                )
            return {
                "total": page.total,
                "limit": page.limit,
                "offset": page.offset,
                "items": [item.as_payload() for item in page.items],
            }

        return _collect(ctx.deps, "get_asset_relations", operation)

    @toolset.tool
    def create_relationship(
        ctx: RunContext[AgentDeps],
        source_id: str,
        target_id: str,
        type_key: str,
        reason: str | None = None,
        notes: str | None = None,
        effective_at: str | None = None,
    ) -> dict[str, Any]:
        """Crear una relación dirigida tipada entre dos activos existentes."""

        def operation() -> dict[str, Any]:
            with _relations(ctx.deps) as relationships:
                view = relationships.create(
                    ctx.deps.principal,
                    source_id=source_id,
                    target_id=target_id,
                    type_key=type_key,
                    reason=reason,
                    notes=notes,
                    effective_at=moment(effective_at),
                )
            return {"relationship": view.as_payload()}

        return _collect(ctx.deps, "create_relationship", operation)

    @toolset.tool
    def remove_relationship(
        ctx: RunContext[AgentDeps],
        relationship_id: str,
        reason: str | None = None,
        notes: str | None = None,
        effective_at: str | None = None,
    ) -> dict[str, Any]:
        """Eliminar una relación existente conservando el historial de ambos activos."""

        def operation() -> dict[str, Any]:
            with _relations(ctx.deps) as relationships:
                view = relationships.remove(
                    ctx.deps.principal,
                    relationship_id,
                    reason=reason,
                    notes=notes,
                    effective_at=moment(effective_at),
                )
            return {"removed": view.as_payload()}

        return _collect(ctx.deps, "remove_relationship", operation)

    @toolset.tool
    def move_host(
        ctx: RunContext[AgentDeps],
        child_id: str,
        new_host_id: str,
        reason: str,
        notes: str | None = None,
        effective_at: str | None = None,
    ) -> dict[str, Any]:
        """Mover una VM o contenedor a otro host sin perder su identidad."""

        def operation() -> dict[str, Any]:
            with _relations(ctx.deps) as relationships:
                result = relationships.move_host(
                    ctx.deps.principal,
                    child_id,
                    new_host_id,
                    reason=reason,
                    notes=notes,
                    effective_at=moment(effective_at),
                )
            return result.as_payload()

        return _collect(ctx.deps, "move_host", operation)

    @toolset.tool
    def get_asset_map(
        ctx: RunContext[AgentDeps],
        site_id: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Consultar sedes y posiciones de plano acotadas para el mapa."""

        def operation() -> dict[str, Any]:
            with _service(ctx.deps) as inventory:
                mapped = inventory.map(
                    ctx.deps.principal, site_id=site_id, limit=limit, offset=offset
                )
            return mapped.as_payload()

        return _collect(ctx.deps, "get_asset_map", operation)

    @toolset.tool
    def list_redundancy_groups(
        ctx: RunContext[AgentDeps],
        query: str | None = None,
        active: bool | None = None,
        mode: str | None = None,
        limit: int = 10,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Listar grupos de redundancia con sus réplicas, de forma acotada."""

        def operation() -> dict[str, Any]:
            with _redundancy(ctx.deps) as redundancy:
                page = redundancy.list(
                    ctx.deps.principal,
                    query=query,
                    active=active,
                    mode=mode,
                    limit=limit,
                    offset=offset,
                )
            return {"groups": page.as_payload()}

        return _collect(ctx.deps, "list_redundancy_groups", operation)

    @toolset.tool
    def get_redundancy_group(ctx: RunContext[AgentDeps], group_id: str) -> dict[str, Any]:
        """Leer un grupo de redundancia: modo, activación, roles y hosts reales."""

        def operation() -> dict[str, Any]:
            with _redundancy(ctx.deps) as redundancy:
                view = redundancy.get(ctx.deps.principal, group_id)
            return {"group": view.as_payload()}

        return _collect(ctx.deps, "get_redundancy_group", operation)

    @toolset.tool
    def save_redundancy_group(
        ctx: RunContext[AgentDeps],
        group_id: str | None = None,
        name: str | None = None,
        description: str | None = None,
        mode: str | None = None,
        active: bool | None = None,
        members: list[RedundancyMemberArg] | None = None,
        reason: str | None = None,
        notes: str | None = None,
        effective_at: str | None = None,
    ) -> dict[str, Any]:
        """Crear un grupo (sin group_id) o modificarlo con la lista completa de réplicas."""

        def operation() -> dict[str, Any]:
            specs = (
                None
                if members is None
                else [
                    {"asset_id": member.asset_id, "role": member.role, "share": member.share}
                    for member in members
                ]
            )
            with _redundancy(ctx.deps) as redundancy:
                if group_id is None:
                    if name is None or mode is None or specs is None:
                        raise ValidationFailed(
                            "name, mode and members are required to create a group"
                        )
                    view = redundancy.create(
                        ctx.deps.principal,
                        name=name,
                        mode=mode,
                        members=specs,
                        description=description,
                        active=True if active is None else active,
                        reason=reason,
                        notes=notes,
                        effective_at=moment(effective_at),
                    )
                else:
                    changes: dict[str, Any] = {
                        "reason": reason,
                        "notes": notes,
                        "effective_at": moment(effective_at),
                    }
                    if name is not None:
                        changes["name"] = name
                    if description is not None:
                        changes["description"] = description
                    if mode is not None:
                        changes["mode"] = mode
                    if active is not None:
                        changes["active"] = active
                    if specs is not None:
                        changes["members"] = specs
                    view = redundancy.update(ctx.deps.principal, group_id, **changes)
            return {"group": view.as_payload()}

        return _collect(ctx.deps, "save_redundancy_group", operation)

    @toolset.tool
    def search_maintenance(
        ctx: RunContext[AgentDeps],
        state: str | None = None,
        status: str | None = None,
        category: str | None = None,
        site: str | None = None,
        site_id: str | None = None,
        asset_id: str | None = None,
        maintenance_type: str | None = None,
        due_from: str | None = None,
        due_to: str | None = None,
        completed_from: str | None = None,
        completed_to: str | None = None,
        upcoming_days: int = 30,
        limit: int = 10,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Consultar mantenimientos pendientes, próximos o atrasados, acotado por página."""
        bounded_limit, bounded_offset = _bounded_page(limit, offset)
        horizon = max(0, min(int(upcoming_days), 365))

        def operation() -> dict[str, Any]:
            with _maintenance(ctx.deps) as maintenance:
                page = maintenance.list_plans(
                    ctx.deps.principal,
                    state=state,
                    status=status,
                    category=category,
                    site=site,
                    site_id=site_id,
                    asset_id=asset_id,
                    maintenance_type=maintenance_type,
                    due_from=_optional_iso_date(due_from, "dueFrom"),
                    due_to=_optional_iso_date(due_to, "dueTo"),
                    completed_from=_optional_iso_date(completed_from, "completedFrom"),
                    completed_to=_optional_iso_date(completed_to, "completedTo"),
                    upcoming_days=horizon,
                    limit=bounded_limit,
                    offset=bounded_offset,
                )
                return _page_payload(page)

        return _collect(ctx.deps, "search_maintenance", operation)

    @toolset.tool
    def complete_maintenance(
        ctx: RunContext[AgentDeps],
        plan_id: str,
        completed_on: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any]:
        """Completar un mantenimiento autorizado; el servicio calcula el próximo vencimiento."""

        def operation() -> dict[str, Any]:
            completed_value = _optional_iso_date(completed_on, "completedOn")
            with _maintenance(ctx.deps) as maintenance:
                view = maintenance.complete_plan(
                    ctx.deps.principal, plan_id, completed_on=completed_value, notes=notes
                )
                return {"plan": view.as_payload()}

        return _collect(ctx.deps, "complete_maintenance", operation)

    @toolset.tool
    def record_intervention(
        ctx: RunContext[AgentDeps],
        asset_id: str,
        type: str = "corrective",
        description: str | None = None,
        technician_person_id: str | None = None,
        occurred_on: str | None = None,
        status: str | None = None,
        notes: str | None = None,
        parts: list[InterventionPartArg] | None = None,
        labor_cost: str | None = None,
        attachment_ids: list[str] | None = None,
        incident_id: str | None = None,
        plan_id: str | None = None,
    ) -> dict[str, Any]:
        """Registrar una intervención completa en una sola llamada, con repuestos y adjuntos."""

        def operation() -> dict[str, Any]:
            values: dict[str, Any] = {"assetId": asset_id, "type": type}
            optional = {
                "description": description,
                "technicianPersonId": technician_person_id,
                "occurredOn": occurred_on,
                "status": status,
                "notes": notes,
                "laborCost": labor_cost,
                "incidentId": incident_id,
                "planId": plan_id,
            }
            values.update({key: value for key, value in optional.items() if value is not None})
            if parts is not None:
                values["parts"] = [
                    {
                        key: value
                        for key, value in {
                            "name": part.name,
                            "quantity": part.quantity,
                            "unitCost": part.unit_cost,
                        }.items()
                        if value is not None
                    }
                    for part in parts
                ]
            attachments = _bounded_ids(attachment_ids, "attachmentIds")
            if attachments is not None:
                values["attachmentIds"] = attachments
            with _interventions(ctx.deps) as interventions:
                view = interventions.create(ctx.deps.principal, values)
                return {"intervention": view.as_payload()}

        return _collect(ctx.deps, "record_intervention", operation)

    @toolset.tool
    def create_incident(
        ctx: RunContext[AgentDeps],
        primary_asset_id: str,
        description: str,
        priority: str = "normal",
        affected_asset_ids: list[str] | None = None,
        responsible_person_id: str | None = None,
        opened_on: str | None = None,
    ) -> dict[str, Any]:
        """Crear un incidente con su activo principal y todos los afectados en una sola llamada."""

        def operation() -> dict[str, Any]:
            values: dict[str, Any] = {
                "primaryAssetId": primary_asset_id,
                "description": description,
                "priority": priority,
            }
            affected = _bounded_ids(affected_asset_ids, "affectedAssetIds")
            if affected is not None:
                values["affectedAssetIds"] = affected
            if responsible_person_id is not None:
                values["responsiblePersonId"] = responsible_person_id
            if opened_on is not None:
                values["openedOn"] = opened_on
            with _interventions(ctx.deps) as interventions:
                view = interventions.create_incident(ctx.deps.principal, values)
                return {"incident": view.as_payload()}

        return _collect(ctx.deps, "create_incident", operation)

    @toolset.tool
    def link_incident_assets(
        ctx: RunContext[AgentDeps], incident_id: str, affected_asset_ids: list[str]
    ) -> dict[str, Any]:
        """Reemplazar el conjunto de activos afectados de un incidente existente."""

        def operation() -> dict[str, Any]:
            affected = _bounded_ids(affected_asset_ids, "affectedAssetIds") or []
            with _interventions(ctx.deps) as interventions:
                view = interventions.update_incident_assets(
                    ctx.deps.principal, incident_id, affected
                )
                return {"incident": view.as_payload()}

        return _collect(ctx.deps, "link_incident_assets", operation)

    @toolset.tool
    def get_technical_history(
        ctx: RunContext[AgentDeps], asset_id: str, limit: int = 20, offset: int = 0
    ) -> dict[str, Any]:
        """Consultar el historial técnico real de un activo: intervenciones e incidentes."""
        bounded_limit, bounded_offset = _bounded_page(limit, offset)

        def operation() -> dict[str, Any]:
            with _interventions(ctx.deps) as interventions:
                page = interventions.asset_technical_history(
                    ctx.deps.principal, asset_id, limit=bounded_limit, offset=bounded_offset
                )
                return page.as_payload()

        return _collect(ctx.deps, "get_technical_history", operation)

    @toolset.tool
    def prepare_incident_resolution(
        ctx: RunContext[AgentDeps], incident_id: str, note: str | None = None
    ) -> dict[str, Any]:
        """Preparar la resolución de un incidente; devuelve un token que no resuelve nada aún."""

        def operation() -> dict[str, Any]:
            with _interventions(ctx.deps) as interventions:
                suggestion = interventions.prepare_resolution(
                    ctx.deps.principal, incident_id, note=note
                )
                return {"resolution": suggestion.as_payload()}

        return _collect(ctx.deps, "prepare_incident_resolution", operation)

    @toolset.tool
    def confirm_incident_resolution(
        ctx: RunContext[AgentDeps],
        incident_id: str,
        token: str,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Confirmar una resolución preparada; la autoridad y el estado se revalidan ahora."""

        def operation() -> dict[str, Any]:
            with _interventions(ctx.deps) as interventions:
                view = interventions.confirm_resolution(
                    ctx.deps.principal, incident_id, token, note=note
                )
                return {"incident": view.as_payload()}

        return _collect(ctx.deps, "confirm_incident_resolution", operation)

    @toolset.tool
    def search_incidents(
        ctx: RunContext[AgentDeps],
        active: bool | None = None,
        status: str | None = None,
        priority: str | None = None,
        category: str | None = None,
        site: str | None = None,
        asset_id: str | None = None,
        responsible_person_id: str | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        limit: int = 10,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Consultar incidentes por estado, prioridad, activo, responsable o período."""
        bounded_limit, bounded_offset = _bounded_page(limit, offset)

        def operation() -> dict[str, Any]:
            with _interventions(ctx.deps) as interventions:
                page = interventions.list_incidents(
                    ctx.deps.principal,
                    active=active,
                    status=status,
                    priority=priority,
                    category=category,
                    site=site,
                    asset_id=asset_id,
                    responsible_person_id=responsible_person_id,
                    from_date=from_date,
                    to_date=to_date,
                    limit=bounded_limit,
                    offset=bounded_offset,
                )
                return _page_payload(page)

        return _collect(ctx.deps, "search_incidents", operation)

    @toolset.tool
    def get_asset_availability(
        ctx: RunContext[AgentDeps], asset_id: str, period: str = "24h"
    ) -> dict[str, Any]:
        """Consultar disponibilidad real, procedencia y período; nunca inferir una caída."""
        from itsm.monitoring.projection import summarize_device

        def operation() -> dict[str, Any]:
            with _monitoring(ctx.deps) as service:
                return summarize_device(service.get_device(ctx.deps.principal, asset_id, period))

        return _collect(ctx.deps, "get_asset_availability", operation)

    @toolset.tool
    def get_asset_metrics(
        ctx: RunContext[AgentDeps], asset_id: str, period: str = "24h"
    ) -> dict[str, Any]:
        """Consultar métricas históricas acotadas con período y procedencia de Prometheus."""
        from itsm.monitoring.projection import summarize_device

        def operation() -> dict[str, Any]:
            with _monitoring(ctx.deps) as service:
                return summarize_device(
                    service.get_device(ctx.deps.principal, asset_id, period), include_series=True
                )

        return _collect(ctx.deps, "get_asset_metrics", operation)

    @toolset.tool
    def investigate_outage(
        ctx: RunContext[AgentDeps], asset_id: str, period: str = "24h"
    ) -> dict[str, Any]:
        """Investigar disponibilidad y alertas persistidas.

        No inventar causas ni recuperaciones.
        """
        from itsm.monitoring.projection import summarize_alert, summarize_device

        def operation() -> dict[str, Any]:
            with _monitoring(ctx.deps) as service:
                result = summarize_device(service.get_device(ctx.deps.principal, asset_id, period))
                alerts = service.list_alerts(ctx.deps.principal, asset_id=asset_id, limit=10)
                result["alerts"] = {
                    **alerts,
                    "items": [summarize_alert(item) for item in alerts["items"]],
                }
                return result

        return _collect(ctx.deps, "investigate_outage", operation)

    @toolset.tool
    def list_active_alerts(
        ctx: RunContext[AgentDeps], asset_id: str | None = None, limit: int = 10, offset: int = 0
    ) -> dict[str, Any]:
        """Consultar una página acotada de alertas activas autorizadas."""
        from itsm.monitoring.projection import summarize_alert

        def operation() -> dict[str, Any]:
            with _monitoring(ctx.deps) as service:
                bounded_limit, bounded_offset = _bounded_page(limit, offset)
                page = service.list_alerts(
                    ctx.deps.principal,
                    limit=bounded_limit,
                    offset=bounded_offset,
                    state="firing",
                    asset_id=asset_id,
                )
                return {**page, "items": [summarize_alert(item) for item in page["items"]]}

        return _collect(ctx.deps, "list_active_alerts", operation)

    @toolset.tool
    def acknowledge_alert(
        ctx: RunContext[AgentDeps], alert_id: str, notes: str = ""
    ) -> dict[str, Any]:
        """Reconocer una alerta autorizada sin resolverla ni cerrar su incidente."""
        from itsm.monitoring.projection import summarize_alert

        def operation() -> dict[str, Any]:
            with _monitoring(ctx.deps) as service:
                return summarize_alert(service.acknowledge(ctx.deps.principal, alert_id, notes))

        return _collect(ctx.deps, "acknowledge_alert", operation)

    @toolset.tool
    def link_alert_incident(
        ctx: RunContext[AgentDeps], alert_id: str, incident_id: str | None = None
    ) -> dict[str, Any]:
        """Vincular un incidente existente o crear uno canónico, con autorización vigente."""
        from itsm.monitoring.projection import summarize_alert

        def operation() -> dict[str, Any]:
            with _monitoring(ctx.deps) as service:
                return summarize_alert(
                    service.link_incident(ctx.deps.principal, alert_id, incident_id)
                )

        return _collect(ctx.deps, "link_alert_incident", operation)

    @toolset.tool
    def prepare_monitoring_maintenance(ctx: RunContext[AgentDeps], alert_id: str) -> dict[str, Any]:
        """Preparar una ventana de mantenimiento sugerida, sin guardarla ni silenciar."""

        def operation() -> dict[str, Any]:
            with _monitoring(ctx.deps) as service:
                return service.prepare_maintenance(ctx.deps.principal, alert_id)

        return _collect(ctx.deps, "prepare_monitoring_maintenance", operation)

    def workflow(ctx, name, call):
        """Run one workflow tool; every row-bearing result stays compact for the chat."""
        from itsm.workflows.service import WorkflowService, compact_operation

        def operation():
            with ctx.deps.session_factory() as session:
                service = WorkflowService(session, ctx.deps.settings, source="agent")
                return compact_operation(call(service, ctx.deps.principal))

        return _collect(ctx.deps, name, operation)

    @toolset.tool
    def prepare_inventory_import(
        ctx: RunContext[AgentDeps], csv_text: str, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Analyze bounded CSV text without changing inventory; no path or URL inputs."""
        return workflow(
            ctx,
            "prepare_inventory_import",
            lambda s, p: s.analyze(p, csv_text.encode(), "assets.csv", options),
        )

    @toolset.tool
    def preview_bulk_operation(
        ctx: RunContext[AgentDeps],
        asset_ids: list[str],
        changes: dict[str, Any],
        action: str = "update",
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Prepare an exact immutable-target preview; human approval is separate."""
        return workflow(
            ctx,
            "preview_bulk_operation",
            lambda s, p: s.preview(
                p, asset_ids=asset_ids, changes=changes, action=action, reason=reason
            ),
        )

    @toolset.tool
    def get_inventory_operation(
        ctx: RunContext[AgentDeps], operation_id: str, offset: int = 0, limit: int = 20
    ) -> dict[str, Any]:
        """Read compact conflicts, progress and final row receipts."""
        return workflow(
            ctx,
            "get_inventory_operation",
            lambda s, p: s.get(p, operation_id, offset=offset, limit=min(limit, 50)),
        )

    @toolset.tool
    def resolve_import_conflict(
        ctx: RunContext[AgentDeps],
        operation_id: str,
        index: int,
        action: str,
        asset_id: str | None = None,
        values: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Resolve one row; every change invalidates any previous human approval."""
        return workflow(
            ctx,
            "resolve_import_conflict",
            lambda s, p: s.resolve(p, operation_id, index, action, asset_id, values),
        )

    @toolset.tool
    def apply_inventory_operation(ctx: RunContext[AgentDeps], operation_id: str) -> dict[str, Any]:
        """Apply only a human-approved fixed preview under current permissions."""
        return workflow(ctx, "apply_inventory_operation", lambda s, p: s.execute(p, operation_id))

    def reports(
        ctx: RunContext[AgentDeps],
        name: str,
        operation: Callable[[Any, Principal, str | None], dict[str, Any]],
    ) -> dict[str, Any]:
        from itsm.reports.service import build_report_service
        from itsm.tasks import create_task_queue

        def execute() -> dict[str, Any]:
            service = build_report_service(
                ctx.deps.settings,
                ctx.deps.session_factory,
                task_queue=create_task_queue(ctx.deps.settings),
            )
            return operation(service, ctx.deps.principal, ctx.deps.credential_digest)

        return _collect(ctx.deps, name, execute)

    @toolset.tool
    def list_report_templates(ctx: RunContext[AgentDeps]) -> dict[str, Any]:
        """List authorized default and custom structured report templates."""
        return reports(
            ctx,
            "list_report_templates",
            lambda service, principal, _digest: service.templates(principal),
        )

    @toolset.tool
    def prepare_report(ctx: RunContext[AgentDeps], request: ReportRequest) -> dict[str, Any]:
        """Preview canonical filters and up to twenty rows, without rendering or queuing."""

        def operation(service, principal, _digest):
            preview = service.preview(principal, request)
            return {
                "matched": preview["matched"],
                "assets": preview["assets"][:20],
                "rows": preview["rows"][:20],
                "columns": preview["columns"],
                "summary": preview["summary"],
                "hasMore": len(preview["assets"]) > 20 or len(preview["rows"]) > 20,
            }

        return reports(ctx, "prepare_report", operation)

    @toolset.tool
    def generate_report(ctx: RunContext[AgentDeps], request: ReportRequest) -> dict[str, Any]:
        """Queue a canonical PDF/CSV/Excel report and return its durable job locator."""
        return reports(
            ctx,
            "generate_report",
            lambda service, principal, digest: service.generate(
                principal, request, credential_digest=digest
            ),
        )

    @toolset.tool
    def report_job_status(ctx: RunContext[AgentDeps], job_id: str) -> dict[str, Any]:
        """Read current owned job progress, errors and protected document references."""
        return reports(
            ctx,
            "report_job_status",
            lambda service, principal, _digest: service.job(principal, job_id),
        )

    @toolset.tool
    def report_documents(ctx: RunContext[AgentDeps], job_id: str) -> dict[str, Any]:
        """Read protected download references for a job, never server paths or file bytes."""

        def operation(service, principal, _digest):
            job = service.job(principal, job_id)
            return {"id": job["id"], "status": job["status"], "documents": job["documents"]}

        return reports(ctx, "report_documents", operation)

    @toolset.tool
    def generate_labels(ctx: RunContext[AgentDeps], request: ReportRequest) -> dict[str, Any]:
        """Queue physical labels using explicit structured dimensions and asset filters."""
        if request.labels is None:
            return _failed(
                ctx.deps, "generate_labels", ValidationFailed("label options are required")
            )
        return reports(
            ctx,
            "generate_labels",
            lambda service, principal, digest: service.generate(
                principal, request, credential_digest=digest
            ),
        )

    @toolset.tool
    def get_operational_summary(
        ctx: RunContext[AgentDeps],
        period: str = "24h",
        category: str | None = None,
        site_id: str | None = None,
    ) -> dict[str, Any]:
        """Resumir disponibilidad, alertas, incidentes y actividad del período indicado."""
        return _operational(
            ctx.deps,
            "get_operational_summary",
            lambda session, identity: operations_tools.operational_summary(
                session,
                identity,
                ctx.deps.settings,
                ctx.deps.principal,
                source="agent",
                period=period,
                category=category,
                site_id=site_id,
            ),
        )

    @toolset.tool
    def search_everything(
        ctx: RunContext[AgentDeps],
        query: str,
        kinds: list[str] | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Buscar entidades canónicas por texto con tipos y página acotados."""
        return _operational(
            ctx.deps,
            "search_everything",
            lambda session, identity: operations_tools.search_everything(
                session,
                identity,
                ctx.deps.settings,
                ctx.deps.principal,
                source="agent",
                query=query,
                kinds=kinds,
                limit=limit,
                offset=offset,
            ),
        )

    @toolset.tool
    def query_relationships(
        ctx: RunContext[AgentDeps],
        asset_id: str | None = None,
        depth: int = 2,
        direction: str = "both",
        type_key: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Recorrer relaciones desde un activo o paginar el grafo global persistido."""
        return _operational(
            ctx.deps,
            "query_relationships",
            lambda session, identity: operations_tools.query_relationships(
                session,
                identity,
                ctx.deps.settings,
                ctx.deps.principal,
                source="agent",
                asset_id=asset_id,
                depth=depth,
                direction=direction,
                type_key=type_key,
                limit=limit,
                offset=offset,
            ),
        )

    @toolset.tool
    def list_saved_views(ctx: RunContext[AgentDeps]) -> dict[str, Any]:
        """Leer las vistas, favoritos y accesos guardados de la identidad actual."""
        return _operational(
            ctx.deps,
            "list_saved_views",
            lambda session, identity: operations_tools.list_saved_views(
                session, identity, ctx.deps.principal, source="agent"
            ),
        )

    @toolset.tool
    def get_system_status(ctx: RunContext[AgentDeps]) -> dict[str, Any]:
        """Leer el estado factual y redactado de la instalación y del ejecutor externo."""
        return _system_collect(
            ctx.deps,
            "get_system_status",
            lambda service: service.status(ctx.deps.principal),
        )

    @toolset.tool
    def get_system_configuration(ctx: RunContext[AgentDeps]) -> dict[str, Any]:
        """Leer las preferencias finitas de despliegue propias de la aplicación."""
        return _system_collect(
            ctx.deps,
            "get_system_configuration",
            lambda service: service.configuration(ctx.deps.principal),
        )

    @toolset.tool
    def list_system_providers(ctx: RunContext[AgentDeps]) -> dict[str, Any]:
        """Listar los proveedores de IA permitidos y la selección persistida."""
        return _system_collect(
            ctx.deps,
            "list_system_providers",
            lambda service: service.providers(ctx.deps.principal),
        )

    @toolset.tool
    def configure_system_provider(
        ctx: RunContext[AgentDeps],
        provider: Literal["openai", "anthropic"],
        model: str,
    ) -> dict[str, Any]:
        """Persistir el proveedor y modelo permitidos; las credenciales siguen siendo externas."""
        return _system_collect(
            ctx.deps,
            "configure_system_provider",
            lambda service: service.set_provider(
                ctx.deps.principal, {"provider": provider, "model": model}
            ),
        )

    @toolset.tool
    def list_system_modules(ctx: RunContext[AgentDeps]) -> dict[str, Any]:
        """Listar los módulos oficiales registrados y su estado habilitado."""
        return _system_collect(
            ctx.deps,
            "list_system_modules",
            lambda service: service.modules(ctx.deps.principal),
        )

    @toolset.tool
    def set_system_module(
        ctx: RunContext[AgentDeps],
        module_id: str,
        enabled: bool,
    ) -> dict[str, Any]:
        """Habilitar o deshabilitar un módulo no oficial del catálogo verificado."""
        return _system_collect(
            ctx.deps,
            "set_system_module",
            lambda service: service.set_module(ctx.deps.principal, module_id, {"enabled": enabled}),
        )

    @toolset.tool
    def prepare_system_update(ctx: RunContext[AgentDeps]) -> dict[str, Any]:
        """Solicitar al ejecutor externo configurado la preparación de una actualización."""
        return _system_collect(
            ctx.deps,
            "prepare_system_update",
            lambda service: service.operation(ctx.deps.principal, "update.prepare"),
        )

    @toolset.tool
    def create_system_backup(ctx: RunContext[AgentDeps]) -> dict[str, Any]:
        """Solicitar al ejecutor externo configurado una copia de seguridad verificada."""
        return _system_collect(
            ctx.deps,
            "create_system_backup",
            lambda service: service.operation(ctx.deps.principal, "backup.create"),
        )

    register_agent_extension_tools(toolset, _extension_collect)
    return toolset


def resolve_model(
    settings: Settings,
    selection: Any = None,
    *,
    http_client: Any = None,
) -> Model:
    """Build the selected provider/model; credentials come from the environment."""
    if isinstance(selection, ProviderModelSelection):
        return cast(Model, build_provider_model(selection, http_client=http_client))
    if selection is not None:
        provider_name, model_name = selection.provider, selection.model
    else:
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


#: Inlined text/CSV is bounded; a longer document is truncated with an
#: explicit marker so nothing is dropped silently.
_MAX_INLINE_TEXT = 16_000


def _inline_text(item: ChatAttachmentInput) -> str:
    """Render a stored text attachment as a bounded, clearly fenced block."""

    body = item.data.decode("utf-8-sig", errors="replace")
    if len(body) > _MAX_INLINE_TEXT:
        body = f"{body[:_MAX_INLINE_TEXT]}\n[contenido truncado]"
    return f"Archivo adjunto {item.filename}:\n```\n{body}\n```"


def user_content(prompt: str, attachments: Sequence[ChatAttachmentInput]) -> str | list[Any]:
    """Prompt text plus validated attachment bytes; never a remote URL.

    Images and documents travel as Pydantic AI ``BinaryContent`` built from the
    stored bytes, so no provider ever fetches a URL supplied by a browser.
    Text/CSV is inlined because every model accepts it.
    """
    from pydantic_ai.messages import BinaryContent

    parts: list[Any] = []
    for item in attachments:
        if item.kind == "text":
            block = _inline_text(item)
            prompt = f"{prompt}\n\n{block}" if prompt else block
        else:
            parts.append(BinaryContent(data=item.data, media_type=item.media_type))
    if not parts:
        return prompt
    if prompt:
        parts.append(prompt)
    return parts


def user_prompt(request: ChatRequest) -> str | list[Any]:
    """Full browser request as the user turn the provider receives."""

    prompt = request.message
    if request.assetId:
        marker = f"Activo seleccionado: {request.assetId}"
        prompt = f"{prompt}\n\n{marker}" if prompt else marker
    return user_content(prompt, request.attachments)


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
        system: Any = None,
        provider_http_client: Any = None,
        extensions: Any = None,
        extension_development: Any = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._model = model
        self._system = system
        self._provider_http_client = provider_http_client
        self._extensions = extensions
        self._extension_development = extension_development
        self._owns_provider_client = provider_http_client is None
        self._agent: Agent[AgentDeps, str] | None = None
        self._selection_key: tuple[str, str] | None = None

    async def aclose(self) -> None:
        """Close the provider transport this runtime created, if any."""
        client = self._provider_http_client
        self._agent = None
        self._selection_key = None
        if client is None or not self._owns_provider_client:
            return
        self._provider_http_client = None
        self._owns_provider_client = False
        close = getattr(client, "aclose", None)
        if close is not None:
            await close()

    def attach_system(self, system: Any) -> None:
        """Use the application's canonical system service for typed system tools."""
        self._system = system

    @property
    def configured(self) -> bool:
        if self._model is not None:
            return True
        return self._selection() is not None

    def _selection(self) -> Any:
        """Read the persisted selection now, so a change affects the next turn."""
        if self._model is not None:
            return None
        from itsm.system.providers import effective_selection

        try:
            with self._session_factory() as session:
                return effective_selection(session, self._settings)
        except Exception as exc:  # a missing table falls back to the environment
            logger.warning("provider selection could not be read: %s", type(exc).__name__)
            return None

    def _compose(self, model: Model) -> Agent[AgentDeps, str]:
        agent: Agent[AgentDeps, str] = Agent(
            model,
            deps_type=AgentDeps,
            output_type=str,
            instructions=INSTRUCTIONS,
            retries=1,
            model_settings=ModelSettings(max_tokens=self._settings.agent_max_output_tokens),
            toolsets=[build_toolset()],
        )
        return agent

    def _build(
        self,
        selection: Any = None,
        provider_selection: ProviderModelSelection | None = None,
        *,
        http_client: Any = None,
    ) -> Agent[AgentDeps, str]:
        model = self._model
        if model is None:
            if provider_selection is not None:
                client = http_client or self._provider_http_client
                if client is None:
                    client = build_provider_http_client(
                        allow_private=provider_selection.allow_private
                    )
                    self._provider_http_client = client
                    self._owns_provider_client = True
                try:
                    model = resolve_model(
                        self._settings,
                        provider_selection,
                        http_client=client,
                    )
                except AgentUnavailable:
                    raise
                except Exception as exc:  # provider construction must stay explicit
                    logger.warning("agent provider could not be configured: %s", type(exc).__name__)
                    raise AgentUnavailable() from None
            elif selection is None:
                raise AgentUnavailable()
            else:
                try:
                    model = resolve_model(self._settings, selection)
                except AgentUnavailable:
                    raise
                except Exception as exc:  # provider construction must stay explicit
                    logger.warning("agent model could not be configured: %s", type(exc).__name__)
                    raise AgentUnavailable() from None
        return self._compose(model)

    def _ensure(
        self,
        provider_selection: ProviderModelSelection | None = None,
        *,
        http_client: Any = None,
    ) -> Agent[AgentDeps, str]:
        if provider_selection is not None:
            # Provider records can change between turns; never reuse a model
            # built for a previous endpoint or credential.
            return self._build(provider_selection=provider_selection, http_client=http_client)
        if self._model is not None:
            if self._agent is None:
                self._agent = self._build()
            return self._agent
        selection = self._selection()
        key = None if selection is None else (selection.provider, selection.model)
        if self._agent is None or key != self._selection_key:
            self._agent = self._build(selection)
            self._selection_key = key
        return self._agent

    def chat(
        self,
        principal: Principal,
        request: ChatRequest,
        *,
        credential_digest: str | None = None,
        provider_selection: ProviderModelSelection | None = None,
    ) -> ChatReply:
        """Run one bounded turn; tool authorization happens per operation."""
        reply, _ = self.chat_with_usage(
            principal,
            request,
            credential_digest=credential_digest,
            provider_selection=provider_selection,
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
    ) -> tuple[ChatReply, AgentUsage]:
        """Shared run that also returns real usage, including on failure."""
        turn_client = None
        if provider_selection is not None and self._provider_http_client is None:
            # A guarded client is scoped to this turn: a global provider's
            # unrestricted pool must never be reused for a personal one.
            turn_client = build_provider_http_client(allow_private=provider_selection.allow_private)
        try:
            agent = self._ensure(provider_selection, http_client=turn_client)
            if quota is not None:
                from itsm.agents.quota import BudgetedModel

                agent = self._compose(
                    BudgetedModel(
                        agent.model,
                        quota,
                        context_tokens=self._settings.agent_context_token_bound,
                        output_tokens=self._settings.agent_max_output_tokens,
                    )
                )
            deps = AgentDeps(
                settings=self._settings,
                session_factory=self._session_factory,
                principal=principal,
                credential_digest=credential_digest,
                system=self._system,
                extensions=self._extensions,
                extension_development=self._extension_development,
            )
            prompt = user_prompt(request)
            tokens = usage if usage is not None else AgentUsage()
            run_usage = RunUsage()
            limits = UsageLimits(
                request_limit=self._settings.agent_max_steps,
                tool_calls_limit=self._settings.agent_max_steps * 4,
            )
            if token_limit is not None and token_limit > 0:
                limits = UsageLimits(
                    request_limit=self._settings.agent_max_steps,
                    tool_calls_limit=self._settings.agent_max_steps * 4,
                    total_tokens_limit=token_limit,
                )
            try:
                if turn_client is None:
                    result = agent.run_sync(
                        prompt,
                        deps=deps,
                        message_history=_history(request.conversation),
                        usage_limits=limits,
                        usage=run_usage,
                    )
                else:
                    transport = turn_client
                    turn_client = None
                    result = asyncio.run(
                        self._run_provider_turn(
                            agent,
                            prompt,
                            deps,
                            request,
                            limits,
                            run_usage,
                            transport,
                        )
                    )
            except BaseException:
                self._apply_usage(tokens, run_usage)
                raise
            self._apply_usage(tokens, run_usage)
            message = result.output.strip() or "No pude completar la solicitud."
            return (
                ChatReply(
                    message=message[:4000],
                    actions=deps.actions,
                    results=deps.results,
                    approvalPending=deps.approval_pending,
                ),
                tokens,
            )
        finally:
            if turn_client is not None:
                try:
                    asyncio.run(turn_client.aclose())
                except Exception:
                    logger.warning("provider transport could not be closed")

    async def _run_provider_turn(
        self,
        agent: Agent[AgentDeps, str],
        prompt: str | list[Any],
        deps: AgentDeps,
        request: ChatRequest,
        limits: UsageLimits,
        run_usage: RunUsage,
        transport: Any,
    ) -> Any:
        """Run provider inference and close its transport on the same loop."""
        try:
            return await agent.run(
                prompt,
                deps=deps,
                message_history=_history(request.conversation),
                usage_limits=limits,
                usage=run_usage,
            )
        finally:
            try:
                await transport.aclose()
            except Exception:
                logger.warning("provider transport could not be closed")

    @staticmethod
    def _apply_usage(target: AgentUsage, source: RunUsage) -> None:
        target.input_tokens = max(0, int(getattr(source, "input_tokens", 0) or 0))
        target.output_tokens = max(0, int(getattr(source, "output_tokens", 0) or 0))


__all__ = [
    "INSTRUCTIONS",
    "SYSTEM_TOOL_NAMES",
    "TOOL_NAMES",
    "AgentDeps",
    "AgentRuntime",
    "AgentUnavailable",
    "AgentUsage",
    "BatchUpdateArg",
    "ChatAction",
    "ChatAttachmentInput",
    "ChatReply",
    "ChatRequest",
    "ConversationTurn",
    "InterventionPartArg",
    "ProviderModelSelection",
    "build_toolset",
    "resolve_model",
    "user_content",
    "user_prompt",
]
