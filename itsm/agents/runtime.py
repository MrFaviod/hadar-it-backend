"""Conversational inventory assistant built on a real Pydantic AI agent.

The agent is deliberately narrow: typed inventory, directory and relationship
tools over the canonical services, a server-configured provider/model and
bounded steps, history, input and output. It has no shell, SQL, filesystem or
HTTP tool, and untrusted chat text cannot grant permissions, supply a principal,
forge history metadata or choose a service source.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Literal

from itsm.config import Settings
from itsm.directory.service import DirectoryService
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
from itsm.redundancy.service import RedundancyService
from itsm.relationships.service import RelationshipService
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
- Los mantenimientos y las intervenciones se registran con las herramientas técnicas;
  completar un mantenimiento recalcula su próximo vencimiento.
- Preparar una resolución de incidente no lo resuelve: solo la confirmación con el
  token preparado y la autoridad vigente lo cambia de estado.
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


def _bounded_page(limit: int, offset: int) -> tuple[int, int]:
    """Clamp one tool page so a model cannot request unbounded rows."""
    return max(1, min(int(limit), MAX_RESULTS)), max(0, int(offset))


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


class RedundancyMemberArg(BaseModel):
    """One member of a group; the asset id must be an existing permanent UUID."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1, max_length=36)
    role: str | None = None
    share: Any = None


class InterventionPartArg(BaseModel):
    """One part consumed by an intervention; money is a decimal string or number."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    quantity: str | float | int | None = None
    unit_cost: str | float | None = None


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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
    def archive_asset(
        ctx: RunContext[AgentDeps], asset_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """Archivar sin cambiar estado, responsable ni ubicación."""
        return _execute(
            ctx.deps,
            "archive_asset",
            lambda service: service.archive(ctx.deps.principal, asset_id, reason=reason),
        )

    @agent.tool
    def restore_asset(ctx: RunContext[AgentDeps], asset_id: str) -> dict[str, Any]:
        """Restaurar un activo archivado, sin alterar sus otros datos."""
        return _execute(
            ctx.deps, "restore_asset", lambda service: service.restore(ctx.deps.principal, asset_id)
        )

    @agent.tool
    def retire_asset(ctx: RunContext[AgentDeps], asset_id: str, reason: str) -> dict[str, Any]:
        """Dar de baja con motivo y controles de transición y asignación."""
        return _execute(
            ctx.deps,
            "retire_asset",
            lambda service: service.retire(ctx.deps.principal, asset_id, reason=reason),
        )

    @agent.tool
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

    @agent.tool
    def get_inventory_config(ctx: RunContext[AgentDeps]) -> dict[str, Any]:
        """Consultar formularios, campos, estados y reglas configurados."""
        return _execute(
            ctx.deps,
            "get_inventory_config",
            lambda service: InventoryCatalog(service._session, ctx.deps.settings).get(
                ctx.deps.principal
            ),
        )

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
    def get_redundancy_group(ctx: RunContext[AgentDeps], group_id: str) -> dict[str, Any]:
        """Leer un grupo de redundancia: modo, activación, roles y hosts reales."""

        def operation() -> dict[str, Any]:
            with _redundancy(ctx.deps) as redundancy:
                view = redundancy.get(ctx.deps.principal, group_id)
            return {"group": view.as_payload()}

        return _collect(ctx.deps, "get_redundancy_group", operation)

    @agent.tool
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

    @agent.tool
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
        horizon = max(1, min(int(upcoming_days), 365))

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
                    due_from=due_from,
                    due_to=due_to,
                    completed_from=completed_from,
                    completed_to=completed_to,
                    upcoming_days=horizon,
                    limit=bounded_limit,
                    offset=bounded_offset,
                )
                return _page_payload(page)

        return _collect(ctx.deps, "search_maintenance", operation)

    @agent.tool
    def complete_maintenance(
        ctx: RunContext[AgentDeps],
        plan_id: str,
        completed_on: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any]:
        """Completar un mantenimiento autorizado; el servicio calcula el próximo vencimiento."""

        def operation() -> dict[str, Any]:
            if completed_on is not None and len(completed_on) > 10:
                raise ValidationFailed("completedOn must be an ISO date (YYYY-MM-DD)")
            with _maintenance(ctx.deps) as maintenance:
                view = maintenance.complete_plan(
                    ctx.deps.principal, plan_id, completed_on=completed_on, notes=notes
                )
                return {"plan": view.as_payload()}

        return _collect(ctx.deps, "complete_maintenance", operation)

    @agent.tool
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
        labor_cost: str | float | None = None,
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    @agent.tool
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

    def workflow(ctx, name, call):
        """Run one workflow tool; every row-bearing result stays compact for the chat."""
        from itsm.workflows.service import WorkflowService, compact_operation

        def operation():
            with ctx.deps.session_factory() as session:
                service = WorkflowService(session, ctx.deps.settings, source="agent")
                return compact_operation(call(service, ctx.deps.principal))

        return _collect(ctx.deps, name, operation)

    @agent.tool
    def prepare_inventory_import(
        ctx: RunContext[AgentDeps], csv_text: str, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Analyze bounded CSV text without changing inventory; no path or URL inputs."""
        return workflow(
            ctx,
            "prepare_inventory_import",
            lambda s, p: s.analyze(p, csv_text.encode(), "assets.csv", options),
        )

    @agent.tool
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

    @agent.tool
    def get_inventory_operation(
        ctx: RunContext[AgentDeps], operation_id: str, offset: int = 0, limit: int = 20
    ) -> dict[str, Any]:
        """Read compact conflicts, progress and final row receipts."""
        return workflow(
            ctx,
            "get_inventory_operation",
            lambda s, p: s.get(p, operation_id, offset=offset, limit=min(limit, 50)),
        )

    @agent.tool
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

    @agent.tool
    def apply_inventory_operation(ctx: RunContext[AgentDeps], operation_id: str) -> dict[str, Any]:
        """Apply only a human-approved fixed preview under current permissions."""
        return workflow(ctx, "apply_inventory_operation", lambda s, p: s.execute(p, operation_id))


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
    "InterventionPartArg",
    "resolve_model",
]
