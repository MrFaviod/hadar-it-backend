"""Selected inventory, directory and relationship tools exposed over MCP.

The server is mounted inside the existing FastAPI application. Every request is
authenticated by the same persisted bearer credential as the REST API, and each
tool re-validates that credential immediately before touching the database, so a
revoked machine identity cannot keep using an open MCP session. Tools never
accept an actor, a source or a permission from their arguments: the principal
comes from the trusted bearer transport and history source is always ``mcp``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import date
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.dependencies import get_http_headers
from itsm.config import Settings
from itsm.directory.service import DirectoryService
from itsm.identity.hashing import hash_token
from itsm.identity.service import (
    AuthenticationFailed,
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
from itsm.inventory.service import BATCH_LIMIT, AssetView, InventoryService
from itsm.operations import tools as operations_tools
from itsm.redundancy.service import RedundancyService
from itsm.relationships.service import RelationshipService
from itsm.reports.schemas import ReportRequest
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

logger = logging.getLogger("itsm.mcp")

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
)

INSTRUCTIONS = """\
These tools operate on the ITSM asset inventory with the permissions of the
authenticated machine identity. IDs are permanent UUIDs; the quick code may
change. Use search/get before updating, and never assume an asset exists.
Maintenance completion recalculates the next due date; interventions and
incidents are recorded in one structured call. Preparing an incident resolution
never changes its status: only confirming the prepared token, revalidated
against current authority and state, resolves it.
Monitoring reports Prometheus provenance and the queried period. Missing data or
an unavailable metrics service is not proof that a device is down. Acknowledging
never resolves an alert, recovery never closes an incident, and preparing a
maintenance window does not persist or silence anything.
Reports and labels accept structured templates, canonical filters and bounded physical
dimensions, never HTML or shell commands. Preparation does not queue a file. Generation
returns a durable job; only completed status confirms protected document references.
Operational summaries and global search report their period, engine and provenance;
relational queries start from a focus or page the global graph, never dump every module.
"""


def compact(view: AssetView, fields: list[str] | None = None) -> dict[str, Any]:
    """Project only explicitly allowed public fields."""
    return project(view, fields)


MAX_PAGE = 50


def _bounded_page(limit: int, offset: int) -> tuple[int, int]:
    """Clamp one tool page so an external agent cannot request unbounded rows."""
    return max(1, min(int(limit), MAX_PAGE)), max(0, int(offset))


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
    if len(values) > MAX_PAGE:
        raise ValidationFailed(f"{label} must contain at most {MAX_PAGE} ids")
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


class DatabaseTokenVerifier(TokenVerifier):
    """Validate machine bearer tokens against persisted credentials per request."""

    def __init__(self, settings: Settings, session_factory: Callable[[], Session]) -> None:
        super().__init__(required_scopes=["assets.view"])
        self._settings = settings
        self._session_factory = session_factory

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            with self._session_factory() as session:
                service = IdentityService(session, self._settings)
                context = service.authenticate_token(token)
        except AuthenticationFailed, PermissionDenied:
            return None
        except Exception:  # storage errors must never authenticate anyone
            logger.exception("mcp token verification failed")
            return None
        return AccessToken(
            token=token,
            client_id=context.principal.actor_id,
            scopes=list(context.permissions),
            subject=context.principal.username,
            claims={
                "actorKind": context.principal.kind,
                "username": context.principal.username,
            },
        )


class RedundancyMemberInput(BaseModel):
    """One group member as sent on the wire; the asset id must already exist."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1, max_length=36)
    role: str | None = None
    share: Any = None


class BatchUpdateInput(BaseModel):
    """One bounded batch entry; the permanent id is the only target selector."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1, max_length=36)
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


class InterventionPartInput(BaseModel):
    """One consumed part; money uses canonical decimal strings."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    quantity: int
    unit_cost: str | None = None


def _bearer_token() -> str:
    """Read the raw bearer token from the trusted HTTP transport, never the args."""
    headers = get_http_headers(include={"authorization"})
    scheme, _, token = headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise ToolError("authentication required")
    return token.strip()


def _translate(exc: Exception) -> ToolError:
    if isinstance(exc, PermissionDenied):
        return ToolError("permission denied")
    if isinstance(exc, Conflict):
        return ToolError(str(exc))
    if isinstance(exc, NotFound):
        return ToolError("asset not found")
    if isinstance(exc, ValidationFailed):
        return ToolError(str(exc))
    logger.error("mcp inventory operation failed: %s", type(exc).__name__)
    return ToolError("inventory operation failed")


def create_mcp_server(settings: Settings, session_factory: Callable[[], Session]) -> FastMCP:
    """Build the mounted server with typed inventory, directory and technical tools."""
    server = FastMCP(
        "itsm-inventory",
        instructions=INSTRUCTIONS,
        auth=DatabaseTokenVerifier(settings, session_factory),
    )

    @contextmanager
    def inventory() -> Iterator[tuple[InventoryService, Principal]]:
        token = _bearer_token()
        with session_factory() as session:
            identity = IdentityService(session, settings)
            try:
                context = identity.authenticate_token(token)
            except AuthenticationFailed, PermissionDenied:
                raise ToolError("authentication required") from None
            yield InventoryService(session, settings, identity=identity), context.principal

    def run(operation: Callable[[InventoryService, Principal], Any]) -> Any:
        try:
            with inventory() as (service, principal):
                return operation(service, principal)
        except ToolError:
            raise
        except Exception as exc:
            raise _translate(exc) from None

    def run_with(
        factory: Callable[
            [],
            Any,
        ],
        operation: Callable[[Any, Principal], Any],
    ) -> Any:
        """Run one tool against another canonical service with the same bearer principal."""
        try:
            with factory() as (service, principal):
                return operation(service, principal)
        except ToolError:
            raise
        except Exception as exc:
            raise _translate(exc) from None

    @contextmanager
    def directory() -> Iterator[tuple[DirectoryService, Principal]]:
        token = _bearer_token()
        with session_factory() as session:
            identity = IdentityService(session, settings)
            try:
                context = identity.authenticate_token(token)
            except AuthenticationFailed, PermissionDenied:
                raise ToolError("authentication required") from None
            yield DirectoryService(session, settings, identity=identity), context.principal

    @contextmanager
    def relations() -> Iterator[tuple[RelationshipService, Principal]]:
        token = _bearer_token()
        with session_factory() as session:
            identity = IdentityService(session, settings)
            try:
                context = identity.authenticate_token(token)
            except AuthenticationFailed, PermissionDenied:
                raise ToolError("authentication required") from None
            yield (
                RelationshipService(session, settings, identity=identity, source="mcp"),
                context.principal,
            )

    @contextmanager
    def redundancy() -> Iterator[tuple[RedundancyService, Principal]]:
        token = _bearer_token()
        with session_factory() as session:
            identity = IdentityService(session, settings)
            try:
                context = identity.authenticate_token(token)
            except AuthenticationFailed, PermissionDenied:
                raise ToolError("authentication required") from None
            yield (
                RedundancyService(session, settings, identity=identity, source="mcp"),
                context.principal,
            )

    @contextmanager
    def maintenance() -> Iterator[tuple[Any, Principal]]:
        from itsm.maintenance.service import MaintenanceService

        token = _bearer_token()
        with session_factory() as session:
            identity = IdentityService(session, settings)
            try:
                context = identity.authenticate_token(token)
            except AuthenticationFailed, PermissionDenied:
                raise ToolError("authentication required") from None
            yield (
                MaintenanceService(session, settings, identity=identity, source="mcp"),
                context.principal,
            )

    @contextmanager
    def interventions() -> Iterator[tuple[Any, Principal]]:
        from itsm.interventions.service import InterventionService

        token = _bearer_token()
        with session_factory() as session:
            identity = IdentityService(session, settings)
            try:
                context = identity.authenticate_token(token)
            except AuthenticationFailed, PermissionDenied:
                raise ToolError("authentication required") from None
            yield (
                InterventionService(session, settings, identity=identity, source="mcp"),
                context.principal,
            )

    @contextmanager
    def monitoring() -> Iterator[tuple[Any, Principal]]:
        from itsm.monitoring.service import MonitoringService
        from itsm.notifications.service import record_alert_event

        token = _bearer_token()
        with session_factory() as session:
            identity = IdentityService(session, settings)
            try:
                context = identity.authenticate_token(token)
            except AuthenticationFailed, PermissionDenied:
                raise ToolError("authentication required") from None
            yield (
                MonitoringService(
                    session, settings, identity=identity, source="mcp", notifier=record_alert_event
                ),
                context.principal,
            )

    @contextmanager
    def operations() -> Iterator[tuple[Session, IdentityService, Principal]]:
        """Expose one revalidated session to the shared operational tools."""
        token = _bearer_token()
        with session_factory() as session:
            identity = IdentityService(session, settings)
            try:
                context = identity.authenticate_token(token)
            except AuthenticationFailed, PermissionDenied:
                raise ToolError("authentication required") from None
            yield session, identity, context.principal

    def run_operations(
        operation: Callable[[Session, IdentityService, Principal], Any],
    ) -> Any:
        """Run one shared query, mapping only identity errors to tool text."""
        try:
            with operations() as (session, identity, principal):
                return operation(session, identity, principal)
        except ToolError:
            raise
        except IdentityError as exc:
            raise _translate(exc) from None
        except Exception as exc:
            logger.warning("mcp operational tool failed: %s", type(exc).__name__)
            raise ToolError("operational query failed") from None

    @server.tool
    def search_assets(
        query: str | None = None,
        category: str | None = None,
        site: str | None = None,
        status: str | None = None,
        quick_code: str | None = None,
        limit: int = 10,
        archived: bool | None = None,
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Search assets by text, category, site, status or quick code."""

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            page = service.search(
                principal,
                query=query,
                category=category,
                site=site,
                status=status,
                quick_code=quick_code,
                limit=limit,
                archived=archived,
            )
            return {"total": page.total, "items": [compact(view, fields) for view in page.items]}

        return run(operation)

    @server.tool
    def get_asset(asset_id: str, fields: list[str] | None = None) -> dict[str, Any]:
        """Read one asset by its permanent UUID."""

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            return compact(service.get(principal, asset_id), fields)

        return run(operation)

    @server.tool
    def create_asset(
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
        """Register a new asset; the server generates the permanent id."""
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

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            validate_fields(fields)
            return compact(
                service.create(
                    principal,
                    {key: value for key, value in values.items() if value is not None},
                ),
                fields,
            )

        return run(operation)

    @server.tool
    def update_asset(
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
        """Update selected fields of one asset; its permanent id never changes."""
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

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            validate_fields(fields)
            return compact(service.update(principal, asset_id, changes), fields)

        return run(operation)

    @server.tool
    def batch_update_assets(
        updates: list[BatchUpdateInput], fields: list[str] | None = None
    ) -> dict[str, Any]:
        """Update several assets atomically; the whole batch is bounded."""
        if len(updates) > BATCH_LIMIT:
            raise ToolError(f"updates must have at most {BATCH_LIMIT} entries")
        changes = []
        for item in updates:
            payload = item.model_dump(exclude_none=True)
            asset_id = payload.pop("asset_id")
            changes.append({"id": asset_id, **payload})

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            validate_fields(fields)
            result = service.batch(principal, update=changes)
            return {
                "created": [compact(view, fields) for view in result.created],
                "updated": [compact(view, fields) for view in result.updated],
            }

        return run(operation)

    @server.tool
    def clone_asset(
        asset_id: str, name: str | None = None, fields: list[str] | None = None
    ) -> dict[str, Any]:
        """Duplicate an asset with a fresh permanent UUID and quick code."""

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            validate_fields(fields)
            return compact(
                service.clone(principal, asset_id, {"name": name} if name else None), fields
            )

        return run(operation)

    @server.tool
    def archive_asset(asset_id: str, reason: str | None = None) -> dict[str, Any]:
        """Archive without changing location, responsible or status."""
        return run(
            lambda service, principal: compact(service.archive(principal, asset_id, reason=reason))
        )

    @server.tool
    def restore_asset(asset_id: str) -> dict[str, Any]:
        """Remove the archive flag without changing other asset properties."""
        return run(lambda service, principal: compact(service.restore(principal, asset_id)))

    @server.tool
    def retire_asset(asset_id: str, reason: str) -> dict[str, Any]:
        """Retire with a recorded reason and service-level assignment checks."""
        return run(
            lambda service, principal: compact(service.retire(principal, asset_id, reason=reason))
        )

    @server.tool
    def get_asset_history(asset_id: str, limit: int = 20, offset: int = 0) -> dict[str, Any]:
        """Read bounded immutable history, including retained history after purge."""
        return run(
            lambda service, principal: history_payload(
                service.history(principal, asset_id, limit=limit, offset=offset)
            )
        )

    @server.tool
    def get_inventory_config() -> dict[str, Any]:
        """Read configured category forms, fields, statuses and code rules."""
        return run(
            lambda service, principal: InventoryCatalog(service._session, settings).get(principal)
        )

    @server.tool
    def search_locations(
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
        """Search sites, buildings, floors or rooms; tree mode returns a bounded hierarchy."""

        def operation(service: DirectoryService, principal: Principal) -> dict[str, Any]:
            if tree:
                built = service.location_tree(
                    principal, root_id=parent_id, depth=depth, max_nodes=max_nodes
                )
                return {
                    "routes": [node.location.as_payload() for node in built.roots],
                    "nodeCount": built.node_count,
                    "depth": built.depth,
                    "truncated": built.truncated,
                }
            page = service.list_locations(
                principal,
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

        return run_with(directory, operation)

    @server.tool
    def search_people(
        query: str | None = None,
        status: str | None = None,
        department_id: str | None = None,
        site_id: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Search responsible people by text, status, department or site."""

        def operation(service: DirectoryService, principal: Principal) -> dict[str, Any]:
            page = service.list_people(
                principal,
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

        return run_with(directory, operation)

    @server.tool
    def assign_asset(
        asset_id: str,
        person_id: str,
        reason: str | None = None,
        notes: str | None = None,
        effective_at: str | None = None,
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Assign one asset to an active directory person."""

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            validate_fields(fields)
            return compact(
                service.assign_responsible(
                    principal,
                    asset_id,
                    person_id,
                    reason=reason,
                    notes=notes,
                    effective_at=moment(effective_at),
                ),
                fields,
            )

        return run(operation)

    @server.tool
    def return_asset(
        asset_id: str,
        reason: str,
        notes: str | None = None,
        effective_at: str | None = None,
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Record the return of an assigned asset and clear its responsible person."""

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            validate_fields(fields)
            return compact(
                service.return_responsible(
                    principal,
                    asset_id,
                    reason=reason,
                    notes=notes,
                    effective_at=moment(effective_at),
                ),
                fields,
            )

        return run(operation)

    @server.tool
    def transfer_asset(
        asset_id: str,
        reason: str,
        site_id: str | None = None,
        location_id: str | None = None,
        notes: str | None = None,
        effective_at: str | None = None,
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Transfer an asset to another site or location without changing its id."""

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            validate_fields(fields)
            return compact(
                service.transfer(
                    principal,
                    asset_id,
                    site_id=site_id,
                    location_id=location_id,
                    reason=reason,
                    notes=notes,
                    effective_at=moment(effective_at),
                ),
                fields,
            )

        return run(operation)

    @server.tool
    def get_asset_relations(
        asset_ids: list[str],
        type_key: str | None = None,
        direction: str = "both",
        limit: int = 20,
    ) -> dict[str, Any]:
        """Read the relations of several assets in one bounded call."""

        def operation(service: RelationshipService, principal: Principal) -> dict[str, Any]:
            page = service.list(
                principal,
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

        return run_with(relations, operation)

    @server.tool
    def create_relationship(
        source_id: str,
        target_id: str,
        type_key: str,
        reason: str | None = None,
        notes: str | None = None,
        effective_at: str | None = None,
    ) -> dict[str, Any]:
        """Create one directed typed relation between two existing assets."""

        def operation(service: RelationshipService, principal: Principal) -> dict[str, Any]:
            view = service.create(
                principal,
                source_id=source_id,
                target_id=target_id,
                type_key=type_key,
                reason=reason,
                notes=notes,
                effective_at=moment(effective_at),
            )
            return view.as_payload()

        return run_with(relations, operation)

    @server.tool
    def remove_relationship(
        relationship_id: str,
        reason: str | None = None,
        notes: str | None = None,
        effective_at: str | None = None,
    ) -> dict[str, Any]:
        """Remove one relation, keeping the history of both assets."""

        def operation(service: RelationshipService, principal: Principal) -> dict[str, Any]:
            view = service.remove(
                principal,
                relationship_id,
                reason=reason,
                notes=notes,
                effective_at=moment(effective_at),
            )
            return view.as_payload()

        return run_with(relations, operation)

    @server.tool
    def move_host(
        child_id: str,
        new_host_id: str,
        reason: str,
        notes: str | None = None,
        effective_at: str | None = None,
    ) -> dict[str, Any]:
        """Move a virtual asset to another host without losing its permanent id."""

        def operation(service: RelationshipService, principal: Principal) -> dict[str, Any]:
            return service.move_host(
                principal,
                child_id,
                new_host_id,
                reason=reason,
                notes=notes,
                effective_at=moment(effective_at),
            ).as_payload()

        return run_with(relations, operation)

    @server.tool
    def get_asset_map(
        site_id: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Read bounded organizational map data: sites and plan positions."""

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            return service.map(principal, site_id=site_id, limit=limit, offset=offset).as_payload()

        return run(operation)

    @server.tool
    def list_redundancy_groups(
        query: str | None = None,
        active: bool | None = None,
        mode: str | None = None,
        limit: int = 10,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List redundancy groups with their replicas in one bounded page."""

        def operation(service: RedundancyService, principal: Principal) -> dict[str, Any]:
            page = service.list(
                principal,
                query=query,
                active=active,
                mode=mode,
                limit=limit,
                offset=offset,
            )
            return {"groups": page.as_payload()}

        return run_with(redundancy, operation)

    @server.tool
    def get_redundancy_group(group_id: str) -> dict[str, Any]:
        """Read one redundancy group: mode, activation, roles and real hosts."""

        def operation(service: RedundancyService, principal: Principal) -> dict[str, Any]:
            return {"group": service.get(principal, group_id).as_payload()}

        return run_with(redundancy, operation)

    @server.tool
    def save_redundancy_group(
        group_id: str | None = None,
        name: str | None = None,
        description: str | None = None,
        mode: str | None = None,
        active: bool | None = None,
        members: list[RedundancyMemberInput] | None = None,
        reason: str | None = None,
        notes: str | None = None,
        effective_at: str | None = None,
    ) -> dict[str, Any]:
        """Create a group (no group_id) or replace it with a complete member list."""

        def operation(service: RedundancyService, principal: Principal) -> dict[str, Any]:
            specs = (
                None
                if members is None
                else [
                    {"asset_id": member.asset_id, "role": member.role, "share": member.share}
                    for member in members
                ]
            )
            if group_id is None:
                if name is None or mode is None or specs is None:
                    raise ValidationFailed("name, mode and members are required to create a group")
                view = service.create(
                    principal,
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
                view = service.update(principal, group_id, **changes)
            return {"group": view.as_payload()}

        return run_with(redundancy, operation)

    @contextmanager
    def workflows():
        from itsm.workflows.service import WorkflowService

        with inventory() as (service, principal):
            yield (
                WorkflowService(
                    service._session,
                    settings,
                    identity=IdentityService(service._session, settings),
                    source="mcp",
                ),
                principal,
            )

    def run_workflow(operation: Callable[[Any, Principal], Any]) -> Any:
        """Run one workflow tool and keep every row-bearing result compact."""
        from itsm.workflows.service import compact_operation

        return compact_operation(run_with(workflows, operation))

    @server.tool
    def prepare_inventory_import(
        csv_text: str, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Analyze CSV text; accepts no filesystem or network locator."""
        return run_workflow(lambda s, p: s.analyze(p, csv_text.encode(), "assets.csv", options))

    @server.tool
    def preview_bulk_operation(
        asset_ids: list[str],
        changes: dict[str, Any],
        action: str = "update",
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Prepare exact targets and changes for separate human approval."""
        return run_workflow(
            lambda s, p: s.preview(
                p, asset_ids=asset_ids, changes=changes, action=action, reason=reason
            )
        )

    @server.tool
    def get_inventory_operation(
        operation_id: str, offset: int = 0, limit: int = 20
    ) -> dict[str, Any]:
        """Read bounded conflicts, progress and receipts."""
        return run_workflow(
            lambda s, p: s.get(p, operation_id, offset=offset, limit=min(limit, 50))
        )

    @server.tool
    def resolve_import_conflict(
        operation_id: str,
        index: int,
        action: str,
        asset_id: str | None = None,
        values: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Resolve a preview row and invalidate previous approval."""
        return run_workflow(
            lambda s, p: s.resolve(p, operation_id, index, action, asset_id, values)
        )

    @server.tool
    def apply_inventory_operation(operation_id: str) -> dict[str, Any]:
        """Execute an already human-approved operation with current bearer permissions."""
        return run_workflow(lambda s, p: s.execute(p, operation_id))

    def run_report(operation: Callable[[Any, Principal, str], Any]) -> dict[str, Any]:
        from itsm.reports.service import build_report_service
        from itsm.tasks import create_task_queue

        # Revalidate the transport bearer before the operation. Only its digest
        # is stored as the job locator; the worker re-checks that exact credential.
        token = _bearer_token()
        with session_factory() as session:
            identity = IdentityService(session, settings)
            try:
                context = identity.authenticate_token(token)
            except AuthenticationFailed, PermissionDenied:
                raise ToolError("authentication required") from None
            try:
                service = build_report_service(
                    settings, session_factory, task_queue=create_task_queue(settings)
                )
                return operation(service, context.principal, hash_token(token))
            except ToolError:
                raise
            except Exception as exc:
                raise _translate(exc) from None

    @server.tool
    def list_report_templates() -> dict[str, Any]:
        """List authorized default and custom structured report templates."""
        return run_report(lambda service, principal, _digest: service.templates(principal))

    @server.tool
    def prepare_report(request: ReportRequest) -> dict[str, Any]:
        """Prepare canonical report data without queuing; return at most twenty rows."""

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

        return run_report(operation)

    @server.tool
    def generate_report(request: ReportRequest) -> dict[str, Any]:
        """Queue PDF/CSV/Excel generation and return an authorized durable job locator."""
        return run_report(
            lambda service, principal, digest: service.generate(
                principal, request, credential_digest=digest
            )
        )

    @server.tool
    def report_job_status(job_id: str) -> dict[str, Any]:
        """Read current owned progress, errors and protected document references."""
        return run_report(lambda service, principal, _digest: service.job(principal, job_id))

    @server.tool
    def report_documents(job_id: str) -> dict[str, Any]:
        """Return protected download references, never file bytes or server paths."""

        def operation(service, principal, _digest):
            job = service.job(principal, job_id)
            return {"id": job["id"], "status": job["status"], "documents": job["documents"]}

        return run_report(operation)

    @server.tool
    def generate_labels(request: ReportRequest) -> dict[str, Any]:
        """Queue physical labels for canonical selected/filter-matched assets."""

        def operation(service, principal, digest):
            if request.labels is None:
                raise ValidationFailed("label options are required")
            return service.generate(principal, request, credential_digest=digest)

        return run_report(operation)

    @server.tool
    def search_maintenance(
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
        """List pending, upcoming or overdue maintenance work in one bounded page."""
        bounded_limit, bounded_offset = _bounded_page(limit, offset)
        horizon = max(0, min(int(upcoming_days), 365))

        def operation(service: Any, principal: Principal) -> dict[str, Any]:
            page = service.list_plans(
                principal,
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

        return run_with(maintenance, operation)

    @server.tool
    def complete_maintenance(
        plan_id: str, completed_on: str | None = None, notes: str | None = None
    ) -> dict[str, Any]:
        """Complete authorized preventive work; the service recalculates the next due date."""

        def operation(service: Any, principal: Principal) -> dict[str, Any]:
            completed_value = _optional_iso_date(completed_on, "completedOn")
            view = service.complete_plan(
                principal, plan_id, completed_on=completed_value, notes=notes
            )
            return {"plan": view.as_payload()}

        return run_with(maintenance, operation)

    @server.tool
    def record_intervention(
        asset_id: str,
        type: str = "corrective",
        description: str | None = None,
        technician_person_id: str | None = None,
        occurred_on: str | None = None,
        status: str | None = None,
        notes: str | None = None,
        parts: list[InterventionPartInput] | None = None,
        labor_cost: str | None = None,
        attachment_ids: list[str] | None = None,
        incident_id: str | None = None,
        plan_id: str | None = None,
    ) -> dict[str, Any]:
        """Record one complete intervention, including parts and attachment ids, in one call."""

        def operation(service: Any, principal: Principal) -> dict[str, Any]:
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
            view = service.create(principal, values)
            return {"intervention": view.as_payload()}

        return run_with(interventions, operation)

    @server.tool
    def create_incident(
        primary_asset_id: str,
        description: str,
        priority: str = "normal",
        affected_asset_ids: list[str] | None = None,
        responsible_person_id: str | None = None,
        opened_on: str | None = None,
    ) -> dict[str, Any]:
        """Create an incident with its primary asset and every affected asset in one call."""

        def operation(service: Any, principal: Principal) -> dict[str, Any]:
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
            view = service.create_incident(principal, values)
            return {"incident": view.as_payload()}

        return run_with(interventions, operation)

    @server.tool
    def link_incident_assets(incident_id: str, affected_asset_ids: list[str]) -> dict[str, Any]:
        """Replace the unique affected-asset set of an existing incident."""

        def operation(service: Any, principal: Principal) -> dict[str, Any]:
            affected = _bounded_ids(affected_asset_ids, "affectedAssetIds") or []
            view = service.update_incident_assets(principal, incident_id, affected)
            return {"incident": view.as_payload()}

        return run_with(interventions, operation)

    @server.tool
    def get_technical_history(asset_id: str, limit: int = 20, offset: int = 0) -> dict[str, Any]:
        """Read persisted intervention/incident history for one asset."""
        bounded_limit, bounded_offset = _bounded_page(limit, offset)

        def operation(service: Any, principal: Principal) -> dict[str, Any]:
            page = service.asset_technical_history(
                principal, asset_id, limit=bounded_limit, offset=bounded_offset
            )
            return page.as_payload()

        return run_with(interventions, operation)

    @server.tool
    def prepare_incident_resolution(incident_id: str, note: str | None = None) -> dict[str, Any]:
        """Prepare a resolution suggestion; it never resolves the incident by itself."""

        def operation(service: Any, principal: Principal) -> dict[str, Any]:
            suggestion = service.prepare_resolution(principal, incident_id, note=note)
            return {"resolution": suggestion.as_payload()}

        return run_with(interventions, operation)

    @server.tool
    def confirm_incident_resolution(
        incident_id: str, token: str, note: str | None = None
    ) -> dict[str, Any]:
        """Confirm a prepared resolution; authority and current state are revalidated now."""

        def operation(service: Any, principal: Principal) -> dict[str, Any]:
            view = service.confirm_resolution(principal, incident_id, token, note=note)
            return {"incident": view.as_payload()}

        return run_with(interventions, operation)

    @server.tool
    def search_incidents(
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
        """List incidents by state, priority, asset, responsible person or period."""
        bounded_limit, bounded_offset = _bounded_page(limit, offset)

        def operation(service: Any, principal: Principal) -> dict[str, Any]:
            page = service.list_incidents(
                principal,
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

        return run_with(interventions, operation)

    @server.tool
    def get_asset_availability(asset_id: str, period: str = "24h") -> dict[str, Any]:
        """Read measured availability with explicit missing states, period and provenance."""
        from itsm.monitoring.projection import summarize_device

        return run_with(
            monitoring,
            lambda service, principal: summarize_device(
                service.get_device(principal, asset_id, period)
            ),
        )

    @server.tool
    def get_asset_metrics(asset_id: str, period: str = "24h") -> dict[str, Any]:
        """Read bounded historical Prometheus metrics, not arbitrary PromQL or URLs."""
        from itsm.monitoring.projection import summarize_device

        return run_with(
            monitoring,
            lambda service, principal: summarize_device(
                service.get_device(principal, asset_id, period), include_series=True
            ),
        )

    @server.tool
    def investigate_outage(asset_id: str, period: str = "24h") -> dict[str, Any]:
        """Read real availability and persisted alerts without inventing root causes."""
        from itsm.monitoring.projection import summarize_alert, summarize_device

        def operation(service: Any, principal: Principal) -> dict[str, Any]:
            result = summarize_device(service.get_device(principal, asset_id, period))
            alerts = service.list_alerts(principal, asset_id=asset_id, limit=10)
            result["alerts"] = {
                **alerts,
                "items": [summarize_alert(item) for item in alerts["items"]],
            }
            return result

        return run_with(monitoring, operation)

    @server.tool
    def list_active_alerts(
        asset_id: str | None = None, limit: int = 10, offset: int = 0
    ) -> dict[str, Any]:
        """Read one bounded page of authorized firing alerts."""
        from itsm.monitoring.projection import summarize_alert

        def operation(service: Any, principal: Principal) -> dict[str, Any]:
            bounded_limit, bounded_offset = _bounded_page(limit, offset)
            page = service.list_alerts(
                principal,
                limit=bounded_limit,
                offset=bounded_offset,
                state="firing",
                asset_id=asset_id,
            )
            return {**page, "items": [summarize_alert(item) for item in page["items"]]}

        return run_with(monitoring, operation)

    @server.tool
    def acknowledge_alert(alert_id: str, notes: str = "") -> dict[str, Any]:
        """Acknowledge under current authority without resolving or closing an incident."""
        from itsm.monitoring.projection import summarize_alert

        return run_with(
            monitoring,
            lambda service, principal: summarize_alert(
                service.acknowledge(principal, alert_id, notes)
            ),
        )

    @server.tool
    def link_alert_incident(alert_id: str, incident_id: str | None = None) -> dict[str, Any]:
        """Link an existing incident or create one atomically through the canonical service."""
        from itsm.monitoring.projection import summarize_alert

        return run_with(
            monitoring,
            lambda service, principal: summarize_alert(
                service.link_incident(principal, alert_id, incident_id)
            ),
        )

    @server.tool
    def prepare_monitoring_maintenance(alert_id: str) -> dict[str, Any]:
        """Prepare a maintenance suggestion; it never saves a window or creates a silence."""
        return run_with(
            monitoring, lambda service, principal: service.prepare_maintenance(principal, alert_id)
        )

    @server.tool
    def get_operational_summary(
        period: str = "24h", category: str | None = None, site_id: str | None = None
    ) -> dict[str, Any]:
        """Read the bounded operational summary for the requested period and scope."""
        return run_operations(
            lambda session, identity, principal: operations_tools.operational_summary(
                session,
                identity,
                settings,
                principal,
                source="mcp",
                period=period,
                category=category,
                site_id=site_id,
            )
        )

    @server.tool
    def search_everything(
        query: str,
        kinds: list[str] | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Search authorized canonical entities with a bounded page and reported engine."""
        return run_operations(
            lambda session, identity, principal: operations_tools.search_everything(
                session,
                identity,
                settings,
                principal,
                source="mcp",
                query=query,
                kinds=kinds,
                limit=limit,
                offset=offset,
            )
        )

    @server.tool
    def query_relationships(
        asset_id: str | None = None,
        depth: int = 2,
        direction: str = "both",
        type_key: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Traverse persisted relationships from one focus or page the global graph."""
        return run_operations(
            lambda session, identity, principal: operations_tools.query_relationships(
                session,
                identity,
                settings,
                principal,
                source="mcp",
                asset_id=asset_id,
                depth=depth,
                direction=direction,
                type_key=type_key,
                limit=limit,
                offset=offset,
            )
        )

    @server.tool
    def list_saved_views() -> dict[str, Any]:
        """Read the caller's own views, favorites and shortcuts; shared state stays read-only."""
        return run_operations(
            lambda session, identity, principal: operations_tools.list_saved_views(
                session, identity, principal, source="mcp"
            )
        )

    return server


__all__ = ["TOOL_NAMES", "DatabaseTokenVerifier", "compact", "create_mcp_server"]
