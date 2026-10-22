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
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.dependencies import get_http_headers
from itsm.config import Settings
from itsm.directory.service import DirectoryService
from itsm.identity.service import (
    AuthenticationFailed,
    Conflict,
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
from itsm.redundancy.service import RedundancyService
from itsm.relationships.service import RelationshipService
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
)

INSTRUCTIONS = """\
These tools operate on the ITSM asset inventory with the permissions of the
authenticated machine identity. IDs are permanent UUIDs; the quick code may
change. Use search/get before updating, and never assume an asset exists.
"""


def compact(view: AssetView, fields: list[str] | None = None) -> dict[str, Any]:
    """Project only explicitly allowed public fields."""
    return project(view, fields)


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
    """Build the mounted server with five inventory tools and no REST export."""
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

    return server


__all__ = ["TOOL_NAMES", "DatabaseTokenVerifier", "compact", "create_mcp_server"]
