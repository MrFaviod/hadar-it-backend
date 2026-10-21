"""Selected inventory tools exposed over MCP for external agents.

The server is mounted inside the existing FastAPI application. Every request is
authenticated by the same persisted bearer credential as the REST API, and each
tool re-validates that credential immediately before touching the database, so a
revoked machine identity cannot keep using an open MCP session.
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
from itsm.inventory.projection import project, validate_fields
from itsm.inventory.service import BATCH_LIMIT, AssetView, InventoryService
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
            lambda service, principal: service.history(
                principal, asset_id, limit=limit, offset=offset
            ).as_payload()
        )

    @server.tool
    def get_inventory_config() -> dict[str, Any]:
        """Read configured category forms, fields, statuses and code rules."""
        return run(
            lambda service, principal: InventoryCatalog(service._session, settings).get(principal)
        )

    return server


__all__ = ["TOOL_NAMES", "DatabaseTokenVerifier", "compact", "create_mcp_server"]
