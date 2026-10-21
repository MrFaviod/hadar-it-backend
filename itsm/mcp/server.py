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
)

COMPACT_FIELDS: tuple[str, ...] = (
    "id",
    "quickCode",
    "name",
    "category",
    "site",
    "location",
    "responsible",
    "status",
    "ip",
)

INSTRUCTIONS = """\
These tools operate on the ITSM asset inventory with the permissions of the
authenticated machine identity. IDs are permanent UUIDs; the quick code may
change. Use search/get before updating, and never assume an asset exists.
"""


def compact(view: AssetView) -> dict[str, Any]:
    """Return only the fields an external agent needs."""
    payload = view.as_payload()
    return {field: payload[field] for field in COMPACT_FIELDS}


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
            )
            return {"total": page.total, "items": [compact(view) for view in page.items]}

        return run(operation)

    @server.tool
    def get_asset(asset_id: str) -> dict[str, Any]:
        """Read one asset by its permanent UUID."""

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            return compact(service.get(principal, asset_id))

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
        }

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            return compact(
                service.create(
                    principal,
                    {key: value for key, value in values.items() if value is not None},
                )
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
        }
        changes = {key: value for key, value in values.items() if value is not None}

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            return compact(service.update(principal, asset_id, changes))

        return run(operation)

    @server.tool
    def batch_update_assets(updates: list[BatchUpdateInput]) -> dict[str, Any]:
        """Update several assets atomically; the whole batch is bounded."""
        if len(updates) > BATCH_LIMIT:
            raise ToolError(f"updates must have at most {BATCH_LIMIT} entries")
        changes = []
        for item in updates:
            payload = item.model_dump(exclude_none=True)
            asset_id = payload.pop("asset_id")
            changes.append({"id": asset_id, **payload})

        def operation(service: InventoryService, principal: Principal) -> dict[str, Any]:
            result = service.batch(principal, update=changes)
            return {
                "created": [compact(view) for view in result.created],
                "updated": [compact(view) for view in result.updated],
            }

        return run(operation)

    return server


__all__ = ["TOOL_NAMES", "DatabaseTokenVerifier", "compact", "create_mcp_server"]
