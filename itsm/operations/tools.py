"""Compact operational tools shared by the conversational agent and MCP transports.

Each helper validates only the tool arguments, delegates to the canonical
operational service and bounds the payload returned to a model. Identity,
permissions and data remain the domain services' authority: no helper accepts a
principal, a source or a permission from its caller.
"""

from __future__ import annotations

from typing import Any

from itsm.dashboard.service import DashboardService
from itsm.i18n.documents import localized_message
from itsm.identity.service import IdentityService, Principal, ValidationFailed
from itsm.relationships.service import RelationshipService
from itsm.search.service import SearchService
from itsm.workspace.service import WorkspaceService

MAX_RESULTS = 50
MAX_QUERY = 200
MAX_PERIOD = 16
MAX_LABEL = 64

SEARCH_KINDS: frozenset[str] = frozenset(
    {
        "asset",
        "person",
        "location",
        "site",
        "incident",
        "maintenance",
        "category",
        "section",
        "view",
    }
)


def bounded_page(limit: Any, offset: Any) -> tuple[int, int]:
    """Clamp one tool page so a model cannot request unbounded rows."""
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValidationFailed(
            "limit must be an integer",
            key="api.validation.field_integer",
            params={"field": "limit"},
        )
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValidationFailed(
            "offset must be an integer",
            key="api.validation.field_integer",
            params={"field": "offset"},
        )
    return max(1, min(limit, MAX_RESULTS)), max(0, offset)


def _text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValidationFailed(
            f"{field} must be text",
            key="api.validation.field_text",
            params={"field": field},
        )
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise ValidationFailed(
            f"{field} must be 1-{maximum} characters",
            key="api.operations.field_length_range",
            params={"field": field, "maximum": maximum},
        )
    return normalized


def _optional_text(value: Any, field: str, maximum: int) -> str | None:
    if value is None:
        return None
    return _text(value, field, maximum)


def _kinds(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValidationFailed(
            "kinds must be a list of known result types",
            key="api.operations.kinds_known_types",
        )
    unique = list(dict.fromkeys(value))
    unknown = sorted(set(unique) - SEARCH_KINDS)
    if unknown:
        raise ValidationFailed(
            f"unknown result kinds: {', '.join(unknown)}",
            key="api.operations.unknown_result_kinds",
            params={"kinds": ", ".join(unknown)},
        )
    return unique or None


def _bounded_rows(rows: Any) -> tuple[list[dict[str, Any]], bool]:
    items = [dict(row) for row in rows or [] if isinstance(row, dict)]
    return items[:MAX_RESULTS], len(items) > MAX_RESULTS


def operational_summary(
    session: Any,
    identity: IdentityService,
    settings: Any,
    principal: Principal,
    *,
    source: str,
    period: Any = "24h",
    category: Any = None,
    site_id: Any = None,
) -> dict[str, Any]:
    """Delegate the bounded operational summary and keep its provenance intact."""
    summary = DashboardService(session, identity, settings, source=source).summary(
        principal,
        period=_text(period, "period", MAX_PERIOD),
        category=_optional_text(category, "category", MAX_LABEL),
        site_id=_optional_text(site_id, "siteId", MAX_LABEL),
    )
    # A stable key plus its parameters; the text follows the requester's locale.
    summary["message"] = localized_message(
        session,
        "api.operations.summary_ready",
        identity_id=principal.actor_id,
        params={"period": summary.get("period") or ""},
    )
    return summary


def search_everything(
    session: Any,
    identity: IdentityService,
    settings: Any,
    principal: Principal,
    *,
    source: str,
    query: Any,
    kinds: Any = None,
    limit: Any = 20,
    offset: Any = 0,
) -> dict[str, Any]:
    """Search canonical entities through the configured engine and bounded page."""
    checked_limit, checked_offset = bounded_page(limit, offset)
    page = SearchService(session, identity, settings, source=source).search(
        principal,
        _text(query, "query", MAX_QUERY),
        kinds=_kinds(kinds),
        limit=checked_limit,
        offset=checked_offset,
    )
    result = page.as_payload()
    items, truncated = _bounded_rows(result.get("items"))
    return {
        "items": items,
        "total": result.get("total"),
        "limit": checked_limit,
        "offset": checked_offset,
        "engine": result.get("engine"),
        "fallback": bool(result.get("fallback")),
        "truncated": truncated,
    }


def query_relationships(
    session: Any,
    identity: IdentityService,
    settings: Any,
    principal: Principal,
    *,
    source: str,
    asset_id: Any = None,
    depth: Any = 2,
    direction: Any = "both",
    type_key: Any = None,
    limit: Any = 20,
    offset: Any = 0,
) -> dict[str, Any]:
    """Traverse persisted relationships from one focus, or page the global graph."""
    checked_limit, checked_offset = bounded_page(limit, offset)
    checked_type = _optional_text(type_key, "typeKey", MAX_LABEL)
    view = RelationshipService(session, settings, identity=identity, source=source).graph(
        principal,
        root_id=None if asset_id in (None, "") else asset_id,
        depth=depth,
        direction=direction,
        type_key=checked_type,
        limit=checked_limit,
        offset=checked_offset,
    )
    payload = view.as_payload()
    nodes, nodes_truncated = _bounded_rows(payload["nodes"])
    edges, edges_truncated = _bounded_rows(payload["edges"])
    return {
        "focusId": payload["rootId"],
        "depth": payload["depth"],
        "direction": payload["direction"],
        "typeKey": checked_type,
        "nodes": nodes,
        "edges": edges,
        "returned": {"nodes": len(nodes), "edges": len(edges)},
        "truncated": bool(payload["truncated"]) or nodes_truncated or edges_truncated,
        "nodesTruncated": bool(payload["nodesTruncated"]) or nodes_truncated,
        "edgesTruncated": bool(payload["edgesTruncated"]) or edges_truncated,
        "depthTruncated": bool(payload["depthTruncated"]),
        "total": payload["total"],
        "limit": checked_limit,
        "offset": checked_offset,
    }


def list_saved_views(
    session: Any,
    identity: IdentityService,
    principal: Principal,
    *,
    source: str,
) -> dict[str, Any]:
    """Read the caller's durable workspace state: views, favorites and shortcuts."""
    state = WorkspaceService(session, identity, source=source).get_state(principal)
    views, views_truncated = _bounded_rows(state.get("views"))
    favorites, favorites_truncated = _bounded_rows(state.get("favorites"))
    shortcuts, shortcuts_truncated = _bounded_rows(state.get("shortcuts"))
    return {
        "views": views,
        "favorites": favorites,
        "shortcuts": shortcuts,
        "themeMode": state.get("themeMode"),
        "truncated": views_truncated or favorites_truncated or shortcuts_truncated,
    }


__all__ = [
    "MAX_RESULTS",
    "SEARCH_KINDS",
    "bounded_page",
    "list_saved_views",
    "operational_summary",
    "query_relationships",
    "search_everything",
]
