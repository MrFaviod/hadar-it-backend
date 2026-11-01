"""Durable per-user workspace state plus installation-wide links and remote settings.

Security model:
- personal state and personal shortcuts/views only ever resolve for their owner;
- shared shortcuts and views are readable by any authenticated actor but are
  owner-only for modifications, so one user cannot overwrite another's work;
- publishing shared records and changing the installation remote destinations
  requires the existing Casbin grants (``config.general``/``config.integrations``).

All JSON is bounded before it is stored; URLs are validated as credential-free
HTTP(S) destinations and are always opened by the frontend in a new tab.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from itsm.identity.clock import utcnow
from itsm.identity.service import (
    IdentityService,
    NotFound,
    PermissionDenied,
    Principal,
    ValidationFailed,
)
from itsm.workspace.models import (
    WorkspaceIntegration,
    WorkspaceShortcut,
    WorkspaceUserState,
    WorkspaceView,
)

DEFAULT_WIDGETS: tuple[str, ...] = (
    "availability",
    "alerts",
    "distribution",
    "infrastructure",
    "activity",
    "maintenance",
    "warranties",
    "inventory",
)
WIDGET_CATALOGUE: frozenset[str] = frozenset(DEFAULT_WIDGETS) | {"latency", "incidents"}
THEME_MODES: frozenset[str] = frozenset({"light", "dark", "auto"})
SCOPES: frozenset[str] = frozenset({"personal", "shared"})
STATE_KEYS: frozenset[str] = frozenset({"widgets", "favorites", "usage", "lastViews", "themeMode"})
SHORTCUT_FIELDS: frozenset[str] = frozenset({"name", "url", "icon", "category", "scope"})
VIEW_FIELDS: frozenset[str] = frozenset({"name", "route", "snapshot", "scope"})
INTEGRATION_FIELDS: frozenset[str] = frozenset(
    {"anydeskUrl", "rmmUrl", "anydeskEnabled", "rmmEnabled"}
)
MAX_STATE_BYTES = 16_384
MAX_SNAPSHOT_BYTES = 8_192
MAX_WIDGETS = 24
MAX_FAVORITES = 100
MAX_USAGE_KEYS = 200
MAX_LAST_VIEWS = 50
MAX_NAME = 120
MAX_ROUTE = 128
MAX_ICON = 64
MAX_CATEGORY = 64
MAX_JSON_DEPTH = 5
MAX_URL = 1000
INTEGRATION_ID = "installation"
DEFAULT_ANYDESK_URL = "https://anydesk.com/"
_ROUTE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]*$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _text(value: Any, field: str, *, max_length: int, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValidationFailed(
                f"{field} is required", key="api.validation.field_required", params={"field": field}
            )
        return None
    if not isinstance(value, str):
        raise ValidationFailed(
            f"{field} must be text", key="api.validation.field_text", params={"field": field}
        )
    cleaned = value.strip()
    if not cleaned:
        if required:
            raise ValidationFailed(
                f"{field} is required", key="api.validation.field_required", params={"field": field}
            )
        return None
    if len(cleaned) > max_length or _CONTROL.search(cleaned):
        raise ValidationFailed(
            f"{field} must be at most {max_length} characters",
            key="api.validation.field_max_length",
            params={"field": field, "limit": max_length},
        )
    return cleaned


def _scope(value: Any, *, default: str = "personal") -> str:
    if value is None:
        return default
    if not isinstance(value, str) or value not in SCOPES:
        raise ValidationFailed(
            "scope must be personal or shared", key="api.workspace.scope_personal_shared"
        )
    return value


def _json_bytes(value: Any, field: str, limit: int) -> int:
    try:
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValidationFailed(
            f"{field} must be valid JSON", key="api.validation.field_json", params={"field": field}
        ) from exc
    size = len(encoded.encode("utf-8"))
    if size > limit:
        raise ValidationFailed(
            f"{field} must be at most {limit} bytes",
            key="api.workspace.field_most_limit_bytes",
            params={"field": field, "limit": limit},
        )
    return size


def _depth(value: Any, level: int = 0) -> int:
    if level > MAX_JSON_DEPTH:
        return level
    if isinstance(value, Mapping):
        return max((_depth(item, level + 1) for item in value.values()), default=level)
    if isinstance(value, (list, tuple)):
        return max((_depth(item, level + 1) for item in value), default=level)
    return level


def _snapshot(value: Any, field: str, limit: int) -> dict[str, Any]:
    if value is None:
        raise ValidationFailed(
            f"{field} must be an object", key="api.workspace.field_object", params={"field": field}
        )
    if not isinstance(value, Mapping):
        raise ValidationFailed(
            f"{field} must be an object", key="api.workspace.field_object", params={"field": field}
        )
    plain = dict(value)
    _json_bytes(plain, field, limit)
    if _depth(plain) > MAX_JSON_DEPTH:
        raise ValidationFailed(
            f"{field} is too deeply nested",
            key="api.workspace.field_too_deeply_nested",
            params={"field": field},
        )
    return plain


def _widget_list(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValidationFailed("widgets must be a list", key="api.workspace.widgets_list")
    if len(value) > MAX_WIDGETS:
        raise ValidationFailed(
            f"widgets must contain at most {MAX_WIDGETS} ids",
            key="api.workspace.widgets_contain_most_maximum_ids",
            params={"maximum": MAX_WIDGETS},
        )
    cleaned: list[str] = []
    for item in value:
        if not isinstance(item, str) or item not in WIDGET_CATALOGUE:
            raise ValidationFailed(
                "widgets contains an unknown id", key="api.workspace.widgets_contains_unknown_id"
            )
        if item in cleaned:
            raise ValidationFailed(
                "widgets must not contain duplicates",
                key="api.workspace.widgets_not_contain_duplicates",
            )
        cleaned.append(item)
    return cleaned


def _favorites(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValidationFailed("favorites must be a list", key="api.workspace.favorites_list")
    if len(value) > MAX_FAVORITES:
        raise ValidationFailed(
            f"favorites must contain at most {MAX_FAVORITES} items",
            key="api.workspace.favorites_contain_most_maximum_items",
            params={"maximum": MAX_FAVORITES},
        )
    cleaned: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping):
            raise ValidationFailed(
                "favorites items must be objects", key="api.workspace.favorites_items_objects"
            )
        key = _text(item.get("key"), "favorites.key", max_length=160, required=True)
        kind = _text(item.get("type"), "favorites.type", max_length=32, required=True)
        identifier = _text(item.get("id"), "favorites.id", max_length=64, required=True)
        assert key is not None and kind is not None and identifier is not None
        if key in seen:
            raise ValidationFailed(
                "favorites keys must be unique", key="api.workspace.favorites_keys_unique"
            )
        seen.add(key)
        target = item.get("target")
        payload: dict[str, Any] = {
            "key": key,
            "type": kind,
            "id": identifier,
            "label": _text(item.get("label"), "favorites.label", max_length=160) or identifier,
            "subtitle": _text(item.get("subtitle"), "favorites.subtitle", max_length=240),
            "icon": _text(item.get("icon"), "favorites.icon", max_length=MAX_ICON),
            "target": dict(target)
            if isinstance(target, Mapping)
            else {"kind": kind, "id": identifier},
        }
        _json_bytes(payload, "favorites", MAX_STATE_BYTES)
        cleaned.append(payload)
    return cleaned


def _usage(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise ValidationFailed("usage must be an object", key="api.workspace.usage_object")
    if len(value) > MAX_USAGE_KEYS:
        raise ValidationFailed(
            f"usage must contain at most {MAX_USAGE_KEYS} entries",
            key="api.workspace.usage_contain_most_maximum_entries",
            params={"maximum": MAX_USAGE_KEYS},
        )
    cleaned: dict[str, int] = {}
    for key, count in value.items():
        if not isinstance(key, str) or not key.strip() or len(key) > 160:
            raise ValidationFailed(
                "usage keys must be bounded text", key="api.workspace.usage_keys_bounded_text"
            )
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 1_000_000:
            raise ValidationFailed(
                "usage counts must be integers between 0 and 1000000",
                key="api.workspace.usage_counts_integers_between_0_1000000",
            )
        cleaned[key] = count
    return cleaned


def _last_views(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationFailed("lastViews must be an object", key="api.workspace.lastviews_object")
    if len(value) > MAX_LAST_VIEWS:
        raise ValidationFailed(
            f"lastViews must contain at most {MAX_LAST_VIEWS} entries",
            key="api.workspace.lastviews_contain_most_maximum_entries",
            params={"maximum": MAX_LAST_VIEWS},
        )
    cleaned: dict[str, Any] = {}
    for route, snapshot in value.items():
        if not isinstance(route, str) or not _ROUTE.fullmatch(route) or len(route) > MAX_ROUTE:
            raise ValidationFailed(
                "lastViews routes must be bounded route ids",
                key="api.workspace.lastviews_routes_bounded_route_ids",
            )
        cleaned[route] = _snapshot(snapshot, "lastViews", MAX_STATE_BYTES)
    return cleaned


def _http_url(
    value: Any, field: str, *, allowed_empty: bool = False, max_length: int = MAX_URL
) -> str:
    if value is None:
        if allowed_empty:
            return ""
        raise ValidationFailed(
            f"{field} is required", key="api.validation.field_required", params={"field": field}
        )
    if not isinstance(value, str):
        raise ValidationFailed(
            f"{field} must be text", key="api.validation.field_text", params={"field": field}
        )
    cleaned = value.strip()
    if not cleaned and allowed_empty:
        return ""
    if not cleaned or len(cleaned) > max_length or _CONTROL.search(cleaned) or " " in cleaned:
        raise ValidationFailed(
            f"{field} must be a valid HTTP(S) URL",
            key="api.validation.field_url",
            params={"field": field},
        )
    try:
        parts = urlsplit(cleaned)
        port = parts.port
    except ValueError as exc:
        raise ValidationFailed(
            f"{field} must be a valid HTTP(S) URL",
            key="api.validation.field_url",
            params={"field": field},
        ) from exc
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
    ):
        raise ValidationFailed(
            f"{field} must be a credential-free HTTP(S) URL",
            key="api.workspace.field_credential_free_http_s_url",
            params={"field": field},
        )
    if port is not None and not 1 <= port <= 65535:
        raise ValidationFailed(
            f"{field} must be a valid HTTP(S) URL",
            key="api.validation.field_url",
            params={"field": field},
        )
    return cleaned


def _uuid(value: Any, field: str = "id") -> str:
    if not isinstance(value, str):
        raise ValidationFailed(
            f"{field} must be a UUID", key="api.validation.field_uuid", params={"field": field}
        )
    try:
        return str(UUID(value.strip()))
    except ValueError as exc:
        raise ValidationFailed(
            f"{field} must be a UUID", key="api.validation.field_uuid", params={"field": field}
        ) from exc


def _reject_unknown(values: Mapping[str, Any], allowed: frozenset[str]) -> None:
    unknown = set(values) - allowed
    if unknown:
        raise ValidationFailed(
            "unsupported fields: " + ", ".join(sorted(unknown)),
            key="api.workspace.unsupported_fields",
            params={"fields": ", ".join(sorted(unknown))},
        )


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")


def _shortcut_payload(row: WorkspaceShortcut) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "url": row.url,
        "icon": row.icon,
        "category": row.category,
        "scope": row.scope,
        "ownerId": row.owner_id,
    }


def _view_payload(row: WorkspaceView) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "route": row.route,
        "snapshot": dict(row.snapshot or {}),
        "scope": row.scope,
        "ownerId": row.owner_id,
    }


def _integration_payload(row: WorkspaceIntegration | None) -> dict[str, Any]:
    if row is None:
        return {
            "anydeskUrl": DEFAULT_ANYDESK_URL,
            "rmmUrl": "",
            "anydeskEnabled": True,
            "rmmEnabled": True,
        }
    return {
        "anydeskUrl": row.anydesk_url or "",
        "rmmUrl": row.rmm_url or "",
        "anydeskEnabled": bool(row.anydesk_enabled),
        "rmmEnabled": bool(row.rmm_enabled),
    }


class WorkspaceService:
    """Single implementation of durable workspace preferences and shared records."""

    def __init__(
        self,
        session: Session,
        identity: IdentityService,
        source: str = "api",
    ) -> None:
        self._session = session
        self._identity = identity
        self._source = source

    # -------------------------------------------------------------- helpers
    def _require_actor(self, principal: Principal) -> None:
        identity = self._identity._require_identity(principal.actor_id)
        if not identity.active:
            raise PermissionDenied(
                "identity is not active", key="api.workspace.identity_not_active"
            )

    def _has(self, principal: Principal, permission: str) -> bool:
        return permission in self._identity._persisted_permissions(principal)

    def _require_shared(self, principal: Principal) -> None:
        self._identity.authorize(principal, "config.general", resource="workspace:shared")

    def _audit(self, principal: Principal, action: str, resource: str) -> None:
        self._identity.record_operation(principal, action=action, resource=resource)

    def _state_row(self, principal: Principal) -> WorkspaceUserState | None:
        return self._session.get(WorkspaceUserState, principal.actor_id)

    # ------------------------------------------------------------ user state
    def get_state(self, principal: Principal) -> dict[str, Any]:
        self._require_actor(principal)
        row = self._state_row(principal)
        widgets = (
            list(row.widgets)
            if row is not None and row.widgets is not None
            else list(DEFAULT_WIDGETS)
        )
        return {
            "widgets": widgets,
            "favorites": list(row.favorites or []) if row is not None else [],
            "usage": dict(row.usage or {}) if row is not None else {},
            "lastViews": dict(row.last_views or {}) if row is not None else {},
            "themeMode": row.theme_mode if row is not None else "auto",
            "shortcuts": [_shortcut_payload(item) for item in self._visible_shortcuts(principal)],
            "views": [_view_payload(item) for item in self._visible_views(principal)],
        }

    def save_state(self, principal: Principal, payload: Mapping[str, Any]) -> dict[str, Any]:
        self._require_actor(principal)
        if not isinstance(payload, Mapping):
            raise ValidationFailed("state must be an object", key="api.workspace.state_object")
        _reject_unknown(payload, STATE_KEYS)
        row = self._state_row(principal)
        if row is None:
            row = WorkspaceUserState(user_id=principal.actor_id)
            self._session.add(row)
        if "widgets" in payload:
            row.widgets = _widget_list(payload["widgets"])
        if "favorites" in payload:
            row.favorites = _favorites(payload["favorites"])
        if "usage" in payload:
            row.usage = _usage(payload["usage"])
        if "lastViews" in payload:
            row.last_views = _last_views(payload["lastViews"])
        if "themeMode" in payload:
            mode = payload["themeMode"]
            if not isinstance(mode, str) or mode not in THEME_MODES:
                raise ValidationFailed(
                    "themeMode must be light, dark or auto",
                    key="api.workspace.thememode_light_dark_auto",
                )
            row.theme_mode = mode
        row.updated_at = utcnow()
        _json_bytes(
            {
                "widgets": row.widgets,
                "favorites": row.favorites,
                "usage": row.usage,
                "lastViews": row.last_views,
            },
            "state",
            MAX_STATE_BYTES,
        )
        self._session.commit()
        return self.get_state(principal)

    # -------------------------------------------------------------- shortcuts
    def _visible_shortcuts(self, principal: Principal) -> list[WorkspaceShortcut]:
        return list(
            self._session.scalars(
                select(WorkspaceShortcut)
                .where(
                    (WorkspaceShortcut.scope == "shared")
                    | (WorkspaceShortcut.owner_id == principal.actor_id)
                )
                .order_by(WorkspaceShortcut.created_at, WorkspaceShortcut.id)
            )
        )

    def list_shortcuts(self, principal: Principal) -> list[dict[str, Any]]:
        self._require_actor(principal)
        return [_shortcut_payload(item) for item in self._visible_shortcuts(principal)]

    def _shortcut(self, principal: Principal, shortcut_id: Any) -> WorkspaceShortcut:
        identifier = _uuid(shortcut_id)
        row = self._session.get(WorkspaceShortcut, identifier)
        if row is None:
            raise NotFound("shortcut not found", key="api.workspace.shortcut_not_found")
        if row.scope == "personal" and row.owner_id != principal.actor_id:
            raise NotFound("shortcut not found", key="api.workspace.shortcut_not_found")
        return row

    def create_shortcut(self, principal: Principal, payload: Mapping[str, Any]) -> dict[str, Any]:
        self._require_actor(principal)
        if not isinstance(payload, Mapping):
            raise ValidationFailed(
                "shortcut must be an object", key="api.workspace.shortcut_object"
            )
        _reject_unknown(payload, SHORTCUT_FIELDS)
        scope = _scope(payload.get("scope"))
        if scope == "shared":
            self._require_shared(principal)
        row = WorkspaceShortcut(
            id=str(uuid4()),
            owner_id=principal.actor_id,
            name=_text(payload.get("name"), "name", max_length=MAX_NAME, required=True),
            url=_http_url(payload.get("url"), "url"),
            icon=_text(payload.get("icon"), "icon", max_length=MAX_ICON),
            category=_text(payload.get("category"), "category", max_length=MAX_CATEGORY),
            scope=scope,
        )
        self._session.add(row)
        self._audit(principal, "workspace.shortcut.create", f"workspace:shortcut:{row.id}")
        return _shortcut_payload(row)

    def update_shortcut(
        self, principal: Principal, shortcut_id: Any, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._require_actor(principal)
        if not isinstance(payload, Mapping):
            raise ValidationFailed(
                "shortcut must be an object", key="api.workspace.shortcut_object"
            )
        _reject_unknown(payload, SHORTCUT_FIELDS)
        row = self._shortcut(principal, shortcut_id)
        target_scope = _scope(payload.get("scope"), default=row.scope)
        if row.scope == "shared" or target_scope == "shared":
            self._require_shared(principal)
        if "name" in payload:
            row.name = (
                _text(payload["name"], "name", max_length=MAX_NAME, required=True) or row.name
            )
        if "url" in payload:
            row.url = _http_url(payload["url"], "url")
        if "icon" in payload:
            row.icon = _text(payload["icon"], "icon", max_length=MAX_ICON)
        if "category" in payload:
            row.category = _text(payload["category"], "category", max_length=MAX_CATEGORY)
        if "scope" in payload:
            row.scope = target_scope
        row.updated_at = utcnow()
        self._audit(principal, "workspace.shortcut.update", f"workspace:shortcut:{row.id}")
        return _shortcut_payload(row)

    def delete_shortcut(self, principal: Principal, shortcut_id: Any) -> dict[str, Any]:
        self._require_actor(principal)
        row = self._shortcut(principal, shortcut_id)
        if row.scope == "shared":
            self._require_shared(principal)
        identifier = row.id
        self._session.delete(row)
        self._session.flush()
        self._audit(principal, "workspace.shortcut.delete", f"workspace:shortcut:{identifier}")
        return {"id": identifier, "deleted": True}

    # ------------------------------------------------------------------ views
    def _visible_views(self, principal: Principal) -> list[WorkspaceView]:
        return list(
            self._session.scalars(
                select(WorkspaceView)
                .where(
                    (WorkspaceView.scope == "shared")
                    | (WorkspaceView.owner_id == principal.actor_id)
                )
                .order_by(WorkspaceView.created_at, WorkspaceView.id)
            )
        )

    def list_views(self, principal: Principal) -> list[dict[str, Any]]:
        self._require_actor(principal)
        return [_view_payload(item) for item in self._visible_views(principal)]

    def _view(self, principal: Principal, view_id: Any) -> WorkspaceView:
        identifier = _uuid(view_id)
        row = self._session.get(WorkspaceView, identifier)
        if row is None:
            raise NotFound("view not found", key="api.workspace.view_not_found")
        if row.scope == "personal" and row.owner_id != principal.actor_id:
            raise NotFound("view not found", key="api.workspace.view_not_found")
        return row

    def create_view(self, principal: Principal, payload: Mapping[str, Any]) -> dict[str, Any]:
        self._require_actor(principal)
        if not isinstance(payload, Mapping):
            raise ValidationFailed("view must be an object", key="api.workspace.view_object")
        _reject_unknown(payload, VIEW_FIELDS)
        scope = _scope(payload.get("scope"))
        if scope == "shared":
            self._require_shared(principal)
        route = _text(payload.get("route"), "route", max_length=MAX_ROUTE, required=True)
        assert route is not None
        if not _ROUTE.fullmatch(route):
            raise ValidationFailed(
                "route must be a bounded route id", key="api.workspace.route_bounded_route_id"
            )
        row = WorkspaceView(
            id=str(uuid4()),
            owner_id=principal.actor_id,
            name=_text(payload.get("name"), "name", max_length=MAX_NAME, required=True),
            route=route,
            snapshot=_snapshot(payload.get("snapshot", {}), "snapshot", MAX_SNAPSHOT_BYTES),
            scope=scope,
        )
        self._session.add(row)
        self._audit(principal, "workspace.view.create", f"workspace:view:{row.id}")
        return _view_payload(row)

    def update_view(
        self, principal: Principal, view_id: Any, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._require_actor(principal)
        if not isinstance(payload, Mapping):
            raise ValidationFailed("view must be an object", key="api.workspace.view_object")
        _reject_unknown(payload, VIEW_FIELDS)
        row = self._view(principal, view_id)
        if row.owner_id != principal.actor_id:
            raise PermissionDenied(
                "only the owner can modify a view", key="api.workspace.only_owner_can_modify_view"
            )
        target_scope = _scope(payload.get("scope"), default=row.scope)
        if target_scope == "shared" and row.scope != "shared":
            self._require_shared(principal)
        if "name" in payload:
            row.name = (
                _text(payload["name"], "name", max_length=MAX_NAME, required=True) or row.name
            )
        if "route" in payload:
            route = _text(payload["route"], "route", max_length=MAX_ROUTE, required=True)
            assert route is not None
            if not _ROUTE.fullmatch(route):
                raise ValidationFailed(
                    "route must be a bounded route id", key="api.workspace.route_bounded_route_id"
                )
            row.route = route
        if "snapshot" in payload:
            row.snapshot = _snapshot(payload["snapshot"], "snapshot", MAX_SNAPSHOT_BYTES)
        if "scope" in payload:
            row.scope = target_scope
        row.updated_at = utcnow()
        self._audit(principal, "workspace.view.update", f"workspace:view:{row.id}")
        return _view_payload(row)

    def delete_view(self, principal: Principal, view_id: Any) -> dict[str, Any]:
        self._require_actor(principal)
        row = self._view(principal, view_id)
        if row.owner_id != principal.actor_id:
            raise PermissionDenied(
                "only the owner can delete a view", key="api.workspace.only_owner_can_delete_view"
            )
        identifier = row.id
        self._session.delete(row)
        self._session.flush()
        self._audit(principal, "workspace.view.delete", f"workspace:view:{identifier}")
        return {"id": identifier, "deleted": True}

    # ----------------------------------------------------------- integrations
    def _integration_row(self) -> WorkspaceIntegration | None:
        return self._session.get(WorkspaceIntegration, INTEGRATION_ID)

    def _require_remote_read(self, principal: Principal) -> None:
        permissions = self._identity._persisted_permissions(principal)
        if "assets.remote" in permissions:
            self._identity.authorize(principal, "assets.remote", resource="workspace:integrations")
            return
        self._identity.authorize(
            principal, "config.integrations", resource="workspace:integrations"
        )

    def get_integrations(self, principal: Principal) -> dict[str, Any]:
        self._require_actor(principal)
        self._require_remote_read(principal)
        return _integration_payload(self._integration_row())

    def save_integrations(self, principal: Principal, payload: Mapping[str, Any]) -> dict[str, Any]:
        self._require_actor(principal)
        self._identity.authorize(
            principal, "config.integrations", resource="workspace:integrations"
        )
        if not isinstance(payload, Mapping):
            raise ValidationFailed(
                "integrations must be an object", key="api.workspace.integrations_object"
            )
        _reject_unknown(payload, INTEGRATION_FIELDS)
        row = self._integration_row()
        if row is None:
            row = WorkspaceIntegration(
                id=INTEGRATION_ID,
                anydesk_url=DEFAULT_ANYDESK_URL,
                rmm_url="",
                anydesk_enabled=True,
                rmm_enabled=True,
            )
            self._session.add(row)
        if "anydeskUrl" in payload:
            row.anydesk_url = _http_url(
                payload["anydeskUrl"], "anydeskUrl", allowed_empty=True, max_length=500
            )
        if "rmmUrl" in payload:
            row.rmm_url = _http_url(payload["rmmUrl"], "rmmUrl", allowed_empty=True, max_length=500)
        for key, column in (
            ("anydeskEnabled", "anydesk_enabled"),
            ("rmmEnabled", "rmm_enabled"),
        ):
            if key in payload:
                value = payload[key]
                if not isinstance(value, bool):
                    raise ValidationFailed(
                        f"{key} must be a boolean",
                        key="api.workspace.key_boolean",
                        params={"key": key},
                    )
                setattr(row, column, value)
        row.updated_at = utcnow()
        self._audit(principal, "workspace.integrations.update", "workspace:integrations")
        return _integration_payload(row)


__all__ = [
    "DEFAULT_WIDGETS",
    "WIDGET_CATALOGUE",
    "WorkspaceService",
]
