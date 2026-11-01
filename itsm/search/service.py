"""Canonical search service (contract C2).

SQL is the primary source of truth and the default engine.  Meilisearch is an
optional, disposable accelerator: every hit it returns is rehydrated from SQL
and re-authorized against the caller's live permissions before it can reach a
response.  An engine outage therefore degrades to SQL instead of an error, and
a stale index entry can never expose an entity that was deleted, archived or
deactivated.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.identity.service import IdentityService, PermissionDenied, Principal, ValidationFailed
from itsm.search import documents
from itsm.search.engine import SearchEngineError, engine_from_settings
from itsm.search.models import SearchIndexState

MAX_QUERY_LENGTH = 200
MAX_LIMIT = 50
DEFAULT_LIMIT = 20
MAX_OFFSET = 200
MAX_ENGINE_OFFSET = 1000

TYPES: tuple[str, ...] = (
    "asset",
    "person",
    "location",
    "site",
    "incident",
    "maintenance",
    "category",
    "section",
    "view",
)

#: Canonical permission that gates each entity type.  Search never invents a
#: grant: it reuses the exact code the owning module already enforces.
TYPE_PERMISSIONS: dict[str, str] = {
    "asset": "assets.view",
    "person": "people.view",
    "location": "assets.view",
    "site": "assets.view",
    "incident": "assets.view",
    "maintenance": "assets.view",
    "category": "assets.view",
}
SECTION_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "people": ("people.view",),
    "config-seguridad": ("users.view",),
    "config-general": ("config.general",),
    "config-apariencia": ("config.general",),
    "config-categorias": ("config.categories",),
    "config-activos": ("config.categories", "config.general"),
    "config-sedes": ("config.sites",),
    "config-personas": ("config.departments",),
    "config-integraciones": ("config.integrations",),
    "config-relaciones": ("config.general",),
    "config-mantenimiento": ("assets.edit",),
    "config-supervision": ("assets.edit",),
    "config-alertas": ("assets.edit",),
    "config-notificaciones": ("config.integrations",),
    "config-mapas": ("config.sites",),
    "config-datos": ("assets.edit",),
    "config-reportes": ("config.general",),
    "config-garantias": ("config.general",),
    "config-qr": ("config.general",),
    "config-etiquetas": ("config.general",),
}
SECTION_DEFAULT_PERMISSION = "assets.view"


@dataclass(frozen=True)
class SearchPage:
    items: tuple[dict[str, Any], ...]
    total: int
    limit: int
    offset: int
    engine: str
    fallback: bool

    def as_payload(self) -> dict[str, Any]:
        return {
            "items": list(self.items),
            "total": self.total,
            "limit": self.limit,
            "offset": self.offset,
            "engine": self.engine,
            "fallback": self.fallback,
        }


def _bounded_int(value: Any, field: str, *, low: int, high: int, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationFailed(
            f"{field} must be an integer",
            key="api.validation.field_integer",
            params={"field": field},
        )
    if value < low or value > high:
        raise ValidationFailed(
            f"{field} must be between {low} and {high}",
            key="api.search.field_between_low_high",
            params={"field": field, "low": low, "high": high},
        )
    return value


class SearchService:
    """One request-scoped search facade over SQL and the optional engine."""

    def __init__(
        self,
        session: Session,
        identity: IdentityService | None,
        settings: Settings,
        *,
        source: str = "api",
    ) -> None:
        self._session = session
        self._identity = identity
        self._settings = settings
        self._source = source

    # ------------------------------------------------------------- permissions
    def _allowed(self, principal: Principal, permission: str, cache: dict[str, bool]) -> bool:
        if permission in cache:
            return cache[permission]
        if self._identity is None:
            cache[permission] = False
            return False
        try:
            self._identity.authorize(principal, permission, resource="search")
        except PermissionDenied:
            cache[permission] = False
        else:
            cache[permission] = True
        return cache[permission]

    def _allowed_types(
        self, principal: Principal, kinds: Sequence[str], cache: dict[str, bool]
    ) -> list[str]:
        allowed: list[str] = []
        for kind in kinds:
            permission = TYPE_PERMISSIONS.get(kind)
            if permission is not None and self._allowed(principal, permission, cache):
                allowed.append(kind)
        return allowed

    def authorize_index_admin(self, principal: Principal) -> None:
        """Require the same configuration privilege the other admin surfaces use."""
        if self._identity is None:
            raise PermissionDenied(key="api.search.permission_denied")
        self._identity.authorize(principal, "config.general", resource="search:index")

    # ------------------------------------------------------------------ search
    def search(
        self,
        principal: Principal,
        query: str,
        kinds: Iterable[str] | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> SearchPage:
        if not isinstance(query, str) or not query.strip():
            raise ValidationFailed("q is required", key="api.search.q_required")
        query = " ".join(query.split())
        if len(query) > MAX_QUERY_LENGTH:
            raise ValidationFailed(
                f"q must be at most {MAX_QUERY_LENGTH} characters",
                key="api.search.q_most_maximum_characters",
                params={"maximum": MAX_QUERY_LENGTH},
            )
        limit = _bounded_int(limit, "limit", low=1, high=MAX_LIMIT, default=DEFAULT_LIMIT)
        offset = _bounded_int(offset, "offset", low=0, high=MAX_OFFSET, default=0)
        requested = self._kinds(kinds)
        cache: dict[str, bool] = {}
        allowed = set(self._allowed_types(principal, requested, cache))
        sql_kinds = [kind for kind in requested if kind in allowed]

        ranked, sql_total = documents.sql_search(self._session, query, sql_kinds, limit + offset)
        sections = self._sections(principal, query, requested, cache)
        views = (
            documents.view_matches(self._session, principal, query) if "view" in requested else []
        )
        sql_total += len(sections) + len(views)

        indexed_kinds = [kind for kind in sql_kinds if kind in documents.INDEXED_TYPES]
        engine = engine_from_settings(self._settings) if indexed_kinds else None
        if engine is None:
            merged = self._compose(ranked, [], sections, views)
            return SearchPage(
                items=tuple(merged[offset : offset + limit]),
                total=sql_total,
                limit=limit,
                offset=offset,
                engine="sql",
                fallback=False,
            )
        try:
            hits, _engine_total = engine.search(
                query,
                types=indexed_kinds,
                limit=min(limit + offset, MAX_ENGINE_OFFSET),
            )
        except SearchEngineError:
            merged = self._compose(ranked, [], sections, views)
            return SearchPage(
                items=tuple(merged[offset : offset + limit]),
                total=sql_total,
                limit=limit,
                offset=offset,
                engine="sql",
                fallback=True,
            )
        finally:
            engine.close()

        scoped_hits = [hit for hit in hits if hit.get("type") in indexed_kinds]
        engine_items = self._rehydrate(principal, scoped_hits, cache)
        merged = self._compose(ranked, engine_items, sections, views)
        # Engine counts can include stale or newly restricted records. Only
        # canonical SQL counts and reauthorized matches are public authority.
        total = max(sql_total, len(merged))
        return SearchPage(
            items=tuple(merged[offset : offset + limit]),
            total=total,
            limit=limit,
            offset=offset,
            engine="meilisearch",
            fallback=False,
        )

    @staticmethod
    def _compose(
        ranked: Sequence[tuple[int, dict[str, Any]]],
        engine_items: Sequence[dict[str, Any]],
        sections: Sequence[dict[str, Any]],
        views: Sequence[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Exact identifier matches first, then engine hits, then the rest."""
        ordered: list[dict[str, Any]] = []
        ordered.extend(item for score, item in ranked if score >= documents.EXACT_SCORE)
        ordered.extend(engine_items)
        ordered.extend(item for score, item in ranked if score < documents.EXACT_SCORE)
        ordered.extend(sections)
        ordered.extend(views)
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for item in ordered:
            if item["key"] in seen:
                continue
            seen.add(item["key"])
            unique.append(item)
        return unique

    @staticmethod
    def _kinds(kinds: Iterable[str] | None) -> list[str]:
        if kinds is None:
            return list(TYPES)
        if isinstance(kinds, str):
            values = [part.strip() for part in kinds.split(",") if part.strip()]
        else:
            values = [str(part).strip() for part in kinds if str(part).strip()]
        if not values:
            return list(TYPES)
        unknown = sorted(set(values) - set(TYPES))
        if unknown:
            raise ValidationFailed(
                "unsupported search kinds: " + ", ".join(unknown),
                key="api.search.unsupported_search_kinds",
                params={"kinds": ", ".join(unknown)},
            )
        return list(dict.fromkeys(values))

    # -------------------------------------------------------------- rehydrate
    def _rehydrate(
        self,
        principal: Principal,
        hits: Sequence[dict[str, Any]],
        cache: dict[str, bool],
    ) -> list[dict[str, Any]]:
        """Rebuild every engine hit from SQL, dropping anything no longer valid."""
        items: list[dict[str, Any]] = []
        for hit in hits:
            kind = str(hit.get("type") or "")
            entity_id = str(hit.get("entity_id") or "")
            permission = TYPE_PERMISSIONS.get(kind)
            if permission is None or not entity_id:
                continue
            if not self._allowed(principal, permission, cache):
                continue
            item = documents.build_item(self._session, kind, entity_id)
            if item is not None:
                items.append(item)
        return items

    # ---------------------------------------------------------------- sections
    def _sections(
        self,
        principal: Principal,
        query: str,
        requested: Sequence[str],
        cache: dict[str, bool],
    ) -> list[dict[str, Any]]:
        if "section" not in requested:
            return []
        query_tokens = documents.tokens(query)
        results: list[dict[str, Any]] = []
        for section in documents.sections():
            permissions = SECTION_PERMISSIONS.get(section["id"], (SECTION_DEFAULT_PERMISSION,))
            if not any(self._allowed(principal, code, cache) for code in permissions):
                continue
            haystack = " ".join([section["label"], section["subtitle"], *section["keywords"]])
            if documents.matches(haystack, query_tokens):
                results.append(section["item"])
        return results

    # ------------------------------------------------------------------ status
    def status(self) -> dict[str, Any]:
        state = self._session.get(SearchIndexState, 1)
        configured = bool((getattr(self._settings, "meilisearch_url", None) or "").strip())
        available = False
        engine = engine_from_settings(self._settings)
        if engine is not None:
            try:
                available = engine.available()
            finally:
                engine.close()
        return {
            "configured": configured,
            "available": available,
            "engine": "meilisearch" if configured else "sql",
            "index": getattr(self._settings, "search_index_name", "itsm_entities"),
            "status": "idle" if state is None else state.status,
            "lastSyncAt": None
            if state is None or state.last_sync_at is None
            else state.last_sync_at.isoformat(),
            "lastRebuildAt": None
            if state is None or state.last_rebuild_at is None
            else state.last_rebuild_at.isoformat(),
            "lastError": None if state is None else state.last_error,
            "documentCount": 0 if state is None else state.document_count,
            "pending": documents.pending_count(self._session),
        }


__all__ = [
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "MAX_OFFSET",
    "MAX_QUERY_LENGTH",
    "SECTION_PERMISSIONS",
    "TYPES",
    "TYPE_PERMISSIONS",
    "SearchPage",
    "SearchService",
]
