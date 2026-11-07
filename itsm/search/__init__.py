"""Global search: canonical SQL queries with an optional Meilisearch index."""

from __future__ import annotations

from itsm.search.api import create_search_router, get_search_service
from itsm.search.documents import register_view_source
from itsm.search.indexer import (
    execute_rebuild,
    execute_sync,
    install_search_sync,
    process_search_rebuild,
    process_search_sync,
)
from itsm.search.models import SearchIndexState, SearchSyncOutbox
from itsm.search.service import SearchPage, SearchService

__all__ = [
    "SearchIndexState",
    "SearchPage",
    "SearchService",
    "SearchSyncOutbox",
    "create_search_router",
    "execute_rebuild",
    "execute_sync",
    "get_search_service",
    "install_search_sync",
    "process_search_rebuild",
    "process_search_sync",
    "register_view_source",
]
