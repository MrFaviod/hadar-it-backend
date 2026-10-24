"""Meilisearch HTTP adapter for the optional search engine.

Production traffic uses the pinned ``httpx2`` client only.  The adapter is
deliberately small: it covers health, search, document upsert/delete, index
creation and the atomic swap used by a full rebuild.  Every failure is raised
as a :class:`SearchEngineError` so the canonical service can fall back to SQL.
"""

from __future__ import annotations

import time
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit

import httpx2

from itsm.config import Settings

DEFAULT_INDEX = "itsm_entities"
DEFAULT_TIMEOUT = 5.0
DEFAULT_TIMEOUT_SECONDS = 5
PRIMARY_KEY = "_engine_id"
FILTERABLE = ("type",)


class SearchEngineError(RuntimeError):
    """The engine answered but rejected the request."""


class SearchEngineUnavailable(SearchEngineError):
    """The engine could not be reached or is temporarily unhealthy."""


class SearchIndexUnavailable(SearchEngineError):
    """The engine is reachable but the configured index does not exist yet."""


def _secret(value: Any) -> str | None:
    if value is None:
        return None
    getter = getattr(value, "get_secret_value", None)
    text = getter() if callable(getter) else str(value)
    return text or None


def _base_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise SearchEngineUnavailable("meilisearch_url must be an http(s) URL")
    if parts.username or parts.password:
        raise SearchEngineUnavailable("meilisearch_url must not embed credentials")
    return url.rstrip("/")


def engine_from_settings(settings: Settings) -> MeiliEngine | None:
    """Build the engine from the existing settings, or ``None`` when disabled."""
    url = str(getattr(settings, "meilisearch_url", None) or "").strip()
    if not url:
        return None
    try:
        base = _base_url(url)
    except SearchEngineUnavailable:
        return None
    timeout = getattr(settings, "meilisearch_http_timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        timeout = DEFAULT_TIMEOUT
    index = str(getattr(settings, "search_index_name", DEFAULT_INDEX) or DEFAULT_INDEX).strip()
    if not index or len(index) > 64:
        index = DEFAULT_INDEX
    key = _secret(getattr(settings, "meilisearch_api_key", None))
    return MeiliEngine(base, key, index, float(timeout))


class MeiliEngine:
    """Synchronous client for the handful of Meilisearch endpoints we need."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        index: str = DEFAULT_INDEX,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        headers = {"Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self.index = index
        self._client = httpx2.Client(base_url=base_url, timeout=timeout, headers=headers)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> MeiliEngine:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------- transport
    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        allowed: tuple[int, ...] = (200, 202),
    ) -> dict[str, Any]:
        try:
            response = self._client.request(method, path, json=json, params=params)
        except httpx2.HTTPError as exc:
            raise SearchEngineUnavailable(f"search engine unreachable: {exc}") from exc
        status = response.status_code
        if status == 404:
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            code = payload.get("code") if isinstance(payload, dict) else None
            if code in {"index_not_found", "index_not_found_error"} or path.startswith("/indexes/"):
                raise SearchIndexUnavailable(f"index not found: {code or path}")
        if status in {408, 429} or status >= 500:
            raise SearchEngineUnavailable(f"search engine unavailable (HTTP {status})")
        if status not in allowed:
            raise SearchEngineError(f"search engine rejected the request (HTTP {status})")
        if not response.content:
            return {}
        try:
            payload = response.json()
        except ValueError as exc:
            raise SearchEngineError("search engine returned invalid JSON") from exc
        return payload if isinstance(payload, dict) else {"items": payload}

    def _task(self, payload: dict[str, Any]) -> int | None:
        value = payload.get("taskUid")
        return value if isinstance(value, int) else None

    def wait_task(self, task_uid: int | None, *, timeout: float | None = None) -> None:
        """Block until an asynchronous Meilisearch task finishes.

        Meilisearch processes tasks in FIFO order; waiting makes the durable
        outbox state truthful instead of claiming success while the engine
        later rejects a document.
        """
        if task_uid is None:
            return
        deadline = time.monotonic() + (timeout if timeout is not None else 10.0)
        while True:
            payload = self._request("GET", f"/tasks/{task_uid}")
            status = payload.get("status")
            if status == "succeeded":
                return
            if status in {"failed", "canceled"}:
                error = payload.get("error") or {}
                message = error.get("message") if isinstance(error, dict) else str(error)
                raise SearchEngineError(f"search engine task {task_uid} {status}: {message}")
            if time.monotonic() >= deadline:
                raise SearchEngineUnavailable(f"search engine task {task_uid} timed out")
            time.sleep(0.02)

    # ---------------------------------------------------------------- health
    def available(self) -> bool:
        try:
            self._request("GET", "/health", allowed=(200,))
        except SearchEngineError:
            return False
        return True

    # ---------------------------------------------------------------- search
    def search(
        self,
        query: str,
        *,
        types: list[str],
        limit: int,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        body: dict[str, Any] = {
            "q": query,
            "limit": limit,
            "offset": offset,
            "attributesToRetrieve": ["id", "type", "entity_id", "label", "subtitle"],
        }
        if types:
            joined = ", ".join(f'"{value}"' for value in types)
            body["filter"] = f"type IN [{joined}]"
        try:
            payload = self._request("POST", f"/indexes/{self.index}/search", json=body)
        except SearchIndexUnavailable:
            raise
        hits = payload.get("hits")
        if not isinstance(hits, list):
            hits = []
        total = payload.get("estimatedTotalHits")
        return [hit for hit in hits if isinstance(hit, dict)], int(total or 0)

    # ------------------------------------------------------------- documents
    def upsert_documents(
        self, documents: list[dict[str, Any]], *, index: str | None = None
    ) -> int | None:
        if not documents:
            return None
        payload = self._request(
            "POST",
            f"/indexes/{index or self.index}/documents",
            json=[
                {**document, PRIMARY_KEY: sha256(str(document["id"]).encode()).hexdigest()}
                for document in documents
            ],
            params={"primaryKey": PRIMARY_KEY},
        )
        return self._task(payload)

    def delete_documents(self, identifiers: list[str], *, index: str | None = None) -> int | None:
        if not identifiers:
            return None
        payload = self._request(
            "POST",
            f"/indexes/{index or self.index}/documents/delete-batch",
            json=[sha256(identifier.encode()).hexdigest() for identifier in identifiers],
        )
        return self._task(payload)

    # ---------------------------------------------------------------- indexes
    def create_index(self, uid: str | None = None) -> None:
        target = uid or self.index
        try:
            self._request("GET", f"/indexes/{target}")
            return
        except SearchIndexUnavailable:
            pass
        payload = self._request(
            "POST",
            "/indexes",
            json={"uid": target, "primaryKey": PRIMARY_KEY},
        )
        self.wait_task(self._task(payload))

    def set_filterable(self, uid: str | None = None) -> None:
        payload = self._request(
            "PUT",
            f"/indexes/{uid or self.index}/settings/filterable-attributes",
            json=list(FILTERABLE),
        )
        self.wait_task(self._task(payload))

    def delete_index(self, uid: str) -> None:
        self._request("DELETE", f"/indexes/{uid}", allowed=(200, 202, 404))

    def swap(self, first: str, second: str) -> None:
        payload = self._request(
            "POST",
            "/swap-indexes",
            json=[{"indexes": [first, second]}],
        )
        self.wait_task(self._task(payload))


__all__ = [
    "DEFAULT_INDEX",
    "MeiliEngine",
    "SearchEngineError",
    "SearchEngineUnavailable",
    "SearchIndexUnavailable",
    "engine_from_settings",
]
