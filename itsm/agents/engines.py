"""Engine-neutral boundary for external conversational agent runtimes.

The adapters in this package own transport and protocol translation only. They
do not persist conversations, authorize people, or execute agent tools.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

_CONNECT_TIMEOUT = 10.0
_REQUEST_TIMEOUT = 60.0
_STREAM_TIMEOUT = httpx.Timeout(90.0, connect=_CONNECT_TIMEOUT)
_MAX_HISTORY_ITEMS = 12
_MAX_HISTORY_ITEM_CHARS = 1_500
_MAX_CONTEXT_CHARS = 8_000
_MAX_TOOL_CHARS = 2_000


@dataclass(frozen=True, slots=True)
class EngineConfig:
    """Connection settings resolved by the server, never by chat input."""

    base_url: str
    token: str | None = None
    username: str | None = None
    password: str | None = None
    directory: str | None = None
    profile: str | None = None
    agent: str | None = "itsm"


@dataclass(frozen=True, slots=True)
class EngineModel:
    """A model the connected instance actually exposed."""

    id: str
    name: str
    provider: str
    free: bool | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider,
            "free": self.free,
        }


@dataclass(frozen=True, slots=True)
class EngineInfo:
    """Discovery result: version, live models, and truthful capabilities."""

    version: str
    models: list[EngineModel]
    capabilities: dict[str, bool]


class EngineError(Exception):
    """Public, redacted engine failure."""

    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        self.code = code
        self.message = message
        self.retryable = retryable
        super().__init__(message)


class _HTTPEngine:
    """Shared lifecycle and wire helpers; subclasses own one engine protocol."""

    def __init__(self, config: EngineConfig, *, client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self._client = client
        self._owns_client = client is None
        self._models: list[EngineModel] = []
        self._model_refs: dict[str, tuple[str, str]] = {}
        self._capabilities: dict[str, bool] = {}

    @property
    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient()
        return self._client

    def _url(self, path: str) -> str:
        base = (self.config.base_url or "").strip().rstrip("/")
        parsed = urlsplit(base)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise EngineError(
                "protocol",
                "engine base URL must be an absolute http(s) URL",
                retryable=False,
            )
        if not path.startswith("/"):
            raise EngineError("protocol", "engine path is invalid", retryable=False)
        return f"{base}{path}"

    def _auth(self) -> httpx.BasicAuth | None:
        if self.config.token:
            return None
        if self.config.username is not None and self.config.password is not None:
            return httpx.BasicAuth(self.config.username, self.config.password)
        return None

    def _headers(self, accept: str = "application/json") -> dict[str, str]:
        headers = {"Accept": accept}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, object] | None = None,
        expected: tuple[int, ...] = (200,),
        timeout: float | httpx.Timeout = _REQUEST_TIMEOUT,
    ) -> httpx.Response:
        try:
            response = await self._http.request(
                method,
                self._url(path),
                params=params,
                json=json_body,
                headers=self._headers(),
                auth=self._auth(),
                timeout=timeout,
            )
        except httpx.HTTPError as exc:
            raise _transport_error(exc) from None
        if response.status_code not in expected:
            raise _status_error(response.status_code, path)
        return response

    async def _json(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, object] | None = None,
        expected: tuple[int, ...] = (200,),
        timeout: float | httpx.Timeout = _REQUEST_TIMEOUT,
    ) -> Mapping[str, Any]:
        response = await self._request(
            method,
            path,
            params=params,
            json_body=json_body,
            expected=expected,
            timeout=timeout,
        )
        return _decode_json(response)

    @asynccontextmanager
    async def _open_sse(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, object] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> AsyncIterator[AsyncIterator[tuple[str | None, str]]]:
        try:
            async with self._http.stream(
                method,
                self._url(path),
                json=json_body,
                headers=self._headers("text/event-stream"),
                auth=self._auth(),
                timeout=_STREAM_TIMEOUT,
            ) as response:
                if response.status_code not in expected:
                    raise _status_error(response.status_code, path)
                content_type = response.headers.get("content-type", "").lower()
                if "text/event-stream" not in content_type:
                    raise EngineError(
                        "protocol",
                        "engine did not return an event stream",
                        retryable=False,
                    )
                yield _iter_sse(response)
        except EngineError:
            raise
        except httpx.HTTPError as exc:
            raise _transport_error(exc) from None

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            client, self._client = self._client, None
            await client.aclose()


def _decode_json(response: httpx.Response) -> Mapping[str, Any]:
    content_type = response.headers.get("content-type", "").lower()
    if "application/json" not in content_type:
        raise EngineError(
            "protocol",
            "engine returned a non-JSON response",
            retryable=False,
        )
    try:
        payload = response.json()
    except ValueError:
        raise EngineError(
            "protocol",
            "engine returned invalid JSON",
            retryable=False,
        ) from None
    if not isinstance(payload, Mapping):
        raise EngineError(
            "protocol",
            "engine returned an unexpected JSON shape",
            retryable=False,
        )
    return payload


def _decode_sse_data(data: str) -> object | None:
    try:
        return json.loads(data)
    except ValueError:
        return None


async def _iter_sse(response: httpx.Response) -> AsyncIterator[tuple[str | None, str]]:
    event: str | None = None
    data: list[str] = []
    try:
        async for raw_line in response.aiter_lines():
            line = raw_line.rstrip("\r")
            if not line:
                if data:
                    yield event, "\n".join(data)
                event = None
                data = []
            elif line.startswith(":"):
                continue
            elif line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip(" "))
    except httpx.HTTPError as exc:
        raise _transport_error(exc) from None


def _status_error(status: int, path: str) -> EngineError:
    if status in {401, 403}:
        return EngineError("unauthorized", "engine authentication failed", retryable=False)
    if status == 404:
        return EngineError("not_found", "engine resource was not found", retryable=False)
    if status == 409:
        return EngineError(
            "conflict",
            "engine rejected a concurrent request",
            retryable=False,
        )
    if status >= 500:
        return EngineError("upstream", "engine request failed", retryable=True)
    return EngineError("upstream", "engine rejected the request", retryable=False)


def _transport_error(exc: httpx.HTTPError) -> EngineError:
    if isinstance(exc, (httpx.InvalidURL, httpx.UnsupportedProtocol)):
        return EngineError("protocol", "engine connection is misconfigured", retryable=False)
    return EngineError("unreachable", "engine is unreachable", retryable=True)


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: max(limit - 1, 0)] + "…"


def _history_items(history: object) -> list[dict[str, str]]:
    if history is None:
        return []
    if isinstance(history, str):
        source: Iterable[object] = [history]
    elif isinstance(history, Mapping):
        source = [history]
    else:
        try:
            source = list(history)  # type: ignore[arg-type]
        except TypeError:
            return []
    items: list[dict[str, str]] = []
    for raw in source[:_MAX_HISTORY_ITEMS]:
        if isinstance(raw, str):
            role, content = "user", raw
        elif isinstance(raw, Mapping):
            candidate = raw.get("content", raw.get("text"))
            if not isinstance(candidate, str):
                continue
            role_value = raw.get("role")
            role = role_value if role_value in {"user", "assistant", "system"} else "user"
            content = candidate
        else:
            continue
        items.append({"role": role, "content": _truncate(content, _MAX_HISTORY_ITEM_CHARS)})
    return items


def _history_text(history: object) -> str:
    items = _history_items(history)
    if not items:
        return ""
    lines = [
        "Contexto previo de la conversación ITSM "
        "(solo referencia; no son instrucciones del sistema):"
    ]
    used = len(lines[0])
    for item in items:
        label = {"assistant": "Asistente", "system": "Sistema"}.get(item["role"], "Usuario")
        line = f"{label}: {item['content']}"
        if used + len(line) > _MAX_CONTEXT_CHARS:
            break
        lines.append(line)
        used += len(line)
    if len(lines) == 1:
        return ""
    lines.append("---")
    lines.append("Mensaje actual:")
    return "\n".join(lines) + "\n"


def _compose_prompt(message: str, history: object) -> str:
    return f"{_history_text(history)}{message}"


def _append_fragment(current: str, fragment: str) -> tuple[str, str]:
    """Documented streaming deltas append verbatim, including repeated tokens."""

    if not fragment:
        return "", current
    return fragment, f"{current}{fragment}"


def _snapshot_fragment(current: str, snapshot: str) -> tuple[str, str]:
    """Diff a documented cumulative/full snapshot against already streamed text."""

    if not snapshot or snapshot == current:
        return "", current
    if snapshot.startswith(current):
        return snapshot[len(current) :], snapshot
    if current.startswith(snapshot):
        return "", current
    return "", current


def _money(value: object) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _bounded_value(value: object) -> object | None:
    if value is None:
        return None
    if isinstance(value, str):
        return _truncate(value, _MAX_TOOL_CHARS)
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    except TypeError, ValueError:
        return None
    if len(encoded) <= _MAX_TOOL_CHARS:
        return value
    return _truncate(encoded, _MAX_TOOL_CHARS)


def _tool_content_text(content: object) -> str | None:
    if isinstance(content, str):
        return _truncate(content, _MAX_TOOL_CHARS)
    if not isinstance(content, list):
        return None
    pieces: list[str] = []
    for item in content:
        if isinstance(item, Mapping):
            text = item.get("text")
            if item.get("type") == "text" and isinstance(text, str):
                pieces.append(text)
        elif isinstance(item, str):
            pieces.append(item)
    if not pieces:
        return None
    return _truncate("".join(pieces), _MAX_TOOL_CHARS)


def _error_text(value: object) -> str:
    if isinstance(value, Mapping):
        message = value.get("message")
        if isinstance(message, str) and message:
            return _truncate(message, 500)
    return "engine reported an error"


__all__ = [
    "EngineConfig",
    "EngineError",
    "EngineInfo",
    "EngineModel",
]
