"""Hermes Agent adapter over its native serve JSON-RPC/WebSocket protocol.

Hermes 0.22.5 ``hermes serve`` exposes a dashboard WebSocket at ``/api/ws``
authenticated by the bundled basic dashboard provider. A loopback-only serve
also publishes its per-process session token at ``/`` (the desktop handshake);
a gated serve requires ``POST /api/auth/ws-ticket`` after password login.

The adapter never falls back to invented ``/v1`` resources or HTTP Basic auth.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import re
from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx
from itsm.agents.engines import (
    EngineConfig,
    EngineError,
    EngineInfo,
    EngineModel,
    _bounded_value,
    _compose_prompt,
    _error_text,
    _HTTPEngine,
    _money,
    _tool_content_text,
)
from itsm.agents.usage import genuine_count, measured_usage, unavailable_usage

_RPC_TIMEOUT = 30.0
_CONNECT_TIMEOUT = 10.0
_MAX_FRAME = 16 * 1024 * 1024
_TOKEN_PAGE = re.compile(r"__HERMES_SESSION_TOKEN__\s*=\s*\"([^\"]+)\"")


def _native_error(error: object) -> EngineError:
    if not isinstance(error, Mapping):
        return EngineError("protocol", "Hermes returned an invalid RPC error", retryable=False)
    code = error.get("code")
    message = error.get("message")
    text = message if isinstance(message, str) and message else "Hermes rejected the request"
    lowered = text.lower()
    if "session not found" in lowered or "not found" in lowered:
        return EngineError("not_found", "Hermes session was not found", retryable=False)
    if "interrupt" in lowered and "not" in lowered:
        return EngineError("not_found", "no active Hermes turn for this session", retryable=False)
    if code == -32601:
        return EngineError(
            "unsupported",
            "the Hermes serve build does not expose the required native method",
            retryable=False,
        )
    return EngineError("upstream", text, retryable=bool(code == -32000))


_USAGE_KEYS = ("input", "output", "cache_read", "cache_write", "reasoning", "total")
_TOP_LEVEL_USAGE = {
    "input": "input_tokens",
    "output": "output_tokens",
    "cache_read": "cache_read_tokens",
    "cache_write": "cache_write_tokens",
    "reasoning": "reasoning_tokens",
    "total": "total_tokens",
}


def _cumulative_counters(payload: Mapping[str, Any]) -> dict[str, int | None] | None:
    """Read one cumulative session snapshot without inventing absent counters."""

    if any(payload.get(key) is not None for key in _TOP_LEVEL_USAGE.values()):
        raw = {key: payload.get(alias) for key, alias in _TOP_LEVEL_USAGE.items()}
    else:
        nested = payload.get("usage")
        source = nested if isinstance(nested, Mapping) else payload
        raw = {
            "input": source.get("input", source.get("input_tokens")),
            "output": source.get("output", source.get("output_tokens")),
            "cache_read": None,
            "cache_write": None,
            "reasoning": source.get("reasoning"),
            "total": source.get("total", source.get("total_tokens")),
        }
    try:
        counters = {key: genuine_count(raw[key]) for key in _USAGE_KEYS}
    except ValueError:
        return None
    if all(value is None for value in counters.values()):
        return None
    return counters


def _usage_cost(payload: Mapping[str, Any] | None) -> float | None:
    if payload is None:
        return None
    nested = payload.get("usage")
    source = nested if isinstance(nested, Mapping) else payload
    for key in ("cost_usd", "cost"):
        value = _money(source.get(key))
        if value is not None and math.isfinite(value) and value >= 0:
            return value
    return None


def _usage_rank(payload: Mapping[str, Any]) -> int:
    """Count known counters so a richer snapshot wins over a partial TUI view."""

    counters = _cumulative_counters(payload)
    if counters is None:
        return 0
    return sum(value is not None for value in counters.values())


def _turn_usage(
    baseline: Mapping[str, int | None] | None,
    final: Mapping[str, int | None] | None,
    payload: Mapping[str, Any] | None,
    cost_payload: Mapping[str, Any] | None = None,
) -> dict[str, object]:
    """Convert cumulative snapshots into one turn delta or explicit unknown."""

    if baseline is None or final is None:
        return unavailable_usage(
            source="engine" if final is not None else "none",
            output_includes_reasoning=True,
        ).event()
    delta: dict[str, int | None] = {}
    comparable = False
    for key in _USAGE_KEYS:
        before = baseline.get(key)
        after = final.get(key)
        if before is None or after is None:
            delta[key] = None
            continue
        if after < before:
            return unavailable_usage(source="engine", output_includes_reasoning=True).event()
        comparable = True
        delta[key] = after - before
    if not comparable:
        return unavailable_usage(source="engine", output_includes_reasoning=True).event()
    return measured_usage(
        input_tokens=delta["input"],
        output_tokens=delta["output"],
        cache_read_tokens=delta["cache_read"],
        cache_write_tokens=delta["cache_write"],
        reasoning_tokens=delta["reasoning"],
        total_tokens=delta["total"],
        total_source="provider" if delta["total"] is not None else None,
        input_includes_cache=False,
        output_includes_reasoning=True,
        cost=_usage_cost(cost_payload if cost_payload is not None else payload),
    ).event()


def _message_complete(
    payload: Mapping[str, Any],
) -> tuple[Mapping[str, Any] | None, bool, bool]:
    """Return ``(cumulative_usage_payload, cancelled, failed)`` for a terminal event."""

    status = payload.get("status")
    usage = payload if _cumulative_counters(payload) is not None else None
    if status == "interrupted":
        return usage, True, False
    if status == "error" or payload.get("failure_reason"):
        return usage, False, True
    return usage, False, False


class HermesEngine(_HTTPEngine):
    """Native Hermes serve transport with persisted native sessions."""

    def __init__(
        self,
        config: EngineConfig,
        *,
        client: httpx.AsyncClient | None = None,
        socket_factory: Any = None,
    ) -> None:
        super().__init__(config, client=client)
        self._socket_factory = socket_factory
        self._ws: Any = None
        self._socket_cm: Any = None
        self._reader: asyncio.Task[None] | None = None
        self._ready = asyncio.Event()
        self._pending: dict[int, asyncio.Future[Mapping[str, Any]]] = {}
        self._queues: dict[str, asyncio.Queue[tuple[str, Mapping[str, Any]] | None]] = {}
        self._live: dict[str, str] = {}
        self._runtime_session: str | None = None
        self._needs_history: set[str] = set()
        self._cancel_requested: set[str] = set()
        self._usage_totals: dict[str, dict[str, int | None]] = {}
        self._rpc_id = 0

    @property
    def _password(self) -> str | None:
        return self.config.password or self.config.token

    async def discover(self) -> EngineInfo:
        await self._connect()
        version = await self._version()
        payload = await self._call("model.options")
        providers = payload.get("providers")
        if not isinstance(providers, list):
            raise EngineError(
                "protocol", "Hermes returned an unexpected provider list", retryable=False
            )
        models: list[EngineModel] = []
        seen: set[tuple[str, str]] = set()
        for row in providers:
            if not isinstance(row, Mapping):
                continue
            slug = row.get("slug")
            ids = row.get("models")
            if not isinstance(slug, str) or not slug or not isinstance(ids, list):
                continue
            for model_id in ids:
                if not isinstance(model_id, str) or not model_id:
                    continue
                key = (slug, model_id)
                if key in seen:
                    continue
                seen.add(key)
                free = row.get("free")
                models.append(
                    EngineModel(
                        id=model_id,
                        name=model_id,
                        provider=slug,
                        free=free if isinstance(free, bool) else None,
                    )
                )
        self._models = models
        capabilities = {
            "streaming": True,
            "sessions": True,
            "model_switch": True,
            "cancel": True,
            "tools": True,
            "usage": True,
            "history": False,
            # Hermes accepts a text prompt only; there is no attachment field in
            # its runtime protocol, so ITSM refuses attachments before spending.
            "attachments": False,
        }
        self._capabilities = capabilities
        return EngineInfo(version=version, models=models, capabilities=dict(capabilities))

    async def inspect_profile_runtime(self) -> dict[str, object]:
        """Read the active profile's live native surface without running a turn.

        The host launch proof owns HOME/identity; this method only corroborates
        what the already-authenticated child exposes.  It creates a disposable
        CLI session so ``tools.list`` reflects the launch profile instead of the
        dashboard profile roster.
        """

        await self._connect()
        params: dict[str, object] = {"source": "cli", "close_on_disconnect": True}
        if self.config.directory:
            params["cwd"] = self.config.directory
        created = await self._call("session.create", params)
        runtime = created.get("session_id")
        stored = created.get("stored_session_id")
        if not isinstance(runtime, str) or not runtime:
            raise EngineError(
                "protocol", "Hermes did not return an inspection session", retryable=False
            )
        try:
            tools_payload = await self._call("tools.list", {"session_id": runtime})
            rows = tools_payload.get("toolsets")
            if not isinstance(rows, list):
                raise EngineError(
                    "protocol", "Hermes returned an unexpected toolset list", retryable=False
                )
            toolsets: list[str] = []
            tool_names: list[str] = []
            for row in rows:
                if not isinstance(row, Mapping) or row.get("enabled") is not True:
                    continue
                name = row.get("name")
                if isinstance(name, str) and name:
                    toolsets.append(name)
                values = row.get("tools")
                if isinstance(values, list):
                    tool_names.extend(item for item in values if isinstance(item, str) and item)
            if not any(name.startswith("mcp__itsm__") for name in tool_names):
                raise EngineError(
                    "protocol",
                    "Hermes did not expose the managed ITSM MCP tools",
                    retryable=False,
                )
            mcp_payload = await self._call("mcp.servers.list", {})
            skills_payload = await self._call("skills.manage", {"action": "list"})
        finally:
            for method, identifier in (
                ("session.close", runtime),
                (
                    "session.delete",
                    stored if isinstance(stored, str) and stored else None,
                ),
            ):
                if identifier is None:
                    continue
                with contextlib.suppress(EngineError):
                    await self._call(method, {"session_id": identifier})

        servers = mcp_payload.get("servers")
        if not isinstance(servers, list):
            raise EngineError(
                "protocol", "Hermes returned an unexpected MCP server list", retryable=False
            )
        mcp_servers: list[dict[str, object]] = []
        for server in servers:
            if (
                not isinstance(server, Mapping)
                or not isinstance(server.get("name"), str)
                or server.get("enabled") is not True
            ):
                continue
            mcp_servers.append(
                {
                    "name": server["name"],
                    "url": server.get("url"),
                    "enabled": True,
                }
            )

        grouped = skills_payload.get("skills")
        skills: list[str] = []
        if isinstance(grouped, Mapping):
            for names in grouped.values():
                if isinstance(names, list):
                    skills.extend(name for name in names if isinstance(name, str) and name)

        base = (self.config.base_url or "").strip().rstrip("/")
        return {
            "protocol": "hermes-native-serve-v1",
            "endpoint": base,
            "profileHome": self.config.directory,
            "toolsets": sorted(set(toolsets)),
            "mcpServers": mcp_servers,
            "skills": sorted(set(skills)),
            "tools": sorted(set(tool_names)),
        }

    async def create_session(self) -> str:
        await self._connect()
        params: dict[str, object] = {
            "source": "cli",
            "close_on_disconnect": False,
        }
        if self.config.directory:
            params["cwd"] = self.config.directory
        payload = await self._call("session.create", params)
        stored = payload.get("stored_session_id")
        runtime = payload.get("session_id")
        if not isinstance(stored, str) or not stored or not isinstance(runtime, str) or not runtime:
            raise EngineError(
                "protocol", "Hermes did not return a session identifier", retryable=False
            )
        self._live[stored] = runtime
        self._needs_history.add(stored)
        self._usage_totals[stored] = {key: 0 for key in _USAGE_KEYS}
        self._queue(runtime)
        return stored

    async def stream(
        self,
        message: str,
        *,
        session_id: str,
        model: str | None = None,
        history: object = None,
        attachments: Sequence[Any] = (),
    ) -> AsyncIterator[dict[str, object]]:
        if not isinstance(message, str) or not message:
            raise EngineError("protocol", "message must not be empty", retryable=False)
        if not isinstance(session_id, str) or not session_id:
            raise EngineError("protocol", "session identifier is required", retryable=False)
        if attachments:
            # The Hermes runtime protocol carries a text prompt only; refusing
            # here means no prompt, tool call or provider spend happens.
            raise EngineError(
                "engine_attachments_unsupported",
                "the Hermes engine accepts text prompts only",
                retryable=False,
            )
        await self._connect()
        was_live = session_id in self._live
        runtime = await self._ensure_session(session_id)
        if not was_live:
            self._usage_totals.pop(session_id, None)
        baseline = self._usage_totals.get(session_id)
        if baseline is None:
            baseline = await self._session_usage(runtime)
            if baseline is not None:
                self._usage_totals[session_id] = baseline
        queue = self._queue(runtime)
        self._cancel_requested.discard(session_id)
        if model:
            provider = self._provider_for(model)
            value = f"{model} --session --provider {provider}" if provider else f"{model} --session"
            switch = await self._call(
                "config.set",
                {"key": "model", "value": value, "session_id": runtime},
            )
            if switch.get("confirm_required"):
                raise EngineError(
                    "confirmation_required",
                    str(switch.get("confirm_message") or "Hermes requires model confirmation"),
                    retryable=False,
                )
        prompt = message
        if session_id in self._needs_history:
            prompt = _compose_prompt(message, history)
        yield {"type": "session", "sessionId": session_id}
        await self._call("prompt.submit", {"session_id": runtime, "text": prompt})
        self._needs_history.discard(session_id)
        cancelled = False
        failed = False
        text_emitted = False
        terminal_error: str | None = None
        usage_payload: Mapping[str, Any] | None = None
        cost_payload: Mapping[str, Any] | None = None
        while True:
            item = await queue.get()
            if item is None:
                if not cancelled and not failed:
                    failed = True
                    terminal_error = "Hermes closed the event stream before the turn completed"
                break
            kind, payload = item
            if kind == "message.delta":
                fragment = payload.get("text")
                if isinstance(fragment, str) and fragment:
                    text_emitted = True
                    yield {"type": "delta", "text": fragment}
                continue
            if kind == "message.complete":
                completion, cancelled, failed = _message_complete(payload)
                if completion is not None:
                    if usage_payload is None or _usage_rank(completion) > _usage_rank(
                        usage_payload
                    ):
                        usage_payload = completion
                    if _usage_cost(completion) is not None:
                        cost_payload = completion
                text = payload.get("text")
                if isinstance(text, str) and text and not text_emitted:
                    yield {"type": "delta", "text": text}
                if failed:
                    reason = payload.get("failure_reason")
                    detail = payload.get("error")
                    terminal_error = (
                        (_error_text(detail) if detail else None)
                        or (reason if isinstance(reason, str) and reason else None)
                        or "Hermes reported a failed turn"
                    )
                break
            if kind == "tool.start":
                event = self._tool_event(payload, "running")
                if event is not None:
                    yield event
                continue
            if kind == "tool.complete":
                event = self._tool_event(payload, "completed")
                if event is not None:
                    yield event
                continue
            if kind == "tool.progress":
                event = self._tool_event(payload, "running")
                if event is not None:
                    yield event
                continue
            if kind == "session.usage":
                if _cumulative_counters(payload) is not None:
                    usage_payload = payload
                continue
            if kind in {"session.error", "error"}:
                failed = True
                reason = payload.get("failure_reason")
                detail = payload.get("error")
                terminal_error = (
                    (_error_text(detail) if detail else None)
                    or (reason if isinstance(reason, str) and reason else None)
                    or _error_text(payload)
                )
                break
        final_usage = _cumulative_counters(usage_payload) if usage_payload is not None else None
        if final_usage is not None:
            self._usage_totals[session_id] = final_usage
        else:
            self._usage_totals.pop(session_id, None)
        yield _turn_usage(baseline, final_usage, usage_payload, cost_payload)
        if terminal_error is not None:
            yield {
                "type": "error",
                "code": "upstream",
                "message": terminal_error,
                "retryable": False,
            }
        if cancelled:
            cancelled = session_id in self._cancel_requested
            self._cancel_requested.discard(session_id)
        yield {"type": "done", "cancelled": cancelled}

    async def cancel(self, session_id: str) -> None:
        runtime = self._live.get(session_id)
        if runtime is None:
            raise EngineError(
                "not_found", "no active Hermes session for this turn", retryable=False
            )
        self._cancel_requested.add(session_id)
        try:
            payload = await self._call("session.interrupt", {"session_id": runtime})
        except EngineError:
            self._cancel_requested.discard(session_id)
            raise
        status = payload.get("status")
        if status == "not_interrupted":
            self._cancel_requested.discard(session_id)
            raise EngineError("not_found", "no active Hermes turn to interrupt", retryable=False)

    # ---------------------------------------------------------------- transport
    async def _connect(self) -> None:
        if self._ws is not None:
            return
        if not self._password:
            raise EngineError(
                "authentication", "Hermes development credential is not configured", retryable=False
            )
        username = self.config.username or "admin"
        try:
            response = await self._http.post(
                self._url("/auth/password-login"),
                json={
                    "provider": "basic",
                    "username": username,
                    "password": self._password,
                    "next": "",
                },
                timeout=_RPC_TIMEOUT,
            )
        except httpx.HTTPError as exc:
            raise EngineError(
                "authentication", f"Hermes login failed: {type(exc).__name__}", retryable=True
            ) from None
        if response.status_code != 200:
            raise EngineError(
                "authentication", "Hermes rejected the development credentials", retryable=False
            )
        credential_name, credential = await self._ws_credential()
        base = (self.config.base_url or "").strip().rstrip("/")
        parsed = urlsplit(base)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise EngineError(
                "protocol", "engine base URL must be an absolute http(s) URL", retryable=False
            )
        scheme = "wss" if parsed.scheme == "https" else "ws"
        uri = urlunsplit(
            (scheme, parsed.netloc, "/api/ws", urlencode({credential_name: credential}), "")
        )
        try:
            if self._socket_factory is None:
                from websockets.asyncio.client import connect

                self._socket_cm = connect(
                    uri, proxy=None, max_size=_MAX_FRAME, open_timeout=_CONNECT_TIMEOUT
                )
                self._ws = await self._socket_cm.__aenter__()
            else:
                self._ws = await self._socket_factory(uri)
        except Exception as exc:
            self._socket_cm = None
            raise EngineError(
                "upstream",
                f"Hermes WebSocket connection failed: {type(exc).__name__}",
                retryable=True,
            ) from None
        self._ready.clear()
        self._reader = asyncio.create_task(self._read_loop())
        try:
            await asyncio.wait_for(self._ready.wait(), timeout=_CONNECT_TIMEOUT)
        except TimeoutError:
            await self._close_socket()
            raise EngineError(
                "upstream", "Hermes did not complete its native handshake", retryable=True
            ) from None

    async def _ws_credential(self) -> tuple[str, str]:
        try:
            response = await self._http.post(self._url("/api/auth/ws-ticket"), timeout=_RPC_TIMEOUT)
        except httpx.HTTPError as exc:
            raise EngineError(
                "authentication", f"Hermes ticket request failed: {type(exc).__name__}"
            ) from None
        if response.status_code == 200:
            payload = response.json()
            ticket = payload.get("ticket") if isinstance(payload, Mapping) else None
            if isinstance(ticket, str) and ticket:
                return "ticket", ticket
        root = await self._http.get(self._url("/"), timeout=_RPC_TIMEOUT)
        match = _TOKEN_PAGE.search(root.text) if root.status_code == 200 else None
        gate = (
            re.search(r"__HERMES_AUTH_REQUIRED__\s*=\s*(true|false)", root.text)
            if root.status_code == 200
            else None
        )
        if match is None or gate is None or gate.group(1) != "false":
            raise EngineError(
                "authentication",
                "Hermes requires a WebSocket ticket, but none was issued",
                retryable=False,
            )
        return "token", match.group(1)

    async def _version(self) -> str:
        try:
            response = await self._http.get(self._url("/openapi.json"), timeout=_RPC_TIMEOUT)
        except httpx.HTTPError:
            return "unknown"
        if response.status_code != 200:
            return "unknown"
        try:
            payload = response.json()
        except ValueError:
            return "unknown"
        info = payload.get("info") if isinstance(payload, Mapping) else None
        version = info.get("version") if isinstance(info, Mapping) else None
        return version if isinstance(version, str) and version else "unknown"

    async def _read_loop(self) -> None:
        try:
            while self._ws is not None:
                raw = await self._ws.recv()
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", "replace")
                try:
                    frame = json.loads(raw)
                except TypeError, ValueError:
                    continue
                if not isinstance(frame, Mapping):
                    continue
                method = frame.get("method")
                if "id" in frame and method is None:
                    future = self._pending.pop(frame.get("id"), None)
                    if future is not None and not future.done():
                        future.set_result(frame)
                    continue
                if method != "event":
                    continue
                params = frame.get("params")
                if not isinstance(params, Mapping):
                    continue
                kind = params.get("type")
                if kind == "gateway.ready":
                    self._ready.set()
                    continue
                session = params.get("session_id")
                payload = params.get("payload")
                if not isinstance(kind, str):
                    continue
                if not isinstance(payload, Mapping):
                    payload = {}
                queue = self._queues.get(session) if isinstance(session, str) else None
                if queue is not None:
                    queue.put_nowait((kind, payload))
        except Exception:
            pass
        finally:
            self._ready.set()
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(
                        EngineError("upstream", "Hermes WebSocket closed", retryable=True)
                    )
            self._pending.clear()
            for queue in self._queues.values():
                queue.put_nowait(None)

    async def _call(
        self, method: str, params: Mapping[str, object] | None = None
    ) -> Mapping[str, Any]:
        if self._ws is None:
            raise EngineError("upstream", "Hermes is not connected", retryable=True)
        self._rpc_id += 1
        request_id = self._rpc_id
        future: asyncio.Future[Mapping[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        frame = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": dict(params or {}),
        }
        try:
            await self._ws.send(json.dumps(frame))
        except Exception as exc:
            self._pending.pop(request_id, None)
            raise EngineError(
                "upstream", f"Hermes WebSocket send failed: {type(exc).__name__}", retryable=True
            ) from None
        try:
            response = await asyncio.wait_for(future, timeout=_RPC_TIMEOUT)
        except TimeoutError:
            self._pending.pop(request_id, None)
            raise EngineError(
                "upstream", "Hermes did not answer the request", retryable=True
            ) from None
        if "error" in response:
            raise _native_error(response.get("error"))
        result = response.get("result")
        return result if isinstance(result, Mapping) else {}

    async def _ensure_session(self, session_id: str) -> str:
        runtime = self._live.get(session_id)
        if runtime is not None:
            return runtime
        try:
            payload = await self._call("session.resume", {"session_id": session_id})
        except EngineError as exc:
            if exc.code == "not_found":
                raise
            raise
        runtime = payload.get("session_id")
        if not isinstance(runtime, str) or not runtime:
            raise EngineError(
                "protocol", "Hermes did not resume the native session", retryable=False
            )
        self._live[session_id] = runtime
        self._queue(runtime)
        return runtime

    async def _session_usage(self, runtime: str) -> dict[str, int | None] | None:
        """Read the native pre-turn cumulative baseline; unknown when unsupported."""

        try:
            payload = await self._call("session.stats", {"session_id": runtime})
        except EngineError:
            return None
        return _cumulative_counters(payload)

    def _queue(self, runtime: str) -> asyncio.Queue[tuple[str, Mapping[str, Any]] | None]:
        queue = self._queues.get(runtime)
        if queue is None:
            queue = asyncio.Queue()
            self._queues[runtime] = queue
        return queue

    def _provider_for(self, model: str) -> str | None:
        for candidate in self._models:
            if candidate.id == model:
                return candidate.provider
        return None

    def _tool_event(self, payload: Mapping[str, Any], default: str) -> dict[str, object] | None:
        name = payload.get("name")
        if not isinstance(name, str) or not name:
            return None
        status = default
        if default == "completed":
            raw = payload.get("status")
            if raw in {"failed", "error"} or payload.get("error"):
                status = "failed"
        event: dict[str, object] = {"type": "tool", "tool": name, "status": status}
        if status == "running":
            value = _bounded_value(payload.get("args") or payload.get("preview"))
            if value is not None:
                event["input"] = value
        else:
            result = payload.get("result")
            value = _tool_content_text(result)
            if value is None and isinstance(result, Mapping):
                value = _bounded_value(json.dumps(result, ensure_ascii=False))
            if value is None:
                value = _tool_content_text(payload.get("result_text"))
            if value is None:
                value = _tool_content_text(payload.get("summary"))
            if value is None and status == "failed":
                value = _error_text(payload.get("error") or payload)
            if value is not None:
                event["output"] = value
        return event

    async def _close_socket(self) -> None:
        reader = self._reader
        self._reader = None
        if reader is not None and reader is not asyncio.current_task():
            reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await reader
        socket_cm = self._socket_cm
        self._socket_cm = None
        self._ws = None
        if socket_cm is not None:
            with contextlib.suppress(Exception):
                await socket_cm.__aexit__(None, None, None)

    async def close(self) -> None:
        await self._close_socket()
        await super().close()
