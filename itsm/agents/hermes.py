"""Hermes Agent adapter over its official HTTP API.

The adapter uses the documented capabilities document to select a transport:

* session chat streaming when both session resources and streamed chat exist,
* native runs with an event stream and an official stop endpoint,
* stateless OpenAI-compatible chat completions for older variants.

No capability is advertised unless the selected transport actually supports it.
The profile is selected by the authenticated API credential configured on the
Hermes server; the official request bodies do not accept an arbitrary profile
name, so this adapter never invents one.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Mapping
from typing import Any

from itsm.agents.engines import (
    EngineConfig,
    EngineError,
    EngineInfo,
    EngineModel,
    _HTTPEngine,
    _append_fragment,
    _bounded_value,
    _compose_prompt,
    _decode_sse_data,
    _error_text,
    _history_items,
    _money,
    _number,
    _snapshot_fragment,
    _tool_content_text,
)

_RECONNECT_ATTEMPTS = 1
_RECONNECT_DELAY_SECONDS = 0.05


class HermesEngine(_HTTPEngine):
    """Translate Hermes session, run, or stateless chat responses to neutral events."""

    def __init__(
        self,
        config: EngineConfig,
        *,
        client: Any = None,
    ) -> None:
        super().__init__(config, client=client)
        self._features: dict[str, bool] = {}
        self._transport = "none"
        self._active_runs: dict[str, str] = {}
        self._cancel_requested: set[str] = set()

    async def discover(self) -> EngineInfo:
        capabilities_payload: Mapping[str, Any] | None = None
        try:
            payload = await self._json("GET", "/v1/capabilities")
            if isinstance(payload, Mapping):
                capabilities_payload = payload
        except EngineError as exc:
            if exc.code != "not_found":
                raise

        version = "unknown"
        if capabilities_payload is not None:
            features = capabilities_payload.get("features")
            if features is not None and not isinstance(features, Mapping):
                raise EngineError(
                    "protocol",
                    "Hermes returned an invalid capability document",
                    retryable=False,
                )
            self._features = (
                {str(key): value is True for key, value in features.items()}
                if isinstance(features, Mapping)
                else {}
            )
            raw_version = capabilities_payload.get("version")
            if isinstance(raw_version, str) and raw_version:
                version = raw_version
            self._transport = _choose_transport(self._features)
        else:
            health = await self._json("GET", "/health")
            status = health.get("status")
            if status not in {"ok", "healthy", "ready"}:
                raise EngineError(
                    "upstream",
                    "Hermes reported an unavailable status",
                    retryable=True,
                )
            raw_version = health.get("version")
            if isinstance(raw_version, str) and raw_version:
                version = raw_version
            self._features = {}
            self._transport = "chat"

        models = await self._discover_models()
        capabilities = _capabilities(self._transport, self._features)
        self._models = models
        self._model_refs = {model.id: (model.provider, model.id) for model in models}
        self._capabilities = capabilities
        return EngineInfo(version=version, models=models, capabilities=dict(capabilities))

    async def create_session(self) -> str:
        if self._transport == "none":
            await self.discover()
        if self._transport == "session":
            payload = await self._json(
                "POST",
                "/api/sessions",
                json_body={"title": "ITSM chat"},
                expected=(200, 201),
            )
            session = payload.get("session")
            session_id = session.get("id") if isinstance(session, Mapping) else None
            if not isinstance(session_id, str) or not session_id:
                raise EngineError(
                    "protocol",
                    "Hermes did not return a session identifier",
                    retryable=False,
                )
            return session_id
        # No engine-side session resource is used by the selected transport.
        return f"itsm-{uuid.uuid4().hex}"

    async def stream(
        self,
        message: str,
        *,
        session_id: str,
        model: str | None = None,
        history: object = None,
    ) -> AsyncIterator[dict[str, object]]:
        if not isinstance(message, str) or not message:
            raise EngineError("protocol", "message must not be empty", retryable=False)
        if not isinstance(session_id, str) or not session_id:
            raise EngineError("protocol", "session identifier is required", retryable=False)
        if self._transport == "none":
            await self.discover()
        if self._transport == "session":
            async for event in self._stream_session(
                message,
                session_id=session_id,
                model=model,
                history=history,
            ):
                yield event
            return
        if self._transport == "runs":
            async for event in self._stream_run(
                message,
                session_id=session_id,
                model=model,
                history=history,
            ):
                yield event
            return
        if self._transport == "chat":
            async for event in self._stream_chat(
                message,
                session_id=session_id,
                model=model,
                history=history,
            ):
                yield event
            return
        raise EngineError(
            "unsupported",
            "this Hermes instance exposes no compatible chat API",
            retryable=False,
        )

    async def cancel(self, session_id: str) -> None:
        if self._transport != "runs" or not self._features.get("run_stop"):
            raise EngineError(
                "unsupported",
                "this Hermes transport has no official turn cancellation",
                retryable=False,
            )
        run_id = self._active_runs.get(session_id)
        if run_id is None:
            raise EngineError(
                "not_found",
                "no active Hermes run for this session",
                retryable=False,
            )
        self._cancel_requested.add(session_id)
        try:
            payload = await self._json(
                "POST",
                f"/v1/runs/{run_id}/stop",
            )
        except EngineError:
            self._cancel_requested.discard(session_id)
            raise
        status = payload.get("status")
        if not isinstance(status, str) or not status:
            self._cancel_requested.discard(session_id)
            raise EngineError(
                "protocol",
                "Hermes did not confirm the stop request",
                retryable=False,
            )

    async def _discover_models(self) -> list[EngineModel]:
        payload = await self._json("GET", "/v1/models")
        data = payload.get("data")
        if not isinstance(data, list):
            raise EngineError(
                "protocol",
                "Hermes returned an unexpected model list",
                retryable=False,
            )
        models: list[EngineModel] = []
        for item in data:
            if isinstance(item, str):
                raw_id = item
                name = item
                provider = "hermes"
            elif isinstance(item, Mapping):
                raw_id = item.get("id")
                if not isinstance(raw_id, str) or not raw_id:
                    continue
                name = item.get("name")
                if not isinstance(name, str) or not name:
                    name = raw_id
                provider = item.get("owned_by")
                if not isinstance(provider, str) or not provider:
                    provider = "hermes"
            else:
                continue
            models.append(
                EngineModel(
                    id=raw_id,
                    name=name,
                    provider=provider,
                    free=None,
                )
            )
        return models

    def _resolve_model(self, model: str | None) -> str | None:
        if model is None or model == "":
            return None
        if model in self._model_refs:
            return model
        if "/" in model:
            provider, model_id = model.split("/", 1)
            if not self._models:
                return model_id
            combined = f"{provider}/{model_id}"
            if combined in self._model_refs:
                return combined
        if not self._models:
            return model
        raise EngineError(
            "model_unavailable",
            "the selected model is not available on this instance",
            retryable=False,
        )

    async def _stream_session(
        self,
        message: str,
        *,
        session_id: str,
        model: str | None,
        history: object,
    ) -> AsyncIterator[dict[str, object]]:
        model_id = self._resolve_model(model)
        prompt = _compose_prompt(message, history)
        self._cancel_requested.discard(session_id)
        yield {"type": "session", "sessionId": session_id}

        body: dict[str, object] = {"input": prompt}
        if model_id is not None:
            body["model"] = model_id

        current_text = ""
        emitted_tools: set[tuple[str, str]] = set()
        cancelled_by_engine = False
        terminal = False
        failure: EngineError | None = None

        try:
            try:
                async with self._open_sse(
                    "POST",
                    f"/api/sessions/{session_id}/chat/stream",
                    json_body=body,
                    expected=(200, 201),
                ) as frames:
                    async for event_name, raw_data in frames:
                        payload = _decode_sse_data(raw_data)
                        if payload == "[DONE]":
                            terminal = True
                            break
                        data = payload if isinstance(payload, Mapping) else {}
                        event_type = event_name or data.get("type")
                        if not isinstance(event_type, str):
                            continue
                        if _session_hint(data) not in {None, session_id}:
                            continue

                        if event_type == "assistant.delta":
                            fragment, current_text = _append_fragment(
                                current_text, _payload_text(data)
                            )
                            if fragment:
                                yield {"type": "delta", "text": fragment}
                        elif event_type in {"tool.started", "tool.completed", "tool.failed"}:
                            for event in _tool_events(
                                event_type, data, emitted_tools
                            ):
                                yield event
                        elif event_type == "run.completed":
                            final_text = _final_text(data)
                            fragment, current_text = _snapshot_fragment(
                                current_text, final_text
                            )
                            if fragment:
                                yield {"type": "delta", "text": fragment}
                            usage = _usage_event(data)
                            if usage is not None:
                                yield usage
                            terminal = True
                            break
                        elif event_type == "run.cancelled":
                            cancelled_by_engine = True
                            terminal = True
                            break
                        elif event_type == "run.failed":
                            yield _error_event(
                                EngineError(
                                    "upstream",
                                    _error_text(data.get("error") or data),
                                    retryable=False,
                                )
                            )
                            terminal = True
                            break
            except EngineError as exc:
                failure = exc

            if not terminal and failure is None:
                failure = EngineError(
                    "unreachable",
                    "Hermes session stream ended before completion",
                    retryable=True,
                )
            if failure is not None and not (
                terminal and (session_id in self._cancel_requested or cancelled_by_engine)
            ):
                yield _error_event(failure)
        finally:
            cancelled = (
                session_id in self._cancel_requested or cancelled_by_engine
            )
            self._cancel_requested.discard(session_id)
        yield {"type": "done", "cancelled": cancelled}

    async def _stream_run(
        self,
        message: str,
        *,
        session_id: str,
        model: str | None,
        history: object,
    ) -> AsyncIterator[dict[str, object]]:
        model_id = self._resolve_model(model)
        self._cancel_requested.discard(session_id)
        yield {"type": "session", "sessionId": session_id}

        body: dict[str, object] = {"input": message, "session_id": session_id}
        history_items = _history_items(history)
        if history_items:
            body["conversation_history"] = history_items
        if model_id is not None:
            body["model"] = model_id

        emitted_tools: set[tuple[str, str]] = set()
        cancelled_by_engine = False
        terminal = False
        failure: EngineError | None = None
        run_id: str | None = None
        current_text = ""

        try:
            try:
                created = await self._json(  # type: ignore[assignment]
                    "POST",
                    "/v1/runs",
                    json_body=body,
                    expected=(200, 201, 202),
                )
            except EngineError as exc:
                failure = exc
            else:
                raw_run_id = created.get("run_id")
                if not isinstance(raw_run_id, str) or not raw_run_id:
                    failure = EngineError(
                        "protocol",
                        "Hermes did not return a run identifier",
                        retryable=False,
                    )
                else:
                    run_id = raw_run_id
                    self._active_runs[session_id] = run_id

            if failure is None and run_id is not None:
                for attempt in range(_RECONNECT_ATTEMPTS + 1):
                    try:
                        async with self._open_sse(
                            "GET",
                            f"/v1/runs/{run_id}/events",
                        ) as frames:
                            async for event_name, raw_data in frames:
                                payload = _decode_sse_data(raw_data)
                                if payload == "[DONE]":
                                    terminal = True
                                    break
                                data = payload if isinstance(payload, Mapping) else {}
                                event_type = event_name or data.get("type")
                                if not isinstance(event_type, str):
                                    continue
                                if _session_hint(data) not in {None, session_id}:
                                    continue
                                if event_type in {
                                    "tool.started",
                                    "tool.completed",
                                    "tool.failed",
                                }:
                                    for event in _tool_events(
                                        event_type, data, emitted_tools
                                    ):
                                        yield event
                                elif event_type == "run.completed":
                                    final_text = _final_text(data)
                                    fragment, current_text = _snapshot_fragment(
                                        current_text, final_text
                                    )
                                    if fragment:
                                        yield {"type": "delta", "text": fragment}
                                    usage = _usage_event(data)
                                    if usage is not None:
                                        yield usage
                                    terminal = True
                                    break
                                elif event_type == "run.cancelled":
                                    cancelled_by_engine = True
                                    terminal = True
                                    break
                                elif event_type == "run.failed":
                                    yield _error_event(
                                        EngineError(
                                            "upstream",
                                            _error_text(data.get("error") or data),
                                            retryable=False,
                                        )
                                    )
                                    terminal = True
                                    break
                    except EngineError as exc:
                        if exc.code == "unreachable" and attempt < _RECONNECT_ATTEMPTS:
                            await asyncio.sleep(_RECONNECT_DELAY_SECONDS)
                            continue
                        failure = exc
                        break
                    if terminal:
                        break
                    if attempt < _RECONNECT_ATTEMPTS:
                        await asyncio.sleep(_RECONNECT_DELAY_SECONDS)
                        continue
                    failure = EngineError(
                        "unreachable",
                        "Hermes run event stream ended before completion",
                        retryable=True,
                    )

            if failure is not None and not (
                terminal and (session_id in self._cancel_requested or cancelled_by_engine)
            ):
                yield _error_event(failure)
        finally:
            if run_id is not None:
                self._active_runs.pop(session_id, None)
                if not terminal:
                    await self._stop_quietly(run_id)
            cancelled = (
                session_id in self._cancel_requested or cancelled_by_engine
            )
            self._cancel_requested.discard(session_id)
        yield {"type": "done", "cancelled": cancelled}

    async def _stream_chat(
        self,
        message: str,
        *,
        session_id: str,
        model: str | None,
        history: object,
    ) -> AsyncIterator[dict[str, object]]:
        model_id = self._resolve_model(model)
        self._cancel_requested.discard(session_id)
        yield {"type": "session", "sessionId": session_id}

        messages = _history_items(history)
        messages.append({"role": "user", "content": message})
        body: dict[str, object] = {"messages": messages, "stream": True}
        if model_id is not None:
            body["model"] = model_id

        current_text = ""
        emitted_tools: set[tuple[str, str]] = set()
        terminal = False
        failure: EngineError | None = None

        try:
            try:
                async with self._open_sse(
                    "POST",
                    "/v1/chat/completions",
                    json_body=body,
                ) as frames:
                    async for event_name, raw_data in frames:
                        if raw_data.strip() == "[DONE]":
                            terminal = True
                            break
                        payload = _decode_sse_data(raw_data)
                        if payload == "[DONE]":
                            terminal = True
                            break
                        data = payload if isinstance(payload, Mapping) else {}
                        if event_name == "hermes.tool.progress":
                            for event in _progress_events(data, emitted_tools):
                                yield event
                            continue
                        usage = _usage_event(data)
                        if usage is not None:
                            yield usage
                        choices = data.get("choices")
                        if isinstance(choices, list):
                            for choice in choices:
                                if not isinstance(choice, Mapping):
                                    continue
                                delta = choice.get("delta")
                                if not isinstance(delta, Mapping):
                                    continue
                                fragment, current_text = _append_fragment(
                                    current_text, _payload_text(delta)
                                )
                                if fragment:
                                    yield {"type": "delta", "text": fragment}
            except EngineError as exc:
                failure = exc

            if failure is not None:
                yield _error_event(failure)
            else:
                terminal = True
        finally:
            cancelled = session_id in self._cancel_requested
            self._cancel_requested.discard(session_id)
        yield {"type": "done", "cancelled": cancelled}

    async def _stop_quietly(self, run_id: str) -> None:
        try:
            await self._json("POST", f"/v1/runs/{run_id}/stop")
        except EngineError:
            return


def _choose_transport(features: Mapping[str, bool]) -> str:
    if features.get("session_resources") and features.get("session_chat_stream"):
        return "session"
    if features.get("run_submission") and features.get("run_events_sse"):
        return "runs"
    if features.get("chat_completions"):
        return "chat"
    return "none"


def _capabilities(transport: str, features: Mapping[str, bool]) -> dict[str, bool]:
    if transport == "session":
        return {
            "streaming": True,
            "sessions": True,
            "model_switch": True,
            "cancel": False,
            "tools": True,
            "usage": True,
            "history": True,
        }
    if transport == "runs":
        return {
            "streaming": False,
            "sessions": False,
            "model_switch": True,
            "cancel": bool(features.get("run_stop")),
            "tools": True,
            "usage": True,
            "history": True,
        }
    if transport == "chat":
        return {
            "streaming": True,
            "sessions": False,
            "model_switch": True,
            "cancel": False,
            "tools": bool(features.get("tool_progress_events")),
            "usage": True,
            "history": True,
        }
    return {
        "streaming": False,
        "sessions": False,
        "model_switch": False,
        "cancel": False,
        "tools": False,
        "usage": False,
        "history": False,
    }


def _session_hint(data: Mapping[str, Any]) -> str | None:
    for key in ("session_id", "sessionID"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    session = data.get("session")
    if isinstance(session, Mapping):
        value = session.get("id")
        if isinstance(value, str) and value:
            return value
    nested = data.get("data")
    if isinstance(nested, Mapping):
        return _session_hint(nested)
    return None


def _payload_text(data: Mapping[str, Any]) -> str:
    for key in ("delta", "text", "content"):
        value = data.get(key)
        if isinstance(value, str):
            return value
    nested = data.get("data")
    if isinstance(nested, Mapping):
        return _payload_text(nested)
    return ""


def _content_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        pieces: list[str] = []
        for item in value:
            if isinstance(item, str):
                pieces.append(item)
            elif isinstance(item, Mapping):
                for key in ("text", "content"):
                    text = item.get(key)
                    if isinstance(text, str):
                        pieces.append(text)
                        break
        return "".join(pieces)
    if isinstance(value, Mapping):
        for key in ("text", "content"):
            text = value.get(key)
            if isinstance(text, str):
                return text
    return ""


def _final_text(data: Mapping[str, Any]) -> str:
    for key in ("content", "answer", "text", "response", "final", "output"):
        text = _content_text(data.get(key))
        if text:
            return text
    message = data.get("message")
    text = _content_text(message)
    if text:
        return text
    messages = data.get("messages")
    if isinstance(messages, list):
        for item in reversed(messages):
            if isinstance(item, Mapping) and item.get("role") == "assistant":
                text = _content_text(item.get("content"))
                if text:
                    return text
    nested = data.get("data")
    if isinstance(nested, Mapping):
        return _final_text(nested)
    return ""


def _tool_events(
    event_type: str,
    data: Mapping[str, Any],
    emitted: set[tuple[str, str]],
) -> list[dict[str, object]]:
    name = data.get("tool") or data.get("name")
    if not isinstance(name, str) or not name:
        return []
    status = {
        "tool.started": "running",
        "tool.completed": "completed",
        "tool.failed": "error",
    }[event_type]
    if (name, status) in emitted:
        return []
    emitted.add((name, status))
    event: dict[str, object] = {"type": "tool", "tool": name, "status": status}
    if status == "running":
        value = _bounded_value(data.get("preview") or data.get("input"))
        if value is not None:
            event["input"] = value
    elif status == "completed":
        value = _tool_content_text(data.get("preview") or data.get("output"))
        if value is None:
            value = _tool_content_text(data.get("result"))
        if value is not None:
            event["output"] = value
    else:
        value = _error_text(data.get("error") or data.get("preview") or data)
        event["output"] = value
    return [event]


def _progress_events(
    data: Mapping[str, Any],
    emitted: set[tuple[str, str]],
) -> list[dict[str, object]]:
    name = data.get("tool") or data.get("name")
    if not isinstance(name, str) or not name:
        return []
    raw_status = data.get("status")
    if raw_status in {"completed", "success", "succeeded"}:
        status = "completed"
    elif raw_status in {"failed", "error"}:
        status = "error"
    else:
        status = "running"
    if (name, status) in emitted:
        return []
    emitted.add((name, status))
    event: dict[str, object] = {"type": "tool", "tool": name, "status": status}
    value = _bounded_value(data.get("input") or data.get("preview"))
    if value is not None and status == "running":
        event["input"] = value
    if status != "running":
        output = _tool_content_text(data.get("output") or data.get("preview"))
        if output is None and status == "error":
            output = _error_text(data.get("error") or data)
        if output is not None:
            event["output"] = output
    return [event]


def _usage_event(payload: Mapping[str, Any]) -> dict[str, object] | None:
    usage = payload.get("usage")
    if not isinstance(usage, Mapping):
        usage = payload
    input_tokens = _number(usage.get("input_tokens"))
    if input_tokens is None:
        input_tokens = _number(usage.get("prompt_tokens"))
    output_tokens = _number(usage.get("output_tokens"))
    if output_tokens is None:
        output_tokens = _number(usage.get("completion_tokens"))
    if input_tokens is None or output_tokens is None:
        return None
    event: dict[str, object] = {
        "type": "usage",
        "inputTokens": input_tokens,
        "outputTokens": output_tokens,
        "source": "reported",
    }
    cost = _money(usage.get("cost_usd"))
    if cost is None:
        cost = _money(payload.get("cost_usd"))
    if cost is not None:
        event["cost"] = cost
    return event


def _error_event(error: EngineError) -> dict[str, object]:
    return {
        "type": "error",
        "code": error.code,
        "message": error.message,
        "retryable": error.retryable,
    }
