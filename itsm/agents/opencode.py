"""OpenCode engine adapters for the v1 and v2 HTTP APIs."""

from __future__ import annotations

import asyncio
import math
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import suppress
from decimal import Decimal
from typing import Any

from itsm.agents.engines import (
    EngineConfig,
    EngineError,
    EngineInfo,
    EngineModel,
    _append_fragment,
    _bounded_value,
    _compose_prompt,
    _decode_sse_data,
    _error_text,
    _HTTPEngine,
    _money,
    _snapshot_fragment,
    _tool_content_text,
)
from itsm.agents.usage import (
    UsageEvidence,
    genuine_count,
    measured_usage,
    unavailable_usage,
)

_V2_CAPABILITIES = {
    "streaming": True,
    "sessions": True,
    "model_switch": True,
    "cancel": True,
    "tools": True,
    "usage": True,
    "history": True,
}

_RECONNECT_ATTEMPTS = 2
_RECONNECT_DELAY = 0.05


class OpenCodeEngine(_HTTPEngine):
    """Translate OpenCode's v2 (or legacy v1) API into neutral events."""

    def __init__(self, config: EngineConfig, *, client: Any = None) -> None:
        super().__init__(config, client=client)
        self._variant: str | None = None
        self._cancel_requested: set[str] = set()

    async def discover(self) -> EngineInfo:
        try:
            info = await self._json("GET", "/api/info")
        except EngineError as exc:
            if exc.code != "not_found":
                raise
            return await self._discover_v1()

        version = info.get("version")
        if not isinstance(version, str) or not version:
            raise EngineError(
                "protocol",
                "OpenCode did not return a server version",
                retryable=False,
            )
        models = await self._discover_v2_models()
        self._variant = "v2"
        self._capabilities = dict(_V2_CAPABILITIES)
        return EngineInfo(version=version, models=models, capabilities=dict(self._capabilities))

    async def _discover_v2_models(self) -> list[EngineModel]:
        params = {"location[directory]": self.config.directory} if self.config.directory else None
        payload = await self._json("GET", "/api/model", params=params)
        data = payload.get("data")
        if not isinstance(data, list):
            raise EngineError(
                "protocol",
                "OpenCode returned an unexpected model list",
                retryable=False,
            )
        models: list[EngineModel] = []
        refs: dict[str, tuple[str, str]] = {}
        for item in data:
            if not isinstance(item, Mapping):
                raise EngineError(
                    "protocol",
                    "OpenCode returned an invalid model entry",
                    retryable=False,
                )
            provider = item.get("providerID")
            model_id = item.get("id")
            name = item.get("name")
            if not isinstance(provider, str) or not provider:
                continue
            if not isinstance(model_id, str) or not model_id:
                continue
            if item.get("enabled") is False:
                continue
            public_id = f"{provider}/{model_id}"
            free = _v2_free(item.get("cost"))
            models.append(
                EngineModel(
                    id=public_id,
                    name=name if isinstance(name, str) and name else model_id,
                    provider=provider,
                    free=free,
                )
            )
            refs[public_id] = (provider, model_id)
        self._model_refs = refs
        self._models = models
        return models

    async def _discover_v1(self) -> EngineInfo:
        health = await self._json("GET", "/global/health")
        if health.get("healthy") is not True:
            raise EngineError("upstream", "OpenCode reported an unhealthy server", retryable=True)
        version = health.get("version")
        if not isinstance(version, str) or not version:
            raise EngineError(
                "protocol",
                "OpenCode did not return a server version",
                retryable=False,
            )
        payload = await self._json("GET", "/config/providers")
        providers = payload.get("providers")
        if isinstance(providers, Mapping):
            providers = list(providers.values())
        if not isinstance(providers, list):
            raise EngineError(
                "protocol",
                "OpenCode returned an unexpected provider list",
                retryable=False,
            )
        models: list[EngineModel] = []
        refs: dict[str, tuple[str, str]] = {}
        for provider in providers:
            if not isinstance(provider, Mapping):
                raise EngineError(
                    "protocol",
                    "OpenCode returned an invalid provider entry",
                    retryable=False,
                )
            provider_id = provider.get("id")
            configured_models = provider.get("models")
            if not isinstance(provider_id, str) or not provider_id:
                continue
            if not isinstance(configured_models, Mapping):
                continue
            for key, raw_model in configured_models.items():
                if not isinstance(key, str) or not key:
                    continue
                detail = raw_model if isinstance(raw_model, Mapping) else {}
                public_id = f"{provider_id}/{key}"
                name = detail.get("name")
                cost = detail.get("cost")
                models.append(
                    EngineModel(
                        id=public_id,
                        name=name if isinstance(name, str) and name else key,
                        provider=provider_id,
                        free=_v1_free(cost),
                    )
                )
                refs[public_id] = (provider_id, key)
        self._model_refs = refs
        self._models = models
        self._variant = "v1"
        self._capabilities = dict(_V2_CAPABILITIES)
        return EngineInfo(version=version, models=models, capabilities=dict(self._capabilities))

    async def create_session(self) -> str:
        if self._variant is None:
            await self.discover()
        if self._variant == "v1":
            payload = await self._json(
                "POST",
                "/session",
                json_body={"title": "ITSM chat"},
            )
            session_id = payload.get("id")
            if not isinstance(session_id, str) or not session_id:
                data = payload.get("data")
                session_id = data.get("id") if isinstance(data, Mapping) else None
            if not isinstance(session_id, str) or not session_id:
                raise EngineError(
                    "protocol",
                    "OpenCode did not return a session identifier",
                    retryable=False,
                )
            return session_id
        if self._variant != "v2":
            raise EngineError(
                "unsupported",
                "session creation is not available for this OpenCode API",
                retryable=False,
            )
        body: dict[str, object] = {"title": "ITSM chat"}
        if self.config.directory:
            body["location"] = {"directory": self.config.directory}
        if self.config.agent:
            body["agent"] = self.config.agent
        payload = await self._json("POST", "/api/session", json_body=body)
        data = payload.get("data")
        if not isinstance(data, Mapping):
            raise EngineError(
                "protocol",
                "OpenCode returned an unexpected session shape",
                retryable=False,
            )
        session_id = data.get("id")
        if not isinstance(session_id, str) or not session_id:
            raise EngineError(
                "protocol",
                "OpenCode did not return a session identifier",
                retryable=False,
            )
        return session_id

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
        if self._variant is None:
            await self.discover()
        if self._variant == "v1":
            async for event in self._stream_v1(
                message,
                session_id=session_id,
                model=model,
                history=history,
            ):
                yield event
            return
        if self._variant != "v2":
            raise EngineError(
                "unsupported",
                "streaming is not available for this OpenCode API",
                retryable=False,
            )

        model_ref = self._resolve_model(model)
        prompt = _compose_prompt(message, history)
        self._cancel_requested.discard(session_id)
        yield {"type": "session", "sessionId": session_id}

        current_text = ""
        assistant_id: str | None = None
        running_tool: str | None = None
        running_tool_id: str | None = None
        emitted_tools: set[tuple[str, str]] = set()
        tool_names: dict[str, str] = {}
        prompt_attempted = False
        prompt_confirmed = False
        terminal = False
        failure: EngineError | None = None
        final_message: Mapping[str, Any] | None = None
        final_messages: list[Mapping[str, Any]] = []
        prompt_message_id: str | None = None
        seen_event_ids: set[str] = set()

        try:
            for attempt in range(_RECONNECT_ATTEMPTS + 1):
                try:
                    async with self._open_sse("GET", "/api/event") as frames:
                        if not prompt_confirmed:
                            if not prompt_attempted:
                                if self.config.agent:
                                    await self._switch_agent(session_id)
                                if model_ref is not None:
                                    await self._switch_model(session_id, model_ref)
                            prompt_attempted = True
                            prompt_message_id = await self._prompt(session_id, prompt)
                            prompt_confirmed = True

                        async for _event_name, raw_data in frames:
                            payload = _decode_sse_data(raw_data)
                            if not isinstance(payload, Mapping):
                                continue
                            envelope_id = payload.get("id")
                            if isinstance(envelope_id, (str, int)):
                                event_key = str(envelope_id)
                                if event_key in seen_event_ids:
                                    continue
                                seen_event_ids.add(event_key)
                            event_type = payload.get("type")
                            data = payload.get("data")
                            if not isinstance(event_type, str) or not isinstance(data, Mapping):
                                continue
                            if data.get("sessionID") != session_id:
                                continue
                            message_id = data.get("assistantMessageID")
                            if isinstance(message_id, str) and message_id:
                                assistant_id = message_id

                            if event_type == "session.text.delta":
                                delta = data.get("delta")
                                if isinstance(delta, str):
                                    fragment, current_text = _append_fragment(current_text, delta)
                                    if fragment:
                                        yield {"type": "delta", "text": fragment}
                            elif event_type == "session.text.ended":
                                final_text = data.get("text")
                                if isinstance(final_text, str):
                                    fragment, current_text = _snapshot_fragment(
                                        current_text, final_text
                                    )
                                    if fragment:
                                        yield {"type": "delta", "text": fragment}
                            elif event_type == "session.tool.input.started":
                                tool_id = data.get("id")
                                tool = _tool_name(data)
                                if isinstance(tool_id, str) and tool:
                                    tool_names[tool_id] = tool
                            elif event_type == "session.tool.called":
                                tool_id = data.get("id")
                                tool = _tool_name(data) or (
                                    tool_names.get(tool_id) if isinstance(tool_id, str) else None
                                )
                                if tool:
                                    running_tool = tool
                                    tool_id = data.get("id")
                                    running_tool_id = tool_id if isinstance(tool_id, str) else None
                                    event: dict[str, object] = {
                                        "type": "tool",
                                        "tool": tool,
                                        "status": "running",
                                    }
                                    tool_input = _bounded_value(data.get("input"))
                                    if tool_input is not None:
                                        event["input"] = tool_input
                                    emitted_tools.add((tool, "running"))
                                    yield event
                            elif event_type == "session.tool.success":
                                tool_id = data.get("id")
                                tool = _tool_name(data) or (
                                    tool_names.get(tool_id) if isinstance(tool_id, str) else None
                                ) or running_tool or "tool"
                                event = {
                                    "type": "tool",
                                    "tool": tool,
                                    "status": "completed",
                                }
                                output = _tool_content_text(data.get("content"))
                                if output is not None:
                                    event["output"] = output
                                emitted_tools.add((tool, "completed"))
                                running_tool = None
                                running_tool_id = None
                                yield event
                            elif event_type == "session.tool.failed":
                                tool_id = data.get("id")
                                tool = _tool_name(data) or (
                                    tool_names.get(tool_id) if isinstance(tool_id, str) else None
                                ) or running_tool or "tool"
                                event = {
                                    "type": "tool",
                                    "tool": tool,
                                    "status": "failed",
                                }
                                output = _tool_content_text(data.get("content"))
                                if output is None:
                                    output = _error_text(data.get("error"))
                                event["output"] = output
                                emitted_tools.add((tool, "failed"))
                                running_tool = None
                                running_tool_id = None
                                yield event
                            elif event_type == "session.status":
                                status = data.get("status")
                                if isinstance(status, Mapping) and status.get("type") == "idle":
                                    terminal = True
                                    break
                            elif event_type in {"session.idle", "session.execution.succeeded"}:
                                terminal = True
                                break
                            elif event_type in {"session.error", "session.execution.failed"}:
                                error = EngineError(
                                    "upstream",
                                    _error_text(data.get("error") or data),
                                    retryable=False,
                                )
                                emitted_error = _error_event(error)
                                yield emitted_error
                                terminal = True
                                break
                            elif running_tool_id and event_type.endswith(".input.ended"):
                                # Input is not surfaced until the tool actually runs.
                                continue

                    if terminal:
                        break
                except EngineError as exc:
                    if prompt_attempted and not prompt_confirmed:
                        failure = exc
                        break
                    if exc.code != "unreachable" or attempt >= _RECONNECT_ATTEMPTS:
                        failure = exc
                        break
                    await asyncio.sleep(_RECONNECT_DELAY)
                    recovered = await self._recover_messages(
                        session_id, prompt_message_id
                    )
                    if recovered:
                        final_messages = recovered
                    final_message = _select_final(final_messages, assistant_id)
                    if final_message is not None:
                        terminal = True
                        break
                    continue

                if terminal:
                    break
                if attempt < _RECONNECT_ATTEMPTS:
                    recovered = await self._recover_messages(
                        session_id, prompt_message_id
                    )
                    if recovered:
                        final_messages = recovered
                    final_message = _select_final(final_messages, assistant_id)
                    if final_message is not None:
                        terminal = True
                        break
                    continue
                failure = EngineError(
                    "unreachable",
                    "engine event stream ended before the turn completed",
                    retryable=True,
                )
                break

            if terminal:
                if final_message is None:
                    recovered = await self._recover_messages(
                        session_id, prompt_message_id
                    )
                    if recovered:
                        final_messages = recovered
                    final_message = _select_final(final_messages, assistant_id)
                if final_message is not None:
                    async for event in self._final_events(
                        final_message, current_text, emitted_tools
                    ):
                        if event["type"] == "delta":
                            fragment, current_text = _append_fragment(
                                current_text, str(event["text"])
                            )
                            if not fragment:
                                continue
                        yield event
            elif failure is not None:
                yield _error_event(failure)
        finally:
            if prompt_attempted and not terminal:
                await self._interrupt_quietly(session_id)
            cancelled = session_id in self._cancel_requested
            self._cancel_requested.discard(session_id)
        if prompt_attempted:
            if final_messages:
                yield _usage_evidence(final_messages).event()
            else:
                yield unavailable_usage(source="engine").event()
        yield {"type": "done", "cancelled": cancelled}

    async def _stream_v1(
        self,
        message: str,
        *,
        session_id: str,
        model: str | None,
        history: object,
    ) -> AsyncIterator[dict[str, object]]:
        model_ref = self._resolve_model(model)
        prompt = _compose_prompt(message, history)
        self._cancel_requested.discard(session_id)
        yield {"type": "session", "sessionId": session_id}

        current_text = ""
        part_texts: dict[str, str] = {}
        emitted_tools: set[tuple[str, str]] = set()
        usage_messages: dict[str, Mapping[str, Any]] = {}
        usage_steps: dict[str, Mapping[str, Any]] = {}
        messages_unreliable = False
        steps_unreliable = False
        baseline_ids: set[str] | None = None
        cancelled_by_engine = False
        prompt_attempted = False
        terminal = False
        failure: EngineError | None = None
        post_task: asyncio.Task[Mapping[str, Any]] | None = None

        try:
            try:
                async with self._open_sse("GET", "/event") as frames:
                    baseline_ids = await self._v1_message_ids(session_id)
                    body: dict[str, object] = {
                        "parts": [{"type": "text", "text": prompt}],
                    }
                    if model_ref is not None:
                        body["model"] = f"{model_ref[0]}/{model_ref[1]}"
                    if self.config.agent:
                        body["agent"] = self.config.agent
                    prompt_attempted = True
                    post_task = asyncio.create_task(self._v1_send_message(session_id, body))
                    async for event_name, raw_data in frames:
                        payload = _decode_sse_data(raw_data)
                        if not isinstance(payload, Mapping):
                            continue
                        event_type = payload.get("type") or event_name
                        properties = payload.get("properties")
                        data = properties if isinstance(properties, Mapping) else payload
                        if not isinstance(event_type, str):
                            continue
                        event_session = data.get("sessionID")
                        if event_session is None:
                            part = data.get("part")
                            if isinstance(part, Mapping):
                                event_session = part.get("sessionID")
                        if event_session is not None and event_session != session_id:
                            continue

                        if event_type == "message.part.updated":
                            part = data.get("part")
                            if not isinstance(part, Mapping):
                                continue
                            part_type = part.get("type")
                            if part_type == "text":
                                incoming = part.get("text")
                                if isinstance(incoming, str):
                                    part_id = str(part.get("id") or part.get("messageID") or "text")
                                    previous = part_texts.get(part_id, "")
                                    fragment, part_texts[part_id] = _snapshot_fragment(
                                        previous, incoming
                                    )
                                    if fragment:
                                        current_text = f"{current_text}{fragment}"
                                        yield {"type": "delta", "text": fragment}
                            elif part_type == "tool":
                                tool = _tool_name(part)
                                state = part.get("state")
                                if not isinstance(tool, str) or not isinstance(state, Mapping):
                                    continue
                                status_value = state.get("status")
                                if status_value in {"pending", "running"}:
                                    status = "running"
                                    output = None
                                elif status_value == "completed":
                                    status = "completed"
                                    output = _tool_content_text(state.get("output"))
                                    if output is None and isinstance(state.get("output"), str):
                                        output = state["output"]
                                elif status_value == "error":
                                    status = "failed"
                                    output = _tool_content_text(state.get("output"))
                                    if output is None:
                                        output = _error_text(state.get("error"))
                                else:
                                    continue
                                if (tool, status) in emitted_tools:
                                    continue
                                event: dict[str, object] = {
                                    "type": "tool",
                                    "tool": tool,
                                    "status": status,
                                }
                                tool_input = _bounded_value(state.get("input"))
                                if tool_input is not None and status == "running":
                                    event["input"] = tool_input
                                if output is not None:
                                    event["output"] = output
                                emitted_tools.add((tool, status))
                                yield event
                            elif part_type == "step-finish":
                                if isinstance(part.get("tokens"), Mapping):
                                    step_message_id = part.get("messageID")
                                    if (
                                        baseline_ids is not None
                                        and isinstance(step_message_id, str)
                                        and step_message_id in baseline_ids
                                    ):
                                        continue
                                    step_key = part.get("id") or step_message_id
                                    if step_key is None:
                                        steps_unreliable = True
                                    else:
                                        usage_steps[str(step_key)] = part
                        elif event_type == "message.updated":
                            info = data.get("info")
                            if (
                                isinstance(info, Mapping)
                                and info.get("role") == "assistant"
                                and isinstance(info.get("tokens"), Mapping)
                            ):
                                message_key = info.get("id") or info.get("messageID")
                                if message_key is None:
                                    messages_unreliable = True
                                elif baseline_ids is not None and str(message_key) in baseline_ids:
                                    continue
                                else:
                                    usage_messages[str(message_key)] = info
                        elif event_type == "session.idle":
                            terminal = True
                            break
                        elif event_type == "session.error":
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

            if post_task is not None:
                try:
                    result = await post_task
                except EngineError as exc:
                    if not (terminal and session_id in self._cancel_requested):
                        failure = failure or exc
                else:
                    final_text = _v1_final_text(result)
                    if final_text:
                        fragment, current_text = _snapshot_fragment(current_text, final_text)
                        if fragment:
                            yield {"type": "delta", "text": fragment}
                    info = result.get("info")
                    if (
                        isinstance(info, Mapping)
                        and info.get("role") == "assistant"
                        and isinstance(info.get("tokens"), Mapping)
                    ):
                        message_key = info.get("id") or info.get("messageID")
                        if message_key is None:
                            messages_unreliable = True
                        elif baseline_ids is None or str(message_key) not in baseline_ids:
                            usage_messages[str(message_key)] = info
                    terminal = True
                    failure = None

            if not terminal and failure is None:
                failure = EngineError(
                    "unreachable",
                    "OpenCode turn ended before completion",
                    retryable=True,
                )
            if failure is not None and not (
                terminal and (session_id in self._cancel_requested or cancelled_by_engine)
            ):
                yield _error_event(failure)
        finally:
            if prompt_attempted and not terminal:
                await self._interrupt_quietly(session_id)
            if post_task is not None and not post_task.done():
                post_task.cancel()
                with suppress(BaseException):
                    await post_task
            cancelled = session_id in self._cancel_requested or cancelled_by_engine
            self._cancel_requested.discard(session_id)
        messages = (
            list(usage_messages.values())
            if usage_messages
            else list(usage_steps.values())
        )
        reliable = baseline_ids is not None and not (
            messages_unreliable if usage_messages else steps_unreliable
        )
        if prompt_attempted:
            if messages and reliable:
                yield _usage_evidence(messages).event()
            else:
                yield unavailable_usage(source="engine").event()
        yield {"type": "done", "cancelled": cancelled}

    async def _v1_message_ids(self, session_id: str) -> set[str] | None:
        """Read the pre-prompt message ids, or None when not trustworthy."""

        try:
            response = await self._request(
                "GET",
                f"/session/{session_id}/message",
                expected=(200,),
            )
            payload = response.json()
        except (EngineError, ValueError):
            return None
        data = payload.get("data") if isinstance(payload, Mapping) else payload
        if not isinstance(data, list):
            return None
        ids: set[str] = set()
        for item in data:
            if not isinstance(item, Mapping):
                return None
            info = item.get("info")
            message = info if isinstance(info, Mapping) else item
            message_id = message.get("id") or message.get("messageID")
            if not isinstance(message_id, str) or not message_id:
                return None
            ids.add(message_id)
        return ids

    async def _v1_send_message(
        self, session_id: str, body: Mapping[str, object]
    ) -> Mapping[str, Any]:
        payload = await self._json(
            "POST",
            f"/session/{session_id}/message",
            json_body=body,
        )
        if not isinstance(payload.get("parts"), list) or not isinstance(
            payload.get("info"), Mapping
        ):
            raise EngineError(
                "protocol",
                "OpenCode did not return the completed turn",
                retryable=False,
            )
        return payload

    async def cancel(self, session_id: str) -> None:
        """Actually interrupt the active execution when OpenCode supports it."""
        if not isinstance(session_id, str) or not session_id:
            raise EngineError("protocol", "session identifier is required", retryable=False)
        if self._variant is None:
            await self.discover()
        self._cancel_requested.add(session_id)
        try:
            if self._variant == "v1":
                response = await self._request(
                    "POST",
                    f"/session/{session_id}/abort",
                    expected=(200,),
                )
                try:
                    accepted = response.json()
                except ValueError:
                    accepted = None
                if accepted is False:
                    self._cancel_requested.discard(session_id)
                return
            payload = await self._json(
                "POST",
                f"/api/session/{session_id}/interrupt",
                json_body={},
            )
        except EngineError:
            self._cancel_requested.discard(session_id)
            raise
        if payload.get("interrupted") is not True:
            self._cancel_requested.discard(session_id)

    async def _switch_agent(self, session_id: str) -> None:
        agent = self.config.agent
        if not agent:
            return
        await self._request(
            "POST",
            f"/api/session/{session_id}/agent",
            json_body={"agent": agent},
            expected=(204,),
        )

    async def _switch_model(self, session_id: str, model_ref: tuple[str, str]) -> None:
        provider, model_id = model_ref
        await self._request(
            "POST",
            f"/api/session/{session_id}/model",
            json_body={"model": {"id": model_id, "providerID": provider}},
            expected=(204,),
        )

    async def _prompt(self, session_id: str, prompt: str) -> str | None:
        payload = await self._json(
            "POST",
            f"/api/session/{session_id}/prompt",
            json_body={"text": prompt},
        )
        data = payload.get("data")
        if not isinstance(data, Mapping):
            raise EngineError(
                "protocol",
                "OpenCode did not acknowledge the prompt",
                retryable=False,
            )
        message_id = data.get("id")
        return message_id if isinstance(message_id, str) else None

    async def _recover_messages(
        self, session_id: str, prompt_message_id: str | None
    ) -> list[Mapping[str, Any]] | None:
        """Return completed assistant messages for this run, or ``None`` on failure.

        The message list is session scoped. When the protocol returns the user
        message that started this run, use it as the anchor so earlier turns are
        not recharged. Without an anchor, all completed assistant messages in the
        session are the only evidence available; callers must treat that as an
        isolation limit rather than proof of run membership.
        """

        try:
            payload = await self._json(
                "GET",
                f"/api/session/{session_id}/message",
                params={"limit": "20", "order": "desc"},
            )
        except EngineError:
            return None
        data = payload.get("data")
        if not isinstance(data, list):
            return None
        if prompt_message_id is None:
            return None
        items = [item for item in data if isinstance(item, Mapping)]
        anchor = next(
            (
                index
                for index, item in enumerate(items)
                if item.get("id") == prompt_message_id and item.get("type") == "user"
            ),
            None,
        )
        if anchor is None:
            return None
        items = items[:anchor]
        messages: list[Mapping[str, Any]] = []
        for item in items:
            if item.get("type") != "assistant":
                continue
            time_value = item.get("time")
            completed = isinstance(time_value, Mapping) and "completed" in time_value
            if not completed and not isinstance(item.get("finish"), str):
                continue
            messages.append(item)
        return messages

    async def _final_events(
        self,
        message: Mapping[str, Any],
        current_text: str,
        emitted_tools: set[tuple[str, str]],
    ) -> AsyncIterator[dict[str, object]]:
        text = _assistant_text(message)
        if text:
            fragment, _ = _snapshot_fragment(current_text, text)
            if fragment:
                yield {"type": "delta", "text": fragment}
        content = message.get("content")
        if isinstance(content, list):
            for part in content:
                if not isinstance(part, Mapping) or part.get("type") != "tool":
                    continue
                tool = part.get("name")
                state = part.get("state")
                if not isinstance(tool, str) or not isinstance(state, Mapping):
                    continue
                status_value = state.get("status")
                if status_value in {"running", "streaming"}:
                    status = "running"
                    output = None
                elif status_value == "completed":
                    status = "completed"
                    output = _tool_content_text(state.get("content"))
                elif status_value == "error":
                    status = "failed"
                    output = _tool_content_text(state.get("content")) or _error_text(
                        state.get("error")
                    )
                else:
                    continue
                if (tool, status) in emitted_tools:
                    continue
                event: dict[str, object] = {
                    "type": "tool",
                    "tool": tool,
                    "status": status,
                }
                if output is not None:
                    event["output"] = output
                emitted_tools.add((tool, status))
                yield event

    def _resolve_model(self, model: str | None) -> tuple[str, str] | None:
        if model is None or model == "":
            return None
        if not isinstance(model, str):
            raise EngineError("model_unavailable", "model selection is invalid", retryable=False)
        if model in self._model_refs:
            return self._model_refs[model]
        if "/" in model:
            provider, model_id = model.split("/", 1)
            if provider and model_id:
                if self._models:
                    raise EngineError(
                        "model_unavailable",
                        "the selected model is not available on this instance",
                        retryable=False,
                    )
                return provider, model_id
        matches = [
            ref for public_id, ref in self._model_refs.items() if public_id.endswith(f"/{model}")
        ]
        if len(matches) == 1:
            return matches[0]
        raise EngineError(
            "model_unavailable",
            "the selected model is not available on this instance",
            retryable=False,
        )

    async def _interrupt_quietly(self, session_id: str) -> None:
        path = (
            f"/session/{session_id}/abort"
            if self._variant == "v1"
            else f"/api/session/{session_id}/interrupt"
        )
        try:
            await self._request("POST", path, json_body={}, expected=(200,))
        except EngineError:
            return


def _price(value: object) -> float | int | None:
    price = _money(value)
    if price is None or not math.isfinite(price) or price < 0:
        return None
    return price


def _cost_free(cost: Mapping[str, object], *, require_cache: bool) -> bool | None:
    """Classify a cost record without assuming provider or free tiers.

    Required input and output prices must be present. v2 requires cache read
    and write prices; v1 treats cache as optional. Any explicit reasoning price
    is included when the record carries one. Missing or malformed required
    metadata is unknown; any positive reported price is paid; all zero is free.
    """
    prices: list[float | int] = []
    for key in ("input", "output"):
        price = _price(cost.get(key))
        if price is None:
            return None
        prices.append(price)
    cache = cost.get("cache")
    if cache is None:
        if require_cache:
            return None
    elif not isinstance(cache, Mapping):
        return None
    else:
        for key in ("read", "write"):
            if key not in cache:
                if require_cache:
                    return None
                continue
            price = _price(cache.get(key))
            if price is None:
                return None
            prices.append(price)
    reasoning = cost.get("reasoning")
    if reasoning is not None:
        price = _price(reasoning)
        if price is None:
            return None
        prices.append(price)
    return not any(price > 0 for price in prices)


def _v1_free(cost: object) -> bool | None:
    if not isinstance(cost, Mapping):
        return None
    return _cost_free(cost, require_cache=False)


def _v1_final_text(result: Mapping[str, Any]) -> str:
    parts = result.get("parts")
    if not isinstance(parts, list):
        return ""
    pieces: list[str] = []
    for part in parts:
        if isinstance(part, Mapping) and part.get("type") == "text":
            text = part.get("text")
            if isinstance(text, str):
                pieces.append(text)
    return "".join(pieces)


def _v2_free(costs: object) -> bool | None:
    if not isinstance(costs, list) or not costs:
        return None
    any_positive = False
    metadata_complete = True
    for cost in costs:
        if not isinstance(cost, Mapping):
            metadata_complete = False
            continue
        entry = _cost_free(cost, require_cache=True)
        if entry is False:
            any_positive = True
        elif entry is None:
            metadata_complete = False
    if any_positive:
        return False
    return True if metadata_complete else None


def _tool_name(data: Mapping[str, Any]) -> str | None:
    for key in ("tool", "name", "toolName"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _assistant_text(message: Mapping[str, Any]) -> str:
    content = message.get("content")
    if not isinstance(content, list):
        return ""
    pieces: list[str] = []
    for part in content:
        if isinstance(part, Mapping) and part.get("type") == "text":
            text = part.get("text")
            if isinstance(text, str):
                pieces.append(text)
    return "".join(pieces)


def _select_final(
    messages: Sequence[Mapping[str, Any]], assistant_id: str | None
) -> Mapping[str, Any] | None:
    if assistant_id is not None:
        for message in messages:
            if message.get("id") == assistant_id:
                return message
        return None
    return messages[0] if messages else None


def _token_count(value: object) -> int | None:
    try:
        return genuine_count(value)
    except (TypeError, ValueError):
        return None


def _usage_cost(value: object) -> float | None:
    amount = _money(value)
    if amount is None or not math.isfinite(float(amount)):
        return None
    return float(amount)


def _usage_evidence(messages: Sequence[Mapping[str, Any]]) -> UsageEvidence:
    """Sum disjoint OpenCode components across distinct assistant messages.

    OpenCode reports uncached input, visible output (excluding reasoning), and
    cache/reasoning children separately. A component missing from any message
    stays unknown for the run; the provider total is not reported by the native
    protocol, so a total is derived only when every component is known.
    """

    totals = {
        "input": 0,
        "output": 0,
        "cache_read": 0,
        "cache_write": 0,
        "reasoning": 0,
    }
    unknown = {key: False for key in totals}
    cost = Decimal(0)
    cost_known = True
    for message in messages:
        tokens = message.get("tokens")
        if not isinstance(tokens, Mapping):
            return unavailable_usage(source="engine")
        cache = tokens.get("cache")
        cache_map = cache if isinstance(cache, Mapping) else {}
        values = {
            "input": _token_count(tokens.get("input")),
            "output": _token_count(tokens.get("output")),
            "cache_read": _token_count(cache_map.get("read")),
            "cache_write": _token_count(cache_map.get("write")),
            "reasoning": _token_count(tokens.get("reasoning")),
        }
        for key, value in values.items():
            if value is None:
                unknown[key] = True
            else:
                totals[key] += value
        amount = _usage_cost(message.get("cost"))
        if amount is None:
            cost_known = False
        else:
            cost += Decimal(str(amount))
    try:
        return measured_usage(
            input_tokens=None if unknown["input"] else totals["input"],
            output_tokens=None if unknown["output"] else totals["output"],
            cache_read_tokens=None if unknown["cache_read"] else totals["cache_read"],
            cache_write_tokens=None if unknown["cache_write"] else totals["cache_write"],
            reasoning_tokens=None if unknown["reasoning"] else totals["reasoning"],
            input_includes_cache=False,
            output_includes_reasoning=False,
            cost=float(cost) if cost_known else None,
        )
    except ValueError:
        return unavailable_usage(source="engine")


def _error_event(error: EngineError) -> dict[str, object]:
    return {
        "type": "error",
        "code": error.code,
        "message": error.message,
        "retryable": error.retryable,
    }


__all__ = ["OpenCodeEngine"]
