"""HTTP adapter for the conversational inventory agent."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from itsm.agents.runtime import AgentRuntime, AgentUnavailable, ChatReply, ChatRequest
from itsm.identity.api import MutationDependency
from itsm.logging import log_event

logger = logging.getLogger("itsm.agent")


def _runtime(request: Request) -> AgentRuntime:
    runtime = getattr(request.app.state, "agent_runtime", None)
    if runtime is None:
        raise HTTPException(status_code=503, detail="agent model is not configured")
    return runtime


def create_agent_router() -> APIRouter:
    """Explicit chat route; tool mutations keep their own permissions."""
    router = APIRouter()

    @router.post("/agent/chat")
    def chat(
        payload: ChatRequest,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, object]:
        runtime = _runtime(request)
        settings = request.app.state.settings
        if context.principal.kind != "human":
            raise HTTPException(
                status_code=422,
                detail="the conversational agent is available to signed-in people",
            )
        if len(payload.message) > settings.agent_message_max_length:
            raise HTTPException(
                status_code=422,
                detail=f"message must be at most {settings.agent_message_max_length} characters",
            )
        if len(payload.conversation) > settings.agent_max_history_messages:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"conversation must have at most {settings.agent_max_history_messages} messages"
                ),
            )
        try:
            reply: ChatReply = runtime.chat(context.principal, payload)
        except AgentUnavailable:
            log_event(logger, "agent.unavailable", level=logging.WARNING)
            raise HTTPException(status_code=503, detail="agent model is not configured") from None
        except Exception as exc:  # provider failures stay factual and redacted
            logger.warning("agent request failed: %s", type(exc).__name__)
            log_event(logger, "agent.request_failed", level=logging.WARNING)
            raise HTTPException(status_code=503, detail="agent model is unavailable") from None
        return reply.model_dump()

    return router


__all__ = ["create_agent_router"]
