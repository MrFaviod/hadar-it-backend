"""FastAPI routes for the managed gateway data plane."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from itsm.ai_gateway.service import (
    MAX_REQUEST_BYTES,
    AiGatewayService,
    GatewayDenied,
    GatewayError,
    GatewayQuotaError,
    GatewayRejected,
    GatewayResult,
    GatewayUnavailable,
    error_payload,
)

_NO_STORE = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


def create_ai_gateway_router(service: AiGatewayService | None = None) -> APIRouter:
    """Build the fixed gateway router.

    ``service`` is explicit for tests and composition; when omitted the router
    reads ``app.state.ai_gateway`` per request so it can be registered before
    startup constructs the service. It must be included under the API prefix,
    yielding ``/api/v1/agent/gateway/v1/...`` on the canonical app.
    """

    router = APIRouter(prefix="/agent/gateway", tags=["ai-gateway"])

    def selected(request: Request) -> AiGatewayService:
        if service is not None:
            return service
        configured = getattr(request.app.state, "ai_gateway", None)
        if configured is None:
            raise GatewayUnavailable(
                "gateway_unavailable", "The managed AI gateway is not configured"
            )
        return configured

    def authenticate(gateway: AiGatewayService, request: Request) -> Any:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            raise GatewayDenied("invalid_lease", "A bearer lease token is required")
        return gateway.authenticate(token)

    @router.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        try:
            gateway = selected(request)
            context = authenticate(gateway, request)
            payload = await _read_json(request, MAX_REQUEST_BYTES + context.attachment_bytes)
            result = await gateway.chat(
                context,
                payload,
                idempotency_key=request.headers.get("idempotency-key"),
            )
            return _render(result)
        except GatewayError as exc:
            return _error_response(exc)

    @router.get("/v1/models")
    def models(request: Request) -> Response:
        try:
            gateway = selected(request)
            context = authenticate(gateway, request)
            return JSONResponse(gateway.models(context), headers=_NO_STORE)
        except GatewayError as exc:
            return _error_response(exc)

    @router.api_route("/v1/responses", methods=["GET", "POST"], include_in_schema=False)
    @router.api_route("/v1/responses/{path:path}", methods=["GET", "POST"], include_in_schema=False)
    def unsupported_responses(path: str | None = None) -> Response:
        return _error_response(
            GatewayError(
                "unsupported_route",
                "The /responses API is not supported by this gateway; use /chat/completions",
                status_code=404,
            )
        )

    return router


async def _read_json(request: Request, limit: int = MAX_REQUEST_BYTES) -> dict[str, Any]:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError as exc:
            raise GatewayRejected(
                "invalid_request", "Content-Length must be a non-negative integer"
            ) from exc
        if declared < 0:
            raise GatewayRejected("invalid_request", "Content-Length is invalid")
        if declared > limit:
            raise GatewayRejected(
                "request_too_large",
                "The request body exceeds the gateway limit",
                status_code=413,
            )

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise GatewayRejected(
                "request_too_large",
                "The request body exceeds the gateway limit",
                status_code=413,
            )
    if not body:
        raise GatewayRejected("invalid_json", "Request body is required")
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise GatewayRejected("invalid_json", "Request body is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise GatewayRejected("invalid_request", "Request body must be a JSON object")
    return payload


def _render(result: GatewayResult) -> Response:
    headers = {**_NO_STORE, **result.headers}
    if result.stream is not None:
        return StreamingResponse(
            result.stream,
            status_code=result.status_code,
            media_type=result.media_type,
            headers=headers,
        )
    return Response(
        content=result.body,
        status_code=result.status_code,
        media_type=result.media_type,
        headers=headers,
    )


def _error_response(exc: GatewayError) -> JSONResponse:
    extra: dict[str, Any] | None = None
    if isinstance(exc, GatewayQuotaError):
        extra = {"remainingTokens": exc.remaining_tokens}
        if exc.period_day is not None:
            extra["periodDay"] = exc.period_day
    return JSONResponse(
        error_payload(exc.code, exc.message, extra=extra),
        status_code=exc.status_code,
        headers={**_NO_STORE, **exc.headers},
    )


__all__ = ["create_ai_gateway_router"]
