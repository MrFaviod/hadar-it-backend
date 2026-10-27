"""Managed OpenAI-compatible gateway with run-scoped leases and bounded accounting."""

from __future__ import annotations

from itsm.ai_gateway.models import AiGatewayCall, AiGatewayLease
from itsm.ai_gateway.router import create_ai_gateway_router
from itsm.ai_gateway.service import (
    AiGatewayService,
    GatewayConflict,
    GatewayDenied,
    GatewayError,
    GatewayQuotaError,
    GatewayRejected,
    GatewayResult,
    GatewayUnavailable,
    GatewayUpstreamError,
    IssuedLease,
    LeaseContext,
    error_payload,
    usage_evidence,
)

__all__ = [
    "AiGatewayCall",
    "AiGatewayLease",
    "AiGatewayService",
    "GatewayConflict",
    "GatewayDenied",
    "GatewayError",
    "GatewayQuotaError",
    "GatewayRejected",
    "GatewayResult",
    "GatewayUnavailable",
    "GatewayUpstreamError",
    "IssuedLease",
    "LeaseContext",
    "create_ai_gateway_router",
    "error_payload",
    "usage_evidence",
]
