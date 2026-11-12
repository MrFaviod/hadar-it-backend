"""Managed AI gateway behavior: scoped leases, bounded admission and truthful accounting.

These tests use the real FastAPI router, a real SQLite lease/call store and an
injectable loopback/mock transport. The quota ledger is a small behavior-valid
double with the published ledger contract; the integration parent reruns the
same service against ``itsm.ai_usage.AiUsageService``. No provider or paid
inference is used.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
from datetime import UTC, datetime, timedelta
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from itsm.agent_integrations.providers import (
    ProviderModelSelection,
    ProviderNetworkPolicy,
)
from itsm.ai_gateway import (
    AiGatewayCall,
    AiGatewayLease,
    AiGatewayService,
    GatewayConflict,
    GatewayDenied,
    GatewayError,
    GatewayQuotaError,
    GatewayRejected,
    GatewayResult,
    LeaseContext,
    create_ai_gateway_router,
)
from itsm.ai_gateway import (
    service as gateway_service,
)
from itsm.config import parse_personal_private_endpoints
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

API = "/api/v1"
GATEWAY = f"{API}/agent/gateway/v1"
CHAT = f"{GATEWAY}/chat/completions"
MODELS = f"{GATEWAY}/models"
RESPONSES = f"{GATEWAY}/responses"
MASTER_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
UPSTREAM_KEY = "upstream-secret"
USAGE_BODY = {
    "id": "chat-1",
    "object": "chat.completion",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
    "usage": {
        "prompt_tokens": 10,
        "completion_tokens": 5,
        "total_tokens": 15,
        "prompt_tokens_details": {"cached_tokens": 4},
        "completion_tokens_details": {"reasoning_tokens": 2},
    },
}
SSE_BODY = (
    b'data: {"id":"chat-1","choices":[{"index":0,"delta":{"role":"assistant"}}]}\n\n'
    b'data: {"id":"chat-1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,'
    b'"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]}}]}\n\n'
    b'data: {"id":"chat-1","choices":[],"usage":{"prompt_tokens":7,'
    b'"completion_tokens":3,"total_tokens":10,"prompt_tokens_details":{"cached_tokens":2}}}\n\n'
    b"data: [DONE]\n\n"
)
SSE_NO_USAGE = (
    b'data: {"id":"chat-1","choices":[{"index":0,"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n\n'
)


class FakeQuotaExceeded(Exception):
    code = "quota_exceeded"

    def __init__(self, remaining: int = 0, period_day: str = "2026-10-27") -> None:
        super().__init__("daily AI usage quota exhausted")
        self.remaining_tokens = remaining
        self.period_day = period_day


class FakeLedger:
    """Behavior-valid ledger double: holds, denial, parent day and idempotency."""

    def __init__(self, company_limit: int = 100_000, personal_limit: int = 100_000) -> None:
        self.remaining = {"company": company_limit, "personal": personal_limit}
        self.reservations: dict[str, dict[str, Any]] = {}
        self.reserve_calls: list[dict[str, Any]] = []
        self.settlements: list[tuple[str, dict[str, Any]]] = []
        self.settle_counts: dict[str, int] = {}
        self.releases: list[str] = []
        self.fail_reserve = False
        self.day = "2026-10-27"
        self.counter = 0

    def seed(
        self,
        *,
        actor_id: str = "user-a",
        funding: str = "company",
        run_id: str = "run-1",
        provider_id: str = "prov-1",
        provider_scope: str = "global",
        provider_name: str = "Provider One",
        model: str = "model-a",
        engine: str = "hermes",
        day: str | None = None,
    ) -> str:
        self.counter += 1
        reservation_id = f"parent-{self.counter}"
        self.reservations[reservation_id] = {
            "actor_id": actor_id,
            "funding": funding,
            "run_id": run_id,
            "provider_id": provider_id,
            "provider_scope": provider_scope,
            "provider_name": provider_name,
            "model": model,
            "engine": engine,
            "parent_reservation_id": None,
            "reserved_tokens": 1,
            "day": day or self.day,
            "status": "pending",
            "settled_tokens": None,
            "idempotency_key": None,
        }
        self.remaining[funding] -= 1
        return reservation_id

    def pending(
        self, *, run_id: str | None = None, user_id: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for reservation_id, row in self.reservations.items():
            if row["status"] not in ("pending", "unresolved"):
                continue
            if run_id is not None and row["run_id"] != run_id:
                continue
            if user_id is not None and row["actor_id"] != user_id:
                continue
            items.append(
                {
                    "reservationId": reservation_id,
                    "runId": row["run_id"],
                    "parentReservationId": row["parent_reservation_id"],
                    "userId": row["actor_id"],
                    "funding": row["funding"],
                    "providerId": row["provider_id"],
                    "providerName": row["provider_name"],
                    "providerScope": row["provider_scope"],
                    "model": row["model"],
                    "engine": row["engine"],
                    "reservedTokens": row["reserved_tokens"],
                    "periodDay": row["day"],
                    "state": row["status"],
                }
            )
            if len(items) >= limit:
                break
        return items

    def reserve(
        self,
        actor_id: str,
        *,
        funding: str,
        reserved_tokens: int,
        provider_id: str | None = None,
        provider_scope: str | None = None,
        provider_name: str | None = None,
        model: str | None = None,
        engine: str | None = None,
        run_id: str | None = None,
        parent_reservation_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> SimpleNamespace:
        record = {
            "actor_id": actor_id,
            "funding": funding,
            "reserved_tokens": reserved_tokens,
            "provider_id": provider_id,
            "provider_scope": provider_scope,
            "provider_name": provider_name,
            "model": model,
            "engine": engine,
            "run_id": run_id,
            "parent_reservation_id": parent_reservation_id,
            "idempotency_key": idempotency_key,
        }
        self.reserve_calls.append(record)
        if self.fail_reserve:
            raise RuntimeError("ledger offline")
        if idempotency_key is not None:
            for reservation_id, row in self.reservations.items():
                if row["idempotency_key"] == idempotency_key and row["actor_id"] == actor_id:
                    record["reservation_id"] = reservation_id
                    return SimpleNamespace(reservation_id=reservation_id, replayed=True)
        if self.remaining[funding] < reserved_tokens:
            raise FakeQuotaExceeded(self.remaining[funding], self.day)
        parent = self.reservations.get(parent_reservation_id or "")
        day = parent["day"] if parent is not None else self.day
        self.remaining[funding] -= reserved_tokens
        self.counter += 1
        reservation_id = f"res-{self.counter}"
        self.reservations[reservation_id] = {
            "actor_id": actor_id,
            "funding": funding,
            "run_id": run_id,
            "provider_id": provider_id,
            "provider_scope": provider_scope,
            "provider_name": provider_name,
            "model": model,
            "engine": engine,
            "parent_reservation_id": parent_reservation_id,
            "reserved_tokens": reserved_tokens,
            "day": day,
            "status": "pending",
            "settled_tokens": None,
            "idempotency_key": idempotency_key,
        }
        record["reservation_id"] = reservation_id
        return SimpleNamespace(reservation_id=reservation_id, replayed=False)

    def settle(self, reservation_id: str, evidence: dict[str, Any]) -> SimpleNamespace:
        self.settle_counts[reservation_id] = self.settle_counts.get(reservation_id, 0) + 1
        self.settlements.append((reservation_id, dict(evidence)))
        row = self.reservations[reservation_id]
        total = evidence.get("totalTokens")
        measured = evidence.get("precision") in ("measured", "estimated") and total is not None
        if row["status"] == "settled":
            return SimpleNamespace(
                state="settled",
                idempotent=True,
                tokens=row["settled_tokens"],
                precision="measured",
                source="provider",
                unresolved=False,
            )
        if not measured:
            row["status"] = "unresolved"
            return SimpleNamespace(
                state="unresolved",
                idempotent=False,
                tokens=None,
                precision=evidence.get("precision", "unavailable"),
                source=evidence.get("source", "none"),
                unresolved=True,
            )
        row["status"] = "settled"
        row["settled_tokens"] = int(total)
        self.remaining[row["funding"]] += row["reserved_tokens"] - int(total)
        return SimpleNamespace(
            state="settled",
            idempotent=False,
            tokens=int(total),
            precision=evidence["precision"],
            source=evidence["source"],
            unresolved=False,
        )

    def release(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("the gateway must never release a reservation automatically")


class Upstream:
    """Injectable guarded-client factory plus captured provider requests."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.responder: Any = None
        self.allow_private_calls: list[bool] = []

    def factory(self, *, allow_private: bool, timeout: float = 30.0) -> httpx.AsyncClient:
        self.allow_private_calls.append(allow_private)
        return httpx.AsyncClient(
            transport=httpx.MockTransport(self._handle),
            follow_redirects=False,
            trust_env=False,
        )

    async def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        responder = self.responder or self._default
        result = responder(request)
        if inspect.isawaitable(result):
            result = await result
        return result

    @staticmethod
    def _default(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=USAGE_BODY)


@pytest.fixture
def harness(tmp_path: Any, settings_factory: Any) -> Any:
    built = _build_harness(tmp_path, settings_factory, name="gateway")
    try:
        yield built
    finally:
        built.client.close()
        built.engine.dispose()


@pytest.fixture
def private_harness(tmp_path: Any, settings_factory: Any) -> Any:
    """Gateway whose deployment allowlists loopback personal endpoints."""
    built = _build_harness(
        tmp_path,
        settings_factory,
        name="gateway-private",
        ai_personal_private_endpoints="127.0.0.0/8",
    )
    try:
        yield built
    finally:
        built.client.close()
        built.engine.dispose()


def _build_harness(tmp_path: Any, settings_factory: Any, *, name: str, **overrides: Any) -> Any:
    settings = settings_factory(
        ai_credential_key=MASTER_KEY,
        database_url=f"sqlite:///{tmp_path / f'{name}.db'}",
        **overrides,
    )
    engine = create_engine(settings.database_url)
    AiGatewayLease.__table__.create(engine)
    AiGatewayCall.__table__.create(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    ledger = FakeLedger()
    upstream = Upstream()
    clock = {"now": NOW}
    service = AiGatewayService(
        settings,
        factory,
        ledger,
        now=lambda: clock["now"],
        client_factory=upstream.factory,
    )
    app = FastAPI()
    app.include_router(create_ai_gateway_router(service), prefix=settings.api_prefix)
    client = TestClient(app)
    return SimpleNamespace(
        settings=settings,
        engine=engine,
        factory=factory,
        service=service,
        ledger=ledger,
        upstream=upstream,
        clock=clock,
        client=client,
    )


def issue(
    harness: Any,
    *,
    funding: str = "company",
    provider_scope: str = "global",
    actor_id: str = "user-a",
    run_id: str = "run-1",
    context_tokens: int = 60,
    output_tokens: int = 40,
    model: str = "model-a",
    ttl_seconds: int = 3600,
    parent: str | None = None,
    provider_id: str = "prov-1",
    provider_name: str = "Provider One",
    engine: str = "hermes",
    base_url: str | None = None,
    allow_private: bool | None = None,
    input_modalities: tuple[str, ...] = (),
    attachment_bytes: int = 0,
) -> tuple[Any, str]:
    if parent is None:
        parent = harness.ledger.seed(
            actor_id=actor_id,
            funding=funding,
            run_id=run_id,
            provider_id=provider_id,
            provider_scope=provider_scope,
            provider_name=provider_name,
            model=model,
            engine=engine,
        )
    if base_url is None:
        base_url = (
            "https://provider.example/v1"
            if provider_scope == "personal"
            else "http://127.0.0.1:18081/v1"
        )
    if allow_private is None:
        allow_private = provider_scope != "personal"
    selection = ProviderModelSelection(
        base_url=base_url,
        model=model,
        api_key=UPSTREAM_KEY,
        allow_private=allow_private,
    )
    lease = harness.service.issue_lease(
        actor_id=actor_id,
        funding=funding,
        parent_reservation_id=parent,
        selection=selection,
        provider_id=provider_id,
        provider_scope=provider_scope,
        provider_name=provider_name,
        model=model,
        engine=engine,
        run_id=run_id,
        context_tokens=context_tokens,
        output_tokens=output_tokens,
        ttl_seconds=ttl_seconds,
        input_modalities=input_modalities,
        attachment_bytes=attachment_bytes,
    )
    return lease, parent


def bearer(lease: Any) -> dict[str, str]:
    return {"Authorization": f"Bearer {lease.bearer_token}"}


def payload(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": "model-a",
        "messages": [{"role": "user", "content": "Hola"}],
        "max_tokens": 40,
    }
    body.update(overrides)
    return body


def child_row(harness: Any) -> dict[str, Any]:
    return next(row for key, row in harness.ledger.reservations.items() if key.startswith("res-"))


def call_rows(harness: Any) -> list[AiGatewayCall]:
    with harness.factory() as db:
        return list(db.scalars(select(AiGatewayCall)).all())


def test_issue_lease_returns_token_once_and_stores_only_sealed_selection(harness: Any) -> None:
    lease, parent = issue(harness)

    assert lease.lease_id
    assert lease.bearer_token
    assert lease.as_dict()["token"] == lease.bearer_token
    assert UPSTREAM_KEY not in json.dumps(lease.as_dict())

    context = harness.service.authenticate(lease.bearer_token)
    assert context.actor_id == "user-a"
    assert context.parent_reservation_id == parent
    assert context.model == "model-a"

    with harness.factory() as db:
        row = db.get(AiGatewayLease, lease.lease_id)
        assert row is not None
        assert row.token_hash != lease.bearer_token
        assert len(row.token_hash) == 64
        assert UPSTREAM_KEY not in row.selection_ciphertext


def test_issue_lease_rejects_missing_or_mismatched_parent(harness: Any) -> None:
    with pytest.raises(GatewayConflict) as missing:
        issue(harness, parent="missing-parent")
    assert missing.value.code == "parent_reservation_unavailable"

    lease, parent = issue(harness)
    with pytest.raises(GatewayRejected) as mismatch:
        issue(harness, parent=parent, model="model-b")
    assert mismatch.value.code == "parent_reservation_mismatch"

    with pytest.raises(GatewayRejected) as scope:
        issue(harness, funding="company", provider_scope="personal")
    assert scope.value.code == "funding_scope_mismatch"
    assert lease.lease_id


def test_issue_lease_requires_a_pending_parent(harness: Any) -> None:
    parent = harness.ledger.seed()
    harness.ledger.reservations[parent]["status"] = "unresolved"

    with pytest.raises(GatewayConflict) as error:
        issue(harness, parent=parent)

    assert error.value.code == "parent_reservation_unavailable"


def test_expired_revoked_and_unknown_tokens_denied_without_upstream(harness: Any) -> None:
    expired, _ = issue(harness, ttl_seconds=10)
    harness.clock["now"] = NOW + timedelta(seconds=11)
    response = harness.client.get(MODELS, headers=bearer(expired))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "expired_lease"

    revoked, _ = issue(harness)
    assert harness.service.revoke(revoked.lease_id) is True
    assert harness.service.revoke(revoked.lease_id) is True
    response = harness.client.get(MODELS, headers=bearer(revoked))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "revoked_lease"

    response = harness.client.get(MODELS, headers={"Authorization": "Bearer nope"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_lease"
    assert harness.upstream.requests == []
    assert harness.ledger.reserve_calls == []


def test_quota_denied_never_calls_upstream_or_keeps_claim(harness: Any) -> None:
    lease, _ = issue(harness)
    harness.ledger.remaining["company"] = 0

    response = harness.client.post(CHAT, json=payload(), headers=bearer(lease))

    assert response.status_code == 429
    error = response.json()["error"]
    assert error["code"] == "quota_exceeded"
    assert error["remainingTokens"] == 0
    assert harness.upstream.requests == []
    assert len(harness.ledger.reserve_calls) == 1
    assert call_rows(harness) == []


def test_model_tamper_and_client_identity_headers_cannot_override_lease(harness: Any) -> None:
    lease, _ = issue(harness)

    response = harness.client.post(CHAT, json=payload(model="model-b"), headers=bearer(lease))
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_model"
    assert harness.upstream.requests == []
    assert harness.ledger.reserve_calls == []

    response = harness.client.post(
        CHAT,
        json=payload(),
        headers={
            **bearer(lease),
            "X-User-Id": "user-b",
            "X-Run-Id": "other-run",
            "X-Funding": "personal",
            "Cookie": "session=stolen",
        },
    )
    assert response.status_code == 200
    forwarded = harness.upstream.requests[0]
    assert forwarded.headers["authorization"] == f"Bearer {UPSTREAM_KEY}"
    for header in ("x-user-id", "x-run-id", "x-funding", "cookie"):
        assert header not in forwarded.headers
    assert harness.ledger.reserve_calls[0]["actor_id"] == "user-a"
    assert harness.ledger.reserve_calls[0]["funding"] == "company"


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"max_tokens": 41}, "output_bound_exceeded"),
        ({"max_tokens": 10, "max_completion_tokens": 11}, "conflicting_output_limit"),
        ({"max_tokens": 0}, "invalid_output_limit"),
        ({"max_tokens": True}, "invalid_output_limit"),
        ({"max_completion_tokens": 41}, "output_bound_exceeded"),
    ],
)
def test_output_caps_rejected_before_forward(harness: Any, overrides: Any, code: str) -> None:
    lease, _ = issue(harness, output_tokens=40)
    body = payload(**overrides)
    if "max_completion_tokens" in overrides and "max_tokens" not in overrides:
        body.pop("max_tokens", None)

    response = harness.client.post(CHAT, json=body, headers=bearer(lease))

    assert response.status_code == 400
    assert response.json()["error"]["code"] == code
    assert harness.ledger.reserve_calls == []
    assert harness.upstream.requests == []


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        (
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "image_url", "image_url": {"url": "http://evil/x.png"}}
                        ],
                    }
                ]
            },
            "unsupported_content",
        ),
        ({"n": 2}, "unsupported_parameter"),
        ({"audio": {"format": "wav"}}, "unsupported_parameter"),
        ({"messages": [{"role": "tool", "content": "x"}]}, "invalid_message"),
        ({"tools": [{"type": "web_search"}]}, "unsupported_tool"),
        ({"stream": "yes"}, "invalid_request"),
    ],
)
def test_unsafe_or_unsupported_payloads_rejected(harness: Any, overrides: Any, code: str) -> None:
    lease, _ = issue(harness)

    response = harness.client.post(CHAT, json=payload(**overrides), headers=bearer(lease))

    assert response.status_code == 400
    assert response.json()["error"]["code"] == code
    assert harness.ledger.reserve_calls == []
    assert harness.upstream.requests == []


def test_body_limit_and_invalid_json_rejected_before_reserve(harness: Any) -> None:
    lease, _ = issue(harness)
    headers = {**bearer(lease), "Content-Type": "application/json"}

    response = harness.client.post(CHAT, content=b"{" + b" " * (2 * 1024 * 1024), headers=headers)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"

    response = harness.client.post(CHAT, content=b"{", headers=headers)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_json"

    assert harness.ledger.reserve_calls == []
    assert harness.upstream.requests == []


def test_nonstream_forwards_pinned_request_and_settles_measured_once(harness: Any) -> None:
    lease, _ = issue(harness)
    tools = [
        {
            "type": "function",
            "function": {
                "name": "lookup",
                "description": "Look up one record",
                "parameters": {"type": "object", "properties": {}},
            },
        }
    ]

    response = harness.client.post(
        CHAT,
        json=payload(tools=tools, max_tokens=25),
        headers={**bearer(lease), "X-Ignored": "value"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == "chat-1"
    forwarded = harness.upstream.requests[0]
    assert forwarded.method == "POST"
    assert forwarded.url.path == "/v1/chat/completions"
    assert forwarded.headers["authorization"] == f"Bearer {UPSTREAM_KEY}"
    assert "x-ignored" not in forwarded.headers
    sent = json.loads(forwarded.content)
    assert sent["model"] == "model-a"
    assert sent["max_tokens"] == 25
    assert sent["tools"] == tools

    row = child_row(harness)
    assert row["status"] == "settled"
    assert row["settled_tokens"] == 15
    assert row["reserved_tokens"] >= 85
    assert row["parent_reservation_id"].startswith("parent-")
    evidence = harness.ledger.settlements[0][1]
    assert evidence["totalTokens"] == 15
    assert evidence["cacheReadTokens"] == 4
    assert evidence["reasoningTokens"] == 2
    assert evidence["cacheIncludedInInput"] is True
    assert evidence["reasoningIncludedInOutput"] is True
    assert harness.ledger.settle_counts == {harness.ledger.settlements[0][0]: 1}
    assert harness.ledger.remaining["company"] == 100_000 - 1 - 15

    assert harness.service.revoke(lease.lease_id) is True
    response = harness.client.post(CHAT, json=payload(), headers=bearer(lease))
    assert response.status_code == 401
    assert len(harness.ledger.settlements) == 1
    assert harness.ledger.releases == []


@pytest.mark.parametrize("status", [400, 500])
def test_upstream_error_status_keeps_hold_and_forwards_provider_error(
    harness: Any, status: int
) -> None:
    lease, _ = issue(harness)
    provider_error = {"error": {"message": "provider says no", "type": "invalid_request_error"}}
    harness.upstream.responder = lambda request: httpx.Response(status, json=provider_error)

    response = harness.client.post(CHAT, json=payload(), headers=bearer(lease))

    assert response.status_code == status
    assert response.json() == provider_error
    row = child_row(harness)
    assert row["status"] == "unresolved"
    assert harness.ledger.remaining["company"] == 100_000 - 1 - row["reserved_tokens"]
    assert harness.ledger.releases == []


def test_missing_usage_and_transport_failure_keep_hold(harness: Any) -> None:
    lease, _ = issue(harness)
    harness.upstream.responder = lambda request: httpx.Response(
        200, json={"id": "chat-1", "choices": []}
    )
    response = harness.client.post(CHAT, json=payload(), headers=bearer(lease))
    assert response.status_code == 200
    first = child_row(harness)
    assert first["status"] == "unresolved"
    assert harness.ledger.settlements[-1][1]["precision"] == "unavailable"

    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    harness.upstream.responder = fail
    response = harness.client.post(CHAT, json=payload(), headers=bearer(lease))
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_unavailable"
    rows = [row for key, row in harness.ledger.reservations.items() if key.startswith("res-")]
    assert [row["status"] for row in rows] == ["unresolved", "unresolved"]
    assert harness.ledger.releases == []


def test_stream_usage_is_measured_and_events_preserved(harness: Any) -> None:
    lease, _ = issue(harness)
    harness.upstream.responder = lambda request: httpx.Response(
        200, headers={"content-type": "text/event-stream"}, content=SSE_BODY
    )

    response = harness.client.post(CHAT, json=payload(stream=True), headers=bearer(lease))

    assert response.status_code == 200
    assert response.content == SSE_BODY
    assert response.headers["content-type"].startswith("text/event-stream")
    forwarded = harness.upstream.requests[0]
    sent = json.loads(forwarded.content)
    assert sent["stream"] is True
    assert sent["stream_options"]["include_usage"] is True
    assert forwarded.headers["accept"] == "text/event-stream"
    row = child_row(harness)
    assert row["status"] == "settled"
    assert row["settled_tokens"] == 10
    evidence = harness.ledger.settlements[0][1]
    assert evidence["cacheReadTokens"] == 2
    assert evidence["totalTokens"] == 10


def test_stream_without_usage_and_disconnect_keep_hold(harness: Any) -> None:
    lease, _ = issue(harness)
    harness.upstream.responder = lambda request: httpx.Response(
        200, headers={"content-type": "text/event-stream"}, content=SSE_NO_USAGE
    )

    response = harness.client.post(CHAT, json=payload(stream=True), headers=bearer(lease))
    assert response.status_code == 200
    first = child_row(harness)
    assert first["status"] == "unresolved"

    async def scenario() -> bytes:
        context = harness.service.authenticate(lease.bearer_token)
        result = await harness.service.chat(context, payload(stream=True))
        assert result.stream is not None
        chunk = await result.stream.__anext__()
        await result.stream.aclose()
        return chunk

    chunk = asyncio.run(scenario())
    assert b"delta" in chunk
    rows = [row for key, row in harness.ledger.reservations.items() if key.startswith("res-")]
    assert [row["status"] for row in rows] == ["unresolved", "unresolved"]
    assert harness.ledger.releases == []

    asyncio.run(scenario())
    assert all(count == 1 for count in harness.ledger.settle_counts.values())


def test_stream_over_bound_is_unresolved(harness: Any, monkeypatch: Any) -> None:
    lease, _ = issue(harness)
    harness.upstream.responder = lambda request: httpx.Response(
        200, headers={"content-type": "text/event-stream"}, content=SSE_BODY
    )
    monkeypatch.setattr(gateway_service, "MAX_STREAM_BYTES", 16)

    response = harness.client.post(CHAT, json=payload(stream=True), headers=bearer(lease))

    assert response.status_code == 200
    row = child_row(harness)
    assert row["status"] == "unresolved"
    assert row["settled_tokens"] is None
    evidence = harness.ledger.settlements[0][1]
    assert evidence["precision"] == "unavailable"
    assert harness.ledger.settle_counts[harness.ledger.settlements[0][0]] == 1
    assert harness.ledger.releases == []


def test_stream_close_failure_still_finalizes_once(harness: Any) -> None:
    class FailingResponse:
        async def aiter_bytes(self):
            yield b'data: {"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}}\n\n'

        async def aclose(self) -> None:
            raise RuntimeError("response close failed")

    class FailingClient:
        async def aclose(self) -> None:
            raise RuntimeError("client close failed")

    async def scenario() -> list[tuple[Any, ...]]:
        calls: list[tuple[Any, ...]] = []
        harness.service._finalize = lambda *args: calls.append(args)
        generator = harness.service._relay(
            response=FailingResponse(),
            client=FailingClient(),
            call_id="call-close",
            reservation_id="reservation-close",
        )
        with pytest.raises(RuntimeError):
            async for _chunk in generator:
                pass
        return calls

    calls = asyncio.run(scenario())

    assert len(calls) == 1
    assert calls[0][0:2] == ("call-close", "reservation-close")
    assert calls[0][2]["totalTokens"] == 5


def test_duplicate_idempotency_rejects_without_second_dispatch(harness: Any) -> None:
    lease, _ = issue(harness)
    headers = {**bearer(lease), "Idempotency-Key": "same-request"}

    first = harness.client.post(CHAT, json=payload(), headers=headers)
    second = harness.client.post(CHAT, json=payload(), headers=headers)

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "duplicate_request"
    assert len(harness.upstream.requests) == 1
    assert len(harness.ledger.reserve_calls) == 1
    assert len(harness.ledger.settlements) == 1


def test_idempotency_key_is_bound_to_run_across_leases(harness: Any) -> None:
    first_lease, parent = issue(harness, run_id="run-1")
    second_lease, _ = issue(harness, run_id="run-1", parent=parent)

    first = harness.client.post(
        CHAT,
        json=payload(),
        headers={**bearer(first_lease), "Idempotency-Key": "shared-key"},
    )
    second = harness.client.post(
        CHAT,
        json=payload(),
        headers={**bearer(second_lease), "Idempotency-Key": "shared-key"},
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "duplicate_request"
    assert len(harness.upstream.requests) == 1
    assert len(harness.ledger.reserve_calls) == 1


def test_tampered_lease_token_is_denied_without_upstream(harness: Any) -> None:
    lease, _ = issue(harness)
    tampered = ("A" if lease.bearer_token[0] != "A" else "B") + lease.bearer_token[1:]

    response = harness.client.get(MODELS, headers={"Authorization": f"Bearer {tampered}"})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_lease"
    assert harness.upstream.requests == []


def test_internal_context_cannot_forge_actor_run_funding_or_parent(harness: Any) -> None:
    lease, _ = issue(harness)
    real = harness.service.authenticate(lease.bearer_token)
    forged = LeaseContext(
        lease_id=real.lease_id,
        actor_id="attacker",
        run_id="run-evil",
        parent_reservation_id="parent-evil",
        funding="personal",
        provider_id="prov-evil",
        provider_scope="personal",
        provider_name="Evil Provider",
        model=real.model,
        engine="evil",
        context_tokens=1,
        output_tokens=1,
        expires_at=real.expires_at,
    )

    result = asyncio.run(harness.service.chat(forged, payload()))

    assert result.status_code == 200
    record = harness.ledger.reserve_calls[-1]
    assert record["actor_id"] == "user-a"
    assert record["run_id"] == "run-1"
    assert record["funding"] == "company"
    assert record["parent_reservation_id"].startswith("parent-")
    assert record["provider_id"] == "prov-1"
    assert record["provider_scope"] == "global"
    assert record["model"] == "model-a"
    assert record["engine"] == "hermes"


def test_oversized_upstream_response_keeps_hold(harness: Any) -> None:
    lease, _ = issue(harness)
    harness.upstream.responder = lambda request: httpx.Response(
        200,
        headers={"content-type": "application/json"},
        content=b"x" * (8 * 1024 * 1024 + 1),
    )

    response = harness.client.post(CHAT, json=payload(), headers=bearer(lease))

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_response_too_large"
    assert child_row(harness)["status"] == "unresolved"
    assert harness.ledger.releases == []


def test_two_concurrent_calls_reserve_before_dispatch_and_only_one_admitted(harness: Any) -> None:
    lease, _ = issue(harness)
    harness.ledger.remaining["company"] = 121

    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.05)
        return httpx.Response(200, json=USAGE_BODY)

    harness.upstream.responder = slow

    async def scenario() -> list[Any]:
        context = harness.service.authenticate(lease.bearer_token)

        async def one() -> Any:
            try:
                return await harness.service.chat(context, payload())
            except GatewayQuotaError as exc:
                return exc

        return await asyncio.gather(one(), one())

    results = asyncio.run(scenario())

    assert sum(isinstance(result, GatewayResult) for result in results) == 1
    assert sum(isinstance(result, GatewayQuotaError) for result in results) == 1
    assert len(harness.upstream.requests) == 1
    assert len(harness.ledger.reserve_calls) == 2
    assert len([key for key in harness.ledger.reservations if key.startswith("res-")]) == 1


def test_late_settlement_keeps_original_parent_day(harness: Any) -> None:
    parent = harness.ledger.seed(day="2026-10-26")
    lease, _ = issue(harness, parent=parent)

    assert harness.client.post(CHAT, json=payload(), headers=bearer(lease)).status_code == 200
    harness.ledger.day = "2026-10-27"
    assert harness.client.post(CHAT, json=payload(), headers=bearer(lease)).status_code == 200

    children = [
        row
        for key, row in harness.ledger.reservations.items()
        if key.startswith("res-") and row["parent_reservation_id"] == parent
    ]
    assert len(children) == 2
    assert {row["day"] for row in children} == {"2026-10-26"}
    assert all(row["status"] == "settled" for row in children)


def test_personal_funding_never_consumes_company_balance(harness: Any) -> None:
    lease, _ = issue(harness, funding="personal", provider_scope="personal")

    response = harness.client.post(CHAT, json=payload(), headers=bearer(lease))

    assert response.status_code == 200
    assert harness.ledger.remaining["personal"] == 100_000 - 1 - 100 + 85
    assert harness.ledger.remaining["company"] == 100_000
    assert {row["funding"] for row in harness.ledger.reservations.values()} == {"personal"}

    company_parent = harness.ledger.seed(funding="company", provider_scope="personal")
    with pytest.raises(GatewayRejected) as error:
        issue(harness, parent=company_parent, funding="company", provider_scope="personal")
    assert error.value.code == "funding_scope_mismatch"


def test_models_is_local_and_responses_is_explicitly_unsupported(harness: Any) -> None:
    lease, _ = issue(harness)

    response = harness.client.get(MODELS, headers=bearer(lease))
    assert response.status_code == 200
    assert response.json()["data"] == [
        {"id": "model-a", "object": "model", "created": 0, "owned_by": "itsm-ai-gateway"}
    ]
    assert harness.upstream.requests == []
    assert harness.ledger.reserve_calls == []

    response = harness.client.post(RESPONSES, json={"model": "model-a"}, headers=bearer(lease))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "unsupported_route"
    assert harness.upstream.requests == []
    assert harness.ledger.reserve_calls == []

    assert harness.client.get(MODELS).status_code == 401


def test_upstream_redirect_is_not_followed_and_hold_is_kept(harness: Any) -> None:
    lease, _ = issue(harness)
    harness.upstream.responder = lambda request: httpx.Response(
        302, headers={"location": "https://evil.example/steal"}
    )

    response = harness.client.post(CHAT, json=payload(), headers=bearer(lease))

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_redirect"
    assert "evil.example" not in response.text
    assert child_row(harness)["status"] == "unresolved"


def test_unsafe_private_personal_endpoint_rejected_at_issue(harness: Any) -> None:
    parent = harness.ledger.seed(funding="personal", provider_scope="personal")
    with pytest.raises(GatewayRejected) as error:
        issue(
            harness,
            parent=parent,
            funding="personal",
            provider_scope="personal",
            base_url="http://127.0.0.1:18081/v1",
            allow_private=False,
        )
    assert error.value.code == "invalid_provider_endpoint"


def test_personal_provider_cannot_allow_private_connections(harness: Any) -> None:
    parent = harness.ledger.seed(funding="personal", provider_scope="personal")
    with pytest.raises(GatewayRejected) as error:
        issue(
            harness,
            parent=parent,
            funding="personal",
            provider_scope="personal",
            base_url="https://provider.example/v1",
            allow_private=True,
        )
    assert error.value.code == "invalid_selection"


def test_ledger_failure_after_claim_abandons_without_dispatch(harness: Any) -> None:
    lease, _ = issue(harness)
    harness.ledger.fail_reserve = True

    response = harness.client.post(CHAT, json=payload(), headers=bearer(lease))

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "quota_unavailable"
    assert harness.upstream.requests == []
    rows = call_rows(harness)
    assert len(rows) == 1
    assert rows[0].state == "unresolved"
    assert rows[0].reservation_id is None
    assert harness.ledger.releases == []


def test_capability_is_honest_and_never_claims_strict_enforcement(harness: Any) -> None:
    capability = harness.service.capability()

    assert capability["mode"] == "managed"
    assert capability["enforcement"] == "admission_only"
    assert capability["strict"] is False
    assert capability["routePrefix"] == f"{API}/agent/gateway/v1"
    assert "not independently verified" in capability["reason"]
    assert "network isolation" in capability["reason"]
    assert UPSTREAM_KEY not in json.dumps(capability)


def test_unknown_idempotency_key_and_auth_denial_do_not_reserve(harness: Any) -> None:
    response = harness.client.post(CHAT, json=payload(), headers={"Authorization": "Bearer no"})
    assert response.status_code == 401
    assert isinstance(response.json()["error"]["code"], str)
    assert harness.ledger.reserve_calls == []

    lease, _ = issue(harness)
    response = harness.client.post(
        CHAT,
        json=payload(),
        headers={**bearer(lease), "Idempotency-Key": "x" * 201},
    )
    assert response.status_code == 400
    assert isinstance(response.json()["error"]["code"], str)
    assert harness.ledger.reserve_calls == []


def test_gateway_errors_are_structured_and_do_not_include_secrets(harness: Any) -> None:
    with pytest.raises(GatewayError) as error:
        harness.service.authenticate("unknown-token")
    assert error.value.status_code == 401
    assert isinstance(error.value, GatewayDenied)
    assert UPSTREAM_KEY not in str(error.value)


def test_migration_follows_ledger_revision() -> None:
    path = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0025_ai_gateway.py"
    spec = spec_from_file_location("ai_gateway_migration_0025", path)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.revision == "0025_ai_gateway"
    assert module.down_revision == "0024_ai_usage"


def test_allowlisted_personal_private_endpoint_is_issued_and_forwarded(
    private_harness: Any,
) -> None:
    parent = private_harness.ledger.seed(funding="personal", provider_scope="personal")

    lease, _ = issue(
        private_harness,
        parent=parent,
        funding="personal",
        provider_scope="personal",
        base_url="http://127.0.0.1:18081/v1",
        allow_private=False,
    )

    response = private_harness.client.post(CHAT, json=payload(), headers=bearer(lease))

    assert response.status_code == 200, response.text
    assert response.json()["choices"][0]["message"]["content"] == "ok"
    # The guarded client is rebuilt at forward time from the deployment policy,
    # never from an authority carried by the lease snapshot.
    policy = private_harness.upstream.allow_private_calls[0]
    assert isinstance(policy, ProviderNetworkPolicy)
    assert [entry.describe() for entry in policy.allowlist] == ["127.0.0.0/8"]


def test_selection_policy_cannot_widen_the_deployment_allowlist(harness: Any) -> None:
    parent = harness.ledger.seed(funding="personal", provider_scope="personal")

    with pytest.raises(GatewayRejected) as error:
        issue(
            harness,
            parent=parent,
            funding="personal",
            provider_scope="personal",
            base_url="http://127.0.0.1:18081/v1",
            allow_private=ProviderNetworkPolicy(
                allowlist=parse_personal_private_endpoints("127.0.0.0/8")
            ),
        )

    assert error.value.code == "invalid_provider_endpoint"
    assert harness.upstream.requests == []


# ------------------------------------------------------- inline attachments
IMAGE_B64 = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32).decode()
PDF_B64 = base64.b64encode(b"%PDF-1.7\ndoc\n%%EOF").decode()


def image_message(url: str) -> dict[str, Any]:
    return {
        "model": "model-a",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "qué ves"},
                    {"type": "image_url", "image_url": {"url": url}},
                ],
            }
        ],
        "max_tokens": 40,
    }


def file_message(data: str) -> dict[str, Any]:
    return {
        "model": "model-a",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "file",
                        "file": {"filename": "informe.pdf", "file_data": data},
                    }
                ],
            }
        ],
        "max_tokens": 40,
    }


def test_lease_admits_inline_image_only_when_declared(harness: Any) -> None:
    lease, _ = issue(harness, input_modalities=("image",), attachment_bytes=len(IMAGE_B64) + 64)

    response = harness.client.post(
        CHAT, json=image_message(f"data:image/png;base64,{IMAGE_B64}"), headers=bearer(lease)
    )

    assert response.status_code == 200, response.text
    forwarded = json.loads(harness.upstream.requests[0].content)
    assert forwarded["messages"][0]["content"][1] == {
        "type": "image_url",
        "image_url": {"url": f"data:image/png;base64,{IMAGE_B64}"},
    }
    assert harness.ledger.reserve_calls


def test_lease_without_image_modality_refuses_image_parts(harness: Any) -> None:
    lease, _ = issue(harness)

    response = harness.client.post(
        CHAT, json=image_message(f"data:image/png;base64,{IMAGE_B64}"), headers=bearer(lease)
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "unsupported_content"
    assert harness.ledger.reserve_calls == []
    assert harness.upstream.requests == []


def test_remote_image_url_stays_refused_even_when_declared(harness: Any) -> None:
    lease, _ = issue(harness, input_modalities=("image",), attachment_bytes=len(IMAGE_B64) + 64)

    response = harness.client.post(
        CHAT, json=image_message("https://evil.example/cat.png"), headers=bearer(lease)
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "unsupported_content"
    assert harness.ledger.reserve_calls == []
    assert harness.upstream.requests == []


def test_attachment_bytes_bound_the_lease(harness: Any) -> None:
    lease, _ = issue(harness, input_modalities=("image",), attachment_bytes=8)

    response = harness.client.post(
        CHAT, json=image_message(f"data:image/png;base64,{IMAGE_B64}"), headers=bearer(lease)
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "unsupported_content"
    assert harness.ledger.reserve_calls == []


def test_lease_admits_inline_pdf_only_when_file_is_declared(harness: Any) -> None:
    lease, _ = issue(harness, input_modalities=("file",), attachment_bytes=4096)
    response = harness.client.post(
        CHAT,
        json=file_message(f"data:application/pdf;base64,{PDF_B64}"),
        headers=bearer(lease),
    )
    assert response.status_code == 200, response.text
    forwarded = json.loads(harness.upstream.requests[0].content)
    assert forwarded["messages"][0]["content"][0]["file"]["filename"] == "informe.pdf"

    text_only, _ = issue(harness, run_id="run-2", parent=harness.ledger.seed(run_id="run-2"))
    refused = harness.client.post(
        CHAT,
        json=file_message(f"data:application/pdf;base64,{PDF_B64}"),
        headers=bearer(text_only),
    )
    assert refused.status_code == 400
    assert refused.json()["error"]["code"] == "unsupported_content"


def test_m3_large_submitted_context_reserves_before_dispatch(harness):
    lease, _ = issue(harness, context_tokens=1)
    response = harness.client.post(
        CHAT,
        json=payload(messages=[{"role": "user", "content": "é" * 1000}]),
        headers=bearer(lease),
    )
    assert response.status_code == 200
    assert child_row(harness)["reserved_tokens"] >= 2040
    assert len(harness.upstream.requests) == 1


def test_m3_large_prompt_quota_denial_leaves_no_call_or_upstream(harness):
    lease, _ = issue(harness, context_tokens=1)
    harness.ledger.remaining["company"] = 500
    before = dict(harness.ledger.remaining)
    response = harness.client.post(
        CHAT,
        json=payload(messages=[{"role": "user", "content": "é" * 1000}]),
        headers=bearer(lease),
    )
    assert response.status_code == 429
    assert harness.ledger.remaining == before
    assert call_rows(harness) == []
    assert harness.upstream.requests == []


@pytest.mark.parametrize("kind", ["image", "file"])
def test_m3_large_binary_keeps_original_body_without_base64_token_charge(harness, kind):
    raw = (
        (b"\x89PNG\r\n\x1a\n" if kind == "image" else b"%PDF-1.7\n")
        + b"\x00" * (1024 * 1024)
        + (b"" if kind == "image" else b"\n%%EOF")
    )
    data = base64.b64encode(raw).decode()
    body = (
        image_message("data:image/png;base64," + data)
        if kind == "image"
        else file_message("data:application/pdf;base64," + data)
    )
    lease, _ = issue(
        harness, input_modalities=(kind,), attachment_bytes=len(data), context_tokens=128000
    )
    harness.ledger.remaining["company"] = 1000000
    response = harness.client.post(CHAT, json=body, headers=bearer(lease))
    assert response.status_code == 200, response.text
    assert child_row(harness)["reserved_tokens"] == 128040
    assert json.loads(harness.upstream.requests[0].content) == body


def test_m3_gateway_text_file_history_and_schema_cannot_hide_behind_binary(harness):
    data = base64.b64encode(("é" * 10000).encode()).decode()
    body = file_message("data:text/plain;base64," + data)
    body["messages"].insert(0, {"role": "system", "content": "history" * 1000})
    body["tools"] = [
        {
            "type": "function",
            "function": {
                "name": "lookup",
                "parameters": {"type": "object", "description": "schema" * 1000},
            },
        }
    ]
    lease, _ = issue(
        harness, input_modalities=("file",), attachment_bytes=len(data), context_tokens=1
    )
    harness.ledger.remaining["company"] = 20000
    before = dict(harness.ledger.remaining)
    response = harness.client.post(CHAT, json=body, headers=bearer(lease))
    assert response.status_code == 429, response.text
    assert harness.ledger.remaining == before
    assert call_rows(harness) == [] and harness.upstream.requests == []


@pytest.mark.parametrize("kind", ["bare_pdf", "pdf_url", "png_url"])
@pytest.mark.parametrize("suffix", [b"", b"\x00", b"\xff"])
def test_m3_mislabeled_text_cannot_lower_admission(harness, kind, suffix):
    raw = b"A" * 100000 + suffix
    encoded = base64.b64encode(raw).decode()
    body = (
        image_message("data:image/png;base64," + encoded)
        if kind == "png_url"
        else file_message(("data:application/pdf;base64," if kind == "pdf_url" else "") + encoded)
    )
    lease, _ = issue(
        harness, input_modalities=("image", "file"), attachment_bytes=len(encoded), context_tokens=1
    )
    harness.ledger.remaining["company"] = 20000
    before = dict(harness.ledger.remaining)
    result = harness.client.post(CHAT, json=body, headers=bearer(lease))
    assert result.status_code == 429, result.text
    assert harness.ledger.remaining == before
    assert call_rows(harness) == [] and harness.upstream.requests == []
