"""In-process exposure limits for the public demo installation (S16).

Only ``RELEASE_MODE=demo`` builds a :class:`DemoLimits`; ``prod`` and ``dev``
start without any limiter and keep their previous behaviour. Everything here is
process-local on purpose: the public demo is one shared state served by one
bounded process (decision D1), so an in-memory bucket is the honest, simplest
control. Behind several workers each process keeps its own buckets and the
reverse proxy adds the network-level limits (see ``docs/demo-public.md``).

Public interface:

* :class:`DemoLimits` — the limit set built from ``ITSM_DEMO_*`` settings.
* :class:`DemoLimitsMiddleware` — ASGI middleware enforcing those limits.
* :func:`client_key` — the client identity a bucket is counted against.
"""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from itsm.config import Settings

#: Upper bound on tracked clients per bucket so a spoofed-source flood cannot
#: grow memory without limit. Idle (full) buckets are dropped first.
_MAX_TRACKED_CLIENTS = 4096


def client_key(*, trusted_proxy: bool, headers: Mapping[str, str], client_host: str) -> str:
    """Return the string a request is counted against.

    ``X-Forwarded-For`` is attacker-controlled unless the request arrived
    through the deployment's own reverse proxy, so it is only honoured when
    ``ITSM_TRUSTED_PROXY`` says the hop in front of this process is trusted. The
    rightmost entry is the address that hop appended.
    """
    if trusted_proxy:
        forwarded = headers.get("x-forwarded-for")
        if forwarded:
            candidate = forwarded.split(",")[-1].strip()
            if candidate:
                return candidate
    return client_host or "unknown"


class TokenBucket:
    """One bucket: tolerates a short burst, then refills steadily."""

    def __init__(
        self, capacity: int, per_minute: int, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._capacity = float(max(capacity, 1))
        self._per_second = max(per_minute, 1) / 60.0
        self._clock = clock
        self._tokens = self._capacity
        self._updated = clock()

    @property
    def full(self) -> bool:
        """Whether the bucket is idle, i.e. costs nothing to forget."""
        return self._tokens >= self._capacity

    def consume(self) -> float | None:
        """Spend one token.

        Returns:
            ``None`` when the request may proceed, otherwise the seconds a
            caller should wait before retrying.
        """
        now = self._clock()
        elapsed = max(now - self._updated, 0.0)
        self._updated = now
        self._tokens = min(self._capacity, self._tokens + elapsed * self._per_second)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return None
        return max((1.0 - self._tokens) / self._per_second, 1.0)


class BucketRegistry:
    """Per-client token buckets with a bounded number of tracked clients."""

    def __init__(
        self, capacity: int, per_minute: int, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._capacity = capacity
        self._per_minute = per_minute
        self._clock = clock
        self._buckets: OrderedDict[str, TokenBucket] = OrderedDict()
        self._lock = threading.Lock()

    def consume(self, key: str) -> float | None:
        """Consume one token for ``key``; return the retry delay when limited."""
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(self._capacity, self._per_minute, clock=self._clock)
                self._buckets[key] = bucket
                self._prune()
            return bucket.consume()

    def _prune(self) -> None:
        if len(self._buckets) <= _MAX_TRACKED_CLIENTS:
            return
        idle = [key for key, bucket in self._buckets.items() if bucket.full]
        for key in idle:
            self._buckets.pop(key, None)
        while len(self._buckets) > _MAX_TRACKED_CLIENTS:
            self._buckets.popitem(last=False)


class DemoLimits:
    """Every exposure limit of the public demo, built once per process."""

    def __init__(self, settings: Settings, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.max_body_bytes = int(settings.demo_max_request_body_bytes)
        self.attachment_max_bytes = min(
            int(settings.demo_attachment_max_bytes), int(settings.attachment_max_bytes)
        )
        self.quota_bytes = int(settings.demo_attachment_quota_bytes)
        self.session_cap = int(settings.demo_max_active_sessions)
        self.max_in_flight = int(settings.demo_max_in_flight)
        self.trusted_proxy = bool(settings.trusted_proxy)
        self._requests = BucketRegistry(
            settings.demo_rate_limit_burst, settings.demo_rate_limit_per_minute, clock=clock
        )
        self._logins = BucketRegistry(
            settings.demo_login_rate_burst, settings.demo_login_rate_per_minute, clock=clock
        )
        self._slots = threading.BoundedSemaphore(self.max_in_flight)

    def client_key(self, headers: Mapping[str, str], client_host: str) -> str:
        return client_key(
            trusted_proxy=self.trusted_proxy, headers=headers, client_host=client_host
        )

    def check_request(self, key: str) -> float | None:
        return self._requests.consume(key)

    def check_login(self, key: str) -> float | None:
        return self._logins.consume(key)

    @staticmethod
    def is_login(path: str) -> bool:
        return path.rstrip("/").endswith("/auth/login")

    def body_limit(self, method: str, path: str) -> int:
        """The largest body this route may carry in the public demo."""
        if method.upper() == "POST" and "/attachments" in path:
            # Attachments have their own, smaller ceiling; the generic cap still
            # has to let them through.
            return max(self.max_body_bytes, self.attachment_max_bytes)
        return self.max_body_bytes

    def acquire_slot(self) -> bool:
        return bool(self._slots.acquire(blocking=False))

    def release_slot(self) -> None:
        try:
            self._slots.release()
        except ValueError:  # pragma: no cover - release without acquire is a bug
            raise RuntimeError("demo in-flight slot released twice") from None


def _error_message(
    status: int, code: str, message: str, retry_after: float | None
) -> tuple[Message, Message]:
    body = (
        '{"error": {"code": "' + code + '", "message": "' + message.replace('"', "'") + '"}}'
    ).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]
    if retry_after is not None:
        headers.append((b"retry-after", str(max(1, math.ceil(retry_after))).encode("ascii")))
    return {"type": "http.response.start", "status": status, "headers": headers}, {
        "type": "http.response.body",
        "body": body,
    }


class DemoLimitsMiddleware:
    """Reject abusive public requests before they reach a route."""

    def __init__(self, app: ASGIApp, limits: DemoLimits) -> None:
        self.app = app
        self.limits = limits

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limits = self.limits
        headers = Headers(scope=scope)
        client_host = scope["client"][0] if scope.get("client") else "unknown"
        key = limits.client_key(headers, client_host)
        path = str(scope.get("path", ""))
        method = str(scope.get("method", "GET"))

        if limits.is_login(path):
            wait = limits.check_login(key)
            if wait is not None:
                await self._reject(send, 429, "login_rate_limited", "too many login attempts", wait)
                return
        wait = limits.check_request(key)
        if wait is not None:
            await self._reject(send, 429, "rate_limited", "request rate limit exceeded", wait)
            return

        if not limits.acquire_slot():
            await self._reject(
                send, 503, "server_busy", "the public demo is busy; retry shortly", 1.0
            )
            return
        try:
            buffered = await self._buffer(receive, send, limits.body_limit(method, path))
            if buffered is None:
                return
            pending = list(buffered)

            async def replay() -> Message:
                if pending:
                    return pending.pop(0)
                return {"type": "http.request", "body": b"", "more_body": False}

            await self.app(scope, replay, send)
        finally:
            limits.release_slot()

    async def _buffer(self, receive: Receive, send: Send, limit: int) -> list[Message] | None:
        """Collect the request body, or reject it when it exceeds ``limit``."""
        buffered: list[Message] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return None
            buffered.append(message)
            total += len(message.get("body", b""))
            if total > limit:
                await self._reject(send, 413, "payload_too_large", "request body is too large")
                return None
            if not message.get("more_body", False):
                return buffered

    @staticmethod
    async def _reject(
        send: Send,
        status: int,
        code: str,
        message: str,
        retry_after: float | None = None,
    ) -> None:
        start, body = _error_message(status, code, message, retry_after)
        await send(start)
        await send(body)
