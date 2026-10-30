"""Public demo restrictions: a demonstration administrator, never the owner (S10, S11).

``RELEASE_MODE=demo`` serves one shared state (decision D1) to anonymous
visitors who log in with :data:`VISITOR_USERNAME`/:data:`VISITOR_PASSWORD`. That
account holds the ``admin`` role, which already lacks every ``system.*``
permission, but it still owns business configuration the public surface must
never expose: deployment operations, extension installation, agent provider
credentials, external notification delivery and identity administration.

Per S11 those capabilities are denied **by the backend**; hiding the UI is not
a control. :class:`DemoRestrictionMiddleware` is a single fail-closed deny-list
installed by :func:`itsm.main.create_app` only for the demo capability set:

* an explicit protected prefix denies every method, including routes this
  process does not know yet, so new/unknown endpoints stay closed;
* a narrower mutation list denies the remaining configuration writes while
  ordinary business reads and writes keep working.

The guard also answers which weak password is acceptable, so the demo-only
``admin/admin`` exception lives next to the mode check that authorises it and
cannot be reached from ``prod`` or ``dev`` (see :func:`visitor_password_waiver`).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from itsm.config import Settings
from itsm.release_mode import ModeCapabilities

#: The public visitor account of the demonstration installation.
VISITOR_USERNAME = "admin"
VISITOR_PASSWORD = "admin"

#: Internal owner created by the demo seed. Its password is generated, used once
#: and discarded: nobody can log in as this account (the last-superadmin
#: invariant, documented in ``docs/demo-public.md``).
INTERNAL_OWNER_USERNAME = "demo.installation-owner"

#: Stable error code returned for every denied demo surface.
DEMO_RESTRICTED = "demo_restricted"

#: Paths (relative to the API prefix) where every method is denied. Trie-like
#: prefixes: ``/system`` also covers ``/system/new/invented/route``.
PROTECTED_PREFIXES: tuple[str, ...] = (
    "/system",
    "/extensions",
    "/agent/chat",
    "/agent/gateway",
    "/agent/integrations",
    "/agent/providers",
    "/agent/sessions",
)

#: Permissions the demo session envelope does not advertise: their surfaces are
#: denied by ``PROTECTED_PREFIXES``, so the UI must not offer them.
DEMO_HIDDEN_PERMISSIONS: frozenset[str] = frozenset({"agents.providers.personal"})

#: Paths (relative to the API prefix) where mutations are denied and reads stay.
PROTECTED_MUTATION_PREFIXES: tuple[str, ...] = (
    "/identity",
    "/notifications/channels",
    "/notifications/rules",
    "/monitoring/exporters",
    "/monitoring/profiles",
    "/monitoring/assets",
    "/workspace/integrations",
    "/tasks/demo",
)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

#: JSON keys whose string value names a delivery transport.
_SENDER_KEYS = frozenset({"kind", "channel", "channels", "type", "provider", "transport"})

#: Transports that leave the instance. ``internal`` (the inbox) does not.
_EXTERNAL_TRANSPORTS = frozenset(
    {
        "smtp",
        "email",
        "mail",
        "webhook",
        "http",
        "https",
        "sms",
        "telegram",
        "slack",
        "msteams",
        "teams",
        "push",
    }
)

#: Bodies larger than this are never inspected; the limit middleware rejects
#: them first anyway.
_MAX_INSPECTED_BODY = 64 * 1024


def is_public_demo(capabilities: ModeCapabilities) -> bool:
    """Whether this capability set is the sealed public demo.

    The demo mode is the only one that forbids system operations, extension
    installation, external delivery and real providers while still allowing
    demonstration seeding. Requiring all four keeps every other mode — including
    a future permissive one — outside this guard.
    """
    return (
        capabilities.allow_seed
        and not capabilities.allow_system_operations
        and not capabilities.allow_extension_install
        and not capabilities.allow_external_notifications
        and not capabilities.allow_ai_providers
    )


def visitor_password_waiver(capabilities: ModeCapabilities) -> str | None:
    """The demo-only weak password, or ``None`` when passwords stay strict.

    Called from :class:`itsm.identity.service.IdentityService` for every
    password it validates. Returning ``None`` keeps the normal minimum length,
    so ``prod`` and ``dev`` refuse ``admin`` exactly as before.
    """
    return VISITOR_PASSWORD if is_public_demo(capabilities) else None


@dataclass(frozen=True)
class DemoRestrictions:
    """The deny-list of the public demo, evaluated per request."""

    api_prefix: str

    def relative(self, path: str) -> str | None:
        """Return ``path`` without the API prefix, or ``None`` outside the API."""
        prefix = self.api_prefix.rstrip("/")
        if not path.startswith(prefix + "/"):
            return None
        return path[len(prefix) :].rstrip("/") or "/"

    def denies(self, method: str, path: str, body: bytes = b"") -> bool:
        """Whether the public demo must refuse this request with 403."""
        relative = self.relative(path)
        if relative is None:
            return False
        for prefix in PROTECTED_PREFIXES:
            if relative == prefix or relative.startswith(prefix + "/"):
                return True
        if method.upper() in _SAFE_METHODS:
            return False
        for prefix in PROTECTED_MUTATION_PREFIXES:
            if relative == prefix or relative.startswith(prefix + "/"):
                return True
        return bool(relative == "/notifications/channels" and publishes_external(body))

    @staticmethod
    def needs_body(method: str, path: str) -> bool:
        """Only channel creation inspects the payload it is about to accept."""
        return method.upper() == "POST" and path.rstrip("/").endswith("/notifications/channels")


def publishes_external(payload: bytes) -> bool:
    """Whether a channel/rule payload would deliver outside the instance."""
    if not payload or len(payload) > _MAX_INSPECTED_BODY:
        return False
    try:
        document: Any = json.loads(payload)
    except ValueError, UnicodeDecodeError:
        return False
    return _mentions_external_transport(document, depth=0)


def _mentions_external_transport(value: Any, depth: int) -> bool:
    if depth > 6:
        return False
    if isinstance(value, Mapping):
        for key, item in value.items():
            if (
                isinstance(item, str)
                and str(key).lower() in _SENDER_KEYS
                and item.lower() in _EXTERNAL_TRANSPORTS
            ):
                return True
            if _mentions_external_transport(item, depth + 1):
                return True
    elif isinstance(value, list | tuple):
        return any(_mentions_external_transport(item, depth + 1) for item in value)
    return False


def build_demo_restrictions(
    settings: Settings, capabilities: ModeCapabilities
) -> DemoRestrictions | None:
    """Build the guard for the demo capability set, or ``None`` for any other mode."""
    if not is_public_demo(capabilities):
        return None
    return DemoRestrictions(api_prefix=str(settings.api_prefix))


def _forbidden() -> tuple[Message, Message]:
    body = (
        '{"error": {"code": "'
        + DEMO_RESTRICTED
        + '", "message": "this capability is disabled in the public demonstration"}}'
    ).encode("utf-8")
    start: Message = {
        "type": "http.response.start",
        "status": 403,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ],
    }
    return start, {"type": "http.response.body", "body": body}


class DemoRestrictionMiddleware:
    """Fail-closed ASGI guard for the public demonstration surface."""

    def __init__(self, app: ASGIApp, restrictions: DemoRestrictions) -> None:
        self.app = app
        self.restrictions = restrictions

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = str(scope.get("method", "GET"))
        path = str(scope.get("path", ""))
        if not self.restrictions.needs_body(method, path):
            if self.restrictions.denies(method, path):
                await self._forbid(send)
                return
            await self.app(scope, receive, send)
            return

        buffered: list[Message] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return
            buffered.append(message)
            total += len(message.get("body", b""))
            if not message.get("more_body", False) or total > _MAX_INSPECTED_BODY:
                break
        body = b"".join(message.get("body", b"") for message in buffered)
        if self.restrictions.denies(method, path, body):
            await self._forbid(send)
            return
        pending = list(buffered)

        async def replay() -> Message:
            if pending:
                return pending.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay, send)

    @staticmethod
    async def _forbid(send: Send) -> None:
        start, body = _forbidden()
        await send(start)
        await send(body)
