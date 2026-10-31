"""The authoring SDK handed to ``register(sdk)`` inside the sandbox.

Everything a handler can reach is an explicit, host-mediated call.  There is no
filesystem helper, no network client, no environment access and no way to run
another process; the kernel refuses those regardless, and every capability is
re-checked by the host against the invoking principal and the manifest
allowlist.  Stdlib only.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable, Mapping
from typing import Any

try:  # script mode (runner) and package mode (host) both resolve
    from protocol import ModuleError
except ImportError:  # pragma: no cover - imported as a package submodule
    from itsm.extensions.runtime.protocol import ModuleError

Handler = Callable[..., Any]


class ExtensionError(ModuleError):
    """Raised inside a handler when the host refuses a capability call."""


class _Channel:
    def __init__(self, reader_fd: int, writer_fd: int) -> None:
        self._reader = reader_fd
        self._writer = writer_fd
        self._buffer = bytearray()
        self.request_id = 0

    def send(self, message: Mapping[str, Any]) -> None:
        payload = (
            json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        )
        written = 0
        while written < len(payload):
            written += os.write(self._writer, payload[written:])

    def receive(self) -> dict[str, Any]:
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self._buffer[:newline])
                del self._buffer[: newline + 1]
                return json.loads(line)
            chunk = os.read(self._reader, 65536)
            if not chunk:
                raise ExtensionError("host channel closed", code="channel_closed")
            self._buffer.extend(chunk)
            if len(self._buffer) > 1024 * 1024:
                raise ExtensionError("host channel overflow", code="channel_overflow")

    def call(self, capability: str, request: Mapping[str, Any]) -> Any:
        self.request_id += 1
        self.send(
            {
                "type": "call",
                "id": self.request_id,
                "capability": capability,
                "request": dict(request),
            }
        )
        while True:
            message = self.receive()
            if message.get("type") != "response" or message.get("id") != self.request_id:
                raise ExtensionError("unexpected host message", code="protocol_error")
            if message.get("ok") is True:
                return message.get("result")
            code = str(message.get("code") or "capability_denied")
            raise ExtensionError(str(message.get("message") or "capability denied"), code=code)


class _HostBridge:
    """The only host surface module code can reach: a call, never a frame.

    The protocol channel stays in the runner, so a handler cannot author a
    ``result``/``error`` frame.  In-process Python cannot make the channel
    unreachable from determined code, which is why the host also refuses any
    terminal frame that does not carry the per-invocation token.
    """

    __slots__ = ("_call",)

    def __init__(self, channel: _Channel) -> None:
        def call(capability: str, request: Mapping[str, Any]) -> Any:
            return channel.call(capability, request)

        self._call = call

    def call(self, capability: str, request: Mapping[str, Any]) -> Any:
        return self._call(capability, request)


class Store:
    """Declared collections persisted in the module's own SQLite file."""

    __slots__ = ("_bridge",)

    def __init__(self, bridge: _HostBridge) -> None:
        self._bridge = bridge

    def get(self, collection: str, record_id: str) -> dict[str, Any] | None:
        return self._bridge.call("store.get", {"collection": collection, "recordId": record_id})

    def list(
        self,
        collection: str,
        limit: int = 50,
        offset: int = 0,
        filters: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._bridge.call(
            "store.list",
            {
                "collection": collection,
                "limit": limit,
                "offset": offset,
                "filters": dict(filters or {}),
            },
        )

    def put(
        self,
        collection: str,
        record_id: str,
        data: Mapping[str, Any],
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        return self._bridge.call(
            "store.put",
            {
                "collection": collection,
                "recordId": record_id,
                "data": dict(data),
                "expectedVersion": expected_version,
            },
        )

    def delete(self, collection: str, record_id: str, expected_version: int | None = None) -> bool:
        return self._bridge.call(
            "store.delete",
            {
                "collection": collection,
                "recordId": record_id,
                "expectedVersion": expected_version,
            },
        )


class Assets:
    """Canonical asset operations; the host applies Casbin for the principal."""

    __slots__ = ("_bridge",)

    def __init__(self, bridge: _HostBridge) -> None:
        self._bridge = bridge

    def get(self, asset_id: str) -> dict[str, Any]:
        return self._bridge.call("assets.get", {"assetId": asset_id})

    def search(self, **filters: Any) -> dict[str, Any]:
        return self._bridge.call("assets.search", dict(filters))

    def resolve(self, entity: str, ids: list[str]) -> dict[str, Any]:
        return self._bridge.call("assets.resolve", {"entity": entity, "ids": list(ids)})

    def create(self, values: Mapping[str, Any], *, idempotencyKey: str) -> dict[str, Any]:
        return self._bridge.call(
            "assets.create", {"values": dict(values), "idempotencyKey": idempotencyKey}
        )

    def update(
        self, asset_id: str, changes: Mapping[str, Any], *, idempotencyKey: str
    ) -> dict[str, Any]:
        return self._bridge.call(
            "assets.update",
            {"assetId": asset_id, "changes": dict(changes), "idempotencyKey": idempotencyKey},
        )

    def archive(
        self, asset_id: str, *, idempotencyKey: str, reason: str | None = None
    ) -> dict[str, Any]:
        return self._bridge.call(
            "assets.archive",
            {"assetId": asset_id, "reason": reason, "idempotencyKey": idempotencyKey},
        )


class Incidents:
    """Canonical incident operations through the public intervention service."""

    __slots__ = ("_bridge",)

    def __init__(self, bridge: _HostBridge) -> None:
        self._bridge = bridge

    def get(self, incident_id: str) -> dict[str, Any]:
        return self._bridge.call("incidents.get", {"incidentId": incident_id})

    def list(self, **filters: Any) -> dict[str, Any]:
        return self._bridge.call("incidents.list", dict(filters))

    def create(self, values: Mapping[str, Any], *, idempotencyKey: str) -> dict[str, Any]:
        return self._bridge.call(
            "incidents.create", {"values": dict(values), "idempotencyKey": idempotencyKey}
        )


class Context:
    """Per-invocation context.  One instance per handler call."""

    __slots__ = (
        "_bridge",
        "_data_path",
        "_db",
        "assets",
        "event",
        "extension_id",
        "incidents",
        "operation",
        "principal",
        "schedule",
        "store",
        "version",
    )

    def __init__(
        self,
        channel: _Channel,
        *,
        principal: Mapping[str, Any],
        extension_id: str,
        version: str,
        operation: str | None,
        event: Mapping[str, Any] | None,
        schedule: str | None,
        data_path: str,
    ) -> None:
        self._bridge = _HostBridge(channel)
        self._data_path = data_path
        self._db: sqlite3.Connection | None = None
        self.principal = dict(principal)
        self.extension_id = extension_id
        self.version = version
        self.operation = operation
        self.event = dict(event) if event is not None else None
        self.schedule = schedule
        self.store = Store(self._bridge)
        self.assets = Assets(self._bridge)
        self.incidents = Incidents(self._bridge)

    @property
    def db(self) -> sqlite3.Connection:
        """A connection to this module's own ``data.sqlite3`` file only."""
        if self._db is None:
            self._db = sqlite3.connect(self._data_path, timeout=2.0, isolation_level=None)
        return self._db

    def notify(
        self,
        *,
        key: str,
        title: str,
        body: str,
        permission: str,
        recipient_ids: list[str] | None = None,
        asset_id: str | None = None,
        url: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return self._bridge.call(
            "notify",
            {
                "key": key,
                "title": title,
                "body": body,
                "permission": permission,
                "recipientIds": list(recipient_ids or []),
                "assetId": asset_id,
                "url": url,
                "idempotencyKey": idempotency_key,
            },
        )

    def authorize(self, permission: str) -> bool:
        return bool(self._bridge.call("authorize", {"permission": permission}))


class ModuleSDK:
    """Collects the handlers a module declares through ``register(sdk)``."""

    def __init__(self) -> None:
        self.operations: dict[str, Handler] = {}
        self.migrations: dict[str, Handler] = {}
        self.schedules: dict[str, Handler] = {}
        self.subscriptions: dict[str, Handler] = {}
        self.reconcile_handler: tuple[str, Handler] | None = None

    def _bind(self, target: dict[str, Handler], kind: str, name: Any, handler: Any) -> None:
        if not isinstance(name, str) or not name:
            raise ExtensionError(f"{kind} name must be a string")
        if not callable(handler):
            raise ExtensionError(f"{kind} {name} handler must be callable")
        if name in target:
            raise ExtensionError(f"duplicate {kind}: {name}")
        target[name] = handler

    def operation(self, name: str, handler: Handler) -> None:
        self._bind(self.operations, "operation", name, handler)

    def migration(self, name: str, handler: Handler) -> None:
        self._bind(self.migrations, "migration", name, handler)

    def schedule(self, name: str, handler: Handler) -> None:
        self._bind(self.schedules, "schedule", name, handler)

    def subscribe(self, name: str, handler: Handler) -> None:
        self._bind(self.subscriptions, "subscription", name, handler)

    def reconcile(self, name: str, handler: Handler) -> None:
        """Declare the single periodic repair handler; called with only context."""
        self.set_reconcile(name, handler)

    def set_reconcile(self, name: str, handler: Handler) -> None:
        """Backward-compatible alias for :meth:`reconcile`."""
        if not callable(handler):
            raise ExtensionError("reconcile handler must be callable")
        self.reconcile_handler = (name, handler)
