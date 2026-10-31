"""Host-side capability broker for sandboxed extension invocations.

Module code never touches the core database, the FastAPI app or a core service
object.  It may only ask the host for one of the manifest-declared capabilities,
and the host answers each call by invoking the *canonical* service with the
invoking principal, so Casbin authorization, validation and auditing stay where
they already live.  Mutating capabilities are additionally gated to mutation
operations and protected by the ``extension_core_calls`` idempotency ledger.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from itsm.extensions.errors import (
    ExtensionIdempotencyConflict,
    ExtensionStoreConflict,
    ExtensionStoreValidation,
    ExtensionValidationFailed,
)
from itsm.extensions.models import ExtensionCoreCall
from itsm.extensions.runtime import sqlite_store

if TYPE_CHECKING:  # pragma: no cover - typing only
    from itsm.extensions.host import ExtensionHostService, _LoadedModule, _ModuleStore
    from itsm.identity.service import Principal

READ_CAPABILITIES = frozenset({"assets.read", "incidents.read"})
WRITE_CAPABILITIES = frozenset({"assets.write", "incidents.write", "notify"})
KNOWN_CAPABILITIES = READ_CAPABILITIES | WRITE_CAPABILITIES

_ASSET_CALLS = {
    "assets.get": "assets.read",
    "assets.search": "assets.read",
    "assets.resolve": "assets.read",
    "assets.create": "assets.write",
    "assets.update": "assets.write",
    "assets.archive": "assets.write",
}
_INCIDENT_CALLS = {
    "incidents.get": "incidents.read",
    "incidents.list": "incidents.read",
    "incidents.create": "incidents.write",
}
_CALL_CAPABILITY = {**_ASSET_CALLS, **_INCIDENT_CALLS, "notify": "notify"}
_MUTATING = frozenset(
    {"assets.create", "assets.update", "assets.archive", "incidents.create", "notify"}
)
_STORE_CALLS = frozenset({"store.get", "store.list", "store.put", "store.delete"})
_STORE_MUTATIONS = frozenset({"store.put", "store.delete"})

_ASSET_SEARCH_FIELDS = frozenset(
    {
        "query",
        "category",
        "site",
        "status",
        "quick_code",
        "asset_id",
        "site_id",
        "location_id",
        "responsible_person_id",
        "archived",
        "limit",
        "offset",
    }
)
_INCIDENT_LIST_FIELDS = frozenset(
    {
        "active",
        "status",
        "priority",
        "category",
        "site",
        "site_id",
        "asset_id",
        "responsible_person_id",
        "from_date",
        "to_date",
        "limit",
        "offset",
    }
)
_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
MAX_LEDGER_RESPONSE_BYTES = 256 * 1024


def request_digest(capability: str, request: Mapping[str, Any]) -> str:
    """Stable SHA-256 of a capability request, excluding the idempotency key."""
    body = {key: value for key, value in request.items() if key != "idempotencyKey"}
    payload = json.dumps(
        {"capability": capability, "request": body},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CapabilityBroker:
    """Answer one module's capability calls inside a single invocation."""

    def __init__(
        self,
        *,
        host: ExtensionHostService,
        principal: Principal,
        loaded: _LoadedModule,
        store: _ModuleStore,
        allow_write: bool,
    ) -> None:
        self._host = host
        self._principal = principal
        self._loaded = loaded
        self._store = store
        self._allow_write = allow_write
        capabilities = frozenset(loaded.manifest.get("capabilities") or ())
        self._capabilities = capabilities

    # ------------------------------------------------------------------ dispatch
    def handle(self, capability: Any, request: Any) -> Any:
        if not isinstance(capability, str) or capability not in (
            _STORE_CALLS | set(_CALL_CAPABILITY) | {"authorize"}
        ):
            raise ExtensionValidationFailed(f"unknown host capability: {capability!r}")
        if not isinstance(request, Mapping):
            raise ExtensionValidationFailed("capability request must be an object")
        if capability in _STORE_CALLS:
            return self._store_call(capability, request)
        if capability == "authorize":
            return self._authorize(request)
        family = _CALL_CAPABILITY[capability]
        if family not in self._capabilities:
            raise ExtensionValidationFailed(
                f"manifest does not declare the {family} capability required by {capability}"
            )
        if capability in _MUTATING:
            if not self._allow_write:
                raise ExtensionValidationFailed("a read-only invocation cannot mutate core data")
            return self._idempotent(capability, request)
        return self._call(capability, request)

    # -------------------------------------------------------------- store calls
    def _store_call(self, capability: str, request: Mapping[str, Any]) -> Any:
        if capability in _STORE_MUTATIONS and not self._allow_write:
            raise ExtensionStoreValidation("this module invocation is read-only")
        collection = request.get("collection")
        if capability == "store.get":
            return self._store.get(collection, request.get("recordId"))
        if capability == "store.list":
            return self._store.list(
                collection,
                limit=request.get("limit", 50),
                offset=request.get("offset", 0),
                filters=request.get("filters") or {},
            )
        if capability == "store.put":
            return self._store.put(
                collection,
                request.get("recordId"),
                request.get("data"),
                request.get("expectedVersion"),
            )
        return self._store.delete(
            collection, request.get("recordId"), request.get("expectedVersion")
        )

    # ----------------------------------------------------------- authorization
    def _authorize(self, request: Mapping[str, Any]) -> bool:
        permission = request.get("permission")
        from itsm.identity.service import IdentityService

        with self._host._session_factory() as session:
            IdentityService(session, self._host._settings).authorize(
                self._principal,
                permission,
                resource=f"extension:{self._loaded.extension_id}",
                commit_denial=False,
            )
        return True

    # ------------------------------------------------------------- idempotency
    def _idempotent(self, capability: str, request: Mapping[str, Any]) -> Any:
        key = request.get("idempotencyKey")
        if not isinstance(key, str) or not _KEY_PATTERN.fullmatch(key):
            raise ExtensionValidationFailed(
                "mutating capability calls require an idempotencyKey of 1-128 URL-safe characters"
            )
        digest = request_digest(capability, request)
        extension_id = self._loaded.extension_id
        with self._host._session_factory() as session:
            existing = session.execute(
                select(ExtensionCoreCall).where(
                    ExtensionCoreCall.extension_id == extension_id,
                    ExtensionCoreCall.call_key == key,
                )
            ).scalar_one_or_none()
            if existing is not None:
                return self._replay(existing, digest)
            session.add(
                ExtensionCoreCall(
                    extension_id=extension_id,
                    call_key=key,
                    capability=capability,
                    request_hash=digest,
                    response_json="",
                )
            )
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                concurrent = session.execute(
                    select(ExtensionCoreCall).where(
                        ExtensionCoreCall.extension_id == extension_id,
                        ExtensionCoreCall.call_key == key,
                    )
                ).scalar_one_or_none()
                if concurrent is None:  # pragma: no cover - defensive
                    raise ExtensionIdempotencyConflict(
                        "idempotency key could not be reserved"
                    ) from None
                return self._replay(concurrent, digest)
        try:
            result = self._call(capability, request)
        except BaseException:
            self._release(extension_id, key)
            raise
        with self._host._session_factory() as session:
            session.execute(
                delete(ExtensionCoreCall).where(
                    ExtensionCoreCall.extension_id == extension_id,
                    ExtensionCoreCall.call_key == key,
                    ExtensionCoreCall.response_json == "",
                )
            )
            serialized = json.dumps(result, sort_keys=True, default=str)
            if len(serialized) > MAX_LEDGER_RESPONSE_BYTES:
                raise ExtensionValidationFailed("capability response is too large to replay")
            session.add(
                ExtensionCoreCall(
                    extension_id=extension_id,
                    call_key=key,
                    capability=capability,
                    request_hash=digest,
                    response_json=serialized,
                )
            )
            session.commit()
        return result

    @staticmethod
    def _replay(row: ExtensionCoreCall, digest: str) -> Any:
        if row.request_hash != digest:
            raise ExtensionIdempotencyConflict(
                "idempotency key was already used with a different request"
            )
        if not row.response_json:
            raise ExtensionIdempotencyConflict("idempotency key is still in progress")
        return json.loads(row.response_json)

    def _release(self, extension_id: str, key: str) -> None:
        with self._host._session_factory() as session:
            session.execute(
                delete(ExtensionCoreCall).where(
                    ExtensionCoreCall.extension_id == extension_id,
                    ExtensionCoreCall.call_key == key,
                    ExtensionCoreCall.response_json == "",
                )
            )
            session.commit()

    # -------------------------------------------------------- canonical calls
    def _call(self, capability: str, request: Mapping[str, Any]) -> Any:
        if capability.startswith("assets."):
            return self._assets(capability, request)
        if capability.startswith("incidents."):
            return self._incidents(capability, request)
        return self._notify(request)

    def _assets(self, capability: str, request: Mapping[str, Any]) -> Any:
        from itsm.inventory.service import InventoryService

        method, _, rest = capability.partition(".")
        with self._host._session_factory() as session:
            service = InventoryService(session, self._host._settings)
            if rest == "get":
                view = service.get(self._principal, _text(request.get("assetId"), "assetId"))
                return view.as_payload()
            if rest == "search":
                filters = _filters(request, _ASSET_SEARCH_FIELDS)
                return service.search(self._principal, **filters).as_payload()
            if rest == "resolve":
                entity = request.get("entity")
                if entity != "asset":
                    raise ExtensionValidationFailed("resolve supports entity asset only")
                ids = request.get("ids")
                if not isinstance(ids, list) or len(ids) > 50:
                    raise ExtensionValidationFailed("resolve ids must be a list of at most 50")
                items = [
                    service.get(self._principal, _text(item, "asset id")).as_payload()
                    for item in ids
                ]
                return {"items": items}
            if rest == "create":
                values = request.get("values")
                if not isinstance(values, Mapping):
                    raise ExtensionValidationFailed("assets.create needs a values object")
                return service.create(self._principal, dict(values)).as_payload()
            if rest == "update":
                changes = request.get("changes")
                if not isinstance(changes, Mapping):
                    raise ExtensionValidationFailed("assets.update needs a changes object")
                view = service.update(
                    self._principal, _text(request.get("assetId"), "assetId"), dict(changes)
                )
                return view.as_payload()
            if rest == "archive":
                reason = request.get("reason")
                if reason is not None:
                    reason = _text(reason, "reason", limit=500)
                view = service.archive(
                    self._principal, _text(request.get("assetId"), "assetId"), reason=reason
                )
                return view.as_payload()
        raise ExtensionValidationFailed(f"unknown assets capability {method}")  # pragma: no cover

    def _incidents(self, capability: str, request: Mapping[str, Any]) -> Any:
        from itsm.interventions.service import InterventionService

        _, _, rest = capability.partition(".")
        with self._host._session_factory() as session:
            service = InterventionService(session, self._host._settings)
            if rest == "get":
                return service.get_incident(
                    self._principal, _text(request.get("incidentId"), "incidentId")
                )
            if rest == "list":
                filters = _filters(request, _INCIDENT_LIST_FIELDS)
                return service.list_incidents(self._principal, **filters).as_payload()
            if rest == "create":
                values = request.get("values")
                if not isinstance(values, Mapping):
                    raise ExtensionValidationFailed("incidents.create needs a values object")
                return service.create_incident(self._principal, dict(values))
        raise ExtensionValidationFailed(f"unknown incidents capability {rest}")  # pragma: no cover

    def _notify(self, request: Mapping[str, Any]) -> Any:
        recipient_ids = request.get("recipientIds") or []
        if not isinstance(recipient_ids, list):
            raise ExtensionValidationFailed("notify recipientIds must be a list")
        asset_id = request.get("assetId")
        url = request.get("url")
        self._host.notify_from_module(
            principal=self._principal,
            loaded=self._loaded,
            recipient_ids=[_text(item, "recipient id") for item in recipient_ids],
            key=_text(request.get("key"), "key", limit=64),
            title=_text(request.get("title"), "title", limit=200),
            body=_text(request.get("body"), "body", limit=4000),
            permission=_text(request.get("permission"), "permission", limit=200),
            asset_id=_text(asset_id, "assetId") if asset_id is not None else None,
            # The host owns the single url contract (native page prefix + length).
            url=url,
        )
        return {"sent": True}


def _text(value: Any, label: str, *, limit: int = 100) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ExtensionValidationFailed(f"{label} must be text of 1-{limit} characters")
    return value


def _filters(request: Mapping[str, Any], allowed: frozenset[str]) -> dict[str, Any]:
    unknown = sorted(set(request) - allowed)
    if unknown:
        raise ExtensionValidationFailed("unsupported filter: " + ", ".join(unknown[:8]))
    return {key: value for key, value in request.items() if value is not None}


def as_store_error(exc: BaseException) -> BaseException:
    """Translate stdlib store errors into the host's public refusals."""
    if isinstance(exc, sqlite_store.StoreConflict):
        return ExtensionStoreConflict(str(exc) or "record version conflict")
    if isinstance(exc, (sqlite_store.StoreValidation, sqlite_store.ModuleError)):
        return ExtensionStoreValidation(str(exc) or "invalid store request")
    return exc


__all__ = [
    "KNOWN_CAPABILITIES",
    "READ_CAPABILITIES",
    "WRITE_CAPABILITIES",
    "CapabilityBroker",
    "as_store_error",
    "request_digest",
]
