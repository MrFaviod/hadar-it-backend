"""Host-owned lifecycle, storage, migrations and dispatch for native extensions.

Trust boundary: an installed extension is approved native Python running in the
host process.  It is not sandboxed or allowlist-isolated at runtime; the only
isolation claims here are the pre-install package admission checks and the
separate fixed validation container owned by the developer toolchain.  Every
installation is an explicit persisted-human-Superadmin action.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import types
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from io import BytesIO
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import quote
from uuid import uuid4

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from itsm.config import Settings
from itsm.extensions import manifest as package_contract
from itsm.extensions import storage
from itsm.extensions.models import (
    ExtensionCandidate,
    ExtensionCollectionRecord,
    ExtensionEvent,
    ExtensionMigration,
    ExtensionModule,
    ExtensionScheduleState,
    ExtensionVersion,
)
from itsm.identity.clock import as_utc, utcnow
from itsm.identity.models import Identity
from itsm.identity.permissions import (
    HUMAN_ACTOR_KIND,
    MACHINE_ACTOR_KINDS,
    PERMISSION_CODES,
    ROLE_SUPERADMIN,
)
from itsm.identity.service import IdentityService, PermissionDenied, Principal

logger = logging.getLogger(__name__)

SDK_VERSION = 1
CANDIDATE_LIMIT = 200
EVENT_LIMIT = 100
MAX_COLLECTION_DATA_BYTES = 256 * 1024
MAX_RECIPIENTS = 100
MAX_REPORT_BYTES = 32 * 1024
_CANDIDATE_STATES = frozenset({"pending", "installing", "installed", "superseded"})

NotifyCallback = Callable[..., None]


class ExtensionHostError(Exception):
    """Base class for host refusals; the API maps these to JSON errors."""


class ExtensionUnavailable(ExtensionHostError):
    pass


class ExtensionValidationFailed(ExtensionHostError):
    def __init__(self, message: str, errors: Iterable[str] = ()) -> None:
        self.errors = tuple(dict.fromkeys(str(error) for error in errors))[:40]
        super().__init__(message)


class ExtensionTooLarge(ExtensionHostError):
    pass


class ExtensionNotFound(ExtensionHostError):
    pass


class ExtensionConflict(ExtensionHostError):
    pass


class ExtensionStale(ExtensionConflict):
    pass


class ExtensionDisabled(ExtensionConflict):
    pass


class ExtensionDigestMismatch(ExtensionConflict):
    pass


class ExtensionRollbackIncompatible(ExtensionConflict):
    pass


class ExtensionImportFailed(ExtensionValidationFailed):
    pass


class ExtensionHandlerFailed(ExtensionHostError):
    pass


class ExtensionStoreConflict(ExtensionConflict):
    pass


class ExtensionStoreValidation(ExtensionValidationFailed):
    pass


class ExtensionMigrationFailed(ExtensionHostError):
    pass


@dataclass(frozen=True)
class ScheduleView:
    extension_id: str
    version: str
    digest: str
    name: str
    handler: str
    interval_seconds: int
    permission: str
    owner_id: str | None
    next_due_at: datetime | None
    last_run_at: datetime | None
    last_error: str | None


@dataclass(frozen=True)
class _LoadedModule:
    extension_id: str
    version: str
    digest: str
    manifest: Mapping[str, Any]
    backend_source: str
    frontend_bytes: bytes
    operations: Mapping[str, Callable[..., Any]]
    migrations: Mapping[str, Callable[..., Any]]
    schedules: Mapping[str, Callable[..., Any]]


class _SDKBinder:
    """Collect exactly the handlers the manifest declares."""

    def __init__(self, manifest: Mapping[str, Any]) -> None:
        self._declared = {
            "operation": {item["name"] for item in manifest["operations"]},
            "migration": {item["handler"] for item in manifest["migrations"]},
            "schedule": {item["name"] for item in manifest["schedules"]},
        }
        self._bound: dict[str, dict[str, Callable[..., Any]]] = {
            "operation": {},
            "migration": {},
            "schedule": {},
        }

    def _bind(self, kind: str, name: Any, handler: Any) -> None:
        if not isinstance(name, str) or name not in self._declared[kind]:
            raise ExtensionImportFailed(f"backend.py bound an undeclared {kind}: {name!r}")
        if not callable(handler):
            raise ExtensionImportFailed(f"{kind} {name} is not callable")
        if name in self._bound[kind]:
            raise ExtensionImportFailed(f"{kind} {name} was bound twice")
        self._bound[kind][name] = handler

    def operation(self, name: Any, handler: Any) -> None:
        self._bind("operation", name, handler)

    def migration(self, name: Any, handler: Any) -> None:
        self._bind("migration", name, handler)

    def schedule(self, name: Any, handler: Any) -> None:
        self._bind("schedule", name, handler)

    def finish(self) -> dict[str, dict[str, Callable[..., Any]]]:
        missing: list[str] = []
        for kind, declared in self._declared.items():
            for name in sorted(declared - set(self._bound[kind])):
                missing.append(f"{kind}:{name}")
        if missing:
            raise ExtensionImportFailed("backend.py did not bind: " + ", ".join(missing))
        return self._bound


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return as_utc(value).isoformat()


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 40:
        raise ExtensionValidationFailed(f"validation {label} must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ExtensionValidationFailed(f"validation {label} must be an ISO timestamp") from None
    if parsed.tzinfo is None:
        raise ExtensionValidationFailed(f"validation {label} must include a timezone")
    return parsed


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise TypeError("non-finite number")
        return value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    as_payload = getattr(value, "as_payload", None)
    if callable(as_payload):
        return _jsonable(as_payload())
    if hasattr(value, "__dataclass_fields__"):
        from dataclasses import asdict

        return _jsonable(asdict(value))
    raise TypeError(f"value of type {type(value).__name__} is not JSON serializable")


def _json_dumps(value: Any, *, sort_keys: bool = False) -> str:
    try:
        return json.dumps(
            _jsonable(value),
            sort_keys=sort_keys,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ExtensionStoreValidation(f"collection data is not JSON: {exc}") from None


def _is_human_superadmin(identity: Identity | None) -> bool:
    return (
        identity is not None
        and identity.active
        and identity.actor_kind == HUMAN_ACTOR_KIND
        and identity.role_id == ROLE_SUPERADMIN
    )


class _ModuleStore:
    """Module-scoped durable collections backed by the host SQL session."""

    def __init__(
        self,
        session: Session,
        extension_id: str,
        collections: frozenset[str],
        *,
        allow_write: bool,
    ) -> None:
        self._session = session
        self._extension_id = extension_id
        self._collections = collections
        self._allow_write = allow_write

    def _require_write(self) -> None:
        if not self._allow_write:
            raise ExtensionStoreValidation("a read-only operation cannot write collections")

    def _collection(self, name: Any) -> str:
        if not isinstance(name, str) or name not in self._collections:
            raise ExtensionStoreValidation(f"unknown collection: {name!r}")
        return name

    @staticmethod
    def _record_id(record_id: Any) -> str:
        if not isinstance(record_id, str) or not record_id or len(record_id) > 64:
            raise ExtensionStoreValidation("record id must be 1-64 characters")
        if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-" for ch in record_id):
            raise ExtensionStoreValidation("record id contains unsupported characters")
        return record_id

    def _row(self, collection: str, record_id: str) -> ExtensionCollectionRecord | None:
        return self._session.execute(
            select(ExtensionCollectionRecord).where(
                ExtensionCollectionRecord.extension_id == self._extension_id,
                ExtensionCollectionRecord.collection == collection,
                ExtensionCollectionRecord.record_id == record_id,
            )
        ).scalar_one_or_none()

    @staticmethod
    def _payload(row: ExtensionCollectionRecord) -> dict[str, Any]:
        return {
            "id": row.record_id,
            "version": row.version,
            "data": json.loads(row.data_json),
        }

    def get(self, collection: str, record_id: str) -> dict[str, Any] | None:
        name = self._collection(collection)
        row = self._row(name, self._record_id(record_id))
        return None if row is None else self._payload(row)

    def list(
        self,
        collection: str,
        limit: int = 20,
        offset: int = 0,
        filters: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        name = self._collection(collection)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ExtensionStoreValidation("limit must be 1-200")
        if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= 1_000_000:
            raise ExtensionStoreValidation("offset must be 0-1000000")
        if filters is None:
            clean_filters: dict[str, Any] = {}
        elif isinstance(filters, Mapping) and len(filters) <= 20:
            clean_filters = {}
            for key, value in filters.items():
                if not isinstance(key, str) or not key or len(key) > 64:
                    raise ExtensionStoreValidation("filter keys must be 1-64 characters")
                if isinstance(value, (Mapping, list, tuple, set, bytes)):
                    raise ExtensionStoreValidation("filter values must be JSON scalars")
                if value is not None and not isinstance(value, (str, int, float, bool)):
                    raise ExtensionStoreValidation("filter values must be JSON scalars")
                clean_filters[key] = value
        else:
            raise ExtensionStoreValidation("filters must be an object with at most 20 keys")
        rows = self._session.execute(
            select(ExtensionCollectionRecord)
            .where(
                ExtensionCollectionRecord.extension_id == self._extension_id,
                ExtensionCollectionRecord.collection == name,
            )
            .order_by(ExtensionCollectionRecord.record_id)
        ).scalars()
        matched: list[dict[str, Any]] = []
        for row in rows:
            data = json.loads(row.data_json)
            if all(data.get(key) == value for key, value in clean_filters.items()):
                matched.append(self._payload(row))
        return {
            "items": matched[offset : offset + limit],
            "total": len(matched),
        }

    def put(
        self,
        collection: str,
        record_id: str,
        data: Mapping[str, Any],
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        self._require_write()
        name = self._collection(collection)
        identifier = self._record_id(record_id)
        if not isinstance(data, Mapping):
            raise ExtensionStoreValidation("collection data must be an object")
        encoded = _json_dumps(data, sort_keys=True)
        if len(encoded.encode("utf-8")) > MAX_COLLECTION_DATA_BYTES:
            raise ExtensionStoreValidation("collection data is too large")
        if expected_version is not None and (
            isinstance(expected_version, bool)
            or not isinstance(expected_version, int)
            or expected_version < 0
        ):
            raise ExtensionStoreValidation("expected_version must be a non-negative integer")
        row = self._row(name, identifier)
        if row is None:
            if expected_version not in (None, 0):
                raise ExtensionStoreConflict("record version does not match")
            row = ExtensionCollectionRecord(
                extension_id=self._extension_id,
                collection=name,
                record_id=identifier,
                version=1,
                data_json=encoded,
            )
            self._session.add(row)
            self._session.flush()
            return self._payload(row)
        if expected_version is not None and expected_version != row.version:
            raise ExtensionStoreConflict("record version does not match")
        next_version = row.version + 1
        changed = self._session.execute(
            update(ExtensionCollectionRecord)
            .where(
                ExtensionCollectionRecord.id == row.id,
                ExtensionCollectionRecord.version == row.version,
            )
            .values(data_json=encoded, version=next_version, updated_at=utcnow())
            .execution_options(synchronize_session="fetch")
        )
        if changed.rowcount != 1:
            raise ExtensionStoreConflict("record version does not match")
        return {"id": identifier, "version": next_version, "data": json.loads(encoded)}

    def delete(
        self,
        collection: str,
        record_id: str,
        expected_version: int | None = None,
    ) -> bool:
        self._require_write()
        name = self._collection(collection)
        if expected_version is not None and (
            isinstance(expected_version, bool)
            or not isinstance(expected_version, int)
            or expected_version < 0
        ):
            raise ExtensionStoreValidation("expected_version must be a non-negative integer")
        row = self._row(name, self._record_id(record_id))
        if row is None:
            if expected_version not in (None, 0):
                raise ExtensionStoreConflict("record version does not match")
            return False
        if expected_version is not None and expected_version != row.version:
            raise ExtensionStoreConflict("record version does not match")
        changed = self._session.execute(
            delete(ExtensionCollectionRecord)
            .where(
                ExtensionCollectionRecord.id == row.id,
                ExtensionCollectionRecord.version == row.version,
            )
            .execution_options(synchronize_session=False)
        )
        if changed.rowcount != 1:
            raise ExtensionStoreConflict("record version does not match")
        return True


class _AssetReadIdentityService(IdentityService):
    """Keep canonical reads from committing a denial on a second connection."""

    def authorize(
        self,
        principal: Principal,
        permission: str,
        *,
        resource: str | None = None,
        commit_denial: bool = False,
    ) -> None:
        super().authorize(
            principal, permission, resource=resource, commit_denial=commit_denial
        )


class _AssetAccess:
    """Read-only canonical inventory views, never direct asset SQL."""

    def __init__(
        self, host: ExtensionHostService, principal: Principal, session: Session
    ) -> None:
        self._host = host
        self._principal = principal
        self._session = session

    def _authorize(self) -> None:
        IdentityService(self._session, self._host._settings).authorize(
            self._principal, "assets.view", resource="extensions:assets", commit_denial=False
        )

    def get(self, asset_id: str) -> dict[str, Any]:
        from itsm.inventory.service import InventoryService

        self._authorize()

        with self._host._session_factory() as session:
            identity = _AssetReadIdentityService(session, self._host._settings)
            view = InventoryService(session, self._host._settings, identity=identity).get(
                self._principal, asset_id
            )
        return _jsonable(view.as_payload())

    def search(self, **filters: Any) -> dict[str, Any]:
        from itsm.inventory.service import InventoryService

        self._authorize()

        with self._host._session_factory() as session:
            identity = _AssetReadIdentityService(session, self._host._settings)
            page = InventoryService(session, self._host._settings, identity=identity).search(
                self._principal, **filters
            )
        return _jsonable(page.as_payload())


class _HostContext:
    """The public SDK context passed to installed handlers."""

    sdk_version = SDK_VERSION

    def __init__(
        self,
        *,
        host: ExtensionHostService,
        principal: Principal,
        session: Session,
        loaded: _LoadedModule,
        operation: str | None,
        schedule: str | None = None,
        collections: frozenset[str] | None = None,
        write_allowed: bool = True,
    ) -> None:
        self.principal = principal
        self.operation = operation
        self.schedule = schedule
        self.extension_id = loaded.extension_id
        self.version = loaded.version
        self.digest = loaded.digest
        self.manifest = loaded.manifest
        self._host = host
        self._session = session
        self._loaded = loaded
        self._write_allowed = write_allowed
        declared = (
            frozenset(item["name"] for item in loaded.manifest["collections"])
            if collections is None
            else collections
        )
        self.store = _ModuleStore(
            session,
            loaded.extension_id,
            declared,
            allow_write=write_allowed,
        )
        self.assets = _AssetAccess(host, principal, session)

    def authorize(self, permission: str) -> None:
        if not isinstance(permission, str) or not permission:
            raise ExtensionValidationFailed("permission must be non-empty text")
        IdentityService(self._session, self._host._settings).authorize(
            self.principal,
            permission,
            resource=f"extension:{self.extension_id}",
            commit_denial=False,
        )

    def notify(
        self,
        *,
        recipient_ids: Sequence[str],
        key: str,
        title: str,
        body: str,
        permission: str,
        asset_id: str | None = None,
        url: str | None = None,
    ) -> None:
        if not self._write_allowed:
            raise ExtensionValidationFailed("a read-only operation cannot notify")
        self._host.notify_from_module(
            session=self._session,
            principal=self.principal,
            loaded=self._loaded,
            recipient_ids=recipient_ids,
            key=key,
            title=title,
            body=body,
            permission=permission,
            asset_id=asset_id,
            url=url,
        )

    @contextmanager
    def transaction(self):
        """Explicit nested savepoint; the host owns the outer commit."""
        if not self._session.in_transaction():
            self._session.execute(select(1))
        nested = self._session.begin_nested()
        try:
            yield self
        except BaseException:
            nested.rollback()
            raise
        nested.commit()


class ExtensionHostService:
    """One host-owned service for installed state, candidates and dispatch."""

    def __init__(
        self,
        settings: Settings,
        session_factory: sessionmaker[Session],
        *,
        notify: NotifyCallback | None = None,
        now: Callable[[], datetime] = utcnow,
        api_prefix: str | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._notify = notify
        self._now = now
        self._api_prefix = (
            api_prefix
            if api_prefix is not None
            else getattr(settings, "api_prefix", "/api/v1")
        ).rstrip("/")
        self._cache: dict[tuple[str, str, str], _LoadedModule] = {}
        self._cache_lock = threading.Lock()
        self._module_locks: dict[str, threading.Lock] = {}
        self._module_locks_guard = threading.Lock()

    @contextmanager
    def _module_lock(self, extension_id: str):
        with self._module_locks_guard:
            lock = self._module_locks.setdefault(extension_id, threading.Lock())
        with lock:
            yield

    # ------------------------------------------------------------ authorization
    def authorize_fresh(
        self, principal: Principal, permission: str, *, resource: str
    ) -> None:
        """Authorize in a dedicated session; denial audit commits there only."""
        with self._session_factory() as session:
            IdentityService(session, self._settings).authorize(
                principal, permission, resource=resource
            )

    def _effective_permissions(
        self, session: Session, principal: Principal
    ) -> frozenset[str]:
        return IdentityService(session, self._settings).effective_permissions(principal)

    def _require_human_superadmin(self, session: Session, principal: Principal) -> Identity:
        identity = session.get(Identity, principal.actor_id)
        if not _is_human_superadmin(identity) or identity.id != principal.actor_id:
            raise PermissionDenied(
                "extension installation requires a persisted human Superadmin"
            )
        return identity

    # ---------------------------------------------------------------- loading
    def _load_module(self, version_row: ExtensionVersion) -> _LoadedModule:
        key = (version_row.extension_id, version_row.version, version_row.digest)
        with self._cache_lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        manifest = json.loads(version_row.manifest_json)
        backend_source = self._member_source(version_row.package_bytes, "backend.py")
        module = types.ModuleType(
            f"itsm_extension_{version_row.extension_id}_{version_row.digest[:12]}"
        )
        module.__file__ = f"<extension:{version_row.extension_id}:{version_row.version}>"
        try:
            code = compile(
                backend_source,
                f"<extension:{version_row.extension_id}:{version_row.version}>",
                "exec",
            )
            exec(code, module.__dict__)
            register = module.__dict__.get("register")
            if not callable(register):
                raise ExtensionImportFailed("backend.py does not export register(sdk)")
            binder = _SDKBinder(manifest)
            register(binder)
            bound = binder.finish()
        except ExtensionHostError:
            raise
        except Exception as exc:
            logger.warning(
                "extension backend registration failed for %s@%s",
                version_row.extension_id,
                version_row.version,
                exc_info=True,
            )
            raise ExtensionImportFailed("extension backend could not be registered") from exc
        loaded = _LoadedModule(
            extension_id=version_row.extension_id,
            version=version_row.version,
            digest=version_row.digest,
            manifest=manifest,
            backend_source=backend_source,
            frontend_bytes=self._member_bytes(version_row.package_bytes, "frontend.js"),
            operations=bound["operation"],
            migrations=bound["migration"],
            schedules=bound["schedule"],
        )
        with self._cache_lock:
            self._cache[key] = loaded
        return loaded

    @staticmethod
    def _member_bytes(package_bytes: bytes, name: str) -> bytes:
        try:
            with zipfile.ZipFile(BytesIO(package_bytes)) as archive:
                return archive.read(name)
        except (KeyError, zipfile.BadZipFile):
            raise ExtensionImportFailed(f"installed package is missing {name}") from None

    @staticmethod
    def _member_source(package_bytes: bytes, name: str) -> str:
        try:
            return ExtensionHostService._member_bytes(package_bytes, name).decode("utf-8")
        except UnicodeDecodeError:
            raise ExtensionImportFailed(f"installed package member is not UTF-8: {name}") from None

    def _drop_cache(self, extension_id: str) -> None:
        with self._cache_lock:
            for key in [key for key in self._cache if key[0] == extension_id]:
                self._cache.pop(key, None)

    # ------------------------------------------------------------------ views
    def _frontend_url(self, extension_id: str, digest: str) -> str:
        return (
            f"{self._api_prefix}/extensions/{quote(extension_id)}/frontend.js"
            f"?digest={quote(digest)}"
        )

    def _module_payload(
        self,
        module: ExtensionModule,
        version_row: ExtensionVersion | None,
    ) -> dict[str, Any]:
        if version_row is None:
            raise ExtensionNotFound("extension has no installed version")
        manifest = json.loads(version_row.manifest_json)
        return {
            "id": module.id,
            "manifest": manifest,
            "digest": version_row.digest,
            "enabled": module.enabled,
            "version": version_row.version,
            "schemaVersion": module.data_schema_version,
            "revision": module.revision,
            "frontendUrl": (
                self._frontend_url(module.id, version_row.digest) if module.enabled else None
            ),
            "operations": manifest["operations"],
        }

    def _event_payload(self, event: Any) -> dict[str, Any]:
        return {
            "id": event.id,
            "action": event.action,
            "actorId": event.actor_id,
            "createdAt": _iso(event.created_at),
            "detail": json.loads(event.detail_json),
        }

    def _history(self, session: Session, extension_id: str) -> list[dict[str, Any]]:
        from itsm.extensions.models import ExtensionEvent

        rows = session.execute(
            select(ExtensionEvent)
            .where(ExtensionEvent.extension_id == extension_id)
            .order_by(ExtensionEvent.id.desc())
            .limit(EVENT_LIMIT)
        ).scalars()
        return [self._event_payload(row) for row in rows]

    def _candidate_detail(
        self,
        session: Session,
        candidate: ExtensionCandidate,
    ) -> dict[str, Any]:
        manifest = json.loads(candidate.manifest_json)
        module = storage.get_module(session, candidate.extension_id)
        current_version_row = (
            storage.get_active_version(session, module) if module is not None else None
        )
        current_manifest = (
            json.loads(current_version_row.manifest_json)
            if current_version_row is not None
            else None
        )
        current_codes = (
            {item["code"] for item in current_manifest["permissions"]}
            if current_manifest is not None
            else set()
        )
        candidate_codes = {item["code"] for item in manifest["permissions"]}
        added = [
            {
                "code": item["code"],
                "label": item["label"],
                "description": item["description"],
            }
            for item in manifest["permissions"]
            if item["code"] not in current_codes
        ]
        removed = sorted(current_codes - candidate_codes)
        from_schema = module.data_schema_version if module is not None else 0
        plan = package_contract.migration_plan(
            manifest, from_schema, manifest["schemaVersion"]
        )
        report = (
            json.loads(candidate.validation_report_json)
            if candidate.validation_report_json
            else None
        )
        rollback_compatible = True
        if current_manifest is not None:
            rollback_compatible = (
                manifest["schemaVersion"]
                in current_manifest["compatibleSchemaVersions"]
            )
        return {
            "id": candidate.id,
            "extensionId": candidate.extension_id,
            "manifest": manifest,
            "version": candidate.version,
            "digest": candidate.digest,
            "state": candidate.state,
            "revision": candidate.revision,
            "submittedBy": candidate.submitted_by,
            "submittedAt": _iso(candidate.submitted_at),
            "validatedAt": _iso(candidate.validated_at),
            "approvedAt": _iso(candidate.approved_at),
            "baseVersion": candidate.base_version,
            "baseRevision": candidate.base_revision,
            "currentVersion": module.active_version if module is not None else None,
            "currentRevision": module.revision if module is not None else None,
            "validationStatus": None if report is None else report.get("status"),
            "validation": report,
            "permissionDelta": {
                "added": added,
                "removed": removed,
                "core": list(manifest["corePermissions"]),
                "grantedTo": "superadmin",
                "note": (
                    "Installation adds only the declared namespaced codes to the persisted "
                    "Superadmin role; no admin, user or machine profile is granted implicitly."
                ),
            },
            "migrationPlan": {
                "from": from_schema,
                "to": manifest["schemaVersion"],
                "required": from_schema != manifest["schemaVersion"],
                "compatible": plan is not None,
                "steps": [] if plan is None else list(plan),
            },
            "trust": {
                "model": "trusted-native",
                "sandboxed": False,
                "statement": (
                    "Approved native code runs in the host process. Validation happens in "
                    "an isolated container before review; installation is a human decision."
                ),
            },
            "rollbackCompatible": rollback_compatible,
            "history": self._history(session, candidate.extension_id),
        }

    # ---------------------------------------------------------------- discovery
    def discovery(self, principal: Principal) -> dict[str, Any]:
        with self._session_factory() as session:
            identity = session.get(Identity, principal.actor_id)
            if identity is None or not identity.active:
                return {"items": [], "sdkVersion": SDK_VERSION}
            permissions = self._effective_permissions(session, principal)
            superadmin = _is_human_superadmin(identity)
            modules = session.execute(
                select(ExtensionModule).order_by(ExtensionModule.id)
            ).scalars()
            items: list[dict[str, Any]] = []
            for module in modules:
                version_row = storage.get_active_version(session, module)
                if version_row is None:
                    continue
                manifest = json.loads(version_row.manifest_json)
                operations = [
                    item
                    for item in manifest["operations"]
                    if item["permission"] in permissions
                ]
                if not superadmin and (not module.enabled or not operations):
                    continue
                payload = self._module_payload(module, version_row)
                payload["operations"] = operations
                items.append(payload)
            return {"items": items, "sdkVersion": SDK_VERSION}

    def list_installed(self, principal: Principal) -> dict[str, Any]:
        return self.discovery(principal)

    def operations(self, principal: Principal, extension_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            module = storage.get_module(session, extension_id)
            if module is None:
                raise ExtensionNotFound("extension not found")
            if not module.enabled:
                raise ExtensionDisabled("extension is disabled")
            version_row = storage.get_active_version(session, module)
            if version_row is None:
                raise ExtensionNotFound("extension has no installed version")
            manifest = json.loads(version_row.manifest_json)
            permissions = self._effective_permissions(session, principal)
            return [
                item for item in manifest["operations"] if item["permission"] in permissions
            ]

    def frontend_script(self, principal: Principal, extension_id: str, *, digest: str) -> bytes:
        with self._session_factory() as session:
            module = storage.get_module(session, extension_id)
            if module is None:
                raise ExtensionNotFound("extension not found")
            if not module.enabled:
                raise ExtensionDisabled("extension is disabled")
            version_row = storage.get_active_version(session, module)
            if version_row is None:
                raise ExtensionNotFound("extension has no installed version")
            if not isinstance(digest, str) or not hmac.compare_digest(digest, version_row.digest):
                raise ExtensionDigestMismatch("frontend digest does not match the installed bytes")
            identity = session.get(Identity, principal.actor_id)
            permissions = self._effective_permissions(session, principal)
            manifest = json.loads(version_row.manifest_json)
            if not _is_human_superadmin(identity) and not any(
                item["permission"] in permissions for item in manifest["operations"]
            ):
                raise PermissionDenied()
            return self._member_bytes(version_row.package_bytes, "frontend.js")

    def skill(
        self, principal: Principal, extension_id: str, name: str
    ) -> dict[str, Any]:
        """Return one installed skill's bounded text; never auto-inject it."""
        with self._session_factory() as session:
            module = storage.get_module(session, extension_id)
            if module is None:
                raise ExtensionNotFound("extension not found")
            if not module.enabled:
                raise ExtensionDisabled("extension is disabled")
            version_row = storage.get_active_version(session, module)
            if version_row is None:
                raise ExtensionNotFound("extension has no installed version")
            manifest = json.loads(version_row.manifest_json)
            declaration = next(
                (item for item in manifest["skills"] if item["name"] == name),
                None,
            )
            if declaration is None:
                raise ExtensionNotFound("skill not found")
            identity = session.get(Identity, principal.actor_id)
            permissions = self._effective_permissions(session, principal)
            if not _is_human_superadmin(identity) and not any(
                item["permission"] in permissions for item in manifest["operations"]
            ):
                raise PermissionDenied()
            content = self._member_bytes(
                version_row.package_bytes, declaration["path"]
            ).decode("utf-8")
            return {
                "name": declaration["name"],
                "description": declaration["description"],
                "content": content,
                "digest": version_row.digest,
                "version": version_row.version,
            }

    def history(self, principal: Principal, extension_id: str) -> dict[str, Any]:
        """Administrator-visible lifecycle history for one extension."""
        self.authorize_fresh(
            principal, "system.modules", resource=f"extension:{extension_id}:history"
        )
        with self._session_factory() as session:
            module = storage.get_module(session, extension_id)
            if module is None:
                raise ExtensionNotFound("extension not found")
            return {
                "extensionId": extension_id,
                "items": self._history(session, extension_id),
            }

    # --------------------------------------------------------------- dispatch
    def invoke(
        self,
        principal: Principal,
        extension_id: str,
        operation: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> Any:
        if not isinstance(extension_id, str) or not extension_id:
            raise ExtensionNotFound("extension not found")
        if not isinstance(operation, str) or not operation:
            raise ExtensionNotFound("operation not found")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            raise ExtensionValidationFailed("arguments must be a JSON object")
        with self._session_factory() as session:
            module = storage.get_module(session, extension_id)
            if module is None:
                raise ExtensionNotFound("extension not found")
            if not module.enabled:
                raise ExtensionDisabled("extension is disabled")
            version_row = storage.get_active_version(session, module)
            if version_row is None:
                raise ExtensionNotFound("extension has no installed version")
            manifest = json.loads(version_row.manifest_json)
            declaration = next(
                (item for item in manifest["operations"] if item["name"] == operation),
                None,
            )
            if declaration is None:
                raise ExtensionNotFound("operation not found")
            permission = declaration["permission"]
        self.authorize_fresh(
            principal, permission, resource=f"extension:{extension_id}:{operation}"
        )
        try:
            package_contract.validate_arguments(declaration["parameters"], arguments)
        except package_contract.PackageError as exc:
            raise ExtensionValidationFailed(str(exc)) from None
        loaded = self._load_module(version_row)
        handler = loaded.operations[operation]
        session = self._session_factory()
        try:
            module = storage.get_module(session, extension_id)
            if module is None:
                raise ExtensionNotFound("extension not found")
            if not module.enabled:
                raise ExtensionDisabled("extension is disabled")
            live = storage.get_active_version(session, module)
            if live is None or live.version != version_row.version or live.digest != version_row.digest:
                raise ExtensionStale("extension changed during invocation")
            context = _HostContext(
                host=self,
                principal=principal,
                session=session,
                loaded=loaded,
                operation=operation,
                write_allowed=bool(declaration["mutation"]),
            )
            result = handler(context, **dict(arguments))
            payload = _jsonable(result)
            identity_service = IdentityService(session, self._settings)
            identity_service.record_operation(
                principal,
                action="extensions.invoke",
                resource=f"extension:{extension_id}:{operation}",
                commit=False,
            )
            session.commit()
            return payload
        except PermissionDenied:
            session.rollback()
            raise
        except ExtensionHostError:
            session.rollback()
            raise
        except Exception as exc:
            session.rollback()
            logger.warning(
                "extension operation failed for %s:%s", extension_id, operation, exc_info=True
            )
            raise ExtensionHandlerFailed("extension operation failed") from exc
        finally:
            session.close()

    def list_schedules(self) -> tuple[ScheduleView, ...]:
        with self._session_factory() as session:
            modules = session.execute(
                select(ExtensionModule)
                .where(ExtensionModule.enabled.is_(True))
                .order_by(ExtensionModule.id)
            ).scalars()
            items: list[ScheduleView] = []
            for module in modules:
                version_row = storage.get_active_version(session, module)
                if version_row is None:
                    continue
                manifest = json.loads(version_row.manifest_json)
                states = {
                    row.name: row
                    for row in session.execute(
                        select(ExtensionScheduleState).where(
                            ExtensionScheduleState.extension_id == module.id
                        )
                    ).scalars()
                }
                for schedule in manifest["schedules"]:
                    state = states.get(schedule["name"])
                    items.append(
                        ScheduleView(
                            extension_id=module.id,
                            version=version_row.version,
                            digest=version_row.digest,
                            name=schedule["name"],
                            handler=schedule["handler"],
                            interval_seconds=schedule["intervalSeconds"],
                            permission=schedule["permission"],
                            owner_id=None if state is None else state.owner_id,
                            next_due_at=(
                                None
                                if state is None or state.next_due_at is None
                                else as_utc(state.next_due_at)
                            ),
                            last_run_at=(
                                None
                                if state is None or state.last_run_at is None
                                else as_utc(state.last_run_at)
                            ),
                            last_error=None if state is None else state.last_error,
                        )
                    )
            return tuple(items)

    def invoke_schedule(
        self, principal: Principal, extension_id: str, schedule_name: str
    ) -> Any:
        """Explicit authorized smoke/force dispatch; does not move due state."""
        with self._module_lock(extension_id):
            return self._invoke_schedule_locked(principal, extension_id, schedule_name)

    def _invoke_schedule_locked(
        self, principal: Principal, extension_id: str, schedule_name: str
    ) -> Any:
        with self._session_factory() as session:
            module = storage.get_module(session, extension_id)
            if module is None:
                raise ExtensionNotFound("extension not found")
            if not module.enabled:
                raise ExtensionDisabled("extension is disabled")
            version_row = storage.get_active_version(session, module)
            if version_row is None:
                raise ExtensionNotFound("extension has no installed version")
            manifest = json.loads(version_row.manifest_json)
            declaration = next(
                (item for item in manifest["schedules"] if item["name"] == schedule_name),
                None,
            )
            if declaration is None:
                raise ExtensionNotFound("schedule not found")
            permission = declaration["permission"]
        self.authorize_fresh(
            principal, permission, resource=f"extension:{extension_id}:schedule:{schedule_name}"
        )
        loaded = self._load_module(version_row)
        handler = loaded.schedules[schedule_name]
        session = self._session_factory()
        try:
            live_module = storage.get_module(session, extension_id)
            if live_module is None or not live_module.enabled:
                raise ExtensionDisabled("extension is disabled")
            live = storage.get_active_version(session, live_module)
            if live is None or live.digest != version_row.digest:
                raise ExtensionStale("extension changed during schedule dispatch")
            context = _HostContext(
                host=self,
                principal=principal,
                session=session,
                loaded=loaded,
                operation=None,
                schedule=schedule_name,
            )
            result = handler(context)
            payload = _jsonable(result)
            IdentityService(session, self._settings).record_operation(
                principal,
                action="extensions.schedule",
                resource=f"extension:{extension_id}:schedule:{schedule_name}",
                commit=False,
            )
            session.commit()
            return payload
        except (PermissionDenied, ExtensionHostError):
            session.rollback()
            raise
        except Exception as exc:
            session.rollback()
            logger.warning(
                "extension schedule failed for %s:%s", extension_id, schedule_name, exc_info=True
            )
            raise ExtensionHandlerFailed("extension schedule failed") from exc
        finally:
            session.close()

    @staticmethod
    def _sync_schedule_states(
        session: Session,
        *,
        extension_id: str,
        manifest: Mapping[str, Any],
        owner_id: str,
        now: datetime,
    ) -> None:
        for schedule in manifest["schedules"]:
            row = session.execute(
                select(ExtensionScheduleState).where(
                    ExtensionScheduleState.extension_id == extension_id,
                    ExtensionScheduleState.name == schedule["name"],
                )
            ).scalar_one_or_none()
            if row is None:
                session.add(
                    ExtensionScheduleState(
                        extension_id=extension_id,
                        name=schedule["name"],
                        owner_id=owner_id,
                        next_due_at=now
                        + timedelta(seconds=int(schedule["intervalSeconds"])),
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                row.owner_id = owner_id
                row.updated_at = now
                if row.next_due_at is None:
                    row.next_due_at = now + timedelta(
                        seconds=int(schedule["intervalSeconds"])
                    )
        session.flush()

    def _mark_schedule_error(
        self,
        state_id: int,
        *,
        now: datetime,
        interval_seconds: int,
        message: str,
    ) -> None:
        with self._session_factory() as session:
            row = session.get(ExtensionScheduleState, state_id)
            if row is None:
                return
            row.last_error = str(message)[:500]
            retry = min(max(int(interval_seconds), 60), 300)
            row.next_due_at = now + timedelta(seconds=retry)
            row.updated_at = now
            session.commit()

    def run_due_schedules(self, now: datetime | None = None) -> dict[str, int]:
        """Claim and run due schedules; parent periodic worker calls this.

        The claim is committed before dispatch, so a crash delays one run but
        cannot duplicate it.  Failures retain a bounded error and a short retry.
        """
        current = as_utc(now) if now is not None else as_utc(self._now())
        with self._session_factory() as session:
            due = list(
                session.execute(
                    select(
                        ExtensionScheduleState.id,
                        ExtensionScheduleState.extension_id,
                        ExtensionScheduleState.name,
                        ExtensionScheduleState.next_due_at,
                    )
                    .join(
                        ExtensionModule,
                        ExtensionModule.id == ExtensionScheduleState.extension_id,
                    )
                    .where(
                        ExtensionModule.enabled.is_(True),
                        ExtensionScheduleState.next_due_at.is_not(None),
                        ExtensionScheduleState.next_due_at <= current,
                    )
                    .order_by(ExtensionScheduleState.next_due_at)
                    .limit(100)
                ).all()
            )
        counts = {"claimed": 0, "succeeded": 0, "failed": 0, "skipped": 0}
        for state_id, extension_id, name, observed_due in due:
            with self._module_lock(extension_id):
                with self._session_factory() as session:
                    row = session.get(ExtensionScheduleState, state_id)
                    module = storage.get_module(session, extension_id)
                    if row is None or module is None or not module.enabled:
                        counts["skipped"] += 1
                        continue
                    if row.next_due_at != observed_due:
                        counts["skipped"] += 1
                        continue
                    version_row = storage.get_active_version(session, module)
                    if version_row is None:
                        counts["skipped"] += 1
                        continue
                    manifest = json.loads(version_row.manifest_json)
                    declaration = next(
                        (item for item in manifest["schedules"] if item["name"] == name),
                        None,
                    )
                    if declaration is None or row.next_due_at is None:
                        counts["skipped"] += 1
                        continue
                    interval = int(declaration["intervalSeconds"])
                    owner = session.get(Identity, row.owner_id) if row.owner_id else None
                    if not _is_human_superadmin(owner):
                        self._mark_schedule_error(
                            state_id,
                            now=current,
                            interval_seconds=interval,
                            message="schedule owner is not an active human Superadmin",
                        )
                        counts["skipped"] += 1
                        continue
                    service = IdentityService(session, self._settings)
                    owner_principal = service.resolve_actor(owner.id)
                    effective = service.effective_permissions(owner_principal)
                    if declaration["permission"] not in effective:
                        self._mark_schedule_error(
                            state_id,
                            now=current,
                            interval_seconds=interval,
                            message="schedule owner no longer holds the declared permission",
                        )
                        counts["skipped"] += 1
                        continue
                    claimed = session.execute(
                        update(ExtensionScheduleState)
                        .where(
                            ExtensionScheduleState.id == state_id,
                            ExtensionScheduleState.next_due_at == observed_due,
                        )
                        .values(
                            next_due_at=current + timedelta(seconds=interval),
                            last_run_at=current,
                            last_error=None,
                            updated_at=current,
                        )
                    )
                    if claimed.rowcount != 1:
                        session.rollback()
                        counts["skipped"] += 1
                        continue
                    session.commit()
                    counts["claimed"] += 1
                try:
                    self._invoke_schedule_locked(owner_principal, extension_id, name)
                except Exception as exc:
                    counts["failed"] += 1
                    self._mark_schedule_error(
                        state_id,
                        now=current,
                        interval_seconds=interval,
                        message=f"schedule {name} failed: {exc}",
                    )
                    logger.warning(
                        "extension schedule %s:%s failed", extension_id, name, exc_info=True
                    )
                else:
                    counts["succeeded"] += 1
        return counts

    # ---------------------------------------------------------------- notifications
    def notify_from_module(
        self,
        *,
        session: Session,
        principal: Principal,
        loaded: _LoadedModule,
        recipient_ids: Sequence[str],
        key: str,
        title: str,
        body: str,
        permission: str,
        asset_id: str | None,
        url: str | None,
    ) -> None:
        if self._notify is None:
            raise ExtensionUnavailable("extension notifications are not configured")
        declared = {item["code"] for item in loaded.manifest["permissions"]}
        if permission not in declared:
            raise ExtensionValidationFailed(
                f"notification permission {permission!r} is not declared by this module"
            )
        if (
            not isinstance(recipient_ids, (list, tuple))
            or not recipient_ids
            or len(recipient_ids) > MAX_RECIPIENTS
        ):
            raise ExtensionValidationFailed("recipient_ids must be a bounded non-empty list")
        clean_ids: list[str] = []
        for value in recipient_ids:
            if not isinstance(value, str) or not value or len(value) > 64:
                raise ExtensionValidationFailed("recipient id is invalid")
            if value in clean_ids:
                continue
            clean_ids.append(value)
        if not isinstance(key, str) or not key or len(key) > 64:
            raise ExtensionValidationFailed("notification key must be 1-64 characters")
        if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-" for ch in key):
            raise ExtensionValidationFailed("notification key contains unsupported characters")
        if not isinstance(title, str) or not 1 <= len(title) <= 200:
            raise ExtensionValidationFailed("notification title must be 1-200 characters")
        if not isinstance(body, str) or not 1 <= len(body) <= 4000:
            raise ExtensionValidationFailed("notification body must be 1-4000 characters")
        if asset_id is not None and (not isinstance(asset_id, str) or len(asset_id) > 64):
            raise ExtensionValidationFailed("notification asset_id is invalid")
        if url is not None and (
            not isinstance(url, str)
            or not url.startswith(f"#/extensiones/{loaded.extension_id}/")
            or len(url) > 500
        ):
            raise ExtensionValidationFailed("notification url must point to its native extension page")
        IdentityService(session, self._settings).authorize(
            principal,
            permission,
            resource=f"extension:{loaded.extension_id}:notify",
            commit_denial=False,
        )
        if asset_id is not None:
            _AssetAccess(self, principal, session).get(asset_id)
        service = IdentityService(session, self._settings)
        authorized: list[str] = []
        for recipient_id in clean_ids:
            identity = session.get(Identity, recipient_id)
            if identity is None or not identity.active or identity.actor_kind != HUMAN_ACTOR_KIND:
                continue
            try:
                recipient = service.resolve_actor(recipient_id)
                effective = service.effective_permissions(recipient)
            except PermissionDenied:
                continue
            if "assets.view" in effective and permission in effective:
                authorized.append(recipient_id)
        if not authorized:
            return
        self._notify(
            session=session,
            principal=principal,
            module_id=loaded.extension_id,
            module_permissions=tuple(sorted(declared)),
            recipient_ids=tuple(authorized),
            key=key,
            title=title,
            body=body,
            permission=permission,
            asset_id=asset_id,
            url=url,
        )

    # --------------------------------------------------------------- candidates
    def submit_candidate(
        self,
        principal: Principal,
        package_bytes: bytes,
        *,
        expected_digest: str | None = None,
    ) -> dict[str, Any]:
        self.authorize_fresh(
            principal, "system.modules", resource="extensions:candidates"
        )
        try:
            package = package_contract.inspect_package(
                package_bytes, expected_digest=expected_digest
            )
        except package_contract.PackageError as exc:
            raise ExtensionValidationFailed(str(exc)) from None
        if len(package.package_bytes) > package_contract.MAX_ARCHIVE_BYTES:
            raise ExtensionTooLarge("package archive is too large")
        manifest = package.manifest
        version = manifest["version"]
        try:
            new_key = package_contract.version_key(version)
        except package_contract.PackageError as exc:
            raise ExtensionValidationFailed(str(exc)) from None
        candidate = ExtensionCandidate(
            id=str(uuid4()),
            extension_id=manifest["id"],
            version=version,
            digest=package.digest,
            manifest_json=json.dumps(manifest, sort_keys=True, separators=(",", ":")),
            package_bytes=package.package_bytes,
            schema_version=manifest["schemaVersion"],
            state="pending",
            revision=1,
            submitted_by=principal.actor_id,
            submitted_at=self._now(),
        )
        session = self._session_factory()
        try:
            module = storage.get_module(session, candidate.extension_id)
            if module is not None and module.active_version is not None:
                if new_key <= package_contract.version_key(module.active_version):
                    raise ExtensionConflict(
                        "candidate version must be newer than the installed version"
                    )
                candidate.base_version = module.active_version
                candidate.base_revision = module.revision
            now = self._now()
            session.execute(
                update(ExtensionCandidate)
                .where(
                    ExtensionCandidate.extension_id == candidate.extension_id,
                    ExtensionCandidate.state == "pending",
                )
                .values(
                    state="superseded",
                    revision=ExtensionCandidate.revision + 1,
                    superseded_at=now,
                )
            )
            session.add(candidate)
            session.flush()
            storage.record_event(
                session,
                extension_id=candidate.extension_id,
                action="extension.candidate.submitted",
                actor_id=principal.actor_id,
                detail={
                    "candidateId": candidate.id,
                    "version": candidate.version,
                    "digest": candidate.digest,
                    "baseVersion": candidate.base_version,
                    "baseRevision": candidate.base_revision,
                },
            )
            IdentityService(session, self._settings).record_operation(
                principal,
                action="extensions.candidate.submitted",
                resource=f"extension:{candidate.extension_id}",
                commit=False,
            )
            detail = self._candidate_detail(session, candidate)
            session.commit()
            return detail
        except IntegrityError:
            session.rollback()
            raise ExtensionConflict("candidate could not be stored") from None
        except ExtensionHostError:
            session.rollback()
            raise
        except SQLAlchemyError:
            session.rollback()
            raise
        finally:
            session.close()

    def record_validation_report(
        self,
        candidate_id: str,
        report: Mapping[str, Any],
        *,
        expected_version: int,
    ) -> dict[str, Any]:
        """Trusted internal ingestion for the fixed validator's digest-bound report."""
        if (
            isinstance(expected_version, bool)
            or not isinstance(expected_version, int)
            or expected_version < 1
        ):
            raise ExtensionValidationFailed("expected_version must be a positive integer")
        normalized = self._validate_report(report)
        session = self._session_factory()
        try:
            candidate = session.get(ExtensionCandidate, candidate_id)
            if candidate is None:
                raise ExtensionNotFound("candidate not found")
            if candidate.state != "pending":
                raise ExtensionConflict("candidate is not pending")
            if normalized["digest"] != candidate.digest:
                raise ExtensionDigestMismatch("validation report digest does not match candidate")
            if expected_version != candidate.revision:
                raise ExtensionStale("candidate changed before validation was recorded")
            candidate.validation_report_json = json.dumps(
                normalized, sort_keys=True, separators=(",", ":")
            )
            candidate.validation_digest = normalized["digest"]
            candidate.validated_at = self._now()
            candidate.revision = candidate.revision + 1
            storage.record_event(
                session,
                extension_id=candidate.extension_id,
                action="extension.candidate.validated",
                actor_id=None,
                detail={
                    "candidateId": candidate.id,
                    "version": candidate.version,
                    "digest": candidate.digest,
                    "status": normalized["status"],
                },
            )
            session.commit()
            return self._candidate_detail(session, candidate)
        except ExtensionHostError:
            session.rollback()
            raise
        except SQLAlchemyError:
            session.rollback()
            raise
        finally:
            session.close()

    @staticmethod
    def _validate_report(report: Mapping[str, Any]) -> dict[str, Any]:
        allowed = {
            "status",
            "digest",
            "sdkVersion",
            "checks",
            "errors",
            "container",
            "completedAt",
        }
        if not isinstance(report, Mapping) or set(report) != allowed:
            raise ExtensionValidationFailed(
                "validation report must contain exactly: "
                + ", ".join(sorted(allowed))
            )
        status = report["status"]
        if status not in ("passed", "failed"):
            raise ExtensionValidationFailed("validation status must be passed or failed")
        digest = report["digest"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest.lower())
        ):
            raise ExtensionValidationFailed("validation digest must be SHA-256 hex")
        if report["sdkVersion"] != SDK_VERSION:
            raise ExtensionValidationFailed("validation sdkVersion must be 1")
        checks = report["checks"]
        if not isinstance(checks, list) or len(checks) > 200:
            raise ExtensionValidationFailed("validation checks must be a bounded list")
        clean_checks: list[dict[str, str]] = []
        for item in checks:
            if not isinstance(item, Mapping) or set(item) != {"name", "status", "detail"}:
                raise ExtensionValidationFailed(
                    "validation checks must contain name, status and detail"
                )
            if not isinstance(item["name"], str) or not 1 <= len(item["name"]) <= 64:
                raise ExtensionValidationFailed("validation check name is invalid")
            if item["status"] not in ("passed", "failed", "skipped"):
                raise ExtensionValidationFailed("validation check status is invalid")
            if not isinstance(item["detail"], str) or len(item["detail"]) > 2000:
                raise ExtensionValidationFailed("validation check detail is invalid")
            clean_checks.append(
                {
                    "name": item["name"],
                    "status": item["status"],
                    "detail": item["detail"],
                }
            )
        errors = report["errors"]
        if (
            not isinstance(errors, list)
            or len(errors) > 100
            or any(not isinstance(value, str) or len(value) > 2000 for value in errors)
        ):
            raise ExtensionValidationFailed("validation errors must be bounded text")
        container = report["container"]
        if not isinstance(container, Mapping):
            raise ExtensionValidationFailed("validation container must be an object")
        try:
            container_json = _json_dumps(container, sort_keys=True)
        except ExtensionStoreValidation as exc:
            raise ExtensionValidationFailed(str(exc)) from None
        if len(container_json.encode("utf-8")) > MAX_REPORT_BYTES:
            raise ExtensionValidationFailed("validation container metadata is too large")
        _parse_timestamp(report["completedAt"], "completedAt")
        return {
            "status": status,
            "digest": digest,
            "sdkVersion": SDK_VERSION,
            "checks": clean_checks,
            "errors": list(errors),
            "container": json.loads(container_json),
            "completedAt": report["completedAt"],
        }

    def list_candidates(self, principal: Principal) -> dict[str, Any]:
        self.authorize_fresh(principal, "system.modules", resource="extensions:candidates")
        with self._session_factory() as session:
            rows = session.execute(
                select(ExtensionCandidate)
                .order_by(
                    ExtensionCandidate.submitted_at.desc(), ExtensionCandidate.id.desc()
                )
                .limit(CANDIDATE_LIMIT)
            ).scalars()
            items: list[dict[str, Any]] = []
            for row in rows:
                module = storage.get_module(session, row.extension_id)
                report = (
                    json.loads(row.validation_report_json)
                    if row.validation_report_json
                    else None
                )
                items.append(
                    {
                        "id": row.id,
                        "extensionId": row.extension_id,
                        "version": row.version,
                        "digest": row.digest,
                        "state": row.state,
                        "revision": row.revision,
                        "submittedAt": _iso(row.submitted_at),
                        "validationStatus": None if report is None else report["status"],
                        "baseVersion": row.base_version,
                        "baseRevision": row.base_revision,
                        "currentVersion": module.active_version if module is not None else None,
                        "currentRevision": module.revision if module is not None else None,
                    }
                )
            return {"items": items, "total": len(items)}

    def candidate_detail(self, principal: Principal, candidate_id: str) -> dict[str, Any]:
        self.authorize_fresh(principal, "system.modules", resource="extensions:candidates")
        with self._session_factory() as session:
            candidate = session.get(ExtensionCandidate, candidate_id)
            if candidate is None:
                raise ExtensionNotFound("candidate not found")
            return self._candidate_detail(session, candidate)

    def approve_candidate(
        self,
        principal: Principal,
        candidate_id: str,
        *,
        digest: str,
        expected_version: int | None,
    ) -> dict[str, Any]:
        self.authorize_fresh(
            principal, "system.modules", resource=f"extensions:candidate:{candidate_id}:approve"
        )
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest.lower())
        ):
            raise ExtensionDigestMismatch("digest must be a SHA-256 hex value")
        if expected_version is not None and (
            isinstance(expected_version, bool)
            or not isinstance(expected_version, int)
            or expected_version < 0
        ):
            raise ExtensionValidationFailed("expectedVersion must be an integer or null")
        session = self._session_factory()
        try:
            self._require_human_superadmin(session, principal)
            candidate = session.get(ExtensionCandidate, candidate_id)
            if candidate is None:
                raise ExtensionNotFound("candidate not found")
            if candidate.state != "pending":
                raise ExtensionConflict("candidate is not pending")
            if not hmac.compare_digest(digest.lower(), candidate.digest):
                raise ExtensionDigestMismatch("candidate digest does not match")
            if candidate.validation_report_json is None:
                raise ExtensionValidationFailed("candidate has no trusted validation report")
            report = json.loads(candidate.validation_report_json)
            if report.get("status") != "passed" or candidate.validation_digest != candidate.digest:
                raise ExtensionValidationFailed("candidate validation did not pass")
            module = storage.get_module(session, candidate.extension_id)
            current_revision = module.revision if module is not None else None
            current_version = module.active_version if module is not None else None
            if expected_version != current_revision:
                raise ExtensionStale("installed revision changed before approval")
            if candidate.base_revision != current_revision:
                raise ExtensionStale("candidate baseline revision is stale")
            if candidate.base_version != current_version:
                raise ExtensionStale("candidate baseline version is stale")
            manifest = package_contract.validate_manifest_dict(
                json.loads(candidate.manifest_json),
                known_core_permissions=PERMISSION_CODES,
            )
            if module is not None and module.active_version is not None:
                if (
                    package_contract.version_key(candidate.version)
                    <= package_contract.version_key(module.active_version)
                ):
                    raise ExtensionConflict("candidate version is not newer than installed")
            from_schema = module.data_schema_version if module is not None else 0
            to_schema = manifest["schemaVersion"]
            plan = package_contract.migration_plan(manifest, from_schema, to_schema)
            if from_schema > to_schema:
                raise ExtensionConflict("schema downgrade requires an explicit rollback")
            if plan is None:
                raise ExtensionConflict("candidate has no compatible migration path")
            now = self._now()
            previous_digest = self._current_digest(session, candidate.extension_id)
            candidate_revision = candidate.revision
            claimed = session.execute(
                update(ExtensionCandidate)
                .where(
                    ExtensionCandidate.id == candidate.id,
                    ExtensionCandidate.state == "pending",
                    ExtensionCandidate.revision == candidate_revision,
                )
                .values(
                    state="installing",
                    revision=candidate_revision + 1,
                    approved_by=principal.actor_id,
                    approved_at=now,
                )
                .execution_options(synchronize_session=False)
            )
            if claimed.rowcount != 1:
                raise ExtensionStale("candidate changed before approval")
            if module is None:
                module = ExtensionModule(
                    id=candidate.extension_id,
                    name=manifest["name"],
                    description=manifest["description"],
                    enabled=True,
                    active_version=candidate.version,
                    data_schema_version=manifest["schemaVersion"],
                    revision=1,
                    created_at=now,
                    updated_at=now,
                )
                session.add(module)
                session.flush()
                installed_revision = 1
            else:
                installed_revision = current_revision + 1
                claimed_module = session.execute(
                    update(ExtensionModule)
                    .where(
                        ExtensionModule.id == module.id,
                        ExtensionModule.revision == current_revision,
                    )
                    .values(revision=installed_revision, updated_at=now)
                    .execution_options(synchronize_session=False)
                )
                if claimed_module.rowcount != 1:
                    raise ExtensionStale("installed version changed before approval")
            for permission in manifest["permissions"]:
                storage.register_extension_permission(
                    session,
                    extension_id=candidate.extension_id,
                    code=permission["code"],
                    label=permission["label"],
                    description=permission["description"],
                )
            IdentityService(session, self._settings).grant_extension_permissions(
                principal,
                role_id=ROLE_SUPERADMIN,
                permissions=[item["code"] for item in manifest["permissions"]],
                resource=f"extension:{candidate.extension_id}",
            )
            self._require_human_superadmin(session, principal)
            loaded = self._load_module_from_candidate(candidate)
            context = _HostContext(
                host=self,
                principal=principal,
                session=session,
                loaded=loaded,
                operation=None,
                collections=frozenset(
                    {
                        *[
                            item["name"]
                            for item in manifest["collections"]
                        ],
                        *self._current_collection_names(session, candidate.extension_id),
                    }
                ),
            )
            for step in plan:
                handler = loaded.migrations[step["handler"]]
                try:
                    handler(context)
                except Exception as exc:
                    raise ExtensionMigrationFailed(
                        f"migration {step['handler']} failed; previous version retained"
                    ) from exc
                session.add(
                    ExtensionMigration(
                        extension_id=candidate.extension_id,
                        package_version=candidate.version,
                        from_schema=step["from"],
                        to_schema=step["to"],
                        applied_at=now,
                        applied_by=principal.actor_id,
                    )
                )
            version_row = ExtensionVersion(
                extension_id=candidate.extension_id,
                version=candidate.version,
                digest=candidate.digest,
                manifest_json=candidate.manifest_json,
                package_bytes=candidate.package_bytes,
                schema_version=manifest["schemaVersion"],
                installed_by=principal.actor_id,
                installed_at=now,
            )
            session.add(version_row)
            session.flush()
            updated = session.execute(
                update(ExtensionModule)
                .where(
                    ExtensionModule.id == module.id,
                    ExtensionModule.revision == installed_revision,
                )
                .values(
                    name=manifest["name"],
                    description=manifest["description"],
                    active_version=candidate.version,
                    data_schema_version=manifest["schemaVersion"],
                    updated_at=now,
                )
                .execution_options(synchronize_session=False)
            )
            if updated.rowcount != 1:
                raise ExtensionStale("installed version changed before approval")
            installed = session.execute(
                update(ExtensionCandidate)
                .where(
                    ExtensionCandidate.id == candidate.id,
                    ExtensionCandidate.state == "installing",
                )
                .values(state="installed", revision=candidate_revision + 2)
                .execution_options(synchronize_session=False)
            )
            if installed.rowcount != 1:
                raise ExtensionStale("candidate changed during approval")
            self._sync_schedule_states(
                session,
                extension_id=candidate.extension_id,
                manifest=manifest,
                owner_id=principal.actor_id,
                now=now,
            )
            storage.record_event(
                session,
                extension_id=candidate.extension_id,
                action="extension.installed",
                actor_id=principal.actor_id,
                detail={
                    "version": candidate.version,
                    "digest": candidate.digest,
                    "schemaVersion": manifest["schemaVersion"],
                    "fromVersion": current_version,
                    "fromDigest": previous_digest,
                    "fromSchemaVersion": from_schema,
                    "enabled": module.enabled if module is not None else False,
                    "revision": installed_revision,
                    "permissions": [item["code"] for item in manifest["permissions"]],
                    "migrations": [
                        {"from": step["from"], "to": step["to"], "handler": step["handler"]}
                        for step in plan
                    ],
                },
            )
            IdentityService(session, self._settings).record_operation(
                principal,
                action="extensions.installed",
                resource=f"extension:{candidate.extension_id}",
                commit=False,
            )
            session.commit()
            self._drop_cache(candidate.extension_id)
            session.expire_all()
            refreshed = session.get(ExtensionCandidate, candidate.id)
            return self._candidate_detail(session, refreshed) if refreshed else {}
        except (PermissionDenied, ExtensionHostError):
            session.rollback()
            raise
        except IntegrityError:
            session.rollback()
            raise ExtensionConflict("candidate installation conflicted with stored state") from None
        except SQLAlchemyError:
            session.rollback()
            raise
        finally:
            session.close()

    def _load_module_from_candidate(self, candidate: ExtensionCandidate) -> _LoadedModule:
        version_row = ExtensionVersion(
            extension_id=candidate.extension_id,
            version=candidate.version,
            digest=candidate.digest,
            manifest_json=candidate.manifest_json,
            package_bytes=candidate.package_bytes,
            schema_version=candidate.schema_version,
        )
        return self._load_module(version_row)

    def _current_collection_names(self, session: Session, extension_id: str) -> set[str]:
        module = storage.get_module(session, extension_id)
        version_row = storage.get_active_version(session, module) if module is not None else None
        if version_row is None:
            return set()
        return {item["name"] for item in json.loads(version_row.manifest_json)["collections"]}

    def _current_digest(self, session: Session, extension_id: str) -> str | None:
        module = storage.get_module(session, extension_id)
        version_row = storage.get_active_version(session, module) if module is not None else None
        return None if version_row is None else version_row.digest

    # ------------------------------------------------------------- enablement
    def set_enabled(
        self,
        principal: Principal,
        extension_id: str,
        *,
        enabled: bool,
        expected_version: int,
    ) -> dict[str, Any]:
        self.authorize_fresh(
            principal, "system.modules", resource=f"extension:{extension_id}:enabled"
        )
        if not isinstance(enabled, bool):
            raise ExtensionValidationFailed("enabled must be a boolean")
        if (
            isinstance(expected_version, bool)
            or not isinstance(expected_version, int)
            or expected_version < 0
        ):
            raise ExtensionValidationFailed("expectedVersion must be a non-negative integer")
        session = self._session_factory()
        try:
            self._require_human_superadmin(session, principal)
            module = storage.get_module(session, extension_id)
            if module is None:
                raise ExtensionNotFound("extension not found")
            version_row = storage.get_active_version(session, module)
            if version_row is None:
                raise ExtensionNotFound("extension has no installed version")
            if module.revision != expected_version:
                raise ExtensionStale("installed revision changed")
            result = session.execute(
                update(ExtensionModule)
                .where(
                    ExtensionModule.id == module.id,
                    ExtensionModule.revision == module.revision,
                )
                .values(enabled=enabled, revision=module.revision + 1, updated_at=self._now())
            )
            if result.rowcount != 1:
                raise ExtensionStale("installed revision changed")
            storage.record_event(
                session,
                extension_id=extension_id,
                action="extension.enabled" if enabled else "extension.disabled",
                actor_id=principal.actor_id,
                detail={
                    "version": version_row.version,
                    "digest": version_row.digest,
                    "enabled": enabled,
                },
            )
            IdentityService(session, self._settings).record_operation(
                principal,
                action="extensions.enabled" if enabled else "extensions.disabled",
                resource=f"extension:{extension_id}",
                commit=False,
            )
            session.commit()
            self._drop_cache(extension_id)
            session.expire_all()
            refreshed = session.get(ExtensionModule, extension_id)
            return self._module_payload(refreshed, version_row) if refreshed else {}
        except (PermissionDenied, ExtensionHostError):
            session.rollback()
            raise
        except SQLAlchemyError:
            session.rollback()
            raise
        finally:
            session.close()

    def rollback(
        self,
        principal: Principal,
        extension_id: str,
        *,
        version: str,
        digest: str,
        expected_version: int,
    ) -> dict[str, Any]:
        self.authorize_fresh(
            principal, "system.modules", resource=f"extension:{extension_id}:rollback"
        )
        if not isinstance(version, str) or not version:
            raise ExtensionValidationFailed("version is required")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest.lower())
        ):
            raise ExtensionValidationFailed("digest must be SHA-256 hex")
        if (
            isinstance(expected_version, bool)
            or not isinstance(expected_version, int)
            or expected_version < 0
        ):
            raise ExtensionValidationFailed("expectedVersion must be a non-negative integer")
        session = self._session_factory()
        try:
            self._require_human_superadmin(session, principal)
            module = storage.get_module(session, extension_id)
            if module is None:
                raise ExtensionNotFound("extension not found")
            if module.revision != expected_version:
                raise ExtensionStale("installed revision changed")
            target = storage.get_version(session, extension_id, version)
            if target is None:
                raise ExtensionNotFound("rollback target version is not installed")
            if not hmac.compare_digest(target.digest, digest.lower()):
                raise ExtensionDigestMismatch("rollback target digest does not match")
            current = storage.get_active_version(session, module)
            if current is None:
                raise ExtensionNotFound("extension has no installed version")
            if target.version == current.version:
                raise ExtensionConflict("rollback target is already active")
            if package_contract.version_key(target.version) >= package_contract.version_key(
                current.version
            ):
                raise ExtensionConflict("rollback target must be older than the active version")
            target_manifest = json.loads(target.manifest_json)
            data_schema = module.data_schema_version
            if data_schema is None:
                raise ExtensionConflict("extension has no data schema version")
            if data_schema not in target_manifest["compatibleSchemaVersions"]:
                raise ExtensionRollbackIncompatible(
                    "active data schema is not compatible with the rollback target"
                )
            updated = session.execute(
                update(ExtensionModule)
                .where(
                    ExtensionModule.id == module.id,
                    ExtensionModule.revision == module.revision,
                )
                .values(active_version=target.version, revision=module.revision + 1, updated_at=self._now())
            )
            if updated.rowcount != 1:
                raise ExtensionStale("installed revision changed")
            self._sync_schedule_states(
                session,
                extension_id=extension_id,
                manifest=target_manifest,
                owner_id=principal.actor_id,
                now=self._now(),
            )
            storage.record_event(
                session,
                extension_id=extension_id,
                action="extension.rolled_back",
                actor_id=principal.actor_id,
                detail={
                    "version": target.version,
                    "digest": target.digest,
                    "schemaVersion": target_manifest["schemaVersion"],
                    "fromVersion": current.version,
                    "fromDigest": current.digest,
                    "targetSchemaVersion": target_manifest["schemaVersion"],
                    "dataSchemaVersion": data_schema,
                    "compatibleSchemaVersions": list(
                        target_manifest["compatibleSchemaVersions"]
                    ),
                },
            )
            IdentityService(session, self._settings).record_operation(
                principal,
                action="extensions.rolled_back",
                resource=f"extension:{extension_id}",
                commit=False,
            )
            session.commit()
            self._drop_cache(extension_id)
            session.expire_all()
            refreshed = session.get(ExtensionModule, extension_id)
            return self._module_payload(refreshed, target) if refreshed else {}
        except (PermissionDenied, ExtensionHostError):
            session.rollback()
            raise
        except SQLAlchemyError:
            session.rollback()
            raise
        finally:
            session.close()


def submit_workspace_candidate(
    host: ExtensionHostService,
    principal: Principal,
    package_bytes: bytes,
    digest: str,
) -> dict[str, Any]:
    """T3 workspace entry point: create a pending candidate, never install."""
    return host.submit_candidate(principal, package_bytes, expected_digest=digest)
