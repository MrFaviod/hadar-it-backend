"""Host-owned lifecycle, storage, migrations and dispatch for native extensions.

Trust boundary (SDK v2): a sandboxed module never runs in this process.  Every
invocation is a fresh ``python -E -s -S -B runner.py`` process restricted by
rlimits, ``no_new_privs``, Landlock and a seccomp deny-list, speaking JSON-lines
over its standard streams.  Declarative modules never carry executable code at
all: the host runs their list/get/put/delete operations against the module's own
SQLite collections.  Module business data lives in
``<extension_data_path>/<id>/data.sqlite3``; the core database keeps only host
metadata plus the ``extension_core_calls`` idempotency ledger for authorized
capability mutations.  Every installation, upgrade and uninstall is an explicit
persisted-human-Superadmin action.
"""

from __future__ import annotations

import hmac
import json
import logging
import sqlite3
import threading
import zipfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from itsm.config import Settings
from itsm.extensions import manifest as package_contract
from itsm.extensions import sandbox, storage
from itsm.extensions.capabilities import CapabilityBroker
from itsm.extensions.models import (
    ExtensionCandidate,
    ExtensionCollectionRecord,
    ExtensionEvent,
    ExtensionMigration,
    ExtensionModule,
    ExtensionPermission,
    ExtensionScheduleState,
    ExtensionVersion,
)
from itsm.extensions.runtime import sqlite_store
from itsm.extensions.sdk import contract as sdk_contract
from itsm.identity.clock import as_utc, utcnow
from itsm.identity.models import Identity, IdentityRolePolicy
from itsm.identity.permissions import (
    HUMAN_ACTOR_KIND,
    PERMISSION_CODES,
    ROLE_SUPERADMIN,
)
from itsm.identity.service import IdentityService, PermissionDenied, Principal

logger = logging.getLogger(__name__)

SDK_VERSION = 2
CANDIDATE_LIMIT = 200
EVENT_LIMIT = 100
MAX_COLLECTION_DATA_BYTES = 256 * 1024
MAX_RECIPIENTS = 100
MAX_REPORT_BYTES = 32 * 1024
_CANDIDATE_STATES = frozenset({"pending", "installing", "installed", "superseded"})

NotifyCallback = Callable[..., None]


from itsm.extensions.errors import (  # noqa: E402 - re-exported host contract
    ExtensionConflict,
    ExtensionDigestMismatch,
    ExtensionDisabled,
    ExtensionHandlerFailed,
    ExtensionHostError,
    ExtensionIdempotencyConflict,
    ExtensionImportFailed,
    ExtensionMigrationFailed,
    ExtensionNotFound,
    ExtensionRequiresUpgrade,
    ExtensionRollbackIncompatible,
    ExtensionSandboxUnavailable,
    ExtensionStale,
    ExtensionStoreConflict,
    ExtensionStoreValidation,
    ExtensionTooLarge,
    ExtensionUnavailable,
    ExtensionValidationFailed,
)

_SNAPSHOT_REVISION_LABEL = "data schema version"


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
    """Admitted module metadata; never executable code in this process."""

    extension_id: str
    version: str
    digest: str
    manifest: Mapping[str, Any]
    runtime: str
    package_bytes: bytes
    frontend_bytes: bytes
    operations: Mapping[str, Mapping[str, Any]]
    migrations: Mapping[str, Mapping[str, Any]]
    schedules: Mapping[str, Mapping[str, Any]]

    @property
    def collections(self) -> frozenset[str]:
        return frozenset(item["name"] for item in self.manifest["collections"])


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


def _legacy_equal(current: Any, stored_json: str) -> bool:
    """Compare a module row's data with the legacy JSON without reordering."""
    try:
        return _jsonable(current) == _jsonable(json.loads(stored_json))
    except TypeError, ValueError:
        return False


def sandbox_availability() -> dict[str, Any]:
    """Report whether this host kernel can execute sandboxed modules at all.

    Declarative modules never need it; a sandboxed module on an unsupported
    kernel fails closed instead of running unsupervised in the host process.
    """
    return sandbox.sandbox_availability()


def _module_status(module: ExtensionModule, manifest: Mapping[str, Any]) -> str:
    """The single status vocabulary shared by discovery and ``GET /status``."""
    if manifest.get("sdkVersion") != SDK_VERSION:
        return "requires_upgrade"
    return "ready" if module.enabled else "disabled"


def _collection_schema(manifest: Mapping[str, Any], collection: str) -> Mapping[str, Any] | None:
    for item in manifest["collections"]:
        if item["name"] == collection:
            return item.get("schema")
    raise ExtensionValidationFailed(f"collection {collection!r} is not declared")


def _declarative_filters(schema: Mapping[str, Any] | None, filters: Any) -> dict[str, Any] | None:
    if filters is None:
        return None
    if not isinstance(filters, Mapping):
        raise ExtensionStoreValidation("filters must be an object")
    declared = set((schema or {}).get("properties") or {})
    if declared:
        unknown = sorted(set(filters) - declared)
        if unknown:
            raise ExtensionStoreValidation("filter on undeclared field: " + ", ".join(unknown[:8]))
    return dict(filters)


def _validate_record(
    collection: str, schema: Mapping[str, Any] | None, data: Any
) -> dict[str, Any]:
    if not isinstance(data, Mapping):
        raise ExtensionStoreValidation("data must be an object")
    try:
        return sdk_contract.validate_collection_value(collection, schema, dict(data))
    except sdk_contract.CollectionError as exc:
        raise ExtensionStoreValidation(str(exc) or "invalid record") from None


@contextmanager
def _store_errors() -> Iterator[None]:
    """Translate stdlib store refusals into the host's public error types."""
    try:
        yield
    except sqlite_store.StoreConflict as exc:
        raise ExtensionStoreConflict(str(exc) or "record version conflict") from None
    except (sqlite_store.StoreValidation, sqlite_store.ModuleError) as exc:
        raise ExtensionStoreValidation(str(exc) or "invalid store request") from None


class _ModuleStore:
    """The module's own collections inside ``<root>/<id>/data.sqlite3``.

    Semantics match the v1 in-core store exactly (get/list/put/delete, CAS via
    ``expected_version``, bounded page and filter shapes) so an upgraded module
    keeps the same programming contract; only the location changed.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        extension_id: str,
        collections: frozenset[str],
        *,
        allow_write: bool,
    ) -> None:
        self._connection = connection
        self._extension_id = extension_id
        self._collections = collections
        self._allow_write = allow_write

    @property
    def connection(self) -> sqlite3.Connection:
        return self._connection

    def _require_write(self) -> None:
        if not self._allow_write:
            raise ExtensionStoreValidation("store is read-only for this invocation")

    def _collection(self, name: Any) -> str:
        if not isinstance(name, str) or not name:
            raise ExtensionStoreValidation("collection name must be text")
        if self._collections and name not in self._collections:
            raise ExtensionStoreValidation(f"collection {name!r} is not declared by the manifest")
        return name

    def _begin(self) -> None:
        if not self._connection.in_transaction:
            self._connection.execute("BEGIN IMMEDIATE")

    def get(self, collection: Any, record_id: Any) -> dict[str, Any] | None:
        with _store_errors():
            return sqlite_store.get(self._connection, self._collection(collection), record_id)

    def list(
        self,
        collection: Any,
        limit: Any = 50,
        offset: Any = 0,
        filters: Any = None,
    ) -> dict[str, Any]:
        with _store_errors():
            return sqlite_store.list_records(
                self._connection,
                self._collection(collection),
                limit=limit,
                offset=offset,
                filters=filters,
            )

    def put(
        self,
        collection: Any,
        record_id: Any,
        data: Any,
        expected_version: Any = None,
    ) -> dict[str, Any]:
        self._require_write()
        with _store_errors():
            name = self._collection(collection)
            self._begin()
            return sqlite_store.put(self._connection, name, record_id, data, expected_version)

    def delete(
        self,
        collection: Any,
        record_id: Any,
        expected_version: Any = None,
    ) -> bool:
        self._require_write()
        with _store_errors():
            name = self._collection(collection)
            self._begin()
            return sqlite_store.delete(self._connection, name, record_id, expected_version)

    def commit(self) -> None:
        if self._connection.in_transaction:
            self._connection.commit()

    def rollback(self) -> None:
        if self._connection.in_transaction:
            self._connection.rollback()

    def close(self) -> None:
        self.rollback()
        self._connection.close()


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
        super().authorize(principal, permission, resource=resource, commit_denial=commit_denial)


class _AssetAccess:
    """Read-only canonical inventory views, never direct asset SQL."""

    def __init__(self, host: ExtensionHostService, principal: Principal, session: Session) -> None:
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
        sandbox_limits: sandbox.SandboxLimits | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._notify = notify
        self._now = now
        self._sandbox_limits = sandbox_limits or sandbox.SandboxLimits()
        self._api_prefix = (
            api_prefix if api_prefix is not None else getattr(settings, "api_prefix", "/api/v1")
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
    def authorize_fresh(self, principal: Principal, permission: str, *, resource: str) -> None:
        """Authorize in a dedicated session; denial audit commits there only."""
        with self._session_factory() as session:
            IdentityService(session, self._settings).authorize(
                principal, permission, resource=resource
            )

    def _effective_permissions(self, session: Session, principal: Principal) -> frozenset[str]:
        return IdentityService(session, self._settings).effective_permissions(principal)

    def _require_human_superadmin(self, session: Session, principal: Principal) -> Identity:
        identity = session.get(Identity, principal.actor_id)
        if not _is_human_superadmin(identity) or identity.id != principal.actor_id:
            raise PermissionDenied("extension installation requires a persisted human Superadmin")
        return identity

    # ---------------------------------------------------------------- loading
    def _load_module(self, version_row: ExtensionVersion) -> _LoadedModule:
        """Admit one installed version; module code is never imported here."""
        key = (version_row.extension_id, version_row.version, version_row.digest)
        with self._cache_lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        manifest = json.loads(version_row.manifest_json)
        sdk_version = manifest.get("sdkVersion")
        if sdk_version != SDK_VERSION:
            raise ExtensionRequiresUpgrade(
                f"extension {version_row.extension_id}@{version_row.version} is an SDK "
                f"{sdk_version} package; the SDK v2 runtime never executes it. Rebuild the "
                "module against SDK v2, then copy its legacy collection rows with "
                "`python -m itsm.extensions relocate-legacy --apply`."
            )
        runtime = manifest["runtime"]
        if runtime == "sandboxed":
            backend_source = self._member_source(version_row.package_bytes, "backend.py")
            if not backend_source.strip():  # pragma: no cover - admission already checks
                raise ExtensionImportFailed("backend.py is empty")
        loaded = _LoadedModule(
            extension_id=version_row.extension_id,
            version=version_row.version,
            digest=version_row.digest,
            manifest=manifest,
            runtime=runtime,
            package_bytes=version_row.package_bytes,
            frontend_bytes=(
                self._member_bytes(version_row.package_bytes, "frontend.js")
                if manifest["frontend"].get("entry")
                else b""
            ),
            operations={item["name"]: item for item in manifest["operations"]},
            migrations={item["handler"]: item for item in manifest["migrations"]},
            schedules={item["name"]: item for item in manifest["schedules"]},
        )
        with self._cache_lock:
            self._cache[key] = loaded
        return loaded

    @staticmethod
    def _member_bytes(package_bytes: bytes, name: str) -> bytes:
        try:
            with zipfile.ZipFile(BytesIO(package_bytes)) as archive:
                return archive.read(name)
        except KeyError, zipfile.BadZipFile:
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
        runtime = manifest.get("runtime", "sandboxed")
        return {
            "id": module.id,
            "manifest": manifest,
            "digest": version_row.digest,
            "enabled": module.enabled,
            "version": version_row.version,
            "schemaVersion": module.data_schema_version,
            "revision": module.revision,
            "runtime": runtime,
            "status": _module_status(module, manifest),
            "sandboxed": runtime == "sandboxed",
            "frontendUrl": (
                self._frontend_url(module.id, version_row.digest)
                if module.enabled and manifest["frontend"].get("entry")
                else None
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
        plan = package_contract.migration_plan(manifest, from_schema, manifest["schemaVersion"])
        report = (
            json.loads(candidate.validation_report_json)
            if candidate.validation_report_json
            else None
        )
        rollback_compatible = True
        if current_manifest is not None:
            rollback_compatible = (
                manifest["schemaVersion"] in current_manifest["compatibleSchemaVersions"]
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
                "model": (
                    "sandboxed-isolation"
                    if manifest.get("runtime") == "sandboxed"
                    else "declarative-host-executed"
                ),
                "sandboxed": manifest.get("runtime") == "sandboxed",
                "runtime": manifest.get("runtime"),
                "statement": (
                    "Sandboxed code never runs in the API or worker process: each call is a "
                    "separate process restricted by rlimits, no_new_privs, Landlock and a "
                    "seccomp deny-list, and every core effect goes through an authorized "
                    "host capability. Declarative modules carry no executable code at all."
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
                    item for item in manifest["operations"] if item["permission"] in permissions
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
            return [item for item in manifest["operations"] if item["permission"] in permissions]

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

    def skill(self, principal: Principal, extension_id: str, name: str) -> dict[str, Any]:
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
            content = self._member_bytes(version_row.package_bytes, declaration["path"]).decode(
                "utf-8"
            )
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
        loaded = self._load_module(version_row)
        self.authorize_fresh(
            principal, permission, resource=f"extension:{extension_id}:{operation}"
        )
        try:
            package_contract.validate_arguments(declaration["parameters"], arguments)
        except package_contract.PackageError as exc:
            raise ExtensionValidationFailed(str(exc)) from None
        with self._module_lock(extension_id):
            self._recheck_installed(
                principal,
                extension_id,
                version_row,
                permission,
                f"extension:{extension_id}:{operation}",
            )
            if loaded.runtime == "declarative":
                result = self._invoke_declarative(
                    loaded, loaded.operations[operation], dict(arguments)
                )
            else:
                result = self._invoke_sandboxed(
                    principal,
                    loaded,
                    kind="operation",
                    name=operation,
                    arguments=dict(arguments),
                    allow_write=bool(declaration["mutation"]),
                )
        self._record_invocation(
            principal, action="extensions.invoke", resource=f"extension:{extension_id}:{operation}"
        )
        return _jsonable(result)

    def _recheck_installed(
        self,
        principal: Principal,
        extension_id: str,
        version_row: ExtensionVersion,
        permission: str,
        resource: str,
    ) -> None:
        """Second check after loading: the installed digest and grant still hold."""
        with self._session_factory() as session:
            module = storage.get_module(session, extension_id)
            if module is None:
                raise ExtensionNotFound("extension not found")
            if not module.enabled:
                raise ExtensionDisabled("extension is disabled")
            live = storage.get_active_version(session, module)
            if (
                live is None
                or live.version != version_row.version
                or live.digest != version_row.digest
            ):
                raise ExtensionStale("extension changed during invocation")
            IdentityService(session, self._settings).authorize(
                principal, permission, resource=resource, commit_denial=False
            )

    def _record_invocation(self, principal: Principal, *, action: str, resource: str) -> None:
        with self._session_factory() as session:
            IdentityService(session, self._settings).record_operation(
                principal, action=action, resource=resource
            )

    # ------------------------------------------------------------------ storage
    def storage_root(self) -> Path:
        return Path(self._settings.extension_data_path)

    def module_dir(self, extension_id: str) -> Path:
        return sqlite_store.data_dir(self.storage_root(), extension_id)

    def _prepare_storage(self, extension_id: str) -> Path:
        return sqlite_store.prepare(self.storage_root(), extension_id)

    def _connect(self, extension_id: str) -> sqlite3.Connection:
        return sqlite_store.connect(self.storage_root(), extension_id)

    def _store(
        self,
        connection: sqlite3.Connection,
        loaded: _LoadedModule,
        *,
        allow_write: bool,
    ) -> _ModuleStore:
        return _ModuleStore(
            connection, loaded.extension_id, loaded.collections, allow_write=allow_write
        )

    # -------------------------------------------------------- declarative runtime
    def _invoke_declarative(
        self,
        loaded: _LoadedModule,
        declaration: Mapping[str, Any],
        arguments: Mapping[str, Any],
    ) -> Any:
        kind = declaration["kind"]
        collection = declaration["collection"]
        schema = _collection_schema(loaded.manifest, collection)
        allowed = sdk_contract.DECLARATIVE_ARGUMENTS[kind][0]
        extra = sorted(set(arguments) - allowed)
        if extra:
            raise ExtensionValidationFailed("unsupported argument: " + ", ".join(extra[:8]))
        connection = self._connect(loaded.extension_id)
        store = self._store(connection, loaded, allow_write=True)
        try:
            result = self._declarative_result(store, kind, collection, schema, arguments)
        except BaseException:
            store.rollback()
            raise
        else:
            store.commit()
            return result
        finally:
            store.close()

    def _declarative_result(
        self,
        store: _ModuleStore,
        kind: str,
        collection: str,
        schema: Mapping[str, Any] | None,
        arguments: Mapping[str, Any],
    ) -> Any:
        if kind == "list":
            return store.list(
                collection,
                limit=arguments.get("limit", 50),
                offset=arguments.get("offset", 0),
                filters=_declarative_filters(schema, arguments.get("filters")),
            )
        if kind == "get":
            return store.get(collection, arguments.get("record_id"))
        if kind == "put":
            data = _validate_record(collection, schema, arguments.get("data"))
            record_id = arguments.get("record_id") or str(uuid4())
            return store.put(collection, record_id, data, arguments.get("expected_version"))
        if kind == "delete":
            deleted = store.delete(
                collection, arguments.get("record_id"), arguments.get("expected_version")
            )
            return {"deleted": deleted}
        raise ExtensionValidationFailed(f"unsupported declarative kind {kind}")

    # ----------------------------------------------------------- sandboxed runtime
    def _invoke_sandboxed(
        self,
        principal: Principal,
        loaded: _LoadedModule,
        *,
        kind: str,
        name: str,
        arguments: Mapping[str, Any],
        allow_write: bool,
        event: Mapping[str, Any] | None = None,
    ) -> Any:
        availability = sandbox_availability()
        if not availability.get("available"):
            raise ExtensionSandboxUnavailable(
                str(availability.get("detail") or "sandbox unavailable")
            )
        self._prepare_storage(loaded.extension_id)
        sandbox.prepare_package(self._settings, loaded.digest, loaded.package_bytes)
        connection = self._connect(loaded.extension_id)
        store = self._store(connection, loaded, allow_write=allow_write)
        broker = CapabilityBroker(
            host=self,
            principal=principal,
            loaded=loaded,
            store=store,
            allow_write=allow_write,
        )
        request = {
            "kind": kind,
            "name": name,
            "arguments": dict(arguments),
            "context": {
                "principal": _jsonable(principal),
                "extensionId": loaded.extension_id,
                "version": loaded.version,
                "operation": name if kind == "operation" else None,
                "schedule": name if kind == "schedule" else None,
                "event": None if event is None else _jsonable(event),
            },
        }
        try:
            result = sandbox.run_module(
                settings=self._settings,
                limits=self._sandbox_limits,
                digest=loaded.digest,
                package_bytes=loaded.package_bytes,
                data_dir=str(self.module_dir(loaded.extension_id)),
                request=request,
                declared={
                    "operations": sorted(loaded.operations),
                    "migrations": sorted(loaded.migrations),
                    "schedules": sorted(item["handler"] for item in loaded.schedules.values()),
                },
                handle_call=broker.handle,
            )
        except BaseException:
            store.rollback()
            raise
        else:
            store.commit()
            return result
        finally:
            store.close()

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

    def invoke_schedule(self, principal: Principal, extension_id: str, schedule_name: str) -> Any:
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
        loaded = self._load_module(version_row)
        self.authorize_fresh(
            principal, permission, resource=f"extension:{extension_id}:schedule:{schedule_name}"
        )
        try:
            self._recheck_installed(
                principal,
                extension_id,
                version_row,
                permission,
                f"extension:{extension_id}:schedule:{schedule_name}",
            )
            if loaded.runtime == "declarative":
                raise ExtensionValidationFailed("declarative modules cannot declare schedules")
            result = self._invoke_sandboxed(
                principal,
                loaded,
                kind="schedule",
                name=declaration["handler"],
                arguments={},
                allow_write=True,
            )
        except PermissionDenied, ExtensionHostError:
            raise
        except Exception as exc:
            logger.warning(
                "extension schedule failed for %s:%s", extension_id, schedule_name, exc_info=True
            )
            raise ExtensionHandlerFailed("extension schedule failed") from exc
        self._record_invocation(
            principal,
            action="extensions.schedule",
            resource=f"extension:{extension_id}:schedule:{schedule_name}",
        )
        return _jsonable(result)

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
                        next_due_at=now + timedelta(seconds=int(schedule["intervalSeconds"])),
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                row.owner_id = owner_id
                row.updated_at = now
                if row.next_due_at is None:
                    row.next_due_at = now + timedelta(seconds=int(schedule["intervalSeconds"]))
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
        if any(
            ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
            for ch in key
        ):
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
            raise ExtensionValidationFailed(
                "notification url must point to its native extension page"
            )
        with self._session_factory() as session:
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
                if (
                    identity is None
                    or not identity.active
                    or identity.actor_kind != HUMAN_ACTOR_KIND
                ):
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
            # The notice session belongs to the host, so the terminal effect is
            # committed here; the enqueue helper deliberately never commits.
            session.commit()

    # --------------------------------------------------------------- candidates
    def submit_candidate(
        self,
        principal: Principal,
        package_bytes: bytes,
        *,
        expected_digest: str | None = None,
    ) -> dict[str, Any]:
        self.authorize_fresh(principal, "system.modules", resource="extensions:candidates")
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
                "validation report must contain exactly: " + ", ".join(sorted(allowed))
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
            raise ExtensionValidationFailed(f"validation sdkVersion must be {SDK_VERSION}")
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
                .order_by(ExtensionCandidate.submitted_at.desc(), ExtensionCandidate.id.desc())
                .limit(CANDIDATE_LIMIT)
            ).scalars()
            items: list[dict[str, Any]] = []
            for row in rows:
                module = storage.get_module(session, row.extension_id)
                report = (
                    json.loads(row.validation_report_json) if row.validation_report_json else None
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
            if (
                module is not None
                and module.active_version is not None
                and package_contract.version_key(candidate.version)
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
            is_upgrade = current_version is not None
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
            self._prepare_storage(candidate.extension_id)
            # D4: extract the reviewed package once, read-only, per digest.
            try:
                sandbox.prepare_package(self._settings, candidate.digest, candidate.package_bytes)
            except (ExtensionValidationFailed, OSError) as exc:
                raise ExtensionImportFailed("extension package could not be materialized") from exc
            if is_upgrade:
                # D3: snapshot through the SQLite backup API before touching data.
                sqlite_store.snapshot(self.storage_root(), candidate.extension_id, from_schema)
            handler_name = plan[-1]["handler"] if plan else ""
            try:
                for step in plan:
                    handler_name = step["handler"]
                    self._invoke_sandboxed(
                        principal,
                        loaded,
                        kind="migration",
                        name=step["handler"],
                        arguments={},
                        allow_write=True,
                        event={"from": step["from"], "to": step["to"]},
                    )
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
            except BaseException as exc:
                if is_upgrade:
                    sqlite_store.restore(self.storage_root(), candidate.extension_id, from_schema)
                logger.warning(
                    "extension migration failed for %s:%s",
                    candidate.extension_id,
                    handler_name,
                    exc_info=True,
                )
                raise ExtensionMigrationFailed(
                    f"migration {handler_name or 'chain'} failed; previous version retained"
                ) from exc
            connection = self._connect(candidate.extension_id)
            try:
                sqlite_store.set_schema_version(connection, to_schema)
            finally:
                connection.close()
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
        except PermissionDenied, ExtensionHostError:
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
        except PermissionDenied, ExtensionHostError:
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
        restore_data: bool = False,
        confirm: str | None = None,
    ) -> dict[str, Any]:
        self.authorize_fresh(
            principal, "system.modules", resource=f"extension:{extension_id}:rollback"
        )
        if not isinstance(restore_data, bool):
            raise ExtensionValidationFailed("restoreData must be a boolean")
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
            restore_snapshot = False
            if data_schema not in target_manifest["compatibleSchemaVersions"]:
                if not restore_data:
                    raise ExtensionRollbackIncompatible(
                        "active data schema is not compatible with the rollback target; "
                        'rollback requires restoreData: true and confirm: "<extension id>"'
                    )
                if confirm != extension_id:
                    raise ExtensionValidationFailed(
                        "restoring data on rollback requires confirm equal to the extension id"
                    )
                target_schema = int(target_manifest["schemaVersion"])
                if target_schema not in {
                    version
                    for version, _ in sqlite_store.snapshot_versions(
                        self.storage_root(), extension_id
                    )
                }:
                    raise ExtensionConflict(
                        "no data snapshot exists for the rollback target schema"
                    )
                restore_snapshot = True
            updated = session.execute(
                update(ExtensionModule)
                .where(
                    ExtensionModule.id == module.id,
                    ExtensionModule.revision == module.revision,
                )
                .values(
                    active_version=target.version,
                    revision=module.revision + 1,
                    data_schema_version=int(target_manifest["schemaVersion"])
                    if restore_snapshot
                    else module.data_schema_version,
                    updated_at=self._now(),
                )
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
                    "compatibleSchemaVersions": list(target_manifest["compatibleSchemaVersions"]),
                },
            )
            IdentityService(session, self._settings).record_operation(
                principal,
                action="extensions.rolled_back",
                resource=f"extension:{extension_id}",
                commit=False,
            )
            session.commit()
            if restore_snapshot:
                restored = sqlite_store.restore(
                    self.storage_root(), extension_id, int(target_manifest["schemaVersion"])
                )
                if not restored:  # pragma: no cover - checked before the update
                    raise ExtensionMigrationFailed("rollback data restore failed")
            self._drop_cache(extension_id)
            session.expire_all()
            refreshed = session.get(ExtensionModule, extension_id)
            return self._module_payload(refreshed, target) if refreshed else {}
        except PermissionDenied, ExtensionHostError:
            session.rollback()
            raise
        except SQLAlchemyError:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------- status
    def status(self, principal: Principal, extension_id: str) -> dict[str, Any]:
        """Administrator view of storage, schema, availability and cursors."""
        self.authorize_fresh(
            principal, "system.modules", resource=f"extension:{extension_id}:status"
        )
        with self._session_factory() as session:
            module = storage.get_module(session, extension_id)
            if module is None:
                raise ExtensionNotFound("extension not found")
            version_row = storage.get_active_version(session, module)
            if version_row is None:
                raise ExtensionNotFound("extension has no installed version")
            manifest = json.loads(version_row.manifest_json)
            status_code = _module_status(module, manifest)
            payload = {
                "id": module.id,
                "status": status_code,
                "enabled": module.enabled,
                "version": version_row.version,
                "digest": version_row.digest,
                "schemaVersion": module.data_schema_version,
                "runtime": manifest.get("runtime", "sandboxed"),
                "revision": module.revision,
                "storagePath": str(self.module_dir(extension_id)),
                "dataSizeBytes": sqlite_store.size_bytes(self.storage_root(), extension_id),
                "snapshots": [
                    {"schemaVersion": version}
                    for version, _ in sqlite_store.snapshot_versions(
                        self.storage_root(), extension_id
                    )
                ],
                "eventCursor": None,
                "stalled": False,
            }
        payload["sandbox"] = sandbox.sandbox_availability()
        return payload

    # ----------------------------------------------------------- uninstall
    def uninstall(
        self, principal: Principal, extension_id: str, *, expected_version: int
    ) -> dict[str, Any]:
        """Remove host metadata and grants; module data is never deleted."""
        self.authorize_fresh(
            principal, "system.modules", resource=f"extension:{extension_id}:uninstall"
        )
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
            version_row = storage.get_active_version(session, module)
            codes = list(
                session.execute(
                    select(ExtensionPermission.code).where(
                        ExtensionPermission.extension_id == extension_id
                    )
                ).scalars()
            )
            session.execute(
                delete(ExtensionScheduleState).where(
                    ExtensionScheduleState.extension_id == extension_id
                )
            )
            session.execute(
                delete(ExtensionMigration).where(ExtensionMigration.extension_id == extension_id)
            )
            session.execute(
                delete(ExtensionVersion).where(ExtensionVersion.extension_id == extension_id)
            )
            session.execute(
                delete(ExtensionCandidate).where(ExtensionCandidate.extension_id == extension_id)
            )
            session.execute(
                delete(ExtensionPermission).where(ExtensionPermission.extension_id == extension_id)
            )
            for code in codes:
                resource, _, operation = code.rpartition(".")
                session.execute(
                    delete(IdentityRolePolicy).where(
                        IdentityRolePolicy.resource == resource,
                        IdentityRolePolicy.operation == operation,
                    )
                )
            session.delete(module)
            storage.record_event(
                session,
                extension_id=extension_id,
                action="extension.uninstalled",
                actor_id=principal.actor_id,
                detail={
                    "version": version_row.version if version_row is not None else None,
                    "digest": version_row.digest if version_row is not None else None,
                    "dataRetained": True,
                    "dataPath": str(self.module_dir(extension_id)),
                },
            )
            IdentityService(session, self._settings).record_operation(
                principal,
                action="extensions.uninstalled",
                resource=f"extension:{extension_id}",
                commit=False,
            )
            session.commit()
            self._drop_cache(extension_id)
            return {
                "uninstalled": True,
                "dataRetained": True,
                "dataPath": str(self.module_dir(extension_id)),
            }
        except PermissionDenied, ExtensionHostError:
            session.rollback()
            raise
        except SQLAlchemyError:
            session.rollback()
            raise
        finally:
            session.close()

    # --------------------------------------------------- legacy relocation
    def relocate_legacy(self, *, apply: bool = False) -> dict[str, Any]:
        """Copy v1 ``extension_collection_records`` into module SQLite files.

        Idempotent by construction: an existing module row always wins, legacy
        rows are only read and never deleted, and no module code is executed.
        """
        with self._session_factory() as session:
            rows = list(
                session.execute(
                    select(ExtensionCollectionRecord).order_by(
                        ExtensionCollectionRecord.extension_id,
                        ExtensionCollectionRecord.collection,
                        ExtensionCollectionRecord.record_id,
                    )
                ).scalars()
            )
            data = [
                (
                    row.extension_id,
                    row.collection,
                    row.record_id,
                    int(row.version),
                    row.data_json,
                )
                for row in rows
            ]
        plan: dict[str, dict[str, int]] = {}
        for extension_id, *_ in data:
            plan.setdefault(extension_id, {"copied": 0, "unchanged": 0, "conflicts": 0})
        for extension_id, collection, record_id, version, data_json in data:
            if not apply:
                plan[extension_id]["copied"] += 1
                continue
            connection = self._connect(extension_id)
            try:
                existing = sqlite_store.get(connection, collection, record_id)
                if existing is None:
                    self._insert_legacy_row(connection, collection, record_id, version, data_json)
                    plan[extension_id]["copied"] += 1
                elif _legacy_equal(existing["data"], data_json):
                    plan[extension_id]["unchanged"] += 1
                else:
                    plan[extension_id]["conflicts"] += 1
            finally:
                connection.close()
        return {
            "apply": apply,
            "extensions": [
                {"extensionId": extension_id, **counts}
                for extension_id, counts in sorted(plan.items())
            ],
            "legacyRowsRetained": len(data),
        }

    @staticmethod
    def _insert_legacy_row(
        connection: sqlite3.Connection,
        collection: str,
        record_id: str,
        version: int,
        data_json: str,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        connection.execute(
            f"INSERT INTO {sqlite_store.RECORDS_TABLE} "
            "(collection, record_id, version, data, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (collection, record_id, version, data_json, now, now),
        )
        connection.commit()


def submit_workspace_candidate(
    host: ExtensionHostService,
    principal: Principal,
    package_bytes: bytes,
    digest: str,
) -> dict[str, Any]:
    """T3 workspace entry point: create a pending candidate, never install."""
    return host.submit_candidate(principal, package_bytes, expected_digest=digest)
