"""Installation-global appearance, durable presets and safe graphics.

The service is the only writer of ``appearance_state``, ``appearance_presets``
and ``appearance_resources``. The public active identity is a snapshot so a
catalog edit can never change the shell before an explicit apply. Imports are
validated completely before a staged row is stored; the active snapshot is
only replaced by an explicit apply, restore or revert.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from copy import deepcopy
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from itsm.appearance import package
from itsm.appearance.builtin import (
    BUILTIN_ASSETS,
    BUILTIN_IDS,
    GENERIC_ID,
    LEGACY_ASSET_PATHS,
    builtin_asset_url,
    builtin_presets,
)
from itsm.appearance.models import AppearancePreset, AppearanceResource, AppearanceState
from itsm.appearance.schemas import GRAPHIC_KEYS, ImportRequest, PresetPayload
from itsm.attachments.storage import BlobStorage, LocalBlobStorage
from itsm.config import Settings
from itsm.identity.clock import utcnow
from itsm.identity.service import (
    Conflict,
    IdentityService,
    NotFound,
    Principal,
    ValidationFailed,
)

RESOURCE_ID = re.compile(r"^[a-f0-9]{32}$")


class AppearanceStorageUnavailable(Exception):
    """Opaque blob storage is unavailable; no filesystem detail is exposed."""


class AppearanceService:
    def __init__(
        self,
        session_factory: Callable[[], Session] | Session,
        identity: IdentityService | None = None,
        settings: Settings | None = None,
        *,
        storage: BlobStorage | None = None,
        source: str = "api",
    ) -> None:
        if settings is None:
            raise TypeError("settings are required")
        self.session_factory = session_factory
        self.settings = settings
        self._identity = identity
        self._storage = storage
        self._source = source

    # ------------------------------------------------------------- plumbing
    @contextmanager
    def _session(self) -> Iterator[Session]:
        if isinstance(self.session_factory, Session):
            yield self.session_factory
            return
        with self.session_factory() as session:
            yield session

    def _storage_backend(self) -> BlobStorage:
        return self._storage or LocalBlobStorage(self.settings.attachment_storage_path)

    def _identity_service(self, session: Session) -> IdentityService:
        return self._identity or IdentityService(session, self.settings)

    def _prefix(self) -> str:
        return self.settings.api_prefix.rstrip("/")

    def _builtins(self) -> dict[str, dict[str, Any]]:
        return builtin_presets(self._prefix())

    def _resource_url(self, resource_id: str) -> str:
        return f"{self._prefix()}/appearance/resources/{resource_id}"

    def _asset_url(self, key: str) -> str:
        return builtin_asset_url(self._prefix(), key)

    def _authorize(self, session: Session, principal: Principal) -> IdentityService:
        identity = self._identity_service(session)
        identity.authorize(principal, "config.general", resource="appearance:installation")
        return identity

    # ---------------------------------------------------------- state views
    def _state(self, session: Session) -> AppearanceState | None:
        return session.get(AppearanceState, 1)

    def _active(self, session: Session) -> tuple[dict[str, Any], str, str | None]:
        state = self._state(session)
        if state is None or not isinstance(state.active, dict):
            return deepcopy(self._builtins()[GENERIC_ID]), GENERIC_ID, None
        return deepcopy(state.active), state.active_id, state.previous_id

    def _envelope(self, session: Session) -> dict[str, Any]:
        active, active_id, previous_id = self._active(session)
        return {
            "active": active,
            "activeId": active_id,
            "previousId": previous_id,
            "builtinIds": list(BUILTIN_IDS),
        }

    def _presets(self, session: Session) -> list[dict[str, Any]]:
        presets = list(self._builtins().values())
        rows = session.execute(
            select(AppearancePreset).order_by(
                AppearancePreset.staged, AppearancePreset.created_at, AppearancePreset.name
            )
        ).scalars()
        presets.extend(deepcopy(row.document) for row in rows)
        return presets

    def _catalog(self, session: Session) -> dict[str, Any]:
        active, active_id, previous_id = self._active(session)
        return {
            "active": active,
            "activeId": active_id,
            "previousId": previous_id,
            "presets": self._presets(session),
            "builtinIds": list(BUILTIN_IDS),
        }

    def active(self) -> dict[str, Any]:
        """Public identity needed by the login shell; contains no private data."""
        with self._session() as session:
            return self._envelope(session)

    def presets(self, principal: Principal) -> dict[str, Any]:
        with self._session() as session:
            return self._catalog(session)

    # ----------------------------------------------------------- validation
    def _normalize_document(
        self, payload: Mapping[str, Any] | PresetPayload, preset_id: str
    ) -> dict[str, Any]:
        if isinstance(payload, PresetPayload):
            parsed = payload
        else:
            try:
                parsed = PresetPayload.model_validate(dict(payload))
            except Exception:
                raise ValidationFailed("appearance preset is invalid") from None
        document = parsed.model_dump()
        document["id"] = preset_id
        document["version"] = 1
        document["description"] = document.get("description") or ""
        return document

    def _store_resource(
        self,
        session: Session,
        kind: str,
        content_type: str,
        data: bytes,
        principal: Principal,
    ) -> tuple[str, list[str]]:
        content_type, width, height = package.validate_resource(kind, content_type, data)
        digest = package.sha256_hex(data)
        existing = session.execute(
            select(AppearanceResource).where(AppearanceResource.sha256 == digest)
        ).scalar_one_or_none()
        if existing is not None:
            return self._resource_url(existing.id), []
        resource_id = uuid4().hex
        blob = self._storage_backend()
        try:
            blob.put(resource_id, data)
        except OSError:
            raise AppearanceStorageUnavailable("appearance storage is unavailable") from None
        row = AppearanceResource(
            id=resource_id,
            content_type=content_type,
            size=len(data),
            sha256=digest,
            blob_key=resource_id,
            width=width,
            height=height,
            created_by=principal.username,
            created_at=utcnow(),
        )
        session.add(row)
        try:
            session.flush()
        except BaseException:
            with suppress(OSError):
                blob.delete(resource_id)
            raise
        return self._resource_url(resource_id), [resource_id]

    def _materialize_branding(
        self,
        session: Session,
        branding: Mapping[str, Any],
        principal: Principal,
    ) -> tuple[dict[str, str], list[str]]:
        prefix = self._prefix()
        resource_prefix = f"{prefix}/appearance/resources/"
        asset_prefix = f"{prefix}/appearance/assets/"
        output: dict[str, str] = {
            "appName": str(branding.get("appName") or ""),
            "organizationName": str(branding.get("organizationName") or ""),
        }
        pending: list[tuple[str, str, bytes]] = []
        for key in GRAPHIC_KEYS:
            reference = (branding.get(key) or "").strip()
            if not reference:
                output[key] = ""
                continue
            if reference.startswith(resource_prefix):
                resource_id = reference[len(resource_prefix) :]
                if RESOURCE_ID.fullmatch(resource_id) is None:
                    raise ValidationFailed(f"{key} references an unknown appearance resource")
                row = session.get(AppearanceResource, resource_id)
                if row is None:
                    raise ValidationFailed(f"{key} references an unknown appearance resource")
                if row.content_type not in package.ALLOWED_TYPES[key]:
                    raise ValidationFailed(f"{key} does not accept the {row.content_type} type")
                output[key] = self._resource_url(resource_id)
                continue
            if reference in LEGACY_ASSET_PATHS:
                asset_key = LEGACY_ASSET_PATHS[reference]
                output[key] = self._asset_url("favicon" if key == "favicon" else asset_key)
                continue
            if reference.startswith(asset_prefix):
                asset_key = reference[len(asset_prefix) :]
                if asset_key not in BUILTIN_ASSETS:
                    raise ValidationFailed(f"{key} references an unknown built-in graphic")
                output[key] = self._asset_url(asset_key)
                continue
            if reference.lower().startswith("data:"):
                parsed = package.parse_data_url(reference)
                if parsed is None:  # pragma: no cover - guarded by the prefix check
                    raise ValidationFailed(f"{key} graphic is invalid")
                content_type, data = parsed
                content_type, _, _ = package.validate_resource(key, content_type, data)
                pending.append((key, content_type, data))
                continue
            raise ValidationFailed(
                f"{key} must be an uploaded image, a stored appearance resource or empty"
            )

        created: list[str] = []
        try:
            for key, content_type, data in pending:
                url, keys = self._store_resource(session, key, content_type, data, principal)
                output[key] = url
                created.extend(keys)
        except BaseException:
            self._discard(created)
            raise
        return output, created

    # ------------------------------------------------------------- mutations
    def _unique_name(
        self, session: Session, desired: str, *, exclude_id: str | None = None
    ) -> str:
        names = {preset["name"] for preset in self._builtins().values()}
        names.update(row.name for row in session.execute(select(AppearancePreset)).scalars())
        if exclude_id is not None:
            row = session.get(AppearancePreset, exclude_id)
            if row is not None:
                names.discard(row.name)
        candidate = desired
        index = 2
        while candidate in names:
            candidate = f"{desired} ({index})"
            index += 1
        return candidate

    def _persist(
        self,
        session: Session,
        document: dict[str, Any],
        principal: Principal,
        *,
        staged: bool,
        existing: AppearancePreset | None = None,
    ) -> AppearancePreset:
        now = utcnow()
        if existing is None:
            row = AppearancePreset(
                id=document["id"],
                name=document["name"],
                version=1,
                description=document.get("description") or "",
                document=document,
                staged=staged,
                created_by=principal.username,
                updated_by=principal.username,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
        else:
            row = existing
            row.name = document["name"]
            row.version = 1
            row.description = document.get("description") or ""
            row.document = document
            row.staged = staged
            row.updated_by = principal.username
            row.updated_at = now
        session.flush()
        return row

    def create_preset(self, principal: Principal, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self._session() as session:
            identity = self._authorize(session, principal)
            document = self._normalize_document(payload, f"custom-{uuid4().hex[:12]}")
            document["name"] = self._unique_name(session, document["name"])
            branding, created = self._materialize_branding(session, document["branding"], principal)
            document["branding"] = branding
            try:
                self._persist(session, document, principal, staged=False)
                session.commit()
            except IntegrityError:
                session.rollback()
                self._discard(created)
                raise Conflict("an appearance preset with that name already exists") from None
            except BaseException:
                session.rollback()
                self._discard(created)
                raise
            identity.record_operation(
                principal,
                action="appearance.preset_created",
                resource=f"appearance-preset:{document['id']}",
            )
            return {"preset": deepcopy(document)}

    def update_preset(
        self, principal: Principal, preset_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if preset_id in BUILTIN_IDS:
            raise Conflict("built-in appearance presets are immutable")
        with self._session() as session:
            identity = self._authorize(session, principal)
            row = session.get(AppearancePreset, preset_id)
            if row is None:
                raise NotFound("appearance preset not found")
            document = self._normalize_document(payload, preset_id)
            if document["name"] != row.name:
                duplicate = session.execute(
                    select(AppearancePreset).where(
                        AppearancePreset.name == document["name"],
                        AppearancePreset.id != preset_id,
                    )
                ).scalar_one_or_none()
                if duplicate is not None or document["name"] in {
                    preset["name"] for preset in self._builtins().values()
                }:
                    raise Conflict("an appearance preset with that name already exists")
            branding, created = self._materialize_branding(session, document["branding"], principal)
            document["branding"] = branding
            try:
                self._persist(session, document, principal, staged=row.staged, existing=row)
                session.commit()
            except IntegrityError:
                session.rollback()
                self._discard(created)
                raise Conflict("an appearance preset with that name already exists") from None
            except BaseException:
                session.rollback()
                self._discard(created)
                raise
            self._gc(session)
            identity.record_operation(
                principal,
                action="appearance.preset_updated",
                resource=f"appearance-preset:{preset_id}",
            )
            return {"preset": deepcopy(document)}

    def delete_preset(self, principal: Principal, preset_id: str) -> None:
        if preset_id in BUILTIN_IDS:
            raise Conflict("built-in appearance presets are immutable")
        with self._session() as session:
            identity = self._authorize(session, principal)
            row = session.get(AppearancePreset, preset_id)
            if row is None:
                raise NotFound("appearance preset not found")
            state = self._state(session)
            if state is not None and state.active_id == preset_id:
                raise Conflict("the active appearance preset cannot be deleted")
            session.delete(row)
            session.commit()
            self._gc(session)
            identity.record_operation(
                principal,
                action="appearance.preset_deleted",
                resource=f"appearance-preset:{preset_id}",
            )

    def apply_preset(self, principal: Principal, preset_id: str) -> dict[str, Any]:
        with self._session() as session:
            identity = self._authorize(session, principal)
            builtins = self._builtins()
            if preset_id in builtins:
                document = deepcopy(builtins[preset_id])
                row = None
            else:
                row = session.get(AppearancePreset, preset_id)
                if row is None:
                    raise NotFound("appearance preset not found")
                document = deepcopy(row.document)
            self._replace_active(session, document, preset_id, principal)
            if row is not None and row.staged:
                row.staged = False
                row.updated_by = principal.username
            session.commit()
            identity.record_operation(
                principal,
                action="appearance.preset_applied",
                resource=f"appearance-preset:{preset_id}",
            )
            return self._catalog(session)

    def restore(self, principal: Principal) -> dict[str, Any]:
        with self._session() as session:
            identity = self._authorize(session, principal)
            document = deepcopy(self._builtins()[GENERIC_ID])
            self._replace_active(session, document, GENERIC_ID, principal)
            session.commit()
            identity.record_operation(
                principal, action="appearance.restored", resource="appearance:installation"
            )
            return self._catalog(session)

    def revert(self, principal: Principal) -> dict[str, Any]:
        with self._session() as session:
            identity = self._authorize(session, principal)
            state = self._state(session)
            if state is None or not isinstance(state.previous, dict) or state.previous_id is None:
                raise Conflict("there is no previous appearance preset to revert to")
            current_document = deepcopy(state.active)
            current_id = state.active_id
            state.active = deepcopy(state.previous)
            state.active_id = state.previous_id
            state.previous = current_document
            state.previous_id = current_id
            state.revision = (state.revision or 0) + 1
            state.updated_by = principal.username
            state.updated_at = utcnow()
            session.commit()
            identity.record_operation(
                principal, action="appearance.reverted", resource="appearance:installation"
            )
            return self._catalog(session)

    def _replace_active(
        self, session: Session, document: dict[str, Any], preset_id: str, principal: Principal
    ) -> None:
        state = self._state(session)
        current, current_id = (None, None)
        if state is None:
            state = AppearanceState(
                id=1,
                active_id=preset_id,
                previous_id=None,
                active=deepcopy(document),
                previous=None,
                revision=0,
                updated_by=principal.username,
                updated_at=utcnow(),
            )
            session.add(state)
        else:
            current = deepcopy(state.active)
            current_id = state.active_id
            state.previous = current
            state.previous_id = current_id
            state.active = deepcopy(document)
            state.active_id = preset_id
            state.revision = (state.revision or 0) + 1
            state.updated_by = principal.username
            state.updated_at = utcnow()
        if current is None:
            state.previous = deepcopy(self._builtins()[GENERIC_ID])
            state.previous_id = GENERIC_ID
        session.flush()

    # --------------------------------------------------------- import/export
    def preview_import(self, principal: Principal, data: bytes) -> dict[str, Any]:
        with self._session() as session:
            self._authorize(session, principal)
            imported = package.read_package(data)
            active, _, _ = self._active(session)
            return {
                "preset": imported.preset,
                "resources": [
                    {
                        "key": resource.key,
                        "name": resource.name,
                        "size": len(resource.data),
                        "type": resource.content_type,
                    }
                    for resource in imported.resources
                ],
                "comparison": self._comparison(session, active, imported.preset),
                "warnings": [],
            }

    def _comparison(
        self, session: Session, active: Mapping[str, Any], imported: Mapping[str, Any]
    ) -> dict[str, Any]:
        changed: dict[str, list[str]] = {"branding": [], "colors": [], "preferences": []}
        for key in GRAPHIC_KEYS:
            left = self._graphic_identity(session, active["branding"].get(key))
            right = self._graphic_identity(session, imported["branding"].get(key))
            if left != right:
                changed["branding"].append(key)
        for key in ("appName", "organizationName"):
            if active["branding"].get(key) != imported["branding"].get(key):
                changed["branding"].append(key)
        for mode in ("light", "dark"):
            if active["colors"].get(mode) != imported["colors"].get(mode):
                changed["colors"].append(mode)
        for key in ("defaultMode", "compact"):
            if active["preferences"].get(key) != imported["preferences"].get(key):
                changed["preferences"].append(key)
        return {
            "sameAsActive": not any(changed.values()),
            "changed": changed,
        }

    def _graphic_identity(self, session: Session, reference: Any) -> str:
        if not reference:
            return ""
        text = str(reference)
        if text.lower().startswith("data:"):
            try:
                parsed = package.parse_data_url(text)
            except ValidationFailed:
                return text
            if parsed is not None:
                return package.sha256_hex(parsed[1])
            return text
        prefix = f"{self._prefix()}/appearance/resources/"
        if text.startswith(prefix):
            row = session.get(AppearanceResource, text[len(prefix) :])
            return "" if row is None else row.sha256
        asset_prefix = f"{self._prefix()}/appearance/assets/"
        if text.startswith(asset_prefix):
            asset = BUILTIN_ASSETS.get(text[len(asset_prefix) :])
            return "" if asset is None else package.sha256_hex(asset[1])
        if text in LEGACY_ASSET_PATHS:
            asset = BUILTIN_ASSETS.get(LEGACY_ASSET_PATHS[text])
            return "" if asset is None else package.sha256_hex(asset[1])
        return text

    def import_preset(self, principal: Principal, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            request = ImportRequest.model_validate(dict(payload))
        except Exception:
            raise ValidationFailed("appearance import request is invalid") from None
        with self._session() as session:
            identity = self._authorize(session, principal)
            builtins = self._builtins()
            existing: AppearancePreset | None = None
            source = request.preset
            if request.policy == "replace":
                if source.name in {preset["name"] for preset in builtins.values()}:
                    raise Conflict("built-in appearance presets are immutable")
                existing = session.execute(
                    select(AppearancePreset).where(AppearancePreset.name == source.name)
                ).scalar_one_or_none()
            preset_id = existing.id if existing is not None else f"custom-{uuid4().hex[:12]}"
            document = self._normalize_document(source, preset_id)
            if existing is None and request.policy == "both":
                document["name"] = self._unique_name(session, document["name"])
            branding, created = self._materialize_branding(session, document["branding"], principal)
            document["branding"] = branding
            try:
                self._persist(session, document, principal, staged=True, existing=existing)
                session.commit()
            except IntegrityError:
                session.rollback()
                self._discard(created)
                raise Conflict("an appearance preset with that name already exists") from None
            except BaseException:
                session.rollback()
                self._discard(created)
                raise
            self._gc(session)
            identity.record_operation(
                principal,
                action="appearance.preset_imported",
                resource=f"appearance-preset:{preset_id}",
            )
            return {"preset": deepcopy(document), "staged": True}

    def export_preset(self, principal: Principal, preset_id: str) -> tuple[str, bytes]:
        with self._session() as session:
            self._authorize(session, principal)
            builtins = self._builtins()
            if preset_id in builtins:
                document = deepcopy(builtins[preset_id])
            else:
                row = session.get(AppearancePreset, preset_id)
                if row is None:
                    raise NotFound("appearance preset not found")
                document = deepcopy(row.document)

            def resolve(key: str, reference: str) -> tuple[str, bytes] | None:
                prefix = self._prefix()
                if reference.startswith(f"{prefix}/appearance/resources/"):
                    resource_id = reference[len(f"{prefix}/appearance/resources/") :]
                    row = session.get(AppearanceResource, resource_id)
                    if row is None:
                        return None
                    data = self._read_blob(row)
                    return row.content_type, data
                if reference.startswith(f"{prefix}/appearance/assets/"):
                    asset_key = reference[len(f"{prefix}/appearance/assets/") :]
                    asset = BUILTIN_ASSETS.get(asset_key)
                    if asset is None:
                        return None
                    return asset
                if reference in LEGACY_ASSET_PATHS:
                    asset = BUILTIN_ASSETS.get(LEGACY_ASSET_PATHS[reference])
                    return asset
                return None

            payload = package.write_package(document, resolve)
            return self._archive_name(document["name"]), payload

    def _archive_name(self, name: str) -> str:
        normalized = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
        slug = re.sub(r"[^A-Za-z0-9._-]+", "-", normalized).strip(" .-_") or "appearance"
        return f"{slug[:100]}.zip"

    # ------------------------------------------------------------- resources
    def _read_blob(self, row: AppearanceResource) -> bytes:
        try:
            data = self._storage_backend().read(row.blob_key, row.size + 1)
        except OSError:
            raise AppearanceStorageUnavailable("appearance storage is unavailable") from None
        if len(data) != row.size or package.sha256_hex(data) != row.sha256:
            raise AppearanceStorageUnavailable("appearance resource failed integrity validation")
        return data

    def resource(self, resource_id: str) -> tuple[str, bytes]:
        if RESOURCE_ID.fullmatch(resource_id) is None:
            raise NotFound("appearance resource not found")
        with self._session() as session:
            row = session.get(AppearanceResource, resource_id)
            if row is None:
                raise NotFound("appearance resource not found")
            return row.content_type, self._read_blob(row)

    def builtin_asset(self, key: str) -> tuple[str, bytes]:
        asset = BUILTIN_ASSETS.get(key)
        if asset is None:
            raise NotFound("appearance asset not found")
        return asset

    # ------------------------------------------------------------- retention
    def _referenced_ids(self, session: Session) -> set[str]:
        prefix = re.escape(f"{self._prefix()}/appearance/resources/")
        expression = re.compile(prefix + r"([a-f0-9]{32})")
        documents: list[dict[str, Any]] = [
            row.document for row in session.execute(select(AppearancePreset)).scalars()
        ]
        state = self._state(session)
        if state is not None:
            documents.append(state.active)
            if isinstance(state.previous, dict):
                documents.append(state.previous)
        references: set[str] = set()
        for document in documents:
            branding = document.get("branding") if isinstance(document, dict) else None
            if not isinstance(branding, dict):
                continue
            for value in branding.values():
                if isinstance(value, str):
                    references.update(expression.findall(value))
        return references

    def _gc(self, session: Session) -> None:
        references = self._referenced_ids(session)
        removed: list[str] = []
        for row in session.execute(select(AppearanceResource)).scalars():
            if row.id not in references:
                removed.append(row.blob_key)
                session.delete(row)
        if not removed:
            return
        session.commit()
        for key in removed:
            with suppress(OSError):
                self._storage_backend().delete(key)

    def _discard(self, blob_keys: list[str]) -> None:
        for key in blob_keys:
            with suppress(OSError):
                self._storage_backend().delete(key)


def build_appearance_service(
    settings: Settings,
    session_factory: Callable[[], Session],
    *,
    storage: BlobStorage | None = None,
) -> AppearanceService:
    """Single construction helper for the FastAPI lifespan and direct tests."""
    return AppearanceService(session_factory, settings=settings, storage=storage)
