"""Canonical report service: authorization, data, composition, jobs and shares.

Every front door (HTTP, Pydantic AI, FastMCP, the Huey worker) calls this module.
The service never trusts a rendered payload, an external URL or a caller-supplied
permission: it re-resolves the principal, asks :class:`IdentityService` for the
concrete capability and stores only a bounded request plus an executor locator.
"""

from __future__ import annotations

import copy
import hashlib
import re
import secrets
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import Any
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session

from itsm.appearance.integration import appearance_report_branding, appearance_report_logo
from itsm.attachments.models import Attachment
from itsm.attachments.service import AttachmentService, StorageUnavailable
from itsm.attachments.storage import BlobStorage, LocalBlobStorage
from itsm.config import Settings
from itsm.i18n.documents import DocumentLocale, read_document_locale
from itsm.identity.clock import as_utc, utcnow
from itsm.identity.models import IdentityCredential, IdentitySession
from itsm.identity.permissions import ROLE_ADMIN, ROLE_SUPERADMIN
from itsm.identity.service import (
    IdentityService,
    NotFound,
    PermissionDenied,
    Principal,
    ValidationFailed,
)
from itsm.interventions.service import InterventionService
from itsm.inventory.models import Asset
from itsm.inventory.service import InventoryService
from itsm.reports import composition, qr, rendering
from itsm.reports.data import (
    DEFAULT_FIELDS,
    DEFAULT_HISTORY_FIELDS,
    DEFAULT_WARRANTY_FIELDS,
    GROUP_FIELDS,
    HISTORY_FIELDS,
    PUBLIC_FIELDS,
    WARRANTY_FIELDS,
    ReportTable,
    asset_filters,
    csv_bytes,
    export_table,
    group_table,
    history_filters,
    history_table,
    inventory_table,
    project_asset,
    public_asset,
    select_assets,
    warranty_filter,
    warranty_table,
    xlsx_bytes,
)
from itsm.reports.models import (
    ReportDocument,
    ReportJob,
    ReportSettings,
    ReportShare,
    ReportTemplate,
)
from itsm.reports.schemas import (
    ASSET_FIELDS,
    TEMPLATE_ID_PATTERN,
    ReportRequest,
    ReportSettingsInput,
    TemplateDefinition,
)
from itsm.reports.schemas import (
    builtin_templates as schema_builtin_templates,
)
from itsm.workflows.warranties import WarrantyService

JOB_STATUSES = ("queued", "running", "completed", "failed")
MAX_JOB_LIMIT = 100
MAX_ERRORS = 100
MAX_LOGO_BYTES = 2 * 1024 * 1024
MAX_SETTINGS_BYTES = 16 * 1024
MAX_TEMPLATE_BYTES = 64 * 1024
SHARE_DAYS_MIN = 1
SHARE_DAYS_MAX = 365
SHARE_TOKEN_BYTES = 32
RASTER_TYPES = frozenset({"image/png", "image/jpeg", "image/gif", "image/webp"})
DOCUMENT_MIMES = {
    "pdf": "application/pdf",
    "csv": "text/csv",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
DOCUMENT_EXTENSIONS = {"pdf": ".pdf", "csv": ".csv", "xlsx": ".xlsx"}

_BUILTINS: tuple[dict[str, Any], ...] = tuple(schema_builtin_templates())
BUILTIN_IDS: frozenset[str] = frozenset(item["id"] for item in _BUILTINS)
DEFAULT_TEMPLATE_BY_FAMILY = {
    "inventory": "inventory-list",
    "history": "history-list",
    "warranty": "warranty-list",
}


def builtin_templates() -> list[dict[str, Any]]:
    """Return validated built-ins; they need no seed-time writes."""
    return copy.deepcopy(list(_BUILTINS))


def _builtin(template_id: str) -> dict[str, Any] | None:
    for item in _BUILTINS:
        if item["id"] == template_id:
            return copy.deepcopy(item)
    return None


def _default_template(family: str, labels: Mapping[str, Any] | None) -> dict[str, Any]:
    candidate = "inventory-sheet" if labels is not None else DEFAULT_TEMPLATE_BY_FAMILY[family]
    template = _builtin(candidate)
    if template is None:
        raise ValidationFailed("no default template exists for this family")
    return template


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _bounded_error(exc: BaseException) -> str:
    message = str(exc).strip() or exc.__class__.__name__
    return message[:300]


def _document_name(base: str, extension: str, asset: Any | None = None) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._ -]+", "-", base or "report").strip(" .-")
    cleaned = cleaned[:120] or "report"
    if asset is not None:
        code = re.sub(r"[^A-Za-z0-9._-]+", "-", asset.quick_code).strip(" .-") or "asset"
        cleaned = f"{code}-{cleaned}"
    return f"{cleaned[:170]}{extension}"


@dataclass(frozen=True)
class Collected:
    """Everything one report needs before composition, resolved once."""

    request: dict[str, Any]
    family: str
    output: str
    mode: str
    fields: tuple[str, ...]
    template: dict[str, Any]
    branding: dict[str, Any]
    base_url: str
    title: str
    labels: dict[str, Any] | None
    document: DocumentLocale
    table: ReportTable
    qr_urls: dict[str, str]
    images: dict[str, bytes]
    logo: bytes | None


class ReportService:
    """Single implementation of report rules for HTTP, worker, AI and MCP."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        settings: Settings,
        identity: IdentityService | None = None,
        inventory: InventoryService | None = None,
        warranties: WarrantyService | None = None,
        interventions: Any | None = None,
        storage: BlobStorage | None = None,
        task_queue: Any | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings
        self._identity = identity
        self._inventory = inventory
        self._warranties = warranties
        self._interventions = interventions
        self._storage = storage
        self._task_queue = task_queue

    # ------------------------------------------------------------- plumbing
    @staticmethod
    def _validated(model: type[Any], payload: Any, message: str) -> Any:
        try:
            return model.model_validate(payload)
        except ValidationError as exc:
            raise ValidationFailed(message) from exc

    def _services(
        self, session: Session
    ) -> tuple[IdentityService, InventoryService, WarrantyService]:
        identity = self._identity or IdentityService(session, self.settings)
        inventory = self._inventory or InventoryService(
            session, self.settings, identity=identity, source="internal"
        )
        warranties = self._warranties or WarrantyService(
            session, self.settings, identity=identity, source="internal"
        )
        return identity, inventory, warranties

    def _storage_backend(self) -> BlobStorage:
        return self._storage or LocalBlobStorage(self.settings.attachment_storage_path)

    @staticmethod
    def _request_model(request: ReportRequest | Mapping[str, Any]) -> ReportRequest:
        if isinstance(request, ReportRequest):
            return request
        if isinstance(request, Mapping):
            return ReportService._validated(
                ReportRequest, dict(request), "report request is invalid"
            )
        raise ValidationFailed("report request must be an object")

    @staticmethod
    def _request_dump(model: ReportRequest) -> dict[str, Any]:
        return dict(model.model_dump())

    def _validate_semantics(self, request: Mapping[str, Any]) -> None:
        family = request.get("family")
        if family not in {"inventory", "history", "warranty"}:
            raise ValidationFailed("family must be inventory, history or warranty")
        labels = request.get("labels")
        output = request.get("output") or "pdf"
        mode = request.get("mode") or "consolidated"
        if output not in DOCUMENT_MIMES:
            raise ValidationFailed("output must be pdf, csv or xlsx")
        if mode not in {"consolidated", "individual"}:
            raise ValidationFailed("mode must be consolidated or individual")
        if labels is not None:
            if family != "inventory":
                raise ValidationFailed("labels are only available for the inventory family")
            if output != "pdf":
                raise ValidationFailed("labels require the pdf output")
        allowed_fields = (
            ASSET_FIELDS
            if family == "inventory"
            else HISTORY_FIELDS
            if family == "history"
            else WARRANTY_FIELDS
        )
        for field in request.get("fields") or []:
            if field not in allowed_fields:
                raise ValidationFailed(f"unsupported report field: {field}")
        filters = request.get("filters") or {}
        asset_filters(filters)
        history_filters(filters)
        warranty_filter(filters)
        name = request.get("name")
        if name is not None and (not isinstance(name, str) or len(name.strip()) > 160):
            raise ValidationFailed("name must be at most 160 characters")

    def _resolve_template(self, session: Session, request: Mapping[str, Any]) -> dict[str, Any]:
        family = request["family"]
        inline = request.get("template")
        if inline is not None:
            definition = self._validated(
                TemplateDefinition, inline, "template definition is invalid"
            ).model_dump()
            self._assert_custom_template(definition, family)
            if len(str(definition).encode()) > MAX_TEMPLATE_BYTES:
                raise ValidationFailed("template definition is too large")
            return definition
        template_id = request.get("templateId")
        if template_id:
            template = _builtin(template_id)
            if template is not None:
                if template["family"] != family:
                    raise ValidationFailed("template family does not match the request")
                return template
            row = session.get(ReportTemplate, template_id)
            if row is None:
                raise NotFound("template not found")
            definition = TemplateDefinition.model_validate(row.definition).model_dump()
            if definition["family"] != family:
                raise ValidationFailed("template family does not match the request")
            return definition
        return _default_template(family, request.get("labels"))

    @staticmethod
    def _assert_custom_template(definition: Mapping[str, Any], family: str) -> None:
        template_id = definition.get("id")
        if (
            not isinstance(template_id, str)
            or re.fullmatch(TEMPLATE_ID_PATTERN, template_id) is None
        ):
            raise ValidationFailed("template id is invalid")
        if template_id in BUILTIN_IDS:
            raise ValidationFailed("builtin template ids are reserved")
        if definition.get("family") != family:
            raise ValidationFailed("template family does not match the request")

    def _stored_settings(self, session: Session) -> dict[str, Any]:
        row = session.get(ReportSettings, 1)
        return {} if row is None else dict(row.data or {})

    def _settings_wire(self, session: Session, stored: Mapping[str, Any]) -> dict[str, Any]:
        defaults = ReportSettingsInput().model_dump()
        appearance = appearance_report_branding(session)
        branding = {
            **defaults["branding"],
            **{key: value for key, value in appearance.items() if value},
            **(stored.get("branding") or {}),
        }
        label_defaults = {**defaults["labelDefaults"], **(stored.get("labelDefaults") or {})}
        return {
            "baseUrl": stored.get("baseUrl") or self.settings.report_base_url,
            "branding": branding,
            "labelDefaults": label_defaults,
        }

    @staticmethod
    def _public_branding(branding: Mapping[str, Any]) -> dict[str, Any]:
        return {key: branding.get(key) for key in ("name", "primary", "accent", "header", "footer")}

    def _validate_base_url(self, value: Any) -> str:
        if not isinstance(value, str):
            raise ValidationFailed("baseUrl must be text")
        try:
            return type(self.settings)._validate_report_base_url(value)
        except ValueError as exc:
            raise ValidationFailed(
                "baseUrl must use http(s) without credentials, query or fragment"
            ) from exc

    def _logo_bytes(
        self,
        session: Session,
        identity: IdentityService,
        principal: Principal,
        attachment_id: Any,
    ) -> bytes | None:
        if not attachment_id:
            return appearance_report_logo(session, self.settings, self._storage_backend())
        if not isinstance(attachment_id, str) or len(attachment_id) > 36:
            return None
        row = session.get(Attachment, attachment_id)
        if row is None or row.deleted_at is not None:
            return None
        if row.content_type not in RASTER_TYPES:
            return None
        if row.size < 1 or row.size > min(self.settings.attachment_max_bytes, MAX_LOGO_BYTES):
            return None
        try:
            attachment_service = AttachmentService(
                session, self.settings, identity=identity, source="internal"
            )
            _, data = attachment_service.download(principal, row.asset_id, row.id)
        except NotFound, PermissionDenied, StorageUnavailable:
            return None
        if len(data) > MAX_LOGO_BYTES:
            return None
        return data

    # --------------------------------------------------------------- collection
    def _collect(
        self,
        session: Session,
        identity: IdentityService,
        inventory: InventoryService,
        warranties: WarrantyService,
        principal: Principal,
        request: ReportRequest,
    ) -> Collected:
        identity.authorize(principal, "assets.view", resource="reports:data")
        dump = self._request_dump(request)
        self._validate_semantics(dump)
        document = read_document_locale(
            session, locale=dump.get("locale"), identity_id=principal.actor_id
        )
        family = dump["family"]
        output = dump.get("output") or "pdf"
        mode = dump.get("mode") or "consolidated"
        template = self._resolve_template(session, dump)
        requested_fields = tuple(dump.get("fields") or ())
        if family == "inventory":
            allowed_fields = ASSET_FIELDS
            fallback_fields = DEFAULT_FIELDS
        elif family == "history":
            allowed_fields = HISTORY_FIELDS
            fallback_fields = DEFAULT_HISTORY_FIELDS
        else:
            allowed_fields = WARRANTY_FIELDS
            fallback_fields = DEFAULT_WARRANTY_FIELDS
        for field in requested_fields:
            if field not in allowed_fields:
                raise ValidationFailed(f"unsupported report field: {field}")
        if requested_fields:
            fields = requested_fields
        elif family == "inventory":
            template_fields = tuple(
                field for field in template.get("fields") or () if field in allowed_fields
            )
            fields = template_fields or fallback_fields
        else:
            fields = fallback_fields
        group = dump.get("group") or "none"
        if group not in GROUP_FIELDS:
            raise ValidationFailed("unsupported group")
        assets = select_assets(
            inventory,
            principal,
            asset_ids=dump.get("assetIds"),
            filters=dump.get("filters"),
            max_assets=self.settings.report_max_assets,
        )
        if family == "inventory":
            table = inventory_table(assets, fields, document)
        elif family == "history":
            interventions = self._interventions or InterventionService(
                session, self.settings, identity=identity, source="internal"
            )
            table = history_table(
                inventory,
                interventions,
                principal,
                assets,
                dump.get("filters"),
                fields,
                document,
            )
        else:
            table = warranty_table(
                warranties, principal, assets, dump.get("filters"), fields, document
            )
        table = group_table(table, group, document)
        settings_wire = self._settings_wire(session, self._stored_settings(session))
        branding = settings_wire["branding"]
        base_url = self._validate_base_url(settings_wire["baseUrl"])
        qr_urls = {asset.id: qr.asset_report_url(base_url, asset.id) for asset in assets}
        images: dict[str, bytes] = {}
        if template.get("images") and mode != "individual":
            self._assert_image_budget(len(assets))
            images = self._load_images(inventory, principal, assets)
        logo = self._logo_bytes(session, identity, principal, branding.get("logoAttachmentId"))
        return Collected(
            request=dump,
            family=family,
            output=output,
            mode=mode,
            fields=fields,
            template=template,
            branding=self._public_branding(branding),
            base_url=base_url,
            title=str(dump.get("name") or template.get("name") or document.t("api.reports.title")),
            labels=dump.get("labels"),
            document=document,
            table=table,
            qr_urls=qr_urls,
            images=images,
            logo=logo,
        )

    def _assert_image_budget(self, assets: int) -> None:
        if assets > self.settings.report_max_assets:
            raise ValidationFailed("selection exceeds the report asset limit")

    @staticmethod
    def _load_images(
        inventory: InventoryService, principal: Principal, assets: Sequence[Any]
    ) -> dict[str, bytes]:
        images: dict[str, bytes] = {}
        for asset in assets:
            try:
                images[asset.id] = inventory.image(principal, asset.id, "photo").data
            except NotFound:
                continue
        return images

    def _context(
        self, collected: Collected, assets: Sequence[Any], table: ReportTable
    ) -> dict[str, Any]:
        return {
            "title": collected.title,
            "family": collected.family,
            "generatedAt": utcnow().isoformat(),
            "assets": [project_asset(asset, ASSET_FIELDS) for asset in assets],
            "rows": table.rows,
            "columns": table.columns,
            "summary": table.summary,
            "branding": dict(collected.branding),
            "qrUrls": {asset.id: collected.qr_urls[asset.id] for asset in assets},
            "images": {
                asset.id: collected.images[asset.id]
                for asset in assets
                if asset.id in collected.images
            },
            "logo": collected.logo,
            "locale": collected.document.locale,
            "timezone": collected.document.timezone,
            "currency": collected.document.currency,
            "defaultLocale": collected.document.default_locale,
        }

    def _compose(
        self,
        collected: Collected,
        assets: Sequence[Any],
        table: ReportTable,
        *,
        labels: Mapping[str, Any] | None = None,
    ) -> Any:
        return composition.compose_document(
            collected.template,
            self._context(collected, assets, table),
            labels=dict(labels) if labels is not None else None,
        )

    @staticmethod
    def _subset_table(collected: Collected, asset: Any) -> ReportTable:
        if collected.family == "inventory":
            return inventory_table([asset], collected.fields, collected.document)
        rows = [row for row in collected.table.rows if row.get("assetId") == asset.id]
        counts: dict[str, int] = {}
        key = "action" if collected.family == "history" else "coverage"
        for row in rows:
            value = "unknown" if row.get(key) in (None, "") else str(row[key])
            counts[value] = counts.get(value, 0) + 1
        summary: dict[str, Any] = {"total": len(rows)}
        summary["byAction" if collected.family == "history" else "byCoverage"] = counts
        return ReportTable(
            rows=rows, columns=list(collected.table.columns), summary=summary, assets=(asset,)
        )

    # -------------------------------------------------------------- templates
    def templates(self, principal: Principal) -> dict[str, Any]:
        with self.session_factory() as session:
            identity, _, _ = self._services(session)
            identity.authorize(principal, "assets.view", resource="reports:templates")
            rows = session.execute(
                select(ReportTemplate).order_by(ReportTemplate.created_at, ReportTemplate.id)
            ).scalars()
            custom = [
                self._validated(
                    TemplateDefinition, row.definition, "stored template is invalid"
                ).model_dump()
                for row in rows
            ]
            return {
                "items": [
                    *({**template, "builtin": True} for template in builtin_templates()),
                    *({**template, "builtin": False} for template in custom),
                ]
            }

    def save_template(self, principal: Principal, template: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(template, Mapping):
            raise ValidationFailed("template must be an object")
        definition = self._validated(
            TemplateDefinition, dict(template), "template definition is invalid"
        ).model_dump()
        self._assert_custom_template(definition, str(definition.get("family")))
        if len(str(definition).encode()) > MAX_TEMPLATE_BYTES:
            raise ValidationFailed("template definition is too large")
        with self.session_factory() as session:
            identity, _, _ = self._services(session)
            identity.authorize(principal, "assets.edit", resource="reports:templates")
            row = session.get(ReportTemplate, definition["id"])
            now = utcnow()
            if row is None:
                row = ReportTemplate(
                    id=definition["id"],
                    name=definition["name"],
                    family=definition["family"],
                    definition=definition,
                    version=int(definition["version"]),
                    created_by=principal.username,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            else:
                row.name = definition["name"]
                row.family = definition["family"]
                row.definition = definition
                row.version = int(definition["version"])
                row.updated_at = now
            session.commit()
            identity.record_operation(
                principal,
                action="reports.template_saved",
                resource=f"report-template:{definition['id']}",
            )
            session.commit()
        return definition

    def delete_template(self, principal: Principal, template_id: str) -> None:
        if (
            not isinstance(template_id, str)
            or re.fullmatch(TEMPLATE_ID_PATTERN, template_id) is None
        ):
            raise ValidationFailed("template id is invalid")
        if template_id in BUILTIN_IDS:
            raise ValidationFailed("builtin templates are read-only")
        with self.session_factory() as session:
            identity, _, _ = self._services(session)
            identity.authorize(principal, "assets.edit", resource="reports:templates")
            row = session.get(ReportTemplate, template_id)
            if row is None:
                raise NotFound("template not found")
            session.delete(row)
            session.commit()
            identity.record_operation(
                principal,
                action="reports.template_deleted",
                resource=f"report-template:{template_id}",
            )
            session.commit()

    # --------------------------------------------------------------- settings
    def get_settings(self, principal: Principal) -> dict[str, Any]:
        with self.session_factory() as session:
            identity, _, _ = self._services(session)
            identity.authorize(principal, "assets.view", resource="reports:settings")
            return self._settings_wire(session, self._stored_settings(session))

    def save_settings(self, principal: Principal, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ValidationFailed("settings must be an object")
        parsed = self._validated(
            ReportSettingsInput, dict(payload), "report settings are invalid"
        ).model_dump()
        base_url = self._validate_base_url(parsed.get("baseUrl") or self.settings.report_base_url)
        branding = dict(parsed.get("branding") or {})
        logo_id = branding.get("logoAttachmentId")
        if len(str(parsed).encode()) > MAX_SETTINGS_BYTES:
            raise ValidationFailed("settings are too large")
        with self.session_factory() as session:
            identity, _, _ = self._services(session)
            identity.authorize(principal, "config.general", resource="reports:settings")
            if logo_id:
                row = session.get(Attachment, str(logo_id))
                if (
                    row is None
                    or row.deleted_at is not None
                    or row.content_type not in RASTER_TYPES
                    or row.size < 1
                    or row.size > min(self.settings.attachment_max_bytes, MAX_LOGO_BYTES)
                ):
                    raise ValidationFailed(
                        "logoAttachmentId must reference an existing raster attachment"
                    )
                identity.authorize(principal, "assets.view", resource=f"asset:{row.asset_id}")
            stored = {
                "baseUrl": base_url,
                "branding": branding,
                "labelDefaults": dict(parsed.get("labelDefaults") or {}),
            }
            row = session.get(ReportSettings, 1)
            now = utcnow()
            if row is None:
                row = ReportSettings(
                    id=1, data=stored, updated_by=principal.username, updated_at=now
                )
                session.add(row)
            else:
                row.data = stored
                row.updated_by = principal.username
                row.updated_at = now
            session.commit()
            identity.record_operation(
                principal, action="reports.settings_saved", resource="reports:settings"
            )
            session.commit()
            return self._settings_wire(session, stored)

    # ---------------------------------------------------------------- preview
    def preview(
        self, principal: Principal, request: ReportRequest | Mapping[str, Any]
    ) -> dict[str, Any]:
        model = self._request_model(request)
        with self.session_factory() as session:
            identity, inventory, warranties = self._services(session)
            collected = self._collect(session, identity, inventory, warranties, principal, model)
            document = self._compose(
                collected,
                collected.table.assets,
                collected.table,
                labels=collected.labels,
            )
            html = composition.preview_html(document)
            if len(html.encode("utf-8")) > self.settings.report_max_document_bytes:
                raise ValidationFailed(
                    "preview exceeds the document size limit; narrow the selection"
                )
            return {
                "html": html,
                "assets": [project_asset(asset, ASSET_FIELDS) for asset in collected.table.assets],
                "rows": collected.table.rows,
                "columns": collected.table.columns,
                "summary": collected.table.summary,
                "matched": len(collected.table.assets),
                "truncated": False,
                "template": collected.template,
                "branding": dict(collected.branding),
                "locale": collected.document.locale,
            }

    # ------------------------------------------------------------------- jobs
    def _executor_payload(
        self, principal: Principal, credential_digest: str | None
    ) -> dict[str, Any]:
        return {
            "actorId": principal.actor_id,
            "kind": principal.kind,
            "roleId": principal.role_id,
            "scopes": sorted(principal.scopes),
            "executionId": principal.execution_id,
            "authorizationRef": principal.authorization_ref,
            "sessionId": principal.session_id,
            "credentialDigest": credential_digest,
        }

    def _job_wire(self, session: Session, job: ReportJob) -> dict[str, Any]:
        documents = session.execute(
            select(ReportDocument)
            .where(ReportDocument.job_id == job.id, ReportDocument.deleted_at.is_(None))
            .order_by(ReportDocument.created_at, ReportDocument.id)
        ).scalars()
        return {
            "id": job.id,
            "status": job.status,
            "total": job.total,
            "processed": job.processed,
            "errors": list(job.errors or []),
            "documents": [
                {
                    "id": document.id,
                    "name": document.name,
                    "mime": document.mime,
                    "size": document.size,
                    "downloadUrl": (
                        f"{self.settings.api_prefix}/reports/documents/{document.id}/download"
                    ),
                    "assetId": document.asset_id,
                }
                for document in documents
            ],
            "createdAt": as_utc(job.created_at).isoformat(),
        }

    def generate(
        self,
        principal: Principal,
        request: ReportRequest | Mapping[str, Any],
        *,
        credential_digest: str | None = None,
    ) -> dict[str, Any]:
        model = self._request_model(request)
        with self.session_factory() as session:
            identity, _, _ = self._services(session)
            identity.authorize(principal, "assets.view", resource="reports:jobs")
            dump = self._request_dump(model)
            self._validate_semantics(dump)
            self._resolve_template(session, dump)
            # Persist the effective language: asynchronous rendering must not
            # depend on a preference the requester changes later.
            dump["locale"] = read_document_locale(
                session, locale=dump.get("locale"), identity_id=principal.actor_id
            ).locale
            now = utcnow()
            job_id = str(uuid4())
            job = ReportJob(
                id=job_id,
                owner_id=principal.actor_id,
                request=dump,
                executor=self._executor_payload(principal, credential_digest),
                status="queued",
                total=len(dump.get("assetIds") or []),
                processed=0,
                errors=[],
                created_at=now,
                updated_at=now,
            )
            session.add(job)
            session.commit()
            if self._task_queue is not None:
                try:
                    self._task_queue.submit_report(job_id, job_id)
                except Exception as exc:
                    job.status = "failed"
                    job.errors = [{"message": _bounded_error(exc)}]
                    job.updated_at = utcnow()
                    session.commit()
                    raise
            return self._job_wire(session, job)

    def jobs(self, principal: Principal, limit: int = 50) -> dict[str, Any]:
        if type(limit) is not int or not 1 <= limit <= MAX_JOB_LIMIT:
            raise ValidationFailed(f"limit must be 1-{MAX_JOB_LIMIT}")
        with self.session_factory() as session:
            identity, _, _ = self._services(session)
            identity.authorize(principal, "assets.view", resource="reports:jobs")
            rows = session.execute(
                select(ReportJob)
                .where(ReportJob.owner_id == principal.actor_id)
                .order_by(ReportJob.created_at.desc(), ReportJob.id)
                .limit(limit)
            ).scalars()
            return {"items": [self._job_wire(session, row) for row in rows]}

    @staticmethod
    def _is_admin(principal: Principal) -> bool:
        return principal.role_id in {ROLE_ADMIN, ROLE_SUPERADMIN}

    def job(self, principal: Principal, job_id: str) -> dict[str, Any]:
        with self.session_factory() as session:
            identity, _, _ = self._services(session)
            identity.authorize(principal, "assets.view", resource="reports:jobs")
            job = session.get(ReportJob, job_id)
            if job is None or (
                job.owner_id != principal.actor_id and not self._is_admin(principal)
            ):
                raise NotFound("job not found")
            return self._job_wire(session, job)

    def download(self, principal: Principal, document_id: str) -> tuple[dict[str, Any], bytes]:
        with self.session_factory() as session:
            identity, _, _ = self._services(session)
            identity.authorize(principal, "assets.view", resource="reports:documents")
            document = session.get(ReportDocument, document_id)
            if document is None or document.deleted_at is not None:
                raise NotFound("document not found")
            if document.owner_id != principal.actor_id and not self._is_admin(principal):
                raise NotFound("document not found")
            cutoff = utcnow() - timedelta(days=self.settings.report_retention_days)
            if as_utc(document.created_at) <= cutoff:
                document.deleted_at = utcnow()
                session.commit()
                raise NotFound("document expired")
            data = self._storage_backend().read(
                document.blob_key, self.settings.report_max_document_bytes
            )
            if len(data) != document.size or hashlib.sha256(data).hexdigest() != document.sha256:
                raise StorageUnavailable("document integrity check failed")
            payload = {
                "id": document.id,
                "name": document.name,
                "mime": document.mime,
                "size": document.size,
                "downloadUrl": (
                    f"{self.settings.api_prefix}/reports/documents/{document.id}/download"
                ),
                "assetId": document.asset_id,
            }
            return payload, data

    # -------------------------------------------------------------------- QR
    def qr(self, principal: Principal, asset_id: str) -> dict[str, Any]:
        with self.session_factory() as session:
            identity, inventory, _ = self._services(session)
            asset = inventory.get(principal, asset_id)
            identity.authorize(principal, "assets.view", resource=f"asset:{asset.id}")
            settings_wire = self._settings_wire(session, self._stored_settings(session))
            base_url = self._validate_base_url(settings_wire["baseUrl"])
            url = qr.asset_report_url(base_url, asset.id)
            share = session.execute(
                select(ReportShare)
                .where(
                    ReportShare.asset_id == asset.id,
                    ReportShare.issuer_id == principal.actor_id,
                    ReportShare.revoked_at.is_(None),
                    ReportShare.expires_at > utcnow(),
                )
                .order_by(ReportShare.created_at.desc())
                .limit(1)
            ).scalar_one_or_none()
            share_payload = None
            if share is not None:
                share_payload = {
                    "id": share.id,
                    "fields": list(share.fields or []),
                    "expiresAt": as_utc(share.expires_at).isoformat(),
                    "revokedAt": None,
                }
            return {
                "assetId": asset.id,
                "url": url,
                "svg": qr.qr_svg(url),
                "share": share_payload,
            }

    def asset_report(self, principal: Principal, asset_id: str) -> dict[str, Any]:
        """Limited private data for the authenticated report page (no history/blob links)."""
        with self.session_factory() as session:
            identity, inventory, _ = self._services(session)
            asset = inventory.get(principal, asset_id)
            identity.authorize(principal, "assets.view", resource=f"asset:{asset.id}")
            settings_wire = self._settings_wire(session, self._stored_settings(session))
            base_url = self._validate_base_url(settings_wire["baseUrl"])
            return {
                "asset": project_asset(asset, ASSET_FIELDS),
                "fields": list(ASSET_FIELDS),
                "qr": {"url": qr.asset_report_url(base_url, asset.id)},
            }

    # --------------------------------------------------------------- sharing
    @staticmethod
    def _share_fields(fields: Any) -> list[str]:
        if isinstance(fields, str) or not isinstance(fields, Iterable):
            raise ValidationFailed("fields must be a list of public field keys")
        selected: list[str] = []
        for field in fields:
            if not isinstance(field, str) or field not in PUBLIC_FIELDS:
                raise ValidationFailed("public fields must be one of " + ", ".join(PUBLIC_FIELDS))
            if field not in selected:
                selected.append(field)
        if not selected:
            raise ValidationFailed("at least one public field is required")
        return selected

    def create_share(
        self,
        principal: Principal,
        asset_id: str,
        fields: Sequence[str],
        expires_in_days: int = 30,
    ) -> dict[str, Any]:
        selected = self._share_fields(fields)
        if (
            type(expires_in_days) is not int
            or not SHARE_DAYS_MIN <= expires_in_days <= SHARE_DAYS_MAX
        ):
            raise ValidationFailed("expiresInDays must be 1-365")
        with self.session_factory() as session:
            identity, inventory, _ = self._services(session)
            identity.authorize(principal, "reports.share", resource="reports:shares")
            asset = inventory.get(principal, asset_id)
            settings_wire = self._settings_wire(session, self._stored_settings(session))
            base_url = self._validate_base_url(settings_wire["baseUrl"])
            token = secrets.token_urlsafe(SHARE_TOKEN_BYTES)
            now = utcnow()
            row = ReportShare(
                id=str(uuid4()),
                asset_id=asset.id,
                token_hash=_hash_token(token),
                fields=selected,
                issuer_id=principal.actor_id,
                created_at=now,
                expires_at=now + timedelta(days=expires_in_days),
                revoked_at=None,
                revoked_by=None,
            )
            session.add(row)
            session.commit()
            identity.record_operation(
                principal,
                action="reports.share_created",
                resource=f"report-share:{row.id}",
            )
            session.commit()
            return {
                "id": row.id,
                "url": f"{base_url}/#/reporte/{asset.id}/publico?share={token}",
                "fields": list(row.fields),
                "expiresAt": as_utc(row.expires_at).isoformat(),
            }

    def revoke_share(self, principal: Principal, share_id: str) -> dict[str, Any]:
        with self.session_factory() as session:
            identity, _, _ = self._services(session)
            identity.authorize(principal, "reports.share", resource="reports:shares")
            row = session.get(ReportShare, share_id)
            if row is None:
                raise NotFound("share not found")
            if row.revoked_at is None:
                row.revoked_at = utcnow()
                row.revoked_by = principal.username
                session.commit()
                identity.record_operation(
                    principal,
                    action="reports.share_revoked",
                    resource=f"report-share:{row.id}",
                )
                session.commit()
            return {"id": row.id, "revoked": True}

    def public_report(self, token: str) -> dict[str, Any]:
        """Anonymous, tokenized, independently re-authorized projection only."""
        if not isinstance(token, str) or not 20 <= len(token) <= 200:
            raise NotFound("report not found")
        token_digest = _hash_token(token)
        with self.session_factory() as session:
            row = session.execute(
                select(ReportShare).where(ReportShare.token_hash == token_digest)
            ).scalar_one_or_none()
            if row is None or row.revoked_at is not None or as_utc(row.expires_at) <= utcnow():
                raise NotFound("report not found")
            asset = session.get(Asset, row.asset_id)
            if asset is None:
                raise NotFound("report not found")
            identity, _, _ = self._services(session)
            try:
                issuer = identity.resolve_actor(row.issuer_id)
                identity.authorize(issuer, "reports.share", resource=f"report-share:{row.id}")
            except (PermissionDenied, NotFound) as exc:
                raise NotFound("report not found") from exc
            return {
                "asset": public_asset(session, asset, list(row.fields or [])),
                "fields": list(row.fields or []),
                "expiresAt": as_utc(row.expires_at).isoformat(),
            }

    # ------------------------------------------------------------- execution
    def _resolve_executor(
        self, session: Session, identity: IdentityService, job: ReportJob
    ) -> Principal:
        executor = dict(job.executor or {})
        actor_id = executor.get("actorId")
        if not isinstance(actor_id, str) or not actor_id:
            raise PermissionDenied("report executor is not available")
        principal = identity.resolve_actor(
            actor_id,
            scopes=frozenset(executor.get("scopes") or ()),
            execution_id=executor.get("executionId"),
            authorization_ref=executor.get("authorizationRef"),
        )
        session_id = executor.get("sessionId")
        if principal.kind == "human":
            # A job created through an AI/MCP tool may carry a resolved human
            # principal without a browser session; permission re-resolution below
            # still applies. When a session was used, it must still be live.
            if isinstance(session_id, str) and session_id:
                row = session.get(IdentitySession, session_id)
                if (
                    row is None
                    or row.identity_id != principal.actor_id
                    or row.revoked_at is not None
                    or as_utc(row.expires_at) <= utcnow()
                ):
                    raise PermissionDenied("report executor session is no longer valid")
        else:
            digest = executor.get("credentialDigest")
            if not isinstance(digest, str) or not digest:
                raise PermissionDenied("report executor credential is not available")
            credential = session.execute(
                select(IdentityCredential).where(
                    IdentityCredential.identity_id == principal.actor_id,
                    IdentityCredential.token_digest == digest,
                    IdentityCredential.revoked_at.is_(None),
                )
            ).scalar_one_or_none()
            if credential is None:
                raise PermissionDenied("report executor credential is no longer valid")
        identity.authorize(principal, "assets.view", resource=f"report-job:{job.id}")
        return principal

    def _record_error(self, job: ReportJob, message: str, asset_id: str | None = None) -> None:
        errors = list(job.errors or [])
        if len(errors) >= MAX_ERRORS:
            if not any(item.get("message") == "additional errors omitted" for item in errors):
                errors[-1] = {"message": "additional errors omitted"}
            job.errors = errors
            return
        errors.append({"assetId": asset_id, "message": message[:300]})
        job.errors = errors

    def _fail(
        self, session: Session, job: ReportJob, message: str, asset_id: str | None = None
    ) -> None:
        self._record_error(job, message, asset_id)
        job.status = "failed"
        job.updated_at = utcnow()
        job.completed_at = utcnow()
        session.commit()

    def _requeue(self, session: Session, job: ReportJob, message: str) -> None:
        self._record_error(job, message)
        job.status = "queued"
        job.updated_at = utcnow()
        session.commit()

    @staticmethod
    def _existing_document(
        session: Session, job_id: str, asset_id: str | None
    ) -> ReportDocument | None:
        query = select(ReportDocument).where(
            ReportDocument.job_id == job_id,
            ReportDocument.deleted_at.is_(None),
        )
        query = (
            query.where(ReportDocument.asset_id.is_(None))
            if asset_id is None
            else query.where(ReportDocument.asset_id == asset_id)
        )
        return session.execute(query).scalars().first()

    def _store_document(
        self,
        session: Session,
        job: ReportJob,
        *,
        asset_id: str | None,
        name: str,
        mime: str,
        data: bytes,
    ) -> ReportDocument:
        if not data:
            raise ValidationFailed("report output is empty")
        if len(data) > self.settings.report_max_document_bytes:
            raise ValidationFailed("report output exceeds the document size limit")
        blob_key = uuid4().hex
        storage = self._storage_backend()
        storage.put(blob_key, data)
        document = ReportDocument(
            id=str(uuid4()),
            job_id=job.id,
            owner_id=job.owner_id,
            asset_id=asset_id,
            name=name,
            mime=mime,
            size=len(data),
            blob_key=blob_key,
            sha256=hashlib.sha256(data).hexdigest(),
            created_at=utcnow(),
            deleted_at=None,
            delete_error=None,
        )
        session.add(document)
        try:
            session.commit()
        except Exception:
            session.rollback()
            with suppress(OSError):
                storage.delete(blob_key)
            raise
        return document

    def _render(self, document: Any) -> bytes:
        data = rendering.render_pdf(
            document,
            timeout_seconds=self.settings.report_render_timeout_seconds,
            memory_mb=self.settings.report_render_memory_mb,
            max_bytes=self.settings.report_max_document_bytes,
        )
        if not data.startswith(b"%PDF-"):
            raise RuntimeError("renderer did not return a PDF document")
        return data

    def _run(
        self,
        session: Session,
        identity: IdentityService,
        inventory: InventoryService,
        warranties: WarrantyService,
        principal: Principal,
        job: ReportJob,
    ) -> None:
        model = ReportRequest.model_validate(job.request)
        collected = self._collect(session, identity, inventory, warranties, principal, model)
        assets = collected.table.assets
        job.total = len(assets) if assets else 1
        job.processed = 0
        job.updated_at = utcnow()
        session.commit()
        if collected.output != "pdf":
            if self._existing_document(session, job.id, None) is not None:
                job.processed = job.total
                job.status = "completed"
                job.completed_at = utcnow()
                session.commit()
                return
            mime = DOCUMENT_MIMES[collected.output]
            extension = DOCUMENT_EXTENSIONS[collected.output]
            export = export_table(collected.table, collected.document)
            if collected.output == "csv":
                payload = csv_bytes(export.rows, export.columns)
            else:
                payload = xlsx_bytes(export.rows, export.columns, collected.document)
            name = _document_name(collected.title, extension)
            self._store_document(session, job, asset_id=None, name=name, mime=mime, data=payload)
            job.processed = job.total
            job.status = "completed"
            job.completed_at = utcnow()
            session.commit()
            return
        if collected.mode == "individual" and assets:
            for asset in assets:
                if self._existing_document(session, job.id, asset.id) is not None:
                    job.processed = min(job.processed + 1, job.total)
                    session.commit()
                    continue
                try:
                    subset = self._subset_table(collected, asset)
                    current = collected
                    if collected.template.get("images"):
                        current = replace(
                            collected,
                            images=self._load_images(inventory, principal, [asset]),
                        )
                    document = self._compose(current, [asset], subset, labels=collected.labels)
                    payload = self._render(document)
                    self._store_document(
                        session,
                        job,
                        asset_id=asset.id,
                        name=_document_name(collected.title, ".pdf", asset),
                        mime=DOCUMENT_MIMES["pdf"],
                        data=payload,
                    )
                except OSError, StorageUnavailable, rendering.RenderError:
                    raise
                except Exception as exc:
                    self._record_error(job, _bounded_error(exc), asset.id)
                job.processed = min(job.processed + 1, job.total)
                job.updated_at = utcnow()
                session.commit()
            has_document = (
                session.execute(
                    select(ReportDocument.id)
                    .where(
                        ReportDocument.job_id == job.id,
                        ReportDocument.deleted_at.is_(None),
                    )
                    .limit(1)
                ).first()
                is not None
            )
            job.status = "completed" if has_document else "failed"
            job.completed_at = utcnow()
            session.commit()
            return
        if self._existing_document(session, job.id, None) is not None:
            job.processed = job.total
            job.status = "completed"
            job.completed_at = utcnow()
            session.commit()
            return
        document = self._compose(collected, assets, collected.table, labels=collected.labels)
        payload = self._render(document)
        self._store_document(
            session,
            job,
            asset_id=None,
            name=_document_name(collected.title, ".pdf"),
            mime=DOCUMENT_MIMES["pdf"],
            data=payload,
        )
        job.processed = job.total
        job.status = "completed"
        job.completed_at = utcnow()
        session.commit()

    def execute(self, job_id: str) -> dict[str, Any]:
        """Claim one job atomically, re-resolve authority and process it.

        The claim is one conditional SQL UPDATE evaluated by the database, never
        by the ORM session. The stored session or machine-credential digest is
        revalidated before any rendering. Retryable infrastructure failures are
        persisted and re-raised so Huey can retry; completed documents are never
        duplicated by a retry.
        """
        with self.session_factory() as session:
            job = session.get(ReportJob, job_id)
            if job is None:
                raise NotFound("job not found")
            if job.status == "completed":
                return self._job_wire(session, job)
            now = utcnow()
            stale_before = now - timedelta(
                seconds=max(2 * self.settings.report_render_timeout_seconds + 60, 120)
            )
            claimed = session.execute(
                update(ReportJob)
                .where(
                    ReportJob.id == job_id,
                    or_(
                        ReportJob.status == "queued",
                        and_(
                            ReportJob.status == "running",
                            ReportJob.claimed_at.is_not(None),
                            ReportJob.claimed_at < stale_before,
                        ),
                    ),
                )
                .values(status="running", claimed_at=now, updated_at=now)
                .execution_options(synchronize_session=False)
            )
            session.commit()
            if claimed.rowcount != 1:
                session.refresh(job)
                return self._job_wire(session, job)
            session.refresh(job)
            identity, inventory, warranties = self._services(session)
            try:
                principal = self._resolve_executor(session, identity, job)
            except (PermissionDenied, NotFound) as exc:
                self._fail(session, job, _bounded_error(exc))
                return self._job_wire(session, job)
            try:
                self._run(session, identity, inventory, warranties, principal, job)
            except (OSError, StorageUnavailable, rendering.RenderError) as exc:
                self._requeue(session, job, _bounded_error(exc))
                raise
            except Exception as exc:
                self._fail(session, job, _bounded_error(exc))
            return self._job_wire(session, job)

    # --------------------------------------------------------------- cleanup
    def _delete_blob(self, document: ReportDocument) -> bool:
        try:
            self._storage_backend().delete(document.blob_key)
        except FileNotFoundError:
            return True
        except (OSError, StorageUnavailable) as exc:
            document.delete_error = _bounded_error(exc)[:200]
            return False
        return True

    def cleanup(self) -> dict[str, int]:
        """Tombstone expired metadata first, then delete blobs; retry failures."""
        deleted = 0
        pending = 0
        with self.session_factory() as session:
            now = utcnow()
            cutoff = now - timedelta(days=self.settings.report_retention_days)
            expired = session.execute(
                select(ReportDocument).where(
                    ReportDocument.deleted_at.is_(None),
                    ReportDocument.created_at <= cutoff,
                )
            ).scalars()
            for document in list(expired):
                document.deleted_at = now
                document.delete_error = None
                session.commit()
                if self._delete_blob(document):
                    session.delete(document)
                    deleted += 1
                else:
                    pending += 1
                session.commit()
            retry = session.execute(
                select(ReportDocument).where(ReportDocument.deleted_at.is_not(None))
            ).scalars()
            for document in list(retry):
                if self._delete_blob(document):
                    session.delete(document)
                    deleted += 1
                else:
                    pending += 1
                session.commit()
        return {"deleted": deleted, "pending": pending}


def build_report_service(
    settings: Settings,
    session_factory: Callable[[], Session],
    task_queue: Any | None = None,
) -> ReportService:
    """Single construction helper for API, worker, Pydantic AI and FastMCP."""
    return ReportService(session_factory, settings=settings, task_queue=task_queue)
