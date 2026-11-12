"""Structured wire contracts shared by report services, agents and the API.

Everything crossing this boundary is bounded: unknown keys are rejected, text
is plain (never HTML or CSS) and templates may only name admitted block types
and asset fields.  ``model_dump()`` returns the camelCase wire shape.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    field_validator,
    model_validator,
)

from itsm.i18n.catalog import resolve_installed_locale

FAMILIES: tuple[str, ...] = ("inventory", "history", "warranty")
MODES: tuple[str, ...] = ("list", "sheet")
TEMPLATE_FORMATS: tuple[str, ...] = ("A4", "Letter")
REPORT_OUTPUTS: tuple[str, ...] = ("pdf", "csv", "xlsx")
BLOCK_TYPES: tuple[str, ...] = (
    "heading",
    "text",
    "asset",
    "table",
    "photo",
    "summary",
    "qr",
    "footer",
)
ASSET_FIELDS: tuple[str, ...] = (
    "id",
    "quickCode",
    "name",
    "category",
    "site",
    "location",
    "status",
    "responsible",
    "serial",
    "brand",
    "model",
    "ip",
    "purchaseCost",
    "technical",
)
GROUPINGS: tuple[str, ...] = (
    "none",
    "category",
    "site",
    "responsible",
    "location",
    "status",
)
HISTORY_FIELDS: tuple[str, ...] = (
    "quickCode",
    "name",
    "action",
    "actor",
    "effectiveAt",
    "entityType",
    "entityId",
    "statusOld",
    "statusNew",
    "changes",
    "notes",
    "source",
    "assetId",
)
WARRANTY_FIELDS: tuple[str, ...] = (
    "quickCode",
    "name",
    "category",
    "site",
    "supplier",
    "purchaseDate",
    "expiresOn",
    "coverage",
    "receiptId",
    "notes",
    "assetId",
)
HISTORY_DEFAULT_FIELDS: tuple[str, ...] = (
    "quickCode",
    "action",
    "actor",
    "effectiveAt",
    "entityType",
    "changes",
    "notes",
)
WARRANTY_DEFAULT_FIELDS: tuple[str, ...] = (
    "quickCode",
    "name",
    "category",
    "site",
    "supplier",
    "purchaseDate",
    "expiresOn",
    "coverage",
    "receiptId",
    "notes",
)
INVENTORY_DEFAULT_FIELDS: tuple[str, ...] = (
    "id",
    "quickCode",
    "name",
    "category",
    "site",
    "location",
    "status",
    "responsible",
)
FAMILY_FIELDS: dict[str, tuple[str, ...]] = {
    "inventory": ASSET_FIELDS,
    "history": HISTORY_FIELDS,
    "warranty": WARRANTY_FIELDS,
}
FAMILY_DEFAULT_FIELDS: dict[str, tuple[str, ...]] = {
    "inventory": INVENTORY_DEFAULT_FIELDS,
    "history": HISTORY_DEFAULT_FIELDS,
    "warranty": WARRANTY_DEFAULT_FIELDS,
}
PUBLIC_ASSET_FIELDS: tuple[str, ...] = (
    "id",
    "quickCode",
    "name",
    "category",
    "site",
    "location",
    "status",
)
LABEL_FORMATS: tuple[str, ...] = ("a4-24", "a4-21", "roll-50x30", "roll-80x50", "custom")
LABEL_FIELDS: tuple[str, ...] = (
    "logo",
    "name",
    "id",
    "code",
    "qr",
    "site",
    "location",
    "serial",
)
WARRANTY_FILTERS: tuple[str, ...] = ("all", "active", "expiring", "expired", "missing")

FIELD_LABELS: dict[str, str] = {
    "id": "ID permanente",
    "quickCode": "Código rápido",
    "name": "Nombre",
    "category": "Categoría",
    "site": "Sede",
    "location": "Ubicación",
    "status": "Estado",
    "responsible": "Responsable",
    "serial": "Número de serie",
    "brand": "Marca",
    "model": "Modelo",
    "ip": "Dirección IP",
    "purchaseCost": "Coste de compra",
    "technical": "Datos técnicos",
    "action": "Acción",
    "actor": "Actor",
    "effectiveAt": "Fecha efectiva",
    "entityType": "Tipo de entidad",
    "entityId": "ID de entidad",
    "statusOld": "Estado anterior",
    "statusNew": "Estado nuevo",
    "changes": "Cambios",
    "notes": "Notas",
    "source": "Origen",
    "assetId": "ID del activo",
    "supplier": "Proveedor",
    "purchaseDate": "Fecha de compra",
    "expiresOn": "Vencimiento",
    "coverage": "Cobertura",
    "receiptId": "ID del recibo",
}
LABEL_FIELD_LABELS: dict[str, str] = {
    "logo": "Logotipo",
    "name": "Nombre",
    "id": "ID permanente",
    "code": "Código rápido",
    "qr": "Código QR",
    "site": "Sede",
    "location": "Ubicación",
    "serial": "Número de serie",
}

MAX_ASSET_IDS = 500
MAX_TEMPLATE_BLOCKS = 40
MAX_LABEL_OFFSET = 500
TEMPLATE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"
HANDLE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"
COLOR_PATTERN = re.compile(r"^#[0-9a-f]{6}$")

Family = Literal["inventory", "history", "warranty"]
TemplateMode = Literal["list", "sheet"]
TemplateFormat = Literal["A4", "Letter"]
Output = Literal["pdf", "csv", "xlsx"]
BlockType = Literal["heading", "text", "asset", "table", "photo", "summary", "qr", "footer"]
AssetField = Literal[
    "id",
    "quickCode",
    "name",
    "category",
    "site",
    "location",
    "status",
    "responsible",
    "serial",
    "brand",
    "model",
    "ip",
    "purchaseCost",
    "technical",
]
ReportField = Literal[
    "id",
    "quickCode",
    "name",
    "category",
    "site",
    "location",
    "status",
    "responsible",
    "serial",
    "brand",
    "model",
    "ip",
    "purchaseCost",
    "technical",
    "action",
    "actor",
    "effectiveAt",
    "entityType",
    "entityId",
    "statusOld",
    "statusNew",
    "changes",
    "notes",
    "source",
    "assetId",
    "supplier",
    "purchaseDate",
    "expiresOn",
    "coverage",
    "receiptId",
]
Grouping = Literal["none", "category", "site", "responsible", "location", "status"]
LabelFormat = Literal["a4-24", "a4-21", "roll-50x30", "roll-80x50", "custom"]
LabelField = Literal["logo", "name", "id", "code", "qr", "site", "location", "serial"]
WarrantyFilter = Literal["all", "active", "expiring", "expired", "missing"]


def _control_free(value: str, *, multiline: bool = False) -> str:
    for character in value:
        code = ord(character)
        if code == 127 or (code < 32 and not (multiline and character in "\n\t")):
            raise ValueError("control characters are not allowed")
    return value


def _plain_text(value: Any, *, multiline: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("text must be a string")
    return _control_free(value, multiline=multiline)


def _single_line(value: Any) -> str:
    return _plain_text(value).strip()


def _optional_text(value: Any, *, multiline: bool = False) -> str | None:
    if value is None:
        return None
    text = _plain_text(value, multiline=multiline).strip()
    return text or None


def _uuid_text(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a UUID string")
    text = value.strip()
    if not text:
        raise ValueError(f"{field} must be a UUID string")
    try:
        return str(UUID(text))
    except ValueError:
        raise ValueError(f"{field} must be a UUID string") from None


def _color(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("branding colors must be #rrggbb strings")
    text = value.strip().lower()
    if not text:
        return ""
    if not COLOR_PATTERN.fullmatch(text):
        raise ValueError("branding colors must use the #rrggbb form")
    return text


def _iso_date(value: Any) -> str | None:
    text = _optional_text(value)
    if text is None:
        return None
    try:
        if len(text) == 10:
            return date.fromisoformat(text).isoformat()
        return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        raise ValueError("dates must use ISO-8601 (YYYY-MM-DD)") from None


class TemplateBlock(BaseModel):
    """One admitted composition block; unknown parameters never reach the renderer."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=64, pattern=HANDLE_PATTERN)
    type: BlockType
    label: str = Field(default="", max_length=120)
    text: str = Field(default="", max_length=2000)
    enabled: StrictBool = True

    @field_validator("label")
    @classmethod
    def _check_label(cls, value: str) -> str:
        return _plain_text(value)

    @field_validator("text")
    @classmethod
    def _check_text(cls, value: str) -> str:
        return _plain_text(value, multiline=True)


class TemplateDefinition(BaseModel):
    """Versioned, structured template definition; no code or raw HTML is admitted."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=64, pattern=TEMPLATE_ID_PATTERN)
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    family: Family
    mode: TemplateMode = "list"
    format: TemplateFormat = "A4"
    fields: list[ReportField] = Field(
        default_factory=list, max_length=max(len(value) for value in FAMILY_FIELDS.values())
    )
    logo: StrictBool = True
    images: StrictBool = False
    version: Literal[1] = 1
    blocks: list[TemplateBlock] = Field(
        default_factory=list, min_length=1, max_length=MAX_TEMPLATE_BLOCKS
    )

    @field_validator("name", "description")
    @classmethod
    def _check_name(cls, value: str, info) -> str:
        text = _plain_text(value, multiline=info.field_name == "description")
        stripped = text.strip()
        if info.field_name == "name" and not stripped:
            raise ValueError("template name is required")
        return stripped

    @field_validator("fields")
    @classmethod
    def _unique_fields(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("template fields must not repeat")
        return value

    @model_validator(mode="after")
    def _family_fields(self) -> TemplateDefinition:
        allowed = set(FAMILY_FIELDS[self.family])
        unknown = [field for field in self.fields if field not in allowed]
        if unknown:
            raise ValueError(f"fields are not available for the {self.family} family")
        return self

    @model_validator(mode="after")
    def _unique_blocks(self) -> TemplateDefinition:
        ids = [block.id for block in self.blocks]
        if len(set(ids)) != len(ids):
            raise ValueError("template block ids must be unique")
        return self


class LabelOptions(BaseModel):
    """Bounded physical label geometry; presets are canonicalized by composition."""

    model_config = ConfigDict(extra="forbid")

    formatId: LabelFormat = "a4-24"
    widthMm: float | None = Field(default=None, ge=10, le=500, allow_inf_nan=False)
    heightMm: float | None = Field(default=None, ge=10, le=500, allow_inf_nan=False)
    pageWidthMm: float | None = Field(default=None, ge=20, le=1000, allow_inf_nan=False)
    pageHeightMm: float | None = Field(default=None, ge=20, le=1000, allow_inf_nan=False)
    marginTopMm: float = Field(default=0, ge=0, le=50, allow_inf_nan=False)
    marginRightMm: float = Field(default=0, ge=0, le=50, allow_inf_nan=False)
    marginBottomMm: float = Field(default=0, ge=0, le=50, allow_inf_nan=False)
    marginLeftMm: float = Field(default=0, ge=0, le=50, allow_inf_nan=False)
    gapXmm: float = Field(default=0, ge=0, le=30, allow_inf_nan=False)
    gapYmm: float = Field(default=0, ge=0, le=30, allow_inf_nan=False)
    columns: int = Field(default=1, ge=1, le=12)
    offset: int = Field(default=0, ge=0, le=MAX_LABEL_OFFSET)
    fields: list[LabelField] = Field(
        default_factory=lambda: ["logo", "name", "id", "code", "qr"],
        max_length=len(LABEL_FIELDS),
    )
    logo: StrictBool = False
    qr: StrictBool = False

    @field_validator("fields")
    @classmethod
    def _unique_label_fields(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("label fields must not repeat")
        return value

    @model_validator(mode="after")
    def _custom_geometry_and_content(self) -> LabelOptions:
        if self.formatId == "custom":
            missing = [
                name
                for name in ("widthMm", "heightMm", "pageWidthMm", "pageHeightMm")
                if getattr(self, name) is None
            ]
            if missing:
                raise ValueError(
                    "custom label format requires explicit width, height and page size"
                )
        effective = set(self.fields)
        if self.logo:
            effective.add("logo")
        if self.qr:
            effective.add("qr")
        if not effective:
            raise ValueError("a label needs at least one field")
        return self


class ReportFilters(BaseModel):
    """Explicit filters; empty strings and nulls mean "no filter"."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, serialize_by_alias=True)

    search: str | None = Field(default=None, max_length=200)
    category: str | None = Field(default=None, max_length=120)
    site: str | None = Field(default=None, max_length=120)
    siteId: str | None = Field(default=None, max_length=36)
    locationId: str | None = Field(default=None, max_length=36)
    responsiblePersonId: str | None = Field(default=None, max_length=36)
    status: str | None = Field(default=None, max_length=120)
    archived: StrictBool | None = None
    from_: str | None = Field(default=None, alias="from", max_length=40)
    to: str | None = Field(default=None, max_length=40)
    actor: str | None = Field(default=None, max_length=120)
    event: str | None = Field(default=None, max_length=120)
    warrantyFilter: WarrantyFilter | None = None

    @field_validator("search", "category", "site", "status", "actor", "event")
    @classmethod
    def _optional_plain(cls, value: str | None) -> str | None:
        return _optional_text(value)

    @field_validator("siteId", "locationId", "responsiblePersonId")
    @classmethod
    def _optional_uuid(cls, value: str | None, info) -> str | None:
        if value is None or not value.strip():
            return None
        return _uuid_text(value, field=info.field_name)

    @field_validator("from_", "to")
    @classmethod
    def _dates(cls, value: str | None) -> str | None:
        return _iso_date(value)

    @field_validator("warrantyFilter", mode="before")
    @classmethod
    def _empty_warranty_filter(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            return None
        return value


class ReportRequest(BaseModel):
    """One report request; the server re-resolves data, templates and authority."""

    model_config = ConfigDict(extra="forbid")

    family: Family
    templateId: str | None = Field(default=None, max_length=64, pattern=TEMPLATE_ID_PATTERN)
    template: TemplateDefinition | None = None
    assetIds: list[str] = Field(default_factory=list, max_length=MAX_ASSET_IDS)
    filters: ReportFilters = Field(default_factory=lambda: ReportFilters())
    fields: list[ReportField] = Field(
        default_factory=list, max_length=max(len(value) for value in FAMILY_FIELDS.values())
    )
    group: Grouping = "none"
    mode: Literal["consolidated", "individual"] = "consolidated"
    output: Output = "pdf"
    name: str = Field(default="Reporte", max_length=160)
    locale: str | None = Field(default=None, max_length=35)
    labels: LabelOptions | None = None

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        text = _single_line(value)
        if not text:
            raise ValueError("report name is required")
        return text

    @field_validator("locale")
    @classmethod
    def _installed_locale(cls, value: str | None) -> str | None:
        if value is None:
            return None
        resolved = resolve_installed_locale(value)
        if resolved is None:
            raise ValueError(f"unknown locale: {value}")
        return resolved

    @field_validator("assetIds")
    @classmethod
    def _canonical_ids(cls, value: list[str]) -> list[str]:
        ordered: list[str] = []
        seen: set[str] = set()
        for item in value:
            canonical = _uuid_text(item, field="assetIds entries")
            if canonical not in seen:
                seen.add(canonical)
                ordered.append(canonical)
        return ordered

    @field_validator("fields")
    @classmethod
    def _unique_fields(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("request fields must not repeat")
        return value

    @model_validator(mode="after")
    def _coherent_flags(self) -> ReportRequest:
        allowed = set(FAMILY_FIELDS[self.family])
        unknown = [field for field in self.fields if field not in allowed]
        if unknown:
            raise ValueError(f"fields are not available for the {self.family} family")
        if self.templateId is not None and self.template is not None:
            raise ValueError("provide templateId or template, not both")
        if self.labels is not None:
            if self.family != "inventory":
                raise ValueError("labels are only available for the inventory family")
            if self.output != "pdf":
                raise ValueError("labels are only rendered as PDF")
        return self


class BrandingSettings(BaseModel):
    """Active organization branding; text is plain, colors are hex only."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(default="", max_length=120)
    primary: str = "#0d766e"
    accent: str = "#147c73"
    header: str = Field(default="", max_length=500)
    footer: str = Field(default="", max_length=500)
    logoAttachmentId: str | None = Field(default=None, max_length=36)

    @field_validator("name")
    @classmethod
    def _brand_name(cls, value: str) -> str:
        return _single_line(value)

    @field_validator("primary", "accent")
    @classmethod
    def _brand_color(cls, value: str) -> str:
        return _color(value)

    @field_validator("header", "footer")
    @classmethod
    def _brand_text(cls, value: str) -> str:
        return _plain_text(value, multiline=True)

    @field_validator("logoAttachmentId")
    @classmethod
    def _logo_id(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        return _uuid_text(value, field="logoAttachmentId")


def _normalize_base_url(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("baseUrl must be a string")
    raw = value
    if not raw:
        return ""
    if raw != raw.strip():
        raise ValueError("baseUrl must not start or end with whitespace")
    if len(raw) > 400:
        raise ValueError("baseUrl must be at most 400 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        raise ValueError("baseUrl must not contain control characters")
    if any(character.isspace() for character in raw):
        raise ValueError("baseUrl must not contain whitespace")
    if "?" in raw or "#" in raw:
        raise ValueError("baseUrl must not contain a query string or fragment")
    if "\\" in raw:
        raise ValueError("baseUrl must not contain backslashes")
    if any(character in raw for character in '<>"'):
        raise ValueError("baseUrl must not contain markup characters")
    try:
        parts = urlsplit(raw)
        _ = parts.port
    except ValueError:
        raise ValueError("baseUrl must be a valid http(s) URL") from None
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise ValueError("baseUrl must be http(s) without credentials, query string or fragment")
    path = parts.path or "/"
    if not path.endswith("/"):
        path += "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc, path, "", ""))


class ReportSettingsInput(BaseModel):
    """Configurable report/QR/branding settings; no HTML, CSS or paths admitted."""

    model_config = ConfigDict(extra="forbid")

    baseUrl: str = Field(default="", max_length=400)
    branding: BrandingSettings = Field(default_factory=BrandingSettings)
    labelDefaults: LabelOptions = Field(default_factory=LabelOptions)

    @field_validator("baseUrl")
    @classmethod
    def _base_url(cls, value: str) -> str:
        return _normalize_base_url(value)


def builtin_templates() -> list[dict[str, Any]]:
    """Default templates available immediately, without any seed-time writes."""

    common_footer = TemplateBlock(
        id="footer",
        type="footer",
        label="Pie de documento",
        text="Documento generado por el ITSM.",
    )
    inventory_fields = [
        "id",
        "quickCode",
        "name",
        "category",
        "site",
        "location",
        "status",
        "responsible",
    ]
    definitions = [
        TemplateDefinition(
            id="inventory-list",
            name="Inventario · listado",
            description="Listado consolidado de activos con los campos habituales.",
            family="inventory",
            mode="list",
            format="A4",
            fields=inventory_fields,
            logo=True,
            images=False,
            blocks=[
                TemplateBlock(
                    id="heading",
                    type="heading",
                    label="Inventario de activos",
                    text="Inventario de activos",
                ),
                TemplateBlock(id="table", type="table", label="Activos", text=""),
                TemplateBlock(id="summary", type="summary", label="Resumen por estado", text=""),
                common_footer,
            ],
        ),
        TemplateDefinition(
            id="inventory-sheet",
            name="Ficha de activo",
            description="Ficha individual con datos técnicos, imágenes y QR permanente.",
            family="inventory",
            mode="sheet",
            format="A4",
            fields=[
                "id",
                "quickCode",
                "name",
                "category",
                "site",
                "location",
                "status",
                "responsible",
                "serial",
                "brand",
                "model",
                "technical",
            ],
            logo=True,
            images=True,
            blocks=[
                TemplateBlock(
                    id="heading", type="heading", label="Ficha de activo", text="Ficha de activo"
                ),
                TemplateBlock(id="asset", type="asset", label="Datos del activo", text=""),
                TemplateBlock(id="photo", type="photo", label="Imágenes", text=""),
                TemplateBlock(id="qr", type="qr", label="Código QR permanente", text=""),
                common_footer,
            ],
        ),
        TemplateDefinition(
            id="history-list",
            name="Historial y cambios",
            description="Movimientos, asignaciones e intervenciones en un período.",
            family="history",
            mode="list",
            format="A4",
            fields=list(HISTORY_DEFAULT_FIELDS),
            logo=True,
            images=False,
            blocks=[
                TemplateBlock(
                    id="heading",
                    type="heading",
                    label="Historial de cambios",
                    text="Historial de cambios",
                ),
                TemplateBlock(id="table", type="table", label="Actividad", text=""),
                common_footer,
            ],
        ),
        TemplateDefinition(
            id="warranty-list",
            name="Garantías",
            description="Garantías por activo, cobertura y vencimiento.",
            family="warranty",
            mode="list",
            format="A4",
            fields=list(WARRANTY_DEFAULT_FIELDS),
            logo=True,
            images=False,
            blocks=[
                TemplateBlock(id="heading", type="heading", label="Garantías", text="Garantías"),
                TemplateBlock(id="table", type="table", label="Garantías por activo", text=""),
                common_footer,
            ],
        ),
    ]
    return [definition.model_dump() for definition in definitions]
