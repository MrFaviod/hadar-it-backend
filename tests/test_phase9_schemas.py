"""W1 wire contracts: strict, versioned and safe for the service boundary."""

from __future__ import annotations

import uuid

import pytest
from itsm.reports.schemas import (
    ASSET_FIELDS,
    BLOCK_TYPES,
    FAMILIES,
    FIELD_LABELS,
    GROUPINGS,
    HISTORY_DEFAULT_FIELDS,
    HISTORY_FIELDS,
    LABEL_FIELDS,
    LABEL_FORMATS,
    PUBLIC_ASSET_FIELDS,
    WARRANTY_DEFAULT_FIELDS,
    WARRANTY_FIELDS,
    LabelOptions,
    ReportRequest,
    ReportSettingsInput,
    TemplateDefinition,
    builtin_templates,
)
from pydantic import ValidationError

TEMPLATE_KEYS = {
    "id",
    "name",
    "description",
    "family",
    "mode",
    "format",
    "fields",
    "logo",
    "images",
    "version",
    "blocks",
}
BLOCK_KEYS = {"id", "type", "label", "text", "enabled"}


def asset_id() -> str:
    return str(uuid.uuid4())


def template(*, blocks: list[dict] | None = None, **overrides) -> dict:
    payload = {
        "id": "inventory-list",
        "name": "Inventario",
        "description": "Listado de activos",
        "family": "inventory",
        "mode": "list",
        "format": "A4",
        "fields": ["id", "name"],
        "logo": True,
        "images": False,
        "version": 1,
        "blocks": blocks
        if blocks is not None
        else [
            {"id": "head", "type": "heading", "label": "Inventario", "text": "", "enabled": True}
        ],
    }
    payload.update(overrides)
    return payload


def block(**overrides) -> dict:
    payload = {
        "id": "block-1",
        "type": "text",
        "label": "Nota",
        "text": "Contenido",
        "enabled": True,
    }
    payload.update(overrides)
    return payload


def test_builtin_templates_are_complete_validated_wire_definitions():
    items = builtin_templates()

    assert (
        {item["family"] for item in items}
        == set(FAMILIES)
        == {
            "inventory",
            "history",
            "warranty",
        }
    )
    assert len({item["id"] for item in items}) == len(items)
    assert any(item["mode"] == "list" for item in items)
    assert any(item["mode"] == "sheet" and item["family"] == "inventory" for item in items)
    for item in items:
        assert set(item) == TEMPLATE_KEYS
        assert item["version"] == 1
        assert item["blocks"]
        assert all(set(entry) == BLOCK_KEYS for entry in item["blocks"])
        assert TemplateDefinition.model_validate(item).model_dump() == item

    # Each call returns fresh data: a caller cannot corrupt later documents.
    items[0]["name"] = "mutated"
    items[0]["blocks"][0]["text"] = "mutated"
    assert builtin_templates()[0]["name"] != "mutated"
    assert builtin_templates()[0]["blocks"][0]["text"] != "mutated"


def test_template_definition_accepts_every_documented_block_and_field():
    blocks = [block(id=f"b-{kind}", type=kind) for kind in BLOCK_TYPES]
    payload = template(
        blocks=blocks,
        fields=list(ASSET_FIELDS),
        mode="sheet",
        format="Letter",
        images=True,
    )

    parsed = TemplateDefinition.model_validate(payload)
    dumped = parsed.model_dump()

    assert dumped["fields"] == list(ASSET_FIELDS)
    assert [entry["type"] for entry in dumped["blocks"]] == list(BLOCK_TYPES)
    assert all(set(entry) == BLOCK_KEYS for entry in dumped["blocks"])
    assert set(dumped) == TEMPLATE_KEYS


@pytest.mark.parametrize(
    "overrides",
    [
        {"id": "bad id!"},
        {"id": ""},
        {"name": ""},
        {"name": "x" * 121},
        {"description": "x" * 501},
        {"family": "other"},
        {"mode": "grid"},
        {"format": "A3"},
        {"version": 2},
        {"version": "1"},
        {"fields": ["cost"]},
        {"fields": ["id", "id"]},
        {"fields": [*ASSET_FIELDS, "id"]},
        {"blocks": []},
        {"blocks": [block() for _ in range(41)]},
        {"unexpected": True},
    ],
)
def test_template_definition_rejects_unknown_or_out_of_bound_values(overrides):
    with pytest.raises(ValidationError):
        TemplateDefinition.model_validate(template(**overrides))


@pytest.mark.parametrize(
    "overrides",
    [
        {"type": "script"},
        {"type": "html"},
        {"id": "bad id!"},
        {"label": "x" * 121},
        {"text": "x" * 2001},
        {"enabled": "yes"},
        {"html": "<script>alert(1)</script>"},
        {"unexpected": 1},
    ],
)
def test_template_blocks_reject_anything_outside_the_renderer_allowlist(overrides):
    payload = template(blocks=[block(**overrides)])
    with pytest.raises(ValidationError):
        TemplateDefinition.model_validate(payload)


def test_report_request_defaults_are_safe_and_serialize_camel_case():
    request = ReportRequest(family="inventory")

    assert request.assetIds == []
    assert request.filters.search is None
    assert request.filters.archived is None
    assert request.fields == []
    assert request.group == "none"
    assert request.mode == "consolidated"
    assert request.output == "pdf"
    assert request.name == "Reporte"
    assert request.templateId is None
    assert request.template is None
    assert request.labels is None

    dumped = request.model_dump()
    assert set(dumped) == {
        "family",
        "templateId",
        "template",
        "assetIds",
        "filters",
        "fields",
        "group",
        "mode",
        "output",
        "name",
        "labels",
    }
    assert set(dumped["filters"]) == {
        "search",
        "category",
        "site",
        "siteId",
        "locationId",
        "responsiblePersonId",
        "status",
        "archived",
        "from",
        "to",
        "actor",
        "event",
        "warrantyFilter",
    }
    assert dumped["filters"]["from"] is None
    assert dumped["filters"]["to"] is None


def test_report_request_accepts_asset_filters_and_deduplicates_ids():
    first, second = asset_id(), asset_id()
    request = ReportRequest(
        family="inventory",
        assetIds=[first.upper(), first, second],
        filters={
            "search": "router",
            "category": "Cámara",
            "site": "",
            "siteId": None,
            "archived": False,
            "from": "2026-01-01",
            "to": "2026-02-28",
            "warrantyFilter": "all",
        },
        fields=list(ASSET_FIELDS),
        mode="individual",
        output="xlsx",
        name="Inventario de enero",
    )

    assert request.assetIds == [first, second]
    dumped = request.model_dump()
    assert dumped["filters"]["from"] == "2026-01-01"
    assert dumped["filters"]["to"] == "2026-02-28"
    assert dumped["filters"]["warrantyFilter"] == "all"
    assert dumped["fields"] == list(ASSET_FIELDS)

    limited = ReportRequest(family="inventory", assetIds=[asset_id() for _ in range(500)])
    assert len(limited.assetIds) == 500


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"family": "other"},
        {"family": "inventory", "unexpected": True},
        {"family": "inventory", "output": "docx"},
        {"family": "inventory", "mode": "grid"},
        {"family": "inventory", "name": ""},
        {"family": "inventory", "name": "x" * 161},
        {"family": "inventory", "templateId": "bad id!"},
        {"family": "inventory", "assetIds": ["not-a-uuid"]},
        {"family": "inventory", "assetIds": ["../../etc/passwd"]},
        {"family": "inventory", "assetIds": [""]},
        {"family": "inventory", "assetIds": [asset_id() for _ in range(501)]},
        {"family": "inventory", "fields": ["cost"]},
        {"family": "inventory", "fields": ["id", "id"]},
        {"family": "inventory", "filters": {"unknown": "x"}},
        {"family": "inventory", "filters": {"archived": "yes"}},
        {"family": "inventory", "filters": {"from": "yesterday"}},
        {"family": "inventory", "filters": {"siteId": "not-a-uuid"}},
        {"family": "inventory", "filters": {"warrantyFilter": "maybe"}},
        {"family": "inventory", "templateId": "inventory-list", "template": template()},
        {"family": "history", "labels": LabelOptions().model_dump()},
        {"family": "inventory", "output": "csv", "labels": LabelOptions().model_dump()},
    ],
)
def test_report_request_rejects_ambiguous_or_untrusted_payloads(payload):
    with pytest.raises(ValidationError):
        ReportRequest.model_validate(payload)


def test_report_request_accepts_an_inline_custom_template():
    payload = ReportRequest(
        family="warranty",
        template=template(
            family="warranty",
            id="warranty-custom",
            fields=list(WARRANTY_DEFAULT_FIELDS),
        ),
        output="pdf",
    )
    dumped = payload.model_dump()
    assert dumped["template"]["id"] == "warranty-custom"
    assert dumped["template"]["family"] == "warranty"


def test_label_options_defaults_and_preset_geometry_are_bounded():
    options = LabelOptions()
    dumped = options.model_dump()

    assert set(dumped) == {
        "formatId",
        "widthMm",
        "heightMm",
        "pageWidthMm",
        "pageHeightMm",
        "marginTopMm",
        "marginRightMm",
        "marginBottomMm",
        "marginLeftMm",
        "gapXmm",
        "gapYmm",
        "columns",
        "offset",
        "fields",
        "logo",
        "qr",
    }
    assert dumped["formatId"] == "a4-24"
    assert dumped["fields"] == ["logo", "name", "id", "code", "qr"]
    assert dumped["columns"] == 1
    assert dumped["offset"] == 0
    assert set(LABEL_FORMATS) == {
        "a4-24",
        "a4-21",
        "roll-50x30",
        "roll-80x50",
        "custom",
    }
    assert set(LABEL_FIELDS) == {
        "logo",
        "name",
        "id",
        "code",
        "qr",
        "site",
        "location",
        "serial",
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"formatId": "adhesive-50"},
        {"formatId": "custom"},
        {"formatId": "custom", "widthMm": 50, "heightMm": 30, "pageWidthMm": 100},
        {"formatId": "a4-24", "widthMm": 9},
        {"formatId": "a4-24", "marginTopMm": -1},
        {"formatId": "a4-24", "marginLeftMm": 51},
        {"formatId": "a4-24", "gapXmm": 31},
        {"formatId": "a4-24", "columns": 0},
        {"formatId": "a4-24", "columns": 13},
        {"formatId": "a4-24", "offset": 501},
        {"formatId": "a4-24", "fields": ["cost"]},
        {"formatId": "a4-24", "fields": ["name", "name"]},
        {"formatId": "a4-24", "fields": [], "logo": False, "qr": False},
        {"formatId": "a4-24", "unexpected": True},
    ],
)
def test_label_options_reject_unknown_or_out_of_bound_values(payload):
    with pytest.raises(ValidationError):
        LabelOptions.model_validate(payload)


def test_label_options_accept_custom_geometry_and_extra_fields():
    options = LabelOptions(
        formatId="custom",
        widthMm=50,
        heightMm=30,
        pageWidthMm=100,
        pageHeightMm=100,
        marginTopMm=5,
        marginRightMm=5,
        marginBottomMm=5,
        marginLeftMm=5,
        gapXmm=2,
        gapYmm=2,
        columns=2,
        offset=1,
        fields=["name", "site", "serial"],
        logo=True,
    )
    dumped = options.model_dump()
    assert dumped["formatId"] == "custom"
    assert dumped["widthMm"] == 50
    assert dumped["fields"] == ["name", "site", "serial"]


def test_report_settings_validate_url_branding_and_label_defaults():
    settings = ReportSettingsInput()
    dumped = settings.model_dump()
    assert set(dumped) == {"baseUrl", "branding", "labelDefaults"}
    assert set(dumped["branding"]) == {
        "name",
        "primary",
        "accent",
        "header",
        "footer",
        "logoAttachmentId",
    }
    assert dumped["baseUrl"] == ""
    assert dumped["branding"]["primary"] == "#0d766e"
    assert dumped["branding"]["accent"] == "#147c73"
    assert dumped["labelDefaults"]["formatId"] == "a4-24"

    normalized = ReportSettingsInput(
        baseUrl="https://ITSM.example.com/itsm",
        branding={
            "name": "Acme",
            "primary": "#AABBCC",
            "accent": "",
            "header": "Inventario",
            "footer": "Uso interno",
            "logoAttachmentId": str(uuid.uuid4()).upper(),
        },
    ).model_dump()
    assert normalized["baseUrl"] == "https://ITSM.example.com/itsm/"
    assert normalized["branding"]["primary"] == "#aabbcc"
    assert normalized["branding"]["accent"] == ""
    assert (
        normalized["branding"]["logoAttachmentId"]
        == normalized["branding"]["logoAttachmentId"].lower()
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"baseUrl": "ftp://example.com/"},
        {"baseUrl": "javascript:alert(1)"},
        {"baseUrl": "//example.com/"},
        {"baseUrl": "https://user:pass@example.com/"},
        {"baseUrl": "https://example.com/?query=1"},
        {"baseUrl": "https://example.com/#fragment"},
        {"baseUrl": "https://example.com/?"},
        {"baseUrl": "https://example.com/#"},
        {"baseUrl": " https://example.com/"},
        {"baseUrl": "https://example.com/ "},
        {"baseUrl": "https://example.com/\x00"},
        {"baseUrl": "https://example.com\\path"},
        {"baseUrl": "https://exa mple.com/"},
        {"baseUrl": "https://example.com/" + "x" * 400},
        {"baseUrl": "https://example.com:99999/"},
        {"branding": {"primary": "red"}},
        {"branding": {"primary": "0d766e"}},
        {"branding": {"primary": "#12345"}},
        {"branding": {"name": "x" * 121}},
        {"branding": {"name": "bad\x00name"}},
        {"branding": {"header": "x" * 501}},
        {"branding": {"footer": "x" * 501}},
        {"branding": {"logoAttachmentId": "not-a-uuid"}},
        {"branding": {"css": "body{display:none}"}},
        {"branding": {"unexpected": True}},
        {"labelDefaults": {"formatId": "custom"}},
        {"labelDefaults": {"formatId": "unknown"}},
        {"unexpected": True},
    ],
)
def test_report_settings_reject_untrusted_configuration(payload):
    with pytest.raises(ValidationError):
        ReportSettingsInput.model_validate(payload)


def test_schema_constants_match_the_locked_asset_vocabulary():
    assert set(FAMILIES) == {"inventory", "history", "warranty"}
    assert set(ASSET_FIELDS) == {
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
    }
    assert set(PUBLIC_ASSET_FIELDS) == {
        "id",
        "quickCode",
        "name",
        "category",
        "site",
        "location",
        "status",
    }
    assert set(BLOCK_TYPES) == {
        "heading",
        "text",
        "asset",
        "table",
        "photo",
        "summary",
        "qr",
        "footer",
    }
    assert FIELD_LABELS["purchaseCost"] == "Coste de compra"
    assert FIELD_LABELS["quickCode"] == "Código rápido"
    assert set(GROUPINGS) == {
        "none",
        "category",
        "site",
        "responsible",
        "location",
        "status",
    }
    for field in (*HISTORY_FIELDS, *WARRANTY_FIELDS):
        assert field in FIELD_LABELS


def test_family_fields_are_exact_and_cross_family_keys_are_rejected():
    history = ReportRequest(family="history", group="category", fields=list(HISTORY_FIELDS))
    dumped = history.model_dump()
    assert dumped["group"] == "category"
    assert dumped["fields"] == list(HISTORY_FIELDS)
    assert ReportRequest(family="inventory").group == "none"

    warranty = ReportRequest(family="warranty", group="site", fields=list(WARRANTY_FIELDS))
    assert warranty.model_dump()["fields"] == list(WARRANTY_FIELDS)

    for payload in (
        {"family": "history", "fields": ["purchaseDate"]},
        {"family": "warranty", "fields": ["action"]},
        {"family": "inventory", "fields": ["supplier"]},
        {"family": "history", "group": "asset"},
        {"family": "warranty", "group": "action"},
    ):
        with pytest.raises(ValidationError):
            ReportRequest.model_validate(payload)

    history_template = TemplateDefinition.model_validate(
        template(family="history", fields=list(HISTORY_FIELDS))
    )
    assert history_template.fields == list(HISTORY_FIELDS)
    warranty_template = TemplateDefinition.model_validate(
        template(family="warranty", fields=list(WARRANTY_FIELDS))
    )
    assert warranty_template.fields == list(WARRANTY_FIELDS)
    with pytest.raises(ValidationError):
        TemplateDefinition.model_validate(template(family="warranty", fields=["action"]))
    with pytest.raises(ValidationError):
        TemplateDefinition.model_validate(template(family="history", fields=["supplier"]))

    builtins = {item["id"]: item for item in builtin_templates()}
    assert builtins["history-list"]["fields"] == list(HISTORY_DEFAULT_FIELDS)
    assert builtins["warranty-list"]["fields"] == list(WARRANTY_DEFAULT_FIELDS)
