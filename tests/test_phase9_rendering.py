"""Composition, QR and isolated WeasyPrint rendering behavior."""

from __future__ import annotations

import base64
import io
import multiprocessing
import re
import shutil
import subprocess
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from PIL import Image

from itsm.reports.composition import Composition, compose_document, preview_html
from itsm.reports.qr import asset_report_url, qr_svg
from itsm.reports.rendering import RenderFailed, RenderTimeout, render_pdf
from itsm.reports.schemas import LabelOptions, TemplateDefinition, builtin_templates


def png_bytes(width: int = 40, height: int = 40, color=(20, 120, 110)) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (width, height), color).save(buffer, "PNG")
    return buffer.getvalue()


def jpeg_bytes(width: int = 4000, height: int = 10) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (width, height), (200, 60, 40)).save(buffer, "JPEG")
    return buffer.getvalue()


def asset(asset_id: str, name: str = "Router", quick_code: str = "AF00026") -> dict:
    return {
        "id": asset_id,
        "quickCode": quick_code,
        "name": name,
        "category": "Red",
        "site": "Sede central",
        "location": "Planta 1",
        "status": "Activo",
        "responsible": "Ana",
        "serial": "SN-1",
        "brand": "Acme",
        "model": "R-1",
        "ip": "10.0.0.1",
        "purchaseCost": "199.95",
        "technical": {"ports": 8},
    }


def context(**overrides) -> dict:
    first, second = str(uuid.uuid4()), str(uuid.uuid4())
    base = {
        "title": "Inventario de activos",
        "family": "inventory",
        "generatedAt": "2026-10-23 10:00",
        "assets": [asset(first, "Router principal"), asset(second, "Switch secundario", "AF00027")],
        "rows": [
            {"id": first, "name": "Router principal", "status": "Activo"},
            {"id": second, "name": "Switch secundario", "status": "Activo"},
        ],
        "columns": [{"key": "name", "label": "Nombre"}, {"key": "status", "label": "Estado"}],
        "summary": {
            "total": 2,
            "byStatus": {"Activo": 2},
            "byCategory": {"Red": 2},
        },
        "branding": {
            "name": "Organización Acme",
            "primary": "#0d766e",
            "accent": "#147c73",
            "header": "Inventario operativo",
            "footer": "Uso interno",
        },
        "qrUrls": {
            first: f"https://itam.example.com/#/reporte/{first}",
            second: f"https://itam.example.com/#/reporte/{second}",
        },
        "images": {},
        "logo": None,
    }
    base.update(overrides)
    return base


def inventory_template(**overrides) -> dict:
    payload = next(item for item in builtin_templates() if item["id"] == "inventory-list")
    payload.update(overrides)
    return payload


def sheet_template(**overrides) -> dict:
    payload = next(item for item in builtin_templates() if item["id"] == "inventory-sheet")
    payload.update(overrides)
    return payload


def label(assets: list[dict], **overrides) -> dict:
    payload = {
        "formatId": "a4-24",
        "offset": 0,
        "fields": ["logo", "name", "id", "code", "qr"],
    }
    payload.update(overrides)
    return LabelOptions.model_validate(payload).model_dump()


def css_pairs(html: str, selector: str) -> str:
    return html


# --------------------------------------------------------------------------- QR


def test_asset_report_url_uses_the_permanent_uuid_not_the_quick_code():
    identifier = str(uuid.uuid4())
    expected = f"https://itam.example.com/#/reporte/{identifier}"

    assert asset_report_url("https://itam.example.com/", identifier) == expected
    assert asset_report_url("https://itam.example.com", identifier) == expected
    assert asset_report_url("https://itam.example.com///", identifier) == expected
    assert asset_report_url("https://itam.example.com/itsm", identifier) == (
        f"https://itam.example.com/itsm/#/reporte/{identifier}"
    )
    assert asset_report_url("https://itam.example.com/", identifier.upper()) == expected

    # The stable destination survives moving or recategorizing the asset: it
    # only depends on the permanent UUID.
    moved = {**asset(identifier, "Nuevo nombre", "AF99999"), "category": "Otro"}
    assert asset_report_url("https://itam.example.com/", moved["id"]) == expected

    with pytest.raises(ValueError):
        asset_report_url("https://itam.example.com/", "AF00026")
    with pytest.raises(ValueError):
        asset_report_url("https://itam.example.com/", "../../etc/passwd")


@pytest.mark.parametrize(
    "base",
    [
        "",
        "ftp://itam.example.com/",
        "javascript:alert(1)",
        "https://user:pass@itam.example.com/",
        "https://itam.example.com/?query=1",
        "https://itam.example.com/#fragment",
        "https://itam.example.com/?",
        "https://itam.example.com/#",
        "https://itam.example.com/\x00",
        "https://itam.example.com\\path",
        "https://itam.example.com:99999/",
        "https://itam example.com/",
        " https://itam.example.com/",
        "https://itam.example.com/ ",
    ],
)
def test_asset_report_url_rejects_unsafe_or_unusable_bases(base):
    with pytest.raises(ValueError):
        asset_report_url(base, str(uuid.uuid4()))


def test_qr_svg_has_a_real_quiet_zone_and_no_external_references():
    identifier = str(uuid.uuid4())
    url = asset_report_url("https://itam.example.com/", identifier)
    svg = qr_svg(url)
    expected_modules = 25 + 8  # version-agnostic lower bound sanity check below

    assert svg.startswith("<svg")
    assert "</svg>" in svg
    assert "<script" not in svg.lower()
    assert 'href="http' not in svg and "<image" not in svg
    assert 'fill="#fff"' in svg
    assert 'class="segno"' in svg

    # Quadrant checks: Segno emits a 45-module symbol for this payload at 4x
    # including a four-module quiet zone on each side.
    width = int(re.search(r'width="(\d+)"', svg).group(1))
    assert width % 4 == 0
    modules = width // 4
    assert modules >= expected_modules
    assert modules % 4 == 1  # QR module counts are 21 + 4*n

    other = qr_svg(asset_report_url("https://itam.example.com/", str(uuid.uuid4())))
    assert other != svg

    with pytest.raises(ValueError):
        qr_svg("")
    with pytest.raises(ValueError):
        qr_svg(123)


# ----------------------------------------------------------------- composition


def test_inventory_list_composition_builds_clean_html_and_registered_png_resources():
    logo = jpeg_bytes()
    composition = compose_document(
        inventory_template(), context(logo=logo, images={})
    )

    assert isinstance(composition, Composition)
    assert isinstance(composition.html, str)
    assert set(composition.resources) == {"logo.png"}
    assert composition.resources["logo.png"].startswith(b"\x89PNG\r\n\x1a\n")
    assert 'src="resource://logo.png"' in composition.html
    assert "Organización Acme" in composition.html
    assert "Inventario operativo" in composition.html
    assert 'class="doc-table"' in composition.html
    assert "Router principal" in composition.html
    assert "Total: 2" in composition.html
    assert "Activo" in composition.html
    assert composition.html.lower().count("<script") == 0
    assert "javascript:" not in composition.html.lower()
    assert "http://" not in composition.html and "https://" not in composition.html
    assert "data:image" not in composition.html
    # The composed PDF references only the registered local resource scheme.
    assert 'src="http' not in composition.html and 'src="file' not in composition.html


def test_composition_escapes_every_untrusted_value():
    hostile = "=DANGEROUS()"
    first = str(uuid.uuid4())
    payload = context(
        title="<script>alert(1)</script>",
        branding={"name": "<b>Acme</b>", "header": "<style>body{}</style>", "footer": ""},
        assets=[
            {
                **asset(first, '<img src=x onerror="alert(1)">'),
                "category": "A & B",
                "technical": {"<b>": "<script>"},
            }
        ],
        rows=[{"name": "<td onclick=alert(1)>x</td>", "status": hostile}],
        columns=[{"key": "name", "label": "<th>Nombre</th>"}, {"key": "status", "label": "Estado"}],
        summary={"total": 1, "byStatus": {"<script>": 1}},
    )
    composition = compose_document(
        inventory_template(
            blocks=[
                {"id": "asset", "type": "asset", "label": "", "text": "", "enabled": True},
                {"id": "table", "type": "table", "label": "", "text": "", "enabled": True},
                {"id": "summary", "type": "summary", "label": "", "text": "", "enabled": True},
            ]
        ),
        payload,
    )
    html = composition.html

    assert "<script" not in html.lower()
    assert "<img src=x" not in html
    assert "<b>Acme</b>" not in html
    assert "<style>body{}</style>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in html
    assert "A &amp; B" in html
    assert "&lt;td onclick=alert(1)&gt;x&lt;/td&gt;" in html
    assert "&lt;th&gt;Nombre&lt;/th&gt;" in html
    assert "=DANGEROUS()" in html or "&#x27;=DANGEROUS()" in html


def test_composition_tolerates_missing_invalid_and_oversized_photo_bytes():
    first, second = str(uuid.uuid4()), str(uuid.uuid4())
    payload = context(
        assets=[asset(first), asset(second, "Switch")],
        images={
            first: b"not an image",
            second: png_bytes(4000, 10),
            "unselected": b"ignored",
        },
        logo=b"broken logo",
    )
    composition = compose_document(sheet_template(), payload)

    assert "logo.png" not in composition.resources
    photos = [key for key in composition.resources if key.startswith("photo-")]
    assert len(photos) == 1
    stored = composition.resources[photos[0]]
    assert stored.startswith(b"\x89PNG\r\n\x1a\n")
    with Image.open(io.BytesIO(stored)) as image:
        assert image.format == "PNG"
        assert max(image.size) <= 1200
    assert composition.html.count('class="doc-photo"') == 1
    assert "Switch" in composition.html


def test_composition_table_renders_real_rows_columns_and_empty_state():
    composition = compose_document(
        inventory_template(),
        context(
            assets=[],
            rows=[
                {"name": "Router", "status": "Activo", "extra": "<script>x</script>"},
                {"name": "Switch", "status": None},
            ],
            columns=[
                {"key": "name", "label": "Nombre"},
                {"key": "status", "label": "Estado"},
                {"key": "missing", "label": "Faltante"},
            ],
            summary={},
            images={},
            logo=None,
        ),
    )
    assert "<td>Router</td>" in composition.html
    assert "<td>Activo</td>" in composition.html
    assert "<td>—</td>" in composition.html
    assert "Faltante" in composition.html
    assert 'class="summary-block"' not in composition.html

    empty = compose_document(
        inventory_template(),
        context(assets=[], rows=[], columns=[], summary={}),
    )
    assert empty.html.count("Sin datos para los filtros seleccionados.") >= 1
    assert 'class="doc-table"' in empty.html


def test_composition_summary_is_a_real_count_chart_with_totals_and_facts():
    composition = compose_document(
        inventory_template(),
        context(
            summary={
                "total": 6,
                "cost": "1234.50",
                "withTechnical": 2,
                "byStatus": {"Activo": 4, "Baja": 2},
                "byCategory": {"Cámara": 3, "Router": 3},
                "from": "2026-01-01",
                "to": "2026-01-31",
            }
        ),
    )
    html = composition.html

    assert "Total: 6" in html
    assert "Activo" in html and "4 (67%)" in html
    assert "Baja" in html and "2 (33%)" in html
    assert "Cámara" in html and "3 (50%)" in html
    assert "Router" in html
    assert "Coste total: 1234.50" in html
    assert "Con datos técnicos: 2" in html
    assert 'class="summary-bar"' in html
    assert "placeholder" not in html.lower() and "fake" not in html.lower()


def test_composition_renders_every_block_type_and_honours_enabled():
    blocks = [
        {"id": "h", "type": "heading", "label": "", "text": "Cabecera", "enabled": True},
        {"id": "t", "type": "text", "label": "", "text": "Línea uno\nLínea dos", "enabled": True},
        {"id": "a", "type": "asset", "label": "", "text": "", "enabled": True},
        {"id": "tab", "type": "table", "label": "", "text": "", "enabled": True},
        {"id": "p", "type": "photo", "label": "Fotos", "text": "", "enabled": True},
        {"id": "s", "type": "summary", "label": "Resumen", "text": "", "enabled": True},
        {"id": "q", "type": "qr", "label": "QR", "text": "", "enabled": True},
        {"id": "f", "type": "footer", "label": "", "text": "Pie final", "enabled": True},
        {"id": "off", "type": "text", "label": "", "text": "NO DEBE APARECER", "enabled": False},
    ]
    first = str(uuid.uuid4())
    payload = context(
        assets=[asset(first)],
        images={first: png_bytes()},
        logo=png_bytes(),
        summary={"total": 1, "byStatus": {"Activo": 1}},
        qrUrls={first: f"https://itam.example.com/#/reporte/{first}"},
    )
    composition = compose_document(
        inventory_template(images=True, blocks=blocks), payload
    )
    html = composition.html

    assert "Cabecera" in html
    assert "Línea uno<br>Línea dos" in html
    assert 'class="asset-card"' in html
    assert 'class="doc-table"' in html
    assert 'class="photo-block"' in html
    assert 'class="summary-block"' in html
    assert 'class="qr-block"' in html
    assert "Pie final" in html
    assert "NO DEBE APARECER" not in html
    assert html.count("<svg") >= 1
    assert f"https://itam.example.com/#/reporte/{first}" in html


def test_composition_uses_letter_size_and_page_numbering_css():
    composition = compose_document(
        inventory_template(format="Letter"),
        context(logo=None),
    )
    html = composition.html
    assert "size: Letter;" in html
    assert "counter(page)" in html and "counter(pages)" in html
    assert "position: running(doc-header)" in html
    assert "@top-center" in html
    assert "Página " in html
    assert "Uso interno" in html

    a4 = compose_document(inventory_template(), context(logo=None))
    assert "size: A4;" in a4.html


def test_preview_html_inlines_only_registered_resources_for_the_browser():
    composition = compose_document(inventory_template(), context(logo=png_bytes()))
    preview = preview_html(composition)

    assert 'src="resource://logo.png"' in composition.html
    assert 'src="resource://logo.png"' not in preview
    expected = base64.b64encode(composition.resources["logo.png"]).decode("ascii")
    assert f"data:image/png;base64,{expected}" in preview
    assert "<script" not in preview.lower()

    unregistered = Composition(
        html='<p>ok</p><img src="resource://evil.png">',
        resources={"logo.png": png_bytes()},
    )
    rendered = preview_html(unregistered)
    assert 'src="resource://evil.png"' in rendered


def test_compose_document_rejects_out_of_bound_context_and_templates():
    with pytest.raises(Exception):
        compose_document({**inventory_template(), "unexpected": True}, context())
    with pytest.raises(ValueError):
        compose_document(inventory_template(), {"assets": "not-a-list"})
    with pytest.raises(ValueError):
        compose_document(inventory_template(), context(assets=[{}] * 2001))
    with pytest.raises(ValueError):
        compose_document(inventory_template(), context(rows=[{}] * 5001))
    with pytest.raises(ValueError):
        compose_document(
            inventory_template(),
            context(columns=[{"key": f"c{i}", "label": "x"} for i in range(21)]),
        )
    with pytest.raises(ValueError):
        compose_document(
            sheet_template(images=True),
            context(images={str(uuid.uuid4()): png_bytes() for _ in range(101)}),
        )
    with pytest.raises(ValueError):
        compose_document(inventory_template(), context(branding="not-a-mapping"))


# ---------------------------------------------------------------------- labels


def test_label_sheet_uses_a4_24_preset_geometry_and_paginates():
    assets = [asset(str(uuid.uuid4()), f"Activo {index}") for index in range(25)]
    composition = compose_document(
        inventory_template(), context(assets=assets, rows=[], columns=[], images={}), labels=label(assets)
    )
    html = composition.html

    assert "size: 210mm 297mm;" in html
    assert "width: 70mm;" in html and "height: 37mm;" in html
    assert html.count('class="label-page"') == 2
    assert html.count('class="label-cell"') == 25
    assert "break-after: page" in html
    assert "Activo 0" in html and "Activo 24" in html


def test_label_sheet_uses_a4_21_preset_geometry():
    assets = [asset(str(uuid.uuid4()), f"Activo {index}") for index in range(22)]
    composition = compose_document(
        inventory_template(),
        context(assets=assets, rows=[], columns=[], images={}),
        labels=label(assets, formatId="a4-21"),
    )
    html = composition.html
    assert "size: 210mm 297mm;" in html
    assert "width: 63.5mm;" in html and "height: 38.1mm;" in html
    assert "left: 9.75mm; top: 15.15mm;" in html
    assert html.count('class="label-page"') == 2


@pytest.mark.parametrize(
    ("format_id", "page"),
    [("roll-50x30", "size: 50mm 30mm;"), ("roll-80x50", "size: 80mm 50mm;")],
)
def test_roll_label_presets_use_the_physical_label_page(format_id, page):
    assets = [asset(str(uuid.uuid4()), "Activo rollo")]
    composition = compose_document(
        inventory_template(),
        context(assets=assets, rows=[], columns=[], images={}),
        labels=label(assets, formatId=format_id),
    )
    assert page in composition.html
    assert composition.html.count('class="label-page"') == 1


def test_custom_label_geometry_is_canonicalized_and_rejects_overflow():
    assets = [asset(str(uuid.uuid4()), f"Activo {index}") for index in range(5)]
    options = label(
        assets,
        formatId="custom",
        widthMm=40,
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
    )
    composition = compose_document(
        inventory_template(), context(assets=assets, rows=[], columns=[], images={}), labels=options
    )
    html = composition.html
    assert "size: 100mm 100mm;" in html
    assert "left: 5mm; top: 5mm;" in html
    assert "left: 47mm; top: 37mm;" in html
    assert html.count('class="label-page"') == 2

    with pytest.raises(ValueError):
        compose_document(
            inventory_template(),
            context(assets=assets, rows=[], columns=[], images={}),
            labels=label(
                assets,
                formatId="custom",
                widthMm=60,
                heightMm=30,
                pageWidthMm=100,
                pageHeightMm=100,
                marginLeftMm=5,
                marginRightMm=5,
                columns=2,
            ),
        )
    with pytest.raises(ValueError):
        compose_document(
            inventory_template(),
            context(assets=assets, rows=[], columns=[], images={}),
            labels=label(assets, offset=4, formatId="custom", widthMm=40, heightMm=30,
                         pageWidthMm=100, pageHeightMm=100, marginTopMm=5,
                         marginRightMm=5, marginBottomMm=5, marginLeftMm=5,
                         gapXmm=2, gapYmm=2, columns=2),
        )
    # Preset geometry always wins over caller-supplied dimensions.
    preset = compose_document(
        inventory_template(),
        context(assets=assets, rows=[], columns=[], images={}),
        labels=label(assets, widthMm=10, heightMm=10, columns=4),
    )
    assert "width: 70mm;" in preset.html and "height: 37mm;" in preset.html


def test_labels_render_logo_id_code_name_qr_and_selected_fields_tolerantly():
    first, second = str(uuid.uuid4()), str(uuid.uuid4())
    assets = [asset(first, "Router", "AF00026"), asset(second, "Switch", "AF00027")]
    composition = compose_document(
        inventory_template(),
        context(
            assets=assets,
            rows=[],
            columns=[],
            images={},
            logo=png_bytes(),
            qrUrls={first: f"https://itam.example.com/#/reporte/{first}"},
        ),
        labels=label(
            assets,
            fields=["logo", "name", "id", "code", "qr", "site", "location", "serial"],
        ),
    )
    html = composition.html

    assert 'src="resource://logo.png"' in html
    assert first in html and "AF00026" in html and "Router" in html
    assert "Sede: Sede central" in html
    assert "Ubicación: Planta 1" in html
    assert "Número de serie: SN-1" in html
    assert html.count("<svg") == 1  # the second label tolerates a missing QR
    assert "AF00027" in html


def test_labels_without_assets_render_an_honest_empty_sheet():
    composition = compose_document(
        inventory_template(),
        context(assets=[], rows=[], columns=[], images={}),
        labels=label([]),
    )
    assert composition.html.count('class="label-page"') == 1
    assert "Sin activos para las etiquetas seleccionadas." in composition.html
    assert 'class="label-cell"' not in composition.html


def test_groups_render_headings_counts_and_a_real_chart_without_losing_rows():
    template = inventory_template(fields=["quickCode", "name"])
    payload = context(
        assets=[],
        rows=[
            {"quickCode": "P9-1", "name": "Uno", "group": "Red"},
            {"quickCode": "P9-2", "name": "Dos", "group": "Red"},
            {"quickCode": "P9-3", "name": "Tres", "group": "Sin datos"},
        ],
        columns=[
            {"key": "quickCode", "label": "Código"},
            {"key": "name", "label": "Nombre"},
        ],
        summary={
            "total": 3,
            "groups": [
                {"key": "red", "label": "Red", "count": 2},
                {"key": "none", "label": "Sin datos", "count": 1},
            ],
        },
    )
    html = compose_document(template, payload).html

    assert html.count('class="doc-group"') == 2
    assert "Red (2)" in html and "Sin datos (1)" in html
    assert html.index("P9-1") < html.index("P9-2") < html.index("P9-3")
    assert "Por grupo" in html
    assert "2 (67%)" in html and "1 (33%)" in html
    assert "P9-1" in html and "P9-3" in html




def test_history_and_warranty_templates_fall_back_to_family_columns():
    for template_id, family, expected_headers in (
        (
            "history-list",
            "history",
            [
                "Código rápido",
                "Acción",
                "Actor",
                "Fecha efectiva",
                "Tipo de entidad",
                "Cambios",
                "Notas",
            ],
        ),
        (
            "warranty-list",
            "warranty",
            [
                "Código rápido",
                "Nombre",
                "Categoría",
                "Sede",
                "Proveedor",
                "Fecha de compra",
                "Vencimiento",
                "Cobertura",
                "ID del recibo",
                "Notas",
            ],
        ),
    ):
        payload = next(item for item in builtin_templates() if item["id"] == template_id)
        payload["fields"] = []
        html = compose_document(
            payload,
            {
                "title": template_id,
                "family": family,
                "generatedAt": "2026-10-23 10:00",
                "rows": [{"quickCode": "P9-1", "name": "Uno"}],
                "columns": [],
            },
        ).html
        for header in expected_headers:
            assert f">{header}</th>" in html


def render_context() -> dict:
    first = str(uuid.uuid4())
    return context(
        assets=[asset(first, f"Activo {index}") for index in range(60)],
        rows=[{"name": f"Activo {index}", "status": "Activo"} for index in range(60)],
        columns=[{"key": "name", "label": "Nombre"}, {"key": "status", "label": "Estado"}],
        summary={"total": 60, "byStatus": {"Activo": 60}},
    )


def test_render_pdf_produces_a_real_multipage_pdf(tmp_path):
    composition = compose_document(inventory_template(), render_context())
    pdf = render_pdf(composition, timeout_seconds=60)

    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000
    target = tmp_path / "report.pdf"
    target.write_bytes(pdf)
    pdfinfo = shutil.which("pdfinfo")
    if pdfinfo is None:  # pragma: no cover - poppler is present on the target host
        pytest.skip("pdfinfo is not installed")
    result = subprocess.run(
        [pdfinfo, str(target)], capture_output=True, text=True, timeout=30, check=True
    )
    pages = re.search(r"^Pages:\s+(\d+)", result.stdout, re.MULTILINE)
    assert pages is not None
    assert int(pages.group(1)) >= 2


def test_render_pdf_denies_every_unregistered_url_protocol():
    from weasyprint.urls import URLFetcherResponse

    from itsm.reports.rendering import _RestrictedFetcher

    image = png_bytes()
    fetcher = _RestrictedFetcher({"logo.png": image})
    response = fetcher.fetch("resource://logo.png")
    assert isinstance(response, URLFetcherResponse)
    assert response.read() == image
    assert response.status == 200

    for url in (
        "http://127.0.0.1:1/logo.png",
        "https://example.com/logo.png",
        "file:///etc/passwd",
        "data:image/png;base64,AAAA",
        "resource://evil.png",
        "resource://logo.png?x=1",
        "resource://../logo.png",
        "/etc/passwd",
        "",
    ):
        with pytest.raises(ValueError):
            fetcher.fetch(url)

    hostile = Composition(
        html=(
            "<html><body>"
            '<img src="http://127.0.0.1:1/x.png">'
            '<img src="file:///etc/passwd">'
            '<img src="data:image/png;base64,AAAA">'
            "</body></html>"
        ),
        resources={},
    )
    pdf = render_pdf(hostile, timeout_seconds=60)
    assert pdf.startswith(b"%PDF-")


def test_render_pdf_timeout_is_bounded_and_isolated():
    composition = compose_document(inventory_template(), render_context())
    with pytest.raises(RenderTimeout, match="timed out"):
        render_pdf(composition, timeout_seconds=0.01)
    # A timed-out worker is terminated: the next render still succeeds.
    assert render_pdf(composition, timeout_seconds=60).startswith(b"%PDF-")


def test_render_pdf_bounds_output_and_inputs():
    composition = compose_document(inventory_template(), render_context())
    with pytest.raises(RenderFailed, match="size limit"):
        render_pdf(composition, timeout_seconds=60, max_bytes=1000)

    with pytest.raises(ValueError):
        render_pdf(composition, timeout_seconds=0)
    with pytest.raises(ValueError):
        render_pdf(composition, timeout_seconds=601)
    with pytest.raises(ValueError):
        render_pdf(composition, memory_mb=16)
    with pytest.raises(ValueError):
        render_pdf(composition, max_bytes=0)
    with pytest.raises(ValueError):
        render_pdf(Composition(html="<p>x</p>", resources={"../evil.png": png_bytes()}))
    with pytest.raises(ValueError):
        render_pdf(Composition(html="<p>x</p>", resources={"big.png": b"x" * (8 * 1024 * 1024 + 1)}))
    with pytest.raises(ValueError):
        render_pdf(Composition(html="<p>" + "x" * (8 * 1024 * 1024 + 1) + "</p>", resources={}))


def test_render_pdf_works_inside_a_huey_style_thread():
    composition = compose_document(inventory_template(), render_context())
    with ThreadPoolExecutor(max_workers=1) as pool:
        pdf = pool.submit(render_pdf, composition, timeout_seconds=60).result(timeout=90)
    assert pdf.startswith(b"%PDF-")


def _render_in_child(html: str, resources: dict, connection) -> None:
    try:
        pdf = render_pdf(Composition(html=html, resources=resources), timeout_seconds=60)
        connection.send(("ok", len(pdf), pdf[:8]))
    except BaseException as exc:  # pragma: no cover - surfaced through the pipe
        connection.send(("failed", type(exc).__name__))
    finally:
        connection.close()


def test_render_pdf_works_inside_a_huey_style_process():
    composition = compose_document(inventory_template(), render_context())
    ctx = multiprocessing.get_context("spawn")
    receive, send = ctx.Pipe(duplex=False)
    process = ctx.Process(
        target=_render_in_child, args=(composition.html, composition.resources, send)
    )
    process.start()
    send.close()
    process.join(120)
    assert not process.is_alive()
    assert receive.poll(10)
    result = receive.recv()
    receive.close()
    assert result[0] == "ok", result
    assert result[2].startswith(b"%PDF-")
