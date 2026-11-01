"""Deterministic HTML/CSS composition for reports and physical labels.

This module imports no FastAPI, SQLAlchemy or settings objects at run time: it
receives already authorized and projected data plus the document locale, and
emits self-contained HTML whose only image sources are
``resource://<registered-key>`` references.  ``preview_html`` is the sole place
that turns those registered bytes into browser data URIs; PDF rendering never
uses data, HTTP or file URLs.
"""

from __future__ import annotations

import base64
import html as html_module
import io
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import groupby
from typing import Any

from PIL import Image, ImageOps

from itsm.i18n.catalog import DEFAULT_LOCALE, resolve_installed_locale
from itsm.i18n.documents import DocumentLocale, default_document_locale
from itsm.i18n.settings import DEFAULT_CURRENCY, DEFAULT_TIMEZONE
from itsm.reports.labels import (
    asset_name_label,
    coverage_label,
    family_label,
    field_label,
    label_field_label,
    missing_group_label,
    summary_group_label,
)
from itsm.reports.qr import qr_svg
from itsm.reports.schemas import (
    FAMILY_DEFAULT_FIELDS,
    LabelOptions,
    TemplateDefinition,
)

MAX_ASSETS = 2000
MAX_LABELS = 2000
MAX_ROWS = 5000
MAX_COLUMNS = 20
MAX_IMAGES = 100
MAX_QR_URLS = 2000
MAX_RESOURCE_BYTES = 8 * 1024 * 1024
MAX_PHOTO_EDGE = 1200
MAX_LOGO_EDGE = 600
MAX_IMAGE_PIXELS = 40_000_000
MAX_CELL_CHARS = 500
MAX_BLOCK_CHARS = 5000
MAX_TITLE_CHARS = 200

_BRANDING_FALLBACK = {
    "name": "",
    "primary": "#0d766e",
    "accent": "#147c73",
    "header": "",
    "footer": "",
}
_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
_RESOURCE_SRC = re.compile(r'src="resource://([^"]+)"')
_PAGE_COUNTER = re.compile(r"\{(current|total)\}")


@dataclass(frozen=True, slots=True)
class Composition:
    """HTML plus the exact image bytes it is allowed to reference."""

    html: str
    resources: dict[str, bytes]


@dataclass(frozen=True, slots=True)
class LabelGeometry:
    page_width: float
    page_height: float
    width: float
    height: float
    margin_top: float
    margin_right: float
    margin_bottom: float
    margin_left: float
    gap_x: float
    gap_y: float
    columns: int
    rows: int

    @property
    def capacity(self) -> int:
        return self.columns * self.rows


_PRESET_GEOMETRY: dict[str, dict[str, float | int]] = {
    "a4-24": {
        "page_width": 210.0,
        "page_height": 297.0,
        "width": 70.0,
        "height": 37.0,
        "margin_top": 0.0,
        "margin_right": 0.0,
        "margin_bottom": 0.0,
        "margin_left": 0.0,
        "gap_x": 0.0,
        "gap_y": 0.0,
        "columns": 3,
        "rows": 8,
    },
    "a4-21": {
        "page_width": 210.0,
        "page_height": 297.0,
        "width": 63.5,
        "height": 38.1,
        "margin_top": 15.15,
        "margin_right": 9.75,
        "margin_bottom": 15.15,
        "margin_left": 9.75,
        "gap_x": 0.0,
        "gap_y": 0.0,
        "columns": 3,
        "rows": 7,
    },
    "roll-50x30": {
        "page_width": 50.0,
        "page_height": 30.0,
        "width": 50.0,
        "height": 30.0,
        "margin_top": 0.0,
        "margin_right": 0.0,
        "margin_bottom": 0.0,
        "margin_left": 0.0,
        "gap_x": 0.0,
        "gap_y": 0.0,
        "columns": 1,
        "rows": 1,
    },
    "roll-80x50": {
        "page_width": 80.0,
        "page_height": 50.0,
        "width": 80.0,
        "height": 50.0,
        "margin_top": 0.0,
        "margin_right": 0.0,
        "margin_bottom": 0.0,
        "margin_left": 0.0,
        "gap_x": 0.0,
        "gap_y": 0.0,
        "columns": 1,
        "rows": 1,
    },
}


# --------------------------------------------------------------------- helpers


def _plain(value: Any, limit: int = MAX_BLOCK_CHARS, document: DocumentLocale | None = None) -> str:
    """Plain text for HTML escaping; never interprets markup or URLs."""
    if value is None:
        return ""
    if isinstance(value, bool):
        resolved = document if document is not None else default_document_locale()
        return resolved.t("api.reports.yes" if value else "api.reports.no")
    if isinstance(value, Mapping):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    elif isinstance(value, (list, tuple)):
        text = json.dumps(list(value), ensure_ascii=False, default=str)
    else:
        text = str(value)
    cleaned = "".join(
        character if character in "\n\t" or ord(character) >= 32 else " " for character in text
    )
    return cleaned[:limit]


def _escape(
    value: Any, limit: int = MAX_BLOCK_CHARS, document: DocumentLocale | None = None
) -> str:
    return html_module.escape(_plain(value, limit, document), quote=True)


def _cell(value: Any, document: DocumentLocale | None = None) -> str:
    text = _escape(value, MAX_CELL_CHARS, document)
    return text if text else "—"


def _context_document(context: Mapping[str, Any]) -> DocumentLocale:
    """The document locale carried by a validated context; Spanish by default."""
    raw = context.get("locale")
    if raw is None:
        return default_document_locale()
    if not isinstance(raw, str):
        raise ValueError("context.locale must be a string")
    locale = resolve_installed_locale(raw)
    if locale is None:
        raise ValueError(f"unknown locale: {raw}")
    timezone = context.get("timezone") or DEFAULT_TIMEZONE
    currency = context.get("currency") or DEFAULT_CURRENCY
    default = context.get("defaultLocale") or DEFAULT_LOCALE
    for name, value in (("timezone", timezone), ("currency", currency), ("defaultLocale", default)):
        if not isinstance(value, str) or not value:
            raise ValueError(f"context.{name} must be a non-empty string")
    return DocumentLocale(
        locale=locale, timezone=timezone, currency=currency, default_locale=default
    )


def _mm(value: float) -> str:
    return f"{value:g}"


def _as_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    return value


def _as_list(value: Any, name: str) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ValueError(f"{name} must be a list")
    return list(value)


def _normalize_template(template: Any) -> TemplateDefinition:
    if isinstance(template, TemplateDefinition):
        return template
    if not isinstance(template, Mapping):
        raise ValueError("template must be a mapping")
    return TemplateDefinition.model_validate(dict(template))


def _normalize_branding(value: Any) -> dict[str, str]:
    if value is None:
        raw: Mapping[str, Any] = {}
    else:
        raw = _as_mapping(value, "branding")
    branding = dict(_BRANDING_FALLBACK)
    branding["name"] = _plain(raw.get("name"), 120)
    branding["header"] = _plain(raw.get("header"), 160)
    branding["footer"] = _plain(raw.get("footer"), 160)
    for key in ("primary", "accent"):
        candidate = raw.get(key)
        if isinstance(candidate, str) and _COLOR.fullmatch(candidate):
            branding[key] = candidate.lower()
    return branding


def _relative_luminance(color: str) -> float:
    channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [
        channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast_text(color: str) -> str:
    return "#ffffff" if _relative_luminance(color) < 0.45 else "#0b2331"


def _normalize_raster(
    data: Any, *, max_edge: int, max_bytes: int = MAX_RESOURCE_BYTES
) -> bytes | None:
    """Decode, bound and re-encode a raster image, tolerating every bad input."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    if not raw or len(raw) > max_bytes:
        return None
    try:
        with Image.open(io.BytesIO(raw)) as probe:
            width, height = probe.size
            if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
                return None
            probe.load()
            image = ImageOps.exif_transpose(probe)
            if image.mode in {"RGBA", "LA", "PA"} or (
                image.mode == "P" and "transparency" in probe.info
            ):
                image = image.convert("RGBA")
            else:
                image = image.convert("RGB")
            image.thumbnail((max_edge, max_edge), Image.Resampling.LANCZOS)
            output = io.BytesIO()
            image.save(output, format="PNG", optimize=True)
    except Exception:
        return None
    rendered = output.getvalue()
    if not rendered or len(rendered) > max_bytes:
        return None
    return rendered


def _safe_qr_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > 600:
        return None
    if any(character.isspace() or ord(character) < 32 for character in text):
        return None
    if any(character in text for character in '<>"'):
        return None
    if not (text.startswith("https://") or text.startswith("http://")):
        return None
    return text


def _normalize_context(raw: Any) -> dict[str, Any]:
    context = _as_mapping(raw, "context")
    document = _context_document(context)

    assets = _as_list(context.get("assets"), "context.assets")
    if len(assets) > MAX_ASSETS:
        raise ValueError(f"context.assets exceeds {MAX_ASSETS} entries")
    normalized_assets: list[dict[str, Any]] = []
    for item in assets:
        normalized_assets.append(dict(_as_mapping(item, "context.assets entries")))

    rows = _as_list(context.get("rows"), "context.rows")
    if len(rows) > MAX_ROWS:
        raise ValueError(f"context.rows exceeds {MAX_ROWS} entries")
    normalized_rows = [dict(_as_mapping(item, "context.rows entries")) for item in rows]

    columns_raw = _as_list(context.get("columns"), "context.columns")
    if len(columns_raw) > MAX_COLUMNS:
        raise ValueError(f"context.columns exceeds {MAX_COLUMNS} entries")
    columns: list[dict[str, str]] = []
    for item in columns_raw:
        column = _as_mapping(item, "context.columns entries")
        key = column.get("key")
        label = column.get("label")
        if not isinstance(key, str) or not key.strip() or len(key) > 80:
            raise ValueError("column keys must be 1-80 character strings")
        if label is None:
            label = field_label(key, document)
        if not isinstance(label, str) or len(label) > 120:
            raise ValueError("column labels must be at most 120 characters")
        columns.append({"key": key.strip(), "label": label})

    images_raw = _as_mapping(context.get("images") or {}, "context.images")
    if len(images_raw) > MAX_IMAGES:
        raise ValueError(f"context.images exceeds {MAX_IMAGES} entries")

    qr_raw = _as_mapping(context.get("qrUrls") or {}, "context.qrUrls")
    if len(qr_raw) > MAX_QR_URLS:
        raise ValueError(f"context.qrUrls exceeds {MAX_QR_URLS} entries")
    qr_urls: dict[str, str] = {}
    for key, value in qr_raw.items():
        if not isinstance(key, str):
            raise ValueError("qrUrls keys must be asset id strings")
        if value is not None and not isinstance(value, str):
            raise ValueError("qrUrls values must be strings")
        if isinstance(value, str):
            qr_urls[key] = value

    summary_raw = context.get("summary")
    summary = dict(_as_mapping(summary_raw, "context.summary")) if summary_raw else {}

    return {
        "assets": normalized_assets,
        "rows": normalized_rows,
        "columns": columns,
        "images": {str(key): value for key, value in images_raw.items()},
        "qrUrls": qr_urls,
        "summary": summary,
        "branding": _normalize_branding(context.get("branding")),
        "logo": context.get("logo"),
        "title": _plain(context.get("title"), MAX_TITLE_CHARS),
        "generatedAt": _plain(context.get("generatedAt"), 80),
        "document": document,
    }


# ------------------------------------------------------------------- report CSS


def _page_counter(document: DocumentLocale) -> str:
    """CSS page counters spliced into the localized footer template."""
    pieces: list[str] = []
    for part in _PAGE_COUNTER.split(document.t("api.reports.page_footer")):
        if part == "current":
            pieces.append("counter(page)")
        elif part == "total":
            pieces.append("counter(pages)")
        elif part:
            pieces.append('"' + part.replace("\\", "\\\\").replace('"', '\\"') + '"')
    return " ".join(pieces) or '""'


def _report_css(
    branding: Mapping[str, str],
    template_format: str,
    has_footer: bool,
    document: DocumentLocale,
) -> str:
    primary = branding["primary"]
    accent = branding["accent"]
    on_primary = _contrast_text(primary)
    footer_rule = (
        "@bottom-left { content: element(doc-footer); font-size: 7.5pt; color: #475569; }"
        if has_footer
        else ""
    )
    return f"""
@page {{
  size: {template_format};
  margin: 22mm 14mm 18mm 14mm;
  @top-center {{ content: element(doc-header); vertical-align: bottom; }}
  {footer_rule}
  @bottom-right {{ content: {_page_counter(document)};
  font-size: 7.5pt;
  color: #475569;
  }}
}}
* {{ box-sizing: border-box; }}
body {{ font-family: "DejaVu Sans", Arial, sans-serif;
  font-size: 9.5pt;
  color: #0b2331;
  line-height: 1.35;
  }}
.doc-header {{ position: running(doc-header);
  width: 100%;
  text-align: center;
  border-bottom: 0.5mm solid {primary};
  padding-bottom: 2mm;
  font-size: 9pt;
  color: #0b2331;
  }}
.doc-header img {{ height: 9mm; max-width: 40mm; vertical-align: middle; margin-right: 3mm; }}
.doc-header .org {{ font-weight: 700; letter-spacing: 0.02em; }}
.doc-header .header-text {{ display: block; font-size: 8pt; color: #475569; margin-top: 0.8mm; }}
.doc-footer {{ position: running(doc-footer); font-size: 7.5pt; color: #475569; }}
h1.doc-title {{ font-size: 19pt; line-height: 1.15; margin: 0 0 1mm; color: {primary}; }}
.doc-meta {{ font-size: 8.5pt; color: #475569; margin: 0 0 6mm; }}
h2.section-heading {{ font-size: 12.5pt; color: {primary}; margin: 6mm 0 2mm; break-after: avoid; }}
p.section-text {{ margin: 2mm 0 4mm; white-space: normal; }}
p.section-footer {{ margin-top: 7mm;
  padding-top: 2mm;
  border-top: 0.2mm solid #d7e3e0;
  font-size: 8pt;
  color: #475569;
  }}
table.doc-table {{ width: 100%; border-collapse: collapse; font-size: 7.7pt; margin: 2mm 0 4mm; }}
table.doc-table th {{ background: {primary};
  color: {on_primary};
  text-align: left;
  padding: 1.5mm 1.2mm;
  font-weight: 700;
  }}
table.doc-table td {{ border-bottom: 0.2mm solid #d7e3e0; padding: 1.2mm; vertical-align: top; }}
table.doc-table tr {{ break-inside: avoid; }}
.asset-card {{ break-inside: avoid;
  border: 0.2mm solid #d7e3e0;
  border-radius: 2mm;
  padding: 3mm;
  margin: 0 0 5mm;
  }}
.asset-card h3 {{ margin: 0 0 2mm; color: {primary}; font-size: 12pt; }}
table.asset-facts {{ width: 100%; border-collapse: collapse; font-size: 8.2pt; }}
table.asset-facts th {{ width: 32%;
  text-align: left;
  vertical-align: top;
  color: #475569;
  font-weight: 600;
  padding: 0.7mm 2mm 0.7mm 0;
  }}
table.asset-facts td {{ padding: 0.7mm 0; vertical-align: top; overflow-wrap: anywhere; }}
.mode-sheet .asset-card {{ break-after: page; }}
.mode-sheet .asset-card:last-of-type {{ break-after: auto; }}
.photo-block {{ margin: 4mm 0; break-inside: avoid; }}
.photo-grid figure {{ display: inline-block;
  width: 46%;
  vertical-align: top;
  margin: 0 2mm 3mm 0;
  }}
.photo-grid img.doc-photo {{ max-width: 100%; max-height: 60mm; object-fit: contain; }}
.photo-grid figcaption {{ font-size: 7.5pt; color: #475569; }}
.summary-block {{ break-inside: avoid; margin: 4mm 0; }}
.summary-total {{ font-weight: 700; margin: 1mm 0 2mm; }}
.summary-fact {{ font-size: 8.5pt; color: #475569; margin: 0 0 1mm; }}
.summary-chart {{ margin: 3mm 0; }}
.summary-chart h3 {{ font-size: 9.5pt; margin: 0 0 1.5mm; color: #334155; }}
.summary-row {{ list-style: none; margin: 0 0 1.5mm; }}
.summary-rows {{ margin: 0; padding: 0; }}
.summary-label {{ display: inline-block;
  width: 32%;
  vertical-align: middle;
  font-size: 8pt;
  overflow-wrap: anywhere;
  }}
.summary-bar {{ display: inline-block;
  width: 44%;
  height: 3mm;
  background: #e2eeeb;
  vertical-align: middle;
  margin-right: 2mm;
  }}
.summary-bar span {{ display: block; height: 3mm; background: {accent}; }}
.summary-count {{ display: inline-block;
  width: 18%;
  text-align: right;
  font-size: 8pt;
  vertical-align: middle;
  }}
.qr-block {{ margin: 4mm 0; }}
.qr-grid {{ margin: 0; padding: 0; }}
.qr-card {{ display: inline-block;
  width: 30%;
  vertical-align: top;
  text-align: center;
  margin: 0 2mm 4mm 0;
  break-inside: avoid;
  }}
.qr-card .qr svg {{ width: 30mm; height: 30mm; display: block; margin: 0 auto 1mm; }}
.qr-card figcaption {{ font-size: 7.5pt; color: #334155; overflow-wrap: anywhere; }}
.qr-card .qr-url {{ display: block;
  font-family: "DejaVu Sans Mono", monospace;
  font-size: 6.5pt;
  color: #475569;
  margin-top: 0.6mm;
  }}
.doc-empty {{ color: #475569; font-style: italic; margin: 3mm 0; }}
""".strip()


def _report_header(branding: Mapping[str, str], logo_key: str | None) -> str:
    image = f'<img src="resource://{logo_key}" alt="">' if logo_key else ""
    org = branding["name"] or "ITSM"
    header_text = (
        f'<span class="header-text">{_escape(branding["header"], 160)}</span>'
        if branding["header"]
        else ""
    )
    return (
        f'<header class="doc-header">{image}'
        f'<span class="org">{_escape(org, 120)}</span>{header_text}</header>'
    )


# --------------------------------------------------------------- report blocks


def _asset_value(asset: Mapping[str, Any], key: str) -> Any:
    value = asset.get(key)
    if value is None and key == "purchaseCost":
        value = asset.get("cost")
    return value


def _asset_cards(
    assets: list[dict[str, Any]],
    fields: list[str],
    mode: str,
    document: DocumentLocale,
) -> str:
    cards: list[str] = []
    for item in assets:
        fallback = item.get("name") or item.get("quickCode") or item.get("id")
        name = _escape(fallback or asset_name_label(document), 200)
        facts: list[str] = []
        for key in fields:
            label = field_label(key, document)
            facts.append(
                f'<tr><th scope="row">{_escape(label, 80)}</th>'
                f"<td>{_cell(_asset_value(item, key), document)}</td></tr>"
            )
        cards.append(
            f'<article class="asset-card{" mode-sheet" if mode == "sheet" else ""}">'
            f'<h3>{name}</h3><table class="asset-facts"><tbody>{"".join(facts)}</tbody></table>'
            f"</article>"
        )
    return "".join(cards)


def _table_columns(
    context: Mapping[str, Any], template: TemplateDefinition, document: DocumentLocale
) -> list[dict[str, str]]:
    if context["columns"]:
        return context["columns"]
    keys = list(template.fields)
    if not keys and context["rows"]:
        keys = [key for key in context["rows"][0] if isinstance(key, str) and key != "group"][
            :MAX_COLUMNS
        ]
    if not keys:
        keys = list(FAMILY_DEFAULT_FIELDS[template.family])
    return [{"key": key, "label": field_label(key, document)} for key in keys]


def _table_rows(
    context: Mapping[str, Any],
    columns: list[dict[str, str]],
    template: TemplateDefinition,
) -> list[Mapping[str, Any]]:
    rows = context["rows"]
    if rows or template.family != "inventory" or not context["assets"]:
        return rows
    return [
        {column["key"]: _asset_value(asset, column["key"]) for column in columns}
        for asset in context["assets"]
    ]


def _table_block(
    context: Mapping[str, Any], template: TemplateDefinition, document: DocumentLocale
) -> str:
    columns = _table_columns(context, template, document)
    rows = _table_rows(context, columns, template)
    head = "".join(f'<th scope="col">{_escape(column["label"], 120)}</th>' for column in columns)
    if not rows:
        body = (
            f'<tr><td colspan="{max(1, len(columns))}" class="doc-empty">'
            f"{document.t('api.reports.empty_rows')}</td></tr>"
        )
    else:
        parts: list[str] = []
        for group, chunk in groupby(
            rows,
            key=lambda row: (
                row.get("group") if isinstance(row, Mapping) and "group" in row else None
            ),
        ):
            chunk = list(chunk)
            if group is not None or (
                isinstance(rows[0], Mapping) and "group" in rows[0] and group is None
            ):
                label = _plain(group, 120) or missing_group_label(document)
                parts.append(
                    f'<tr class="doc-group"><th colspan="{max(1, len(columns))}">'
                    f"{_escape(label, 120)} ({len(chunk)})</th></tr>"
                )
            parts.extend(
                "<tr>"
                + "".join(
                    f"<td>{_cell(row.get(column['key']), document)}</td>" for column in columns
                )
                + "</tr>"
                for row in chunk
            )
        body = "".join(parts)
    return (
        '<table class="doc-table"><thead><tr>'
        + head
        + "</tr></thead><tbody>"
        + body
        + "</tbody></table>"
    )


def _summary_block(summary: Mapping[str, Any], document: DocumentLocale) -> str:
    charts: list[tuple[str, list[tuple[str, int]]]] = []
    for key, value in summary.items():
        if not isinstance(key, str) or not key.startswith("by") or not isinstance(value, Mapping):
            continue
        pairs: list[tuple[str, int]] = []
        for label, count in value.items():
            if isinstance(count, bool) or not isinstance(count, int):
                continue
            if not isinstance(label, str):
                continue
            visible = coverage_label(label, document) if key == "byCoverage" else label
            pairs.append((visible, count))
        if pairs:
            label = summary_group_label(key, document)
            charts.append((label, pairs))

    raw_groups = summary.get("groups")
    if isinstance(raw_groups, Sequence) and not isinstance(raw_groups, (str, bytes, bytearray)):
        group_pairs: list[tuple[str, int]] = []
        for entry in raw_groups:
            if not isinstance(entry, Mapping):
                continue
            label, count = entry.get("label"), entry.get("count")
            if isinstance(count, bool) or not isinstance(count, int):
                continue
            if not isinstance(label, str):
                continue
            group_pairs.append((label or missing_group_label(document), count))
        if group_pairs:
            charts.insert(0, (summary_group_label("groups", document), group_pairs))

    total: int | None = None
    raw_total = summary.get("total")
    if isinstance(raw_total, int) and not isinstance(raw_total, bool):
        total = raw_total
    elif charts:
        total = sum(count for _, pairs in charts[:1] for _, count in pairs)

    facts: list[str] = []
    if total is not None:
        text = document.t("api.reports.summary_total", count=total)
        facts.append(f'<p class="summary-total">{_escape(text, 80)}</p>')
    cost = summary.get("cost")
    if isinstance(cost, (str, int, float)) and not isinstance(cost, bool):
        amount = document.money(cost)
        if amount:
            facts.append(
                f'<p class="summary-fact">'
                f"{_escape(document.t('api.reports.summary_cost', amount=amount), 120)}</p>"
            )
    technical = summary.get("withTechnical")
    if isinstance(technical, int) and not isinstance(technical, bool):
        facts.append(
            f'<p class="summary-fact">'
            f"{_escape(document.t('api.reports.summary_technical', count=technical), 120)}</p>"
        )
    start, end = summary.get("from"), summary.get("to")
    if isinstance(start, str) and isinstance(end, str) and (start or end):
        period = document.t(
            "api.reports.summary_period",
            **{"from": document.day(start), "to": document.day(end)},
        )
        facts.append(f'<p class="summary-fact">{_escape(period, 160)}</p>')

    if not charts and not facts:
        return ""

    chart_html: list[str] = []
    for label, pairs in charts:
        chart_total = sum(count for _, count in pairs) or 1
        maximum = max((count for _, count in pairs), default=0) or 1
        rows: list[str] = []
        for entry, count in pairs:
            share = count / chart_total * 100
            width = count / maximum * 100
            rows.append(
                f'<li class="summary-row"><span class="summary-label">{_escape(entry, 120)}</span>'
                f'<span class="summary-bar"><span style="width:{width:.1f}%"></span></span>'
                f'<span class="summary-count">{count} ({share:.0f}%)</span></li>'
            )
        chart_html.append(
            f'<div class="summary-chart"><h3>{_escape(label, 80)}</h3>'
            f'<ul class="summary-rows">{"".join(rows)}</ul></div>'
        )
    return (
        '<section class="summary-block"><h2 class="section-heading">'
        f"{_escape(document.t('api.reports.summary_title'), 80)}</h2>"
        + "".join(facts)
        + "".join(chart_html)
        + "</section>"
    )


def _photo_block(
    context: Mapping[str, Any], resources: dict[str, bytes], document: DocumentLocale
) -> str:
    figures: list[str] = []
    for index, asset in enumerate(context["assets"]):
        asset_id = asset.get("id")
        if not isinstance(asset_id, str):
            continue
        normalized = _normalize_raster(context["images"].get(asset_id), max_edge=MAX_PHOTO_EDGE)
        if normalized is None:
            continue
        key = f"photo-{index}.png"
        resources[key] = normalized
        name = _escape(
            asset.get("name") or asset.get("quickCode") or asset_name_label(document), 200
        )
        figures.append(
            f'<figure><img class="doc-photo" src="resource://{key}" alt="{name}">'
            f"<figcaption>{name}</figcaption></figure>"
        )
    if not figures:
        return ""
    return (
        '<section class="photo-block"><h2 class="section-heading">'
        f"{_escape(document.t('api.reports.images_title'), 80)}</h2>"
        f'<div class="photo-grid">{"".join(figures)}</div></section>'
    )


def _qr_block(context: Mapping[str, Any], document: DocumentLocale) -> str:
    cards: list[str] = []
    for asset in context["assets"]:
        asset_id = asset.get("id")
        if not isinstance(asset_id, str):
            continue
        url = _safe_qr_url(context["qrUrls"].get(asset_id))
        if url is None:
            continue
        try:
            svg = qr_svg(url)
        except ValueError:
            continue
        name = _escape(
            asset.get("name") or asset.get("quickCode") or asset_name_label(document), 200
        )
        cards.append(
            f'<figure class="qr-card"><div class="qr">{svg}</div>'
            f'<figcaption>{name}<code class="qr-url">{_escape(url, 600)}</code>'
            "</figcaption></figure>"
        )
    if not cards:
        return ""
    return (
        '<section class="qr-block"><h2 class="section-heading">'
        f"{_escape(document.t('api.reports.qr_title'), 80)}</h2>"
        f'<div class="qr-grid">{"".join(cards)}</div></section>'
    )


def _render_blocks(
    template: TemplateDefinition,
    context: Mapping[str, Any],
    resources: dict[str, bytes],
    document: DocumentLocale,
) -> str:
    sections: list[str] = []
    for block in template.blocks:
        if not block.enabled:
            continue
        text = _escape(block.text, MAX_BLOCK_CHARS)
        if block.type == "heading":
            content = text or _escape(block.label, 120)
            if content:
                sections.append(f'<h2 class="section-heading">{content}</h2>')
        elif block.type == "text":
            if text:
                sections.append(f'<p class="section-text">{text.replace(chr(10), "<br>")}</p>')
        elif block.type == "asset":
            cards = _asset_cards(context["assets"], list(template.fields), template.mode, document)
            if cards:
                sections.append(f'<section class="asset-block">{cards}</section>')
            else:
                sections.append(
                    f'<p class="doc-empty">{document.t("api.reports.empty_assets")}</p>'
                )
        elif block.type == "table":
            sections.append(_table_block(context, template, document))
        elif block.type == "photo":
            if template.images:
                sections.append(_photo_block(context, resources, document))
        elif block.type == "summary":
            sections.append(_summary_block(context["summary"], document))
        elif block.type == "qr":
            sections.append(_qr_block(context, document))
        elif block.type == "footer":
            if text:
                sections.append(f'<p class="section-footer">{text}</p>')
    return "".join(section for section in sections if section)


def _compose_report(
    template: TemplateDefinition,
    context: Mapping[str, Any],
    logo_key: str | None,
) -> Composition:
    resources: dict[str, bytes] = {}
    normalized_logo = _normalize_raster(context["logo"], max_edge=MAX_LOGO_EDGE)
    if normalized_logo is not None:
        resources["logo.png"] = normalized_logo
        logo_key = "logo.png"
    elif logo_key is not None:
        logo_key = None

    branding = context["branding"]
    document = context["document"]
    header = _report_header(branding, logo_key)
    footer = (
        f'<div class="doc-footer">{_escape(branding["footer"], 160)}</div>'
        if branding["footer"]
        else ""
    )
    title = context["title"] or template.name
    meta_parts = [family_label(template.family, document)]
    if branding["name"]:
        meta_parts.append(branding["name"])
    if context["generatedAt"]:
        meta_parts.append(
            document.t("api.reports.generated", moment=document.moment(context["generatedAt"]))
        )
    meta = " · ".join(_escape(part, 160) for part in meta_parts)
    body = _render_blocks(template, context, resources, document)
    css = _report_css(branding, template.format, bool(branding["footer"]), document)
    html = (
        f'<!DOCTYPE html><html lang="{_escape(document.locale, 35)}"><head><meta charset="utf-8">'
        f"<title>{_escape(title, MAX_TITLE_CHARS)}</title><style>{css}</style></head>"
        f'<body class="mode-{template.mode}">{header}{footer}'
        f'<main><h1 class="doc-title">{_escape(title, MAX_TITLE_CHARS)}</h1>'
        f'<p class="doc-meta">{meta}</p>{body}</main></body></html>'
    )
    return Composition(html=html, resources=resources)


# --------------------------------------------------------------------- labels


def _label_geometry(options: LabelOptions) -> LabelGeometry:
    preset = _PRESET_GEOMETRY.get(options.formatId)
    if preset is not None:
        geometry = LabelGeometry(
            page_width=float(preset["page_width"]),
            page_height=float(preset["page_height"]),
            width=float(preset["width"]),
            height=float(preset["height"]),
            margin_top=float(preset["margin_top"]),
            margin_right=float(preset["margin_right"]),
            margin_bottom=float(preset["margin_bottom"]),
            margin_left=float(preset["margin_left"]),
            gap_x=float(preset["gap_x"]),
            gap_y=float(preset["gap_y"]),
            columns=int(preset["columns"]),
            rows=int(preset["rows"]),
        )
    else:
        if (
            options.widthMm is None
            or options.heightMm is None
            or options.pageWidthMm is None
            or options.pageHeightMm is None
        ):
            raise ValueError("custom label geometry is incomplete")
        usable_width = options.pageWidthMm - options.marginLeftMm - options.marginRightMm
        if (
            usable_width <= 0
            or options.columns * options.widthMm + (options.columns - 1) * options.gapXmm
            > usable_width + 1e-6
        ):
            raise ValueError("custom label columns do not fit the page width")
        usable_height = options.pageHeightMm - options.marginTopMm - options.marginBottomMm
        if usable_height <= 0:
            raise ValueError("custom label margins do not fit the page height")
        rows = math.floor(
            (usable_height + options.gapYmm) / (options.heightMm + options.gapYmm) + 1e-9
        )
        if rows < 1:
            raise ValueError("custom label rows do not fit the page height")
        geometry = LabelGeometry(
            page_width=options.pageWidthMm,
            page_height=options.pageHeightMm,
            width=options.widthMm,
            height=options.heightMm,
            margin_top=options.marginTopMm,
            margin_right=options.marginRightMm,
            margin_bottom=options.marginBottomMm,
            margin_left=options.marginLeftMm,
            gap_x=options.gapXmm,
            gap_y=options.gapYmm,
            columns=options.columns,
            rows=rows,
        )
    if options.offset >= geometry.capacity:
        raise ValueError("label offset exceeds the sheet capacity")
    return geometry


def _label_css(geometry: LabelGeometry) -> str:
    base = min(9.0, max(6.0, geometry.height * 0.17))
    name_size = min(13.0, base + 2.2)
    mono_size = max(5.2, base - 0.8)
    logo_height = min(10.0, geometry.height * 0.2)
    qr_size = min(geometry.height * 0.8, geometry.width * 0.38)
    padding = min(2.5, max(1.2, geometry.width * 0.035))
    return f"""
@page {{ size: {_mm(geometry.page_width)}mm {_mm(geometry.page_height)}mm; margin: 0; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; font-family: "DejaVu Sans", Arial, sans-serif; color: #0b2331; }}
.label-page {{ position: relative;
  width: {_mm(geometry.page_width)}mm;
  height: {_mm(geometry.page_height)}mm;
  overflow: hidden;
  break-after: page;
  page-break-after: always;
  background: #ffffff;
  }}
.label-page:last-child {{ break-after: auto; page-break-after: auto; }}
.label-cell {{ position: absolute;
  overflow: hidden;
  width: {_mm(geometry.width)}mm;
  height: {_mm(geometry.height)}mm;
  padding: {_mm(padding)}mm;
  border: 0.2mm solid #d7e3e0;
  background: #ffffff;
  }}
.label-layout {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
.label-layout td {{ vertical-align: top; padding: 0; }}
.label-text {{ font-size: {base:g}pt; line-height: 1.25; }}
.label-name {{ display: block;
  font-size: {name_size:g}pt;
  font-weight: 700;
  line-height: 1.15;
  margin: 0 0 0.7mm;
  overflow-wrap: anywhere;
  }}
.label-id {{ display: block;
  font-family: "DejaVu Sans Mono", monospace;
  font-size: {mono_size:g}pt;
  color: #334155;
  overflow-wrap: anywhere;
  }}
.label-code {{ display: block;
  font-family: "DejaVu Sans Mono", monospace;
  font-size: {mono_size:g}pt;
  font-weight: 700;
  margin: 0.4mm 0;
  }}
.label-field {{ display: block; font-size: {base:g}pt; color: #334155; overflow-wrap: anywhere; }}
.label-logo {{ display: block; height: {logo_height:g}mm; max-width: 72%; margin: 0 0 1.2mm; }}
.label-qr {{ width: {qr_size:g}mm; text-align: center; }}
.label-qr svg {{ display: block; width: {qr_size:g}mm; height: {qr_size:g}mm; }}
.label-empty {{ position: absolute;
  left: 10mm;
  right: 10mm;
  top: 40%;
  text-align: center;
  color: #475569;
  font-size: 9pt;
  }}
""".strip()


def _label_field_html(field: str, asset: Mapping[str, Any], document: DocumentLocale) -> str:
    if field == "name":
        value = _escape(
            asset.get("name") or asset.get("quickCode") or asset_name_label(document), 200
        )
        return f'<span class="label-name">{value}</span>'
    if field == "id":
        return f'<span class="label-id">{_escape(asset.get("id"), 64)}</span>'
    if field == "code":
        return f'<span class="label-code">{_escape(asset.get("quickCode"), 64)}</span>'
    label = label_field_label(field, document)
    return (
        f'<span class="label-field">{_escape(label, 80)}: '
        f"{_cell(_asset_value(asset, field), document)}</span>"
    )


def _label_cell(
    asset: Mapping[str, Any],
    *,
    fields: list[str],
    geometry: LabelGeometry,
    resources: dict[str, bytes],
    logo_key: str | None,
    qr_urls: Mapping[str, str],
    document: DocumentLocale,
    left: float,
    top: float,
) -> str:
    content: list[str] = []
    if "logo" in fields and logo_key:
        content.append(f'<img class="label-logo" src="resource://{logo_key}" alt="">')
    for field in fields:
        if field in {"logo", "qr"}:
            continue
        content.append(_label_field_html(field, asset, document))
    text_html = f'<td class="label-text">{"".join(content)}</td>'

    qr_html = ""
    if "qr" in fields:
        asset_id = asset.get("id")
        url = _safe_qr_url(qr_urls.get(asset_id)) if isinstance(asset_id, str) else None
        if url is not None:
            try:
                qr_html = f'<div class="label-qr">{qr_svg(url)}</div>'
            except ValueError:
                qr_html = ""
    if qr_html:
        layout = f'<table class="label-layout"><tr>{text_html}<td>{qr_html}</td></tr></table>'
    else:
        layout = f'<table class="label-layout"><tr>{text_html}</tr></table>'
    style = (
        f"left: {_mm(left)}mm; top: {_mm(top)}mm; "
        f"width: {_mm(geometry.width)}mm; height: {_mm(geometry.height)}mm;"
    )
    return f'<div class="label-cell" style="{style}">{layout}</div>'


def _compose_labels(
    template: TemplateDefinition,
    context: Mapping[str, Any],
    options: LabelOptions,
) -> Composition:
    if template.family != "inventory":
        raise ValueError("physical labels are only available for inventory assets")
    assets = context["assets"]
    if len(assets) > MAX_LABELS:
        raise ValueError(f"labels exceed {MAX_LABELS} assets")
    geometry = _label_geometry(options)
    document = context["document"]

    resources: dict[str, bytes] = {}
    normalized_logo = _normalize_raster(context["logo"], max_edge=MAX_LOGO_EDGE)
    logo_key: str | None = None
    if normalized_logo is not None:
        resources["logo.png"] = normalized_logo
        logo_key = "logo.png"

    fields = list(options.fields)
    if options.logo and "logo" not in fields:
        fields.insert(0, "logo")
    if options.qr and "qr" not in fields:
        fields.append("qr")

    pages: list[list[Mapping[str, Any] | None]] = []
    remaining = list(assets)
    first_page = True
    while remaining:
        start = options.offset if first_page else 0
        take = min(geometry.capacity - start, len(remaining))
        page: list[Mapping[str, Any] | None] = [None] * start + remaining[:take]
        pages.append(page)
        remaining = remaining[take:]
        first_page = False
    if not pages:
        pages = [[]]

    pages_html: list[str] = []
    for page in pages:
        cells: list[str] = []
        if not page:
            cells.append(f'<p class="label-empty">{document.t("api.reports.empty_labels")}</p>')
        for index, asset in enumerate(page):
            if asset is None:
                continue
            row, column = divmod(index, geometry.columns)
            left = geometry.margin_left + column * (geometry.width + geometry.gap_x)
            top = geometry.margin_top + row * (geometry.height + geometry.gap_y)
            cells.append(
                _label_cell(
                    asset,
                    fields=fields,
                    geometry=geometry,
                    resources=resources,
                    logo_key=logo_key,
                    qr_urls=context["qrUrls"],
                    document=document,
                    left=left,
                    top=top,
                )
            )
        pages_html.append(f'<div class="label-page">{"".join(cells)}</div>')

    css = _label_css(geometry)
    title = document.t("api.reports.labels_title", name=template.name)
    html = (
        f'<!DOCTYPE html><html lang="{_escape(document.locale, 35)}"><head><meta charset="utf-8">'
        f"<title>{_escape(title, 160)}</title><style>{css}</style></head>"
        f"<body>{''.join(pages_html)}</body></html>"
    )
    return Composition(html=html, resources=resources)


# ---------------------------------------------------------------- public entry


def compose_document(template: dict, context: dict, *, labels: dict | None = None) -> Composition:
    """Compose validated report HTML and its exact registered image resources."""
    definition = _normalize_template(template)
    normalized = _normalize_context(context)
    if labels is None:
        return _compose_report(definition, normalized, None)
    options = (
        labels if isinstance(labels, LabelOptions) else LabelOptions.model_validate(dict(labels))
    )
    return _compose_labels(definition, normalized, options)


def preview_html(composition: Composition) -> str:
    """Inline only registered resources so a sandboxed browser can display them."""
    if not isinstance(composition, Composition):
        raise ValueError("composition must be a Composition")
    if not isinstance(composition.html, str):
        raise ValueError("composition html must be a string")

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        data = composition.resources.get(key)
        if not isinstance(data, (bytes, bytearray)):
            return match.group(0)
        encoded = base64.b64encode(bytes(data)).decode("ascii")
        return f'src="data:image/png;base64,{encoded}"'

    return _RESOURCE_SRC.sub(replace, composition.html)
