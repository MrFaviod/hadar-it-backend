"""Bounded, non-evaluating CSV/XLSX decoding; no filesystem or network inputs."""

from __future__ import annotations

import csv
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date, datetime, time
from decimal import Decimal, InvalidOperation
from io import BytesIO, StringIO
from typing import Any
from zipfile import BadZipFile, ZipFile

from itsm.identity.service import ValidationFailed

MAX_BYTES = 10 * 1024 * 1024
MAX_ROWS = 5000
MAX_COLUMNS = 100
MAX_SHEETS = 20
DATE_FORMATS = ("%d/%m/%Y", "%m/%d/%Y", "%Y-%m-%d")

ALIASES = {
    "quickCode": "quick_code",
    "siteId": "site_id",
    "locationId": "location_id",
    "responsiblePersonId": "responsible_person_id",
    "positionX": "position_x",
    "positionY": "position_y",
}

SHEET_OPTIONS = ("sheetMappings", "sheetSites", "sheetCategories")


def _options(options: Any) -> dict[str, Any]:
    """Validate the bounded option shapes callers may send.

    Unknown keys stay ignored so stored profiles keep working; every documented
    key is checked here rather than inside the row loop.
    """
    if not isinstance(options, dict):
        raise ValidationFailed("import options must be an object")
    values = dict(options)
    header = values.get("headerRow", 1)
    if type(header) is not int or not 1 <= header <= 100:
        raise ValidationFailed("headerRow must be 1-100")
    mapping = values.get("mapping", {})
    if (
        not isinstance(mapping, dict)
        or len(mapping) > MAX_COLUMNS
        or not all(isinstance(k, str) and isinstance(v, str) for k, v in mapping.items())
    ):
        raise ValidationFailed("mapping must map column labels to field names")
    selected = values.get("selectedSheets")
    if selected is not None and (
        not isinstance(selected, list)
        or not 1 <= len(selected) <= MAX_SHEETS
        or any(not isinstance(name, str) or not name for name in selected)
        or len(set(selected)) != len(selected)
    ):
        raise ValidationFailed("selectedSheets must list 1-20 unique sheet names")
    for key in SHEET_OPTIONS:
        entries = values.get(key)
        if entries is None:
            continue
        if (
            not isinstance(entries, dict)
            or len(entries) > MAX_SHEETS
            or any(not isinstance(name, str) or not name for name in entries)
        ):
            raise ValidationFailed(f"{key} must map at most 20 sheet names")
    # An empty per-sheet map means "no override"; an empty target means "ignore
    # this column", matching how the global mapping already works.
    for entry in (values.get("sheetMappings") or {}).values():
        if (
            not isinstance(entry, dict)
            or len(entry) > MAX_COLUMNS
            or not all(isinstance(k, str) and k and isinstance(v, str) for k, v in entry.items())
        ):
            raise ValidationFailed("sheetMappings must map each sheet to header targets")
    for entry in (values.get("sheetSites") or {}).values():
        target = entry if isinstance(entry, dict) else {"site": entry}
        if len(target) != 1 or next(iter(target)) not in {"site", "site_id"}:
            raise ValidationFailed("sheetSites accepts a label or one site/site_id target")
        label = next(iter(target.values()))
        if not isinstance(label, str) or not label.strip() or len(label) > 100:
            raise ValidationFailed("sheetSites accepts a label or one site/site_id target")
    for entry in (values.get("sheetCategories") or {}).values():
        if not isinstance(entry, str) or not entry.strip() or len(entry) > 100:
            raise ValidationFailed("sheetCategories must map each sheet to a category")
    date_format = values.get("dateFormat")
    date_fields = values.get("dateFields")
    if date_format is not None:
        if date_format not in DATE_FORMATS:
            raise ValidationFailed("dateFormat must be one of %d/%m/%Y, %m/%d/%Y, %Y-%m-%d")
        if date_fields is None:
            raise ValidationFailed("dateFormat requires dateFields")
    if date_fields is not None:
        if date_format is None:
            raise ValidationFailed("dateFields requires dateFormat")
        if (
            not isinstance(date_fields, list)
            or not 1 <= len(date_fields) <= MAX_COLUMNS
            or len(set(date_fields)) != len(date_fields)
            or any(
                not isinstance(field, str)
                or not field.startswith("technical.")
                or len(field) <= len("technical.")
                for field in date_fields
            )
        ):
            raise ValidationFailed("dateFields must list technical.* date fields")
    if values.get("inspectOnly") is not None and type(values["inspectOnly"]) is not bool:
        raise ValidationFailed("inspectOnly must be a boolean")
    return values


def wants_inspection(options: Any) -> bool:
    """Whether the caller asked for metadata-only inspection."""
    return isinstance(options, dict) and options.get("inspectOnly") is True


def _sheet_options(options: dict[str, Any], names: list[str]) -> dict[str, Any]:
    """Validate every per-sheet key against the sheet names actually present."""
    available = set(names)
    for name in options.get("selectedSheets") or ():
        if name not in available:
            raise ValidationFailed("selectedSheets names an unknown sheet")
    for key in SHEET_OPTIONS:
        for name in options.get(key) or {}:
            if name not in available:
                raise ValidationFailed(f"{key} names an unknown sheet")
    return options


@contextmanager
def _sheets(data: bytes, filename: str, options: dict[str, Any]) -> Iterator[list[tuple[str, Any]]]:
    """Decode one bounded workbooks worth of sheet row iterators."""
    if not data or len(data) > MAX_BYTES:
        raise ValidationFailed("import must contain 1-10485760 bytes")
    suffix = filename.lower().rsplit(".", 1)[-1]
    workbook = None
    try:
        if suffix == "csv":
            encoding = options.get("encoding", "utf-8-sig")
            if encoding not in {"utf-8", "utf-8-sig", "cp1252", "latin-1"}:
                raise ValidationFailed("unsupported encoding")
            try:
                text = data.decode(encoding)
            except UnicodeError:
                raise ValidationFailed("file does not match selected encoding") from None
            delimiter = options.get("delimiter")
            if delimiter is None:
                try:
                    delimiter = csv.Sniffer().sniff(text[:8192], delimiters=",;\t|").delimiter
                except csv.Error:
                    delimiter = ","
            if delimiter not in {",", ";", "\t", "|"}:
                raise ValidationFailed("unsupported delimiter")
            yield [("CSV", csv.reader(StringIO(text), delimiter=delimiter))]
        elif suffix == "xlsx":
            try:
                with ZipFile(BytesIO(data)) as archive:
                    infos = archive.infolist()
                    if (
                        len(infos) > 1000
                        or sum(i.file_size for i in infos) > 50 * 1024 * 1024
                        or any(i.file_size > 20 * 1024 * 1024 for i in infos)
                    ):
                        raise ValidationFailed("workbook expanded size exceeds limits")
                    if any(i.filename.endswith("vbaProject.bin") for i in infos):
                        raise ValidationFailed("macro workbooks are not supported")
                from openpyxl import load_workbook

                workbook = load_workbook(
                    BytesIO(data), read_only=True, data_only=False, keep_links=False
                )
                if len(workbook.worksheets) > MAX_SHEETS:
                    raise ValidationFailed("workbook exceeds 20 sheets")
                yield [(s.title, s.iter_rows(values_only=True)) for s in workbook.worksheets]
            except BadZipFile, KeyError, ValueError, OSError:
                raise ValidationFailed("invalid XLSX workbook") from None
        else:
            raise ValidationFailed("only CSV and XLSX imports are supported")
    except (csv.Error, UnicodeError) as exc:
        raise ValidationFailed("invalid tabular file") from exc
    finally:
        if workbook is not None:
            workbook.close()


def _date(value: str, pattern: str) -> str | None:
    """Strictly parse one declared date field into a canonical ISO date."""
    try:
        parsed = datetime.strptime(value, pattern)
    except ValueError:
        return None
    if parsed.strftime(pattern) != value:
        return None
    return parsed.date().isoformat()


def _raw(cell: Any) -> str | None:
    """One raw cell as text; formulas stay unevaluated and empty stays null.

    A spreadsheet date carrying no time of day is reported as an ISO date so the
    wizard shows the value the file stores, not an artificial midnight.
    """
    if cell is None:
        return None
    if isinstance(cell, datetime):
        return cell.date().isoformat() if cell.time() == time.min else cell.isoformat()
    if isinstance(cell, date):
        return cell.isoformat()
    return str(cell)


def _labels(cells: tuple[Any, ...]) -> list[str]:
    labels = [str(cell or "").strip() for cell in cells]
    nonempty = [label for label in labels if label]
    if len(set(nonempty)) != len(nonempty):
        raise ValidationFailed("duplicate column headers require correction")
    return labels


def parse(data: bytes, filename: str, options: dict[str, Any]) -> list[dict[str, Any]]:
    """Decode rows with per-sheet mapping, site, category and date options."""
    resolved = _options(options)
    with _sheets(data, filename, resolved) as loaded:
        resolved = _sheet_options(resolved, [name for name, _ in loaded])
        sheet_mappings = resolved.get("sheetMappings") or {}
        sheet_sites = resolved.get("sheetSites") or {}
        sheet_categories = resolved.get("sheetCategories") or {}
        date_fields = set(resolved.get("dateFields") or ())
        date_format = resolved.get("dateFormat")
        output: list[dict[str, Any]] = []
        selected = set(resolved.get("selectedSheets") or [name for name, _ in loaded])
        for sheet, rows in loaded:
            if sheet not in selected:
                continue
            labels = None
            mapping = {**resolved.get("mapping", {}), **sheet_mappings.get(sheet, {})}
            for index, cells in enumerate(rows, 1):
                if len(cells) > MAX_COLUMNS:
                    raise ValidationFailed("sheet exceeds 100 columns")
                if index < resolved.get("headerRow", 1):
                    continue
                if labels is None:
                    labels = _labels(cells)
                    continue
                if not any(cell is not None and str(cell).strip() for cell in cells):
                    continue
                if len(output) >= MAX_ROWS:
                    raise ValidationFailed("import exceeds 5000 data rows")
                values, errors, technical = {}, [], {}
                for label, cell in zip(labels, cells, strict=False):
                    field = mapping.get(label, label)
                    if not field or not label:
                        continue
                    field = ALIASES.get(field, field)
                    if cell is None or str(cell).strip() == "":
                        if resolved.get("overwriteEmpty") is True:
                            values[field] = None
                        continue
                    if isinstance(cell, str) and cell.startswith("="):
                        errors.append(f"formula not evaluated in {label}")
                        continue
                    declared_date = field in date_fields
                    value = (
                        cell.date().isoformat()
                        if declared_date and isinstance(cell, datetime)
                        else cell.isoformat()
                        if isinstance(cell, (date, datetime))
                        else str(cell).strip()
                    )
                    if declared_date and not isinstance(cell, (date, datetime)):
                        parsed = _date(value, date_format or "")
                        if parsed is None:
                            errors.append(f"invalid date in {label}")
                            continue
                        value = parsed
                    if field == "cost":
                        try:
                            decimal = resolved.get("decimalSeparator", ".")
                            if decimal not in {".", ","}:
                                raise ValueError()
                            if decimal == ",":
                                value = value.replace(".", "").replace(",", ".")
                            value = str(Decimal(value))
                        except InvalidOperation, ValueError:
                            errors.append(f"invalid number in {label}")
                    if field.startswith("technical."):
                        technical[field.split(".", 1)[1]] = value
                    else:
                        values[field] = value
                if technical:
                    values["technical"] = technical
                category = sheet_categories.get(sheet) or resolved.get("category")
                if category:
                    values.setdefault("category", category)
                site = sheet_sites.get(sheet)
                if isinstance(site, dict):
                    key, label = next(iter(site.items()))
                    values.setdefault(key, label)
                elif site:
                    values.setdefault("site", site)
                if resolved.get("siteFromSheet") is True:
                    values.setdefault("site", sheet)
                output.append({"sheet": sheet, "line": index, "values": values, "errors": errors})
        return output


def inspect_file(data: bytes, filename: str, options: dict[str, Any]) -> dict[str, Any]:
    """Return bounded raw sheet metadata for the import wizard; applies no mapping.

    Row lists are capped per sheet at :data:`MAX_ROWS`; ``total`` counts the
    returned rows and ``hasMore`` reports that further rows exist. The raw file
    size limit stays :data:`MAX_BYTES`, so one response is bounded by both.
    """
    resolved = _options(options)
    with _sheets(data, filename, resolved) as loaded:
        names = [name for name, _ in loaded]
        resolved = _sheet_options(resolved, names)
        selected = set(resolved.get("selectedSheets") or names)
        sheets: list[dict[str, Any]] = []
        for sheet, rows in loaded:
            if sheet not in selected:
                continue
            columns: list[str] = []
            inspected: list[list[str | None]] = []
            has_more = False
            for index, cells in enumerate(rows, 1):
                if len(cells) > MAX_COLUMNS:
                    raise ValidationFailed("sheet exceeds 100 columns")
                if index < resolved.get("headerRow", 1):
                    continue
                if not columns:
                    columns = _labels(cells)
                    continue
                if not any(cell is not None and str(cell).strip() for cell in cells):
                    continue
                if len(inspected) >= MAX_ROWS:
                    has_more = True
                    break
                inspected.append([_raw(cell) for cell in cells])
            sheets.append(
                {
                    "id": sheet,
                    "name": sheet,
                    "columns": columns,
                    "rows": inspected,
                    "total": len(inspected),
                    "hasMore": has_more,
                }
            )
        return {"sheets": sheets}
