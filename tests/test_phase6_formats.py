"""Import formats: configurable dates, per-sheet options and metadata inspection."""

from __future__ import annotations

import json
from datetime import date
from io import BytesIO

import pytest
from itsm.identity.service import ValidationFailed
from itsm.workflows.models import Operation
from itsm.workflows.parsing import MAX_ROWS, parse
from openpyxl import Workbook
from sqlalchemy import func, select
from tests.test_inventory_api import create_asset

PURCHASE_DATE = "technical.purchaseDate"
SITE_ID = "0b6f8b3e-6b53-4f0e-9c1c-1d2c3b4a5e6f"


def analyze(client, auth, data, filename="assets.csv", options=None):
    return client.post(
        "/api/v1/imports/analyze",
        params={"filename": filename, "options": json.dumps(options or {})},
        content=data,
        headers={**auth, "Content-Type": "application/octet-stream"},
    )


def workbook(*sheets: tuple[str, list[list[object]]]) -> bytes:
    book = Workbook()
    book.remove(book.active)
    for name, rows in sheets:
        sheet = book.create_sheet(title=name)
        for row in rows:
            sheet.append(row)
    buffer = BytesIO()
    book.save(buffer)
    return buffer.getvalue()


def inspect(data: bytes, filename: str = "assets.csv", options: dict | None = None) -> dict:
    from itsm.workflows.parsing import inspect_file

    return inspect_file(data, filename, options or {})


def dated(options: dict | None = None) -> dict:
    return {
        "mapping": {"Compra": PURCHASE_DATE},
        "dateFormat": "%d/%m/%Y",
        "dateFields": [PURCHASE_DATE],
        **(options or {}),
    }


def two_sites() -> bytes:
    return workbook(
        ("Sede A", [["Nombre"], ["Switch A"]]),
        ("Sede B", [["Nombre"], ["Switch B"]]),
    )


# -- configurable date parsing -------------------------------------------------


def test_date_format_parses_the_configured_field_into_an_iso_date():
    rows = parse(b"Compra\n31/12/2024\n", "assets.csv", dated())

    assert rows[0]["values"] == {"technical": {"purchaseDate": "2024-12-31"}}
    assert rows[0]["errors"] == []


@pytest.mark.parametrize(
    ("pattern", "raw", "expected"),
    [
        ("%d/%m/%Y", "05/03/2024", "2024-03-05"),
        ("%m/%d/%Y", "03/05/2024", "2024-03-05"),
        ("%Y-%m-%d", "2024-03-05", "2024-03-05"),
    ],
)
def test_date_format_accepts_every_allowlisted_pattern(pattern, raw, expected):
    options = {**dated(), "dateFormat": pattern}

    rows = parse(f"Compra\n{raw}\n".encode(), "assets.csv", options)

    assert rows[0]["values"]["technical"]["purchaseDate"] == expected


def test_date_format_rejects_a_pattern_outside_the_allowlist():
    options = {**dated(), "dateFormat": "%d-%m-%Y"}

    with pytest.raises(ValidationFailed):
        parse(b"Compra\n31-12-2024\n", "assets.csv", options)


def test_date_field_must_target_a_technical_attribute():
    options = {**dated(), "dateFields": ["purchase_date"]}

    with pytest.raises(ValidationFailed):
        parse(b"Compra\n31/12/2024\n", "assets.csv", options)


def test_date_fields_require_an_explicit_format():
    options = {"mapping": {"Compra": PURCHASE_DATE}, "dateFields": [PURCHASE_DATE]}

    with pytest.raises(ValidationFailed):
        parse(b"Compra\n31/12/2024\n", "assets.csv", options)


def test_date_format_requires_declared_date_fields():
    options = {"mapping": {"Compra": PURCHASE_DATE}, "dateFormat": "%d/%m/%Y"}

    with pytest.raises(ValidationFailed):
        parse(b"Compra\n31/12/2024\n", "assets.csv", options)


def test_impossible_calendar_date_becomes_a_row_error_instead_of_a_value():
    rows = parse(b"Compra\n31/02/2024\n", "assets.csv", dated())

    assert rows[0]["errors"] and "Compra" in rows[0]["errors"][0]
    assert "technical" not in rows[0]["values"]


def test_date_parsing_rejects_values_that_are_not_exactly_formatted():
    rows = parse(b"Compra\n5/3/2024\n", "assets.csv", dated())

    assert rows[0]["errors"] and "Compra" in rows[0]["errors"][0]
    assert "technical" not in rows[0]["values"]


# -- per-sheet selection, mapping, site and category ---------------------------


def test_selected_sheets_parse_only_the_named_sheets():
    rows = parse(two_sites(), "assets.xlsx", {"selectedSheets": ["Sede B"]})

    assert [row["sheet"] for row in rows] == ["Sede B"]
    assert rows[0]["values"] == {"Nombre": "Switch B"}


def test_selected_sheets_reject_an_unknown_sheet_name():
    with pytest.raises(ValidationFailed):
        parse(two_sites(), "assets.xlsx", {"selectedSheets": ["Sede Z"]})


def test_selected_sheets_reject_duplicate_names():
    with pytest.raises(ValidationFailed):
        parse(two_sites(), "assets.xlsx", {"selectedSheets": ["Sede A", "Sede A"]})


def test_selected_sheets_reject_more_names_than_the_workbook_allows():
    with pytest.raises(ValidationFailed):
        parse(two_sites(), "assets.xlsx", {"selectedSheets": [f"S{i}" for i in range(21)]})


def test_sheet_mapping_overrides_the_global_column_mapping():
    rows = parse(
        two_sites(),
        "assets.xlsx",
        {"mapping": {"Nombre": "name"}, "sheetMappings": {"Sede B": {"Nombre": "category"}}},
    )

    by_sheet = {row["sheet"]: row["values"] for row in rows}
    assert by_sheet["Sede A"] == {"name": "Switch A"}
    assert by_sheet["Sede B"] == {"category": "Switch B"}


def test_sheet_mapping_rejects_a_sheet_name_that_is_not_in_the_file():
    with pytest.raises(ValidationFailed):
        parse(two_sites(), "assets.xlsx", {"sheetMappings": {"Sede Z": {"Nombre": "name"}}})


def test_sheet_mapping_rejects_a_non_string_target():
    with pytest.raises(ValidationFailed):
        parse(two_sites(), "assets.xlsx", {"sheetMappings": {"Sede A": {"Nombre": 7}}})


def test_sheet_site_applies_a_legacy_label_to_that_sheet_only():
    rows = parse(two_sites(), "assets.xlsx", {"sheetSites": {"Sede A": "Example Site"}})

    by_sheet = {row["sheet"]: row["values"] for row in rows}
    assert by_sheet["Sede A"] == {"Nombre": "Switch A", "site": "Example Site"}
    assert by_sheet["Sede B"] == {"Nombre": "Switch B"}


def test_sheet_site_accepts_an_explicit_canonical_site_id():
    rows = parse(two_sites(), "assets.xlsx", {"sheetSites": {"Sede A": {"site_id": SITE_ID}}})

    assert rows[0]["values"] == {"Nombre": "Switch A", "site_id": SITE_ID}


def test_sheet_site_rejects_ambiguous_or_unsupported_targets():
    with pytest.raises(ValidationFailed):
        parse(
            two_sites(),
            "assets.xlsx",
            {"sheetSites": {"Sede A": {"site": "A", "site_id": SITE_ID}}},
        )
    with pytest.raises(ValidationFailed):
        parse(two_sites(), "assets.xlsx", {"sheetSites": {"Sede A": {"location": "A"}}})


def test_a_row_site_column_wins_over_the_sheet_site():
    data = workbook(("Sede A", [["Nombre", "Sede"], ["Switch A", "Rack 2"]]))

    rows = parse(
        data,
        "assets.xlsx",
        {"mapping": {"Sede": "site"}, "sheetSites": {"Sede A": "Example Site"}},
    )

    assert rows[0]["values"]["site"] == "Rack 2"


def test_sheet_category_applies_to_that_sheet_only():
    rows = parse(two_sites(), "assets.xlsx", {"sheetCategories": {"Sede A": "Red"}})

    by_sheet = {row["sheet"]: row["values"] for row in rows}
    assert by_sheet["Sede A"] == {"Nombre": "Switch A", "category": "Red"}
    assert by_sheet["Sede B"] == {"Nombre": "Switch B"}


# -- metadata inspection -------------------------------------------------------


def test_inspect_returns_raw_columns_and_rows_per_sheet():
    payload = inspect(
        workbook(("Sede A", [["Nombre", "Compra"], ["Switch", date(2024, 12, 31)]])),
        "assets.xlsx",
    )

    assert set(payload) == {"sheets"}
    sheet = payload["sheets"][0]
    assert sheet["id"] == sheet["name"] == "Sede A"
    assert sheet["columns"] == ["Nombre", "Compra"]
    assert sheet["rows"] == [["Switch", "2024-12-31"]]
    assert sheet["total"] == 1
    assert sheet["hasMore"] is False


def test_inspect_keeps_unmapped_raw_values_untouched():
    payload = inspect(
        workbook(("Sede A", [["Nombre", "Formula"], ["Switch", "=1+1"]])), "assets.xlsx"
    )

    sheet = payload["sheets"][0]
    assert sheet["columns"] == ["Nombre", "Formula"]
    assert sheet["rows"] == [["Switch", "=1+1"]]


def test_inspect_respects_the_selected_sheets():
    payload = inspect(two_sites(), "assets.xlsx", {"selectedSheets": ["Sede B"]})

    assert [sheet["name"] for sheet in payload["sheets"]] == ["Sede B"]


def test_inspect_caps_rows_per_sheet_and_reports_more():
    data = ("Nombre\n" + "".join(f"Equipo {index}\n" for index in range(MAX_ROWS + 1))).encode()

    sheet = inspect(data)["sheets"][0]

    assert len(sheet["rows"]) == MAX_ROWS
    assert sheet["total"] == MAX_ROWS
    assert sheet["hasMore"] is True


# -- service/HTTP boundary -----------------------------------------------------


def test_inspect_only_analysis_has_no_stored_operation_or_asset_effect(signed_in_client):
    client, auth = signed_in_client()
    asset = create_asset(client, auth)
    history = client.get(f"/api/v1/assets/{asset['id']}/history").json()

    response = analyze(
        client,
        auth,
        workbook(("Sede A", [["Nombre"], ["Switch"]])),
        filename="assets.xlsx",
        options={"inspectOnly": True},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert set(payload) == {"sheets"}
    assert payload["sheets"][0]["name"] == "Sede A"
    with client.app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(Operation)) == 0
    assert client.get("/api/v1/assets").json()["total"] == 1
    assert client.get(f"/api/v1/assets/{asset['id']}/history").json() == history


def test_inspect_only_analysis_still_requires_authentication(signed_in_client):
    client, _ = signed_in_client()

    response = client.post(
        "/api/v1/imports/analyze",
        params={"filename": "assets.csv", "options": json.dumps({"inspectOnly": True})},
        content=b"Nombre\nSwitch\n",
        headers={"Content-Type": "application/octet-stream"},
    )

    assert response.status_code == 403
