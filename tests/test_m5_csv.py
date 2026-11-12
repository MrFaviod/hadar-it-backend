"""M5 public CSV exports: text prefixes, typed numbers and import preview fidelity."""

import csv
from io import StringIO

import pytest
from itsm.reports.data import csv_bytes
from tests.test_inventory_api import create_asset
from tests.test_phase6_workflows import analyze


@pytest.mark.parametrize(
    "value", ["=1", "+1", "-1", "@x", "  =1", "\ttext", "\rtext", "\ntext", "\x01=1", "\x7f=1"]
)
def test_report_csv_neutralizes_text_prefixes_and_header(value):
    content = csv_bytes(
        [{"name": value, "cost": -12.5, "zero": 0}],
        [
            {"key": "name", "label": value},
            {"key": "cost", "label": "Cost"},
            {"key": "zero", "label": "Zero"},
        ],
    )
    parsed = list(csv.reader(StringIO(content.decode("utf-8-sig"), newline="")))
    assert parsed == [["'" + value, "Cost", "Zero"], ["'" + value, "-12.5", "0"]]


def test_inventory_export_typed_negative_roundtrip_without_mutation(signed_in_client):
    client, auth = signed_in_client()
    asset = create_asset(client, auth, name="Safe, quoted", cost="12.50")
    response = client.post(
        "/api/v1/assets/export",
        json={"assetIds": [asset["id"]], "fields": ["name", "cost"]},
        headers=auth,
    )
    assert response.status_code == 200, response.text
    parsed = list(csv.reader(StringIO(response.content.decode("utf-8-sig"))))
    assert parsed == [["id", "name", "cost"], [asset["id"], "Safe, quoted", "12.50"]]
    preview = analyze(client, auth, response.content)
    assert preview.status_code == 200, preview.text
    assert preview.json()["rows"][0]["values"]["cost"] == "12.50"
    assert client.get(f"/api/v1/assets/{asset['id']}", headers=auth).json() == asset
    assert client.get("/api/v1/assets", headers=auth).json()["total"] == 1


def test_report_csv_negative_typed_number_and_quotes_roundtrip():
    content = csv_bytes(
        [{"n": -12.5, "label": 'Safe,"quoted"\rline'}],
        [{"key": "n", "label": "Number"}, {"key": "label", "label": "Label"}],
    )
    assert list(csv.reader(StringIO(content.decode("utf-8-sig"), newline=""))) == [
        ["Number", "Label"],
        ["-12.5", 'Safe,"quoted"\rline'],
    ]


@pytest.mark.parametrize(
    "code",
    [
        *range(32),
        *range(127, 160),
        0x20,
        0xA0,
        0x1680,
        *range(0x2000, 0x200B),
        0x2028,
        0x2029,
        0x202F,
        0x205F,
        0x3000,
        0xFEFF,
    ],
)
def test_csv_exhaustive_controls_whitespace_and_typed_values(code):
    value = chr(code) + "text"
    row = {"text": value, "number": -12.5, "numeric_text": "-12.5", "zero": 0}
    original = dict(row)
    content = csv_bytes(
        [row],
        [
            {"key": "text", "label": value},
            {"key": "number", "label": "Number"},
            {"key": "numeric_text", "label": "Text"},
            {"key": "zero", "label": "Zero"},
        ],
    )
    assert list(csv.reader(StringIO(content.decode("utf-8-sig"), newline=""))) == [
        ["'" + value, "Number", "Text", "Zero"],
        ["'" + value, "-12.5", "'-12.5", "0"],
    ]
    assert row == original
