"""Export keeps real CSV semantics while the incumbent controls stay bounded."""

import csv
from io import StringIO

from tests.test_inventory_api import create_asset

DEFAULT_FIELDS = [
    "quick_code",
    "name",
    "category",
    "status",
    "serial",
    "site",
    "location",
    "responsible",
]
BOM = b"\xef\xbb\xbf"


def export(client, auth, body):
    return client.post("/api/v1/assets/export", json=body, headers=auth)


def rows(response):
    assert response.status_code == 200, response.text
    return list(csv.reader(StringIO(response.content.decode("utf-8-sig"))))


def test_export_defaults_keep_comma_header_bom_and_every_default_column(signed_in_client):
    client, auth = signed_in_client()
    asset = create_asset(client, auth, name="Alpha")
    response = export(client, auth, {"assetIds": [asset["id"]]})

    assert response.content.startswith(BOM)
    parsed = rows(response)
    assert parsed[0] == ["id", *DEFAULT_FIELDS]
    assert parsed[1][0] == asset["id"]
    assert parsed[1][1:4] == [asset["quickCode"], "Alpha", asset["category"]]


def test_export_options_drive_separator_header_bom_and_empty_columns(signed_in_client):
    client, auth = signed_in_client()
    asset = create_asset(client, auth, name="Alpha")
    response = export(
        client,
        auth,
        {
            "assetIds": [asset["id"]],
            "fields": ["id", "cost", "technical", "name"],
            "options": {
                "separator": "semicolon",
                "headerRow": False,
                "bom": False,
                "includeEmpty": False,
            },
        },
    )

    assert response.status_code == 200, response.text
    assert not response.content.startswith(BOM)
    assert response.content.decode("utf-8") == f"{asset['id']};Alpha\r\n"


def test_export_keeps_requested_empty_columns_in_field_order_and_escapes_formulas(
    signed_in_client,
):
    client, auth = signed_in_client()
    asset = create_asset(client, auth, name="=DANGEROUS()")
    response = export(
        client,
        auth,
        {
            "assetIds": [asset["id"]],
            "fields": ["name", "id", "cost"],
            "options": {"includeEmpty": True},
        },
    )

    parsed = rows(response)
    assert parsed[0] == ["id", "name", "cost"]
    assert parsed[1] == [asset["id"], "'=DANGEROUS()", ""]


def test_export_selects_the_whole_inventory_only_with_explicit_all_true(signed_in_client):
    client, auth = signed_in_client()
    one = create_asset(client, auth)
    two = create_asset(client, auth, quick_code="SECOND-2")
    parsed = rows(export(client, auth, {"filters": {"all": True}, "fields": ["id"]}))

    assert sorted(row[0] for row in parsed[1:]) == sorted([one["id"], two["id"]])
    for filters in ({"all": False}, {"all": "true"}, {"all": 1}, {}):
        assert export(client, auth, {"filters": filters, "fields": ["id"]}).status_code == 422


def test_export_rejects_unknown_or_malformed_options(signed_in_client):
    client, auth = signed_in_client()
    asset = create_asset(client, auth)
    for options in (
        {"separator": "colon"},
        {"separator": ","},
        {"headerRow": "yes"},
        {"bom": 0},
        {"includeEmpty": None},
        {"unexpected": True},
    ):
        response = export(client, auth, {"assetIds": [asset["id"]], "options": options})
        assert response.status_code == 422, options
