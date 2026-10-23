"""Public workflow rules: parsing, snapshots, immutable IDs and retries."""

from io import BytesIO

from openpyxl import Workbook
from tests.test_inventory_api import create_asset


def analyze(client, auth, data, filename="assets.csv", options=None):
    import json

    return client.post(
        "/api/v1/imports/analyze",
        params={"filename": filename, "options": json.dumps(options or {})},
        content=data,
        headers={**auth, "Content-Type": "application/octet-stream"},
    )


def approve_execute(client, auth, preview):
    approved = client.post(f"/api/v1/operations/{preview['id']}/approve", headers=auth)
    assert approved.status_code == 200, approved.text
    result = client.post(f"/api/v1/operations/{preview['id']}/execute", headers=auth)
    assert result.status_code == 200, result.text
    return result.json()


def test_csv_preview_preserves_assets_and_uuid_empty_fields_and_retry(signed_in_client):
    client, auth = signed_in_client()
    asset = create_asset(client, auth)
    history = client.get(f"/api/v1/assets/{asset['id']}/history").json()
    response = analyze(
        client, auth, f"id,name,serial\n{asset['id']},Renamed,\n,New asset,NEW-7\n".encode()
    )
    assert response.status_code == 200, response.text
    preview = response.json()
    assert [r["classification"] for r in preview["rows"]] == ["safe", "new"]
    assert client.get(f"/api/v1/assets/{asset['id']}").json() == asset
    assert client.get(f"/api/v1/assets/{asset['id']}/history").json() == history
    result = approve_execute(client, auth, preview)
    assert result["summary"] == {"created": 1, "modified": 1, "omitted": 0, "failed": 0}
    updated = client.get(f"/api/v1/assets/{asset['id']}").json()
    assert updated["id"] == asset["id"] and updated["serial"] == asset["serial"]
    retry = client.post(f"/api/v1/operations/{preview['id']}/execute", headers=auth)
    assert retry.json()["summary"] == result["summary"]
    assert client.get("/api/v1/assets").json()["total"] == 2


def test_ambiguous_serial_requires_resolution_and_mapping_profiles_persist(signed_in_client):
    client, auth = signed_in_client()
    one = create_asset(client, auth, serial="DUP")
    create_asset(client, auth, quick_code="SECOND-1", serial="DUP")
    response = analyze(
        client,
        auth,
        b"Equipo;Serie\nReplacement;DUP\n",
        options={"delimiter": ";", "mapping": {"Equipo": "name", "Serie": "serial"}},
    )
    assert response.status_code == 200
    preview = response.json()
    assert preview["rows"][0]["classification"] == "possible_duplicate"
    blocked = client.post(f"/api/v1/operations/{preview['id']}/approve", headers=auth)
    assert blocked.status_code == 409
    resolved = client.post(
        f"/api/v1/operations/{preview['id']}/resolve",
        json={"row": 0, "action": "update", "assetId": one["id"]},
        headers=auth,
    )
    assert resolved.status_code == 200, resolved.text
    assert approve_execute(client, auth, resolved.json())["summary"]["modified"] == 1
    profile = client.post(
        "/api/v1/import-profiles",
        json={"name": "Office CSV", "options": {"delimiter": ";", "mapping": {"Equipo": "name"}}},
        headers=auth,
    )
    assert profile.status_code == 201, profile.text
    assert any(
        p["id"] == profile.json()["id"]
        for p in client.get("/api/v1/import-profiles").json()["items"]
    )


def test_multisheet_xlsx_dates_numbers_custom_fields_and_missing_cells(signed_in_client):
    client, auth = signed_in_client()
    book = Workbook()
    book.active.title = "North"
    book.active.append(["name", "cost", "serial"])
    book.active.append(["Switch", "1.234,50", None])
    second = book.create_sheet("South")
    second.append(["name", "cost", "serial"])
    second.append(["Camera", "10,00", "CAM1"])
    output = BytesIO()
    book.save(output)
    response = analyze(
        client,
        auth,
        output.getvalue(),
        "assets.xlsx",
        {"siteFromSheet": True, "decimalSeparator": ","},
    )
    assert response.status_code == 200, response.text
    rows = response.json()["rows"]
    assert [r["values"]["site"] for r in rows] == ["North", "South"]
    assert rows[0]["values"]["cost"] == "1234.50"
    assert "serial" not in rows[0]["values"]


def test_bulk_requires_approval_stale_fails_partially_preserves_unselected(signed_in_client):
    client, auth = signed_in_client()
    one = create_asset(client, auth)
    two = create_asset(client, auth, quick_code="TWO-2")
    response = client.post(
        "/api/v1/bulk/preview",
        json={"assetIds": [one["id"], two["id"]], "changes": {"brand": "Updated"}},
        headers=auth,
    )
    assert response.status_code == 200, response.text
    preview = response.json()
    assert (
        client.post(f"/api/v1/operations/{preview['id']}/execute", headers=auth).status_code == 409
    )
    assert (
        client.post(f"/api/v1/operations/{preview['id']}/approve", headers=auth).status_code == 200
    )
    assert (
        client.patch(
            f"/api/v1/assets/{two['id']}", json={"name": "Changed concurrently"}, headers=auth
        ).status_code
        == 200
    )
    result = client.post(f"/api/v1/operations/{preview['id']}/execute", headers=auth)
    assert result.status_code == 200
    assert result.json()["summary"]["modified"] == 1
    assert result.json()["summary"]["failed"] == 1
    fresh = client.get(f"/api/v1/assets/{one['id']}").json()
    assert fresh["brand"] == "Updated" and fresh["serial"] == one["serial"]
    assert client.get(f"/api/v1/assets/{two['id']}").json()["brand"] == two["brand"]


def test_export_is_real_csv_with_uuid_and_formula_neutralization(signed_in_client):
    client, auth = signed_in_client()
    asset = create_asset(client, auth, name="=DANGEROUS()")
    response = client.post(
        "/api/v1/assets/export",
        json={"assetIds": [asset["id"]], "fields": ["name", "serial"]},
        headers=auth,
    )
    assert response.status_code == 200, response.text
    assert asset["id"] in response.text and "'=DANGEROUS()" in response.text
    assert response.headers["content-type"].startswith("text/csv")
