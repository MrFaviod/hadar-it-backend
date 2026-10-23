"""Snapshot approval, revocation and parser rejection through public boundaries."""

from io import BytesIO
from zipfile import ZipFile

from tests.test_inventory_api import create_asset
from tests.test_phase6_workflows import analyze


def test_preview_does_not_advance_codes_and_bad_files_leave_inventory_unchanged(signed_in_client):
    client, auth = signed_in_client()
    first = create_asset(client, auth, quick_code="TEST-001")
    assert analyze(client, auth, b"name,quickCode\nImported,TEST-002\n").status_code == 200
    second = create_asset(client, auth, quick_code="TEST-002")
    assert second["quickCode"] == "TEST-002"
    before = client.get("/api/v1/assets/search").json()
    invalid = [(b"bad", "bad.xls"), (b"not zip", "bad.xlsx"), (b"name,name\na,b\n", "bad.csv")]
    bomb = BytesIO()
    with ZipFile(bomb, "w") as archive:
        archive.writestr("word/vbaProject.bin", b"macro")
    invalid.append((bomb.getvalue(), "macro.xlsx"))
    for data, name in invalid:
        response = analyze(client, auth, data, name)
        assert response.status_code == 422, response.text
        assert client.get("/api/v1/assets/search").json() == before
    assert client.get(f"/api/v1/assets/{first['id']}").json() == first


def test_resolving_approved_preview_invalidates_approval(signed_in_client):
    client, auth = signed_in_client()
    asset = create_asset(client, auth)
    preview = client.post(
        "/api/v1/bulk/preview",
        json={"assetIds": [asset["id"]], "changes": {"brand": "One"}},
        headers=auth,
    ).json()
    assert (
        client.post(f"/api/v1/operations/{preview['id']}/approve", headers=auth).status_code == 200
    )
    changed = client.post(
        f"/api/v1/operations/{preview['id']}/resolve",
        json={"row": 0, "action": "update", "assetId": asset["id"], "values": {"brand": "Two"}},
        headers=auth,
    )
    assert changed.status_code == 200
    assert not changed.json()["approved"]
    assert (
        client.post(f"/api/v1/operations/{preview['id']}/execute", headers=auth).status_code == 409
    )
    assert client.get(f"/api/v1/assets/{asset['id']}").json() == asset


def test_import_empty_overwrite_is_explicit_and_permanent_id_never_replaced(signed_in_client):
    client, auth = signed_in_client()
    asset = create_asset(client, auth)
    response = analyze(
        client,
        auth,
        f"id,name,serial\n{asset['id']},Updated,\n".encode(),
        options={"overwriteEmpty": True},
    )
    assert response.status_code == 200
    preview = response.json()
    assert preview["rows"][0]["values"]["serial"] is None
    assert (
        client.post(f"/api/v1/operations/{preview['id']}/approve", headers=auth).status_code == 200
    )
    assert (
        client.post(f"/api/v1/operations/{preview['id']}/execute", headers=auth).status_code == 200
    )
    updated = client.get(f"/api/v1/assets/{asset['id']}").json()
    assert updated["id"] == asset["id"] and updated["serial"] is None
    unknown = analyze(
        client, auth, b"id,name\n00000000-0000-0000-0000-000000000001,Unknown\n"
    ).json()
    assert unknown["rows"][0]["classification"] == "error"
    assert (
        client.post(f"/api/v1/operations/{unknown['id']}/approve", headers=auth).status_code == 409
    )
