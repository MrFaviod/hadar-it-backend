"""Attachment HTTP behavior over isolated SQL and filesystem storage."""

from uuid import uuid4

import pytest
from tests.conftest import sign_in
from tests.test_inventory_api import create_asset


def setup_api(settings_factory, signed_in_client, tmp_path):
    settings = settings_factory(attachment_storage_path=tmp_path / "blobs")
    client, auth = signed_in_client(settings)
    asset = create_asset(client, auth)
    return settings, client, auth, asset


def upload(client, auth, asset_id, data=b"%PDF-1.7\nreceipt\n%%EOF", **params):
    return client.post(
        f"/api/v1/assets/{asset_id}/attachments",
        params={"filename": "receipt.pdf", "category": "receipt", **params},
        content=data,
        headers={**auth, "Content-Type": "application/pdf"},
    )


def test_attachment_survives_logout_and_downloads_original_bytes(
    settings_factory, signed_in_client, tmp_path
):
    settings, client, auth, asset = setup_api(settings_factory, signed_in_client, tmp_path)
    data = b"%PDF-1.7\nreceipt\n%%EOF"
    result = upload(client, auth, asset["id"], data)
    assert result.status_code == 201, result.text
    item = result.json()
    assert item["assetId"] == asset["id"]
    assert item["filename"] == "receipt.pdf"
    assert item["category"] == "receipt"
    assert item["size"] == len(data)
    assert item["id"] != asset["id"]
    assert "path" not in item and "data" not in item
    assert client.post("/api/v1/auth/logout", headers=auth).status_code == 200
    assert client.get(item["downloadUrl"]).status_code == 401
    auth = sign_in(client, settings)
    listed = client.get(f"/api/v1/assets/{asset['id']}/attachments")
    assert listed.status_code == 200
    assert listed.json()["items"] == [item]
    response = client.get(item["downloadUrl"])
    assert response.status_code == 200 and response.content == data
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    history = client.get(f"/api/v1/assets/{asset['id']}/history").json()["items"]
    assert history[-1]["action"] == "attachment_uploaded"
    assert (
        client.delete(
            f"/api/v1/assets/{asset['id']}/attachments/{item['id']}", headers=auth
        ).status_code
        == 204
    )
    assert client.get(item["downloadUrl"]).status_code == 404
    assert client.get(f"/api/v1/assets/{asset['id']}/attachments").json()["items"] == []
    assert list((tmp_path / "blobs").iterdir()) == []
    assert (
        client.get(f"/api/v1/assets/{asset['id']}/history").json()["items"][-1]["action"]
        == "attachment_deleted"
    )


@pytest.mark.parametrize(
    ("data", "params"),
    [
        (b"", {}),
        (b"<svg onload='alert(1)'/>", {"filename": "receipt.svg"}),
        (b"not a PDF", {}),
        (b"%PDF-1.7\n%%EOF", {"filename": "../../receipt.pdf"}),
        (b"%PDF-1.7\n%%EOF", {"category": "invented"}),
        (b"MZ-executable", {"filename": "run.exe"}),
    ],
)
def test_rejected_upload_leaves_inventory_history_and_storage_unchanged(
    settings_factory, signed_in_client, tmp_path, data, params
):
    _, client, auth, asset = setup_api(settings_factory, signed_in_client, tmp_path)
    before = client.get(f"/api/v1/assets/{asset['id']}/history").json()
    result = upload(client, auth, asset["id"], data, **params)
    assert result.status_code == 422, result.text
    assert client.get(f"/api/v1/assets/{asset['id']}/history").json() == before
    assert client.get(f"/api/v1/assets/{asset['id']}").json() == asset
    assert not (tmp_path / "blobs").exists()


def test_cross_asset_attachment_reference_and_purge_are_refused(
    settings_factory, signed_in_client, tmp_path
):
    _, client, auth, asset = setup_api(settings_factory, signed_in_client, tmp_path)
    other = create_asset(client, auth, quick_code="OTHER-001")
    item = upload(client, auth, asset["id"]).json()
    wrong = f"/api/v1/assets/{other['id']}/attachments/{item['id']}"
    assert client.get(wrong + "/download").status_code == 404
    assert client.delete(wrong, headers=auth).status_code == 404
    assert (
        client.post(
            f"/api/v1/assets/{asset['id']}/purge", json={"confirm": True}, headers=auth
        ).status_code
        == 409
    )
    assert client.get(item["downloadUrl"]).status_code == 200
    assert client.get(f"/api/v1/assets/{uuid4()}/attachments").status_code == 404


def test_storage_symlink_is_not_followed(settings_factory, signed_in_client, tmp_path):
    _, client, auth, asset = setup_api(settings_factory, signed_in_client, tmp_path)
    target = tmp_path / "outside"
    target.mkdir()
    (tmp_path / "blobs").symlink_to(target, target_is_directory=True)
    response = upload(client, auth, asset["id"])
    assert response.status_code == 503, response.text
    assert list(target.iterdir()) == []
    assert client.get(f"/api/v1/assets/{asset['id']}/attachments").json()["items"] == []
