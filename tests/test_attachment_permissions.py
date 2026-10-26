"""Attachment authorization, independent storage and interrupted cleanup."""

import pytest
from tests.conftest import sign_in
from tests.inventory_support import prepare, sign_in_as
from tests.test_attachments import setup_api, upload


def test_reader_can_download_but_cannot_upload_delete_or_forge_csrf(
    settings_factory, signed_in_client, tmp_path
):
    from itsm.database import create_engine_from_settings
    from tests.inventory_support import Catalog

    settings, client, auth, asset = setup_api(settings_factory, signed_in_client, tmp_path)
    item = upload(client, auth, asset["id"]).json()
    catalog = Catalog(settings, create_engine_from_settings(settings))
    try:
        catalog.add_user("document-reader", "Document Reader", "user")
    finally:
        catalog.engine.dispose()
    before = client.get(f"/api/v1/assets/{asset['id']}/history").json()
    assert client.post("/api/v1/auth/logout", headers=auth).status_code == 200
    reader = sign_in_as(client, settings, "document-reader")
    assert client.get(item["downloadUrl"]).status_code == 200
    assert upload(client, reader, asset["id"]).status_code == 403
    assert (
        client.delete(
            f"/api/v1/assets/{asset['id']}/attachments/{item['id']}", headers=reader
        ).status_code
        == 403
    )
    assert client.get(f"/api/v1/assets/{asset['id']}/history").json() == before
    assert client.get(f"/api/v1/assets/{asset['id']}/attachments").json()["items"] == [item]
    assert len(list((tmp_path / "blobs").iterdir())) == 1
    assert client.post("/api/v1/auth/logout", headers=reader).status_code == 200
    admin = sign_in(client, settings)
    assert upload(client, {"Origin": settings.auth_origin}, asset["id"]).status_code == 403
    assert (
        upload(client, {**admin, "Origin": "https://untrusted.invalid"}, asset["id"]).status_code
        == 403
    )
    assert client.get(f"/api/v1/assets/{asset['id']}/history").json() == before


def test_upload_limit_rejects_without_creating_storage(
    settings_factory, signed_in_client, tmp_path
):
    from tests.test_inventory_api import create_asset

    settings = settings_factory(attachment_storage_path=tmp_path / "blobs", attachment_max_bytes=8)
    client, auth = signed_in_client(settings)
    asset = create_asset(client, auth)
    before = client.get(f"/api/v1/assets/{asset['id']}/history").json()
    result = upload(client, auth, asset["id"], b"%PDF-1.7\n%%EOF")
    assert result.status_code == 422
    assert client.get(f"/api/v1/assets/{asset['id']}/history").json() == before
    assert not (tmp_path / "blobs").exists()


def test_storage_restart_and_failed_delete_remains_hidden_and_retryable(settings_factory, tmp_path):
    from itsm.attachments.service import AttachmentService, StorageUnavailable
    from itsm.attachments.storage import LocalBlobStorage
    from itsm.inventory.service import InventoryService

    class UnavailableDelete(LocalBlobStorage):
        def delete(self, key):
            raise OSError("storage temporarily read-only")

    catalog = prepare(settings_factory, attachment_storage_path=tmp_path / "blobs")
    try:
        with catalog.session() as session:
            asset = InventoryService(session, catalog.settings).create(
                catalog.admin(), {"name": "Receipt host", "category": "switch"}
            )
            item = AttachmentService(session, catalog.settings).upload(
                catalog.admin(),
                asset.id,
                filename="receipt.pdf",
                category="receipt",
                data=b"%PDF-1.7\n%%EOF",
            )
        with catalog.session() as session:
            documents = AttachmentService(session, catalog.settings)
            assert (
                documents.download(catalog.admin(), asset.id, item["id"])[1] == b"%PDF-1.7\n%%EOF"
            )
            failing = AttachmentService(
                session, catalog.settings, storage=UnavailableDelete(tmp_path / "blobs")
            )
            with pytest.raises(StorageUnavailable):
                failing.delete(catalog.admin(), asset.id, item["id"])
        with catalog.session() as session:
            documents = AttachmentService(session, catalog.settings)
            assert documents.list(catalog.admin(), asset.id)["items"] == []
            before = (
                InventoryService(session, catalog.settings).history(catalog.admin(), asset.id).total
            )
            assert len(list((tmp_path / "blobs").iterdir())) == 1
            documents.delete(catalog.admin(), asset.id, item["id"])
            assert list((tmp_path / "blobs").iterdir()) == []
            assert (
                InventoryService(session, catalog.settings).history(catalog.admin(), asset.id).total
                == before
            )
    finally:
        catalog.engine.dispose()


def test_corrupt_blob_does_not_download_as_valid_document(
    settings_factory, signed_in_client, tmp_path
):
    _, client, auth, asset = setup_api(settings_factory, signed_in_client, tmp_path)
    item = upload(client, auth, asset["id"]).json()
    blob = next((tmp_path / "blobs").iterdir())
    blob.write_bytes(b"corrupt")
    response = client.get(item["downloadUrl"])
    assert response.status_code == 503
    assert response.json() == {
        "error": {"code": "unavailable", "message": "attachment storage unavailable"}
    }
    assert str(tmp_path) not in response.text
