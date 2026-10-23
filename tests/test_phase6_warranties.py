"""Individual warranty state, proof ownership, permissions and preferences."""

from datetime import date, timedelta

from tests.test_attachments import upload
from tests.test_inventory_api import create_asset

PDF = b"%PDF-1.7\nreceipt\n%%EOF"


def test_warranty_expiry_receipt_queries_preferences_and_history(
    signed_in_client, settings_factory, tmp_path
):
    client, auth = signed_in_client(settings_factory(attachment_storage_path=tmp_path / "blobs"))
    asset = create_asset(client, auth)
    attachment = upload(client, auth, asset["id"], PDF).json()
    today = date.today()
    data = {
        "supplier": "Vendor",
        "purchaseDate": today.isoformat(),
        "durationMonths": 12,
        "receiptId": attachment["id"],
        "notes": "Individual coverage",
        "status": "active",
    }
    response = client.put(f"/api/v1/assets/{asset['id']}/warranty", json=data, headers=auth)
    assert response.status_code == 200, response.text
    warranty = response.json()
    assert warranty["assetId"] == asset["id"]
    assert warranty["expiresOn"] == today.replace(year=today.year + 1).isoformat()
    assert warranty["coverage"] == "current"
    assert warranty["receiptId"] == attachment["id"]
    assert client.get(f"/api/v1/assets/{asset['id']}/warranty").json() == warranty
    assert any(
        w["assetId"] == asset["id"]
        for w in client.get("/api/v1/warranties?coverage=current").json()["items"]
    )
    assert (
        client.put(
            "/api/v1/warranty-preferences", json={"expiringDays": 45}, headers=auth
        ).status_code
        == 200
    )
    assert client.get("/api/v1/warranty-preferences").json() == {"expiringDays": 45}
    expired = {**data, "purchaseDate": "2020-01-31", "durationMonths": 1}
    assert (
        client.put(f"/api/v1/assets/{asset['id']}/warranty", json=expired, headers=auth).json()[
            "expiresOn"
        ]
        == "2020-02-29"
    )
    assert (
        client.get("/api/v1/warranties?coverage=expired").json()["items"][0]["assetId"]
        == asset["id"]
    )
    soon = {**data, "expiresOn": (today + timedelta(days=20)).isoformat(), "durationMonths": None}
    assert (
        client.put(f"/api/v1/assets/{asset['id']}/warranty", json=soon, headers=auth).json()[
            "coverage"
        ]
        == "expiring"
    )
    assert (
        client.delete(
            f"/api/v1/assets/{asset['id']}/attachments/{attachment['id']}", headers=auth
        ).status_code
        == 409
    )
    history = client.get(f"/api/v1/assets/{asset['id']}/history").json()["items"]
    assert sum(h["action"] == "warranty_updated" for h in history) == 3
    assert client.delete(f"/api/v1/assets/{asset['id']}/warranty", headers=auth).status_code == 204
    assert client.get(f"/api/v1/assets/{asset['id']}/warranty").status_code == 404


def test_warranty_rejects_foreign_receipt_dates_and_unselected_asset_changes(
    signed_in_client, settings_factory, tmp_path
):
    client, auth = signed_in_client(settings_factory(attachment_storage_path=tmp_path / "blobs"))
    asset = create_asset(client, auth)
    other = create_asset(client, auth, quick_code="OTHER-1")
    receipt = upload(client, auth, other["id"], PDF).json()
    before = client.get(f"/api/v1/assets/{asset['id']}/history").json()
    invalid = [
        {"purchaseDate": "2025-01-01", "expiresOn": "2024-01-01"},
        {"purchaseDate": "2025-01-01", "durationMonths": -1},
        {"purchaseDate": "2025-01-01", "durationMonths": 12, "receiptId": receipt["id"]},
        {"expiresOn": "not a date"},
    ]
    for data in invalid:
        response = client.put(f"/api/v1/assets/{asset['id']}/warranty", json=data, headers=auth)
        assert response.status_code == 422, response.text
        assert client.get(f"/api/v1/assets/{asset['id']}/warranty").status_code == 404
        assert client.get(f"/api/v1/assets/{asset['id']}/history").json() == before
        assert client.get(f"/api/v1/assets/{asset['id']}").json() == asset
