"""Cross-domain technical references preserve canonical inventory and bytes."""

from tests.test_attachments import setup_api, upload


def test_linked_intervention_attachment_requires_explicit_unlink(
    settings_factory, signed_in_client, tmp_path
):
    _, client, auth, asset = setup_api(settings_factory, signed_in_client, tmp_path)
    data = b"%PDF-1.7\ntechnical work\n%%EOF"
    uploaded = upload(client, auth, asset["id"], data=data)
    assert uploaded.status_code == 201, uploaded.text
    attachment = uploaded.json()
    created = client.post(
        "/api/v1/interventions",
        headers=auth,
        json={"assetId": asset["id"], "type": "corrective", "attachmentIds": [attachment["id"]]},
    )
    assert created.status_code == 201, created.text
    endpoint = f"/api/v1/assets/{asset['id']}/attachments/{attachment['id']}"
    denied = client.delete(endpoint, headers=auth)
    assert denied.status_code == 409, denied.text
    downloaded = client.get(attachment["downloadUrl"])
    assert downloaded.status_code == 200 and downloaded.content == data
    changed = client.patch(
        f"/api/v1/interventions/{created.json()['id']}",
        headers=auth,
        json={"attachmentIds": []},
    )
    assert changed.status_code == 200, changed.text
    assert client.delete(endpoint, headers=auth).status_code == 204
    assert client.get(attachment["downloadUrl"]).status_code == 404


def test_technical_references_block_purge_without_mutation(signed_in_client):
    from tests.test_inventory_api import create_asset

    client, auth = signed_in_client()
    for kind in ("plan", "intervention", "primary", "affected"):
        asset = create_asset(client, auth, name=f"Protected {kind}")
        if kind == "plan":
            response = client.post(
                "/api/v1/maintenance/plans",
                headers=auth,
                json={"assetId": asset["id"], "intervalMonths": 6},
            )
        elif kind == "intervention":
            response = client.post(
                "/api/v1/interventions",
                headers=auth,
                json={"assetId": asset["id"], "type": "corrective"},
            )
        else:
            primary = (
                asset if kind == "primary" else create_asset(client, auth, name="Incident primary")
            )
            response = client.post(
                "/api/v1/incidents",
                headers=auth,
                json={
                    "primaryAssetId": primary["id"],
                    "description": "Technical fault",
                    "affectedAssetIds": [asset["id"]] if kind == "affected" else [],
                },
            )
        assert response.status_code == 201, response.text
        history = client.get(f"/api/v1/assets/{asset['id']}/history").json()
        denied = client.post(
            f"/api/v1/assets/{asset['id']}/purge", headers=auth, json={"confirm": True}
        )
        assert denied.status_code == 409, denied.text
        assert client.get(f"/api/v1/assets/{asset['id']}").status_code == 200
        assert client.get(f"/api/v1/assets/{asset['id']}/history").json() == history


def test_virtual_template_alone_does_not_block_purge(signed_in_client):
    from tests.test_inventory_api import create_asset

    client, auth = signed_in_client()
    asset = create_asset(client, auth)
    listed = client.get("/api/v1/maintenance/plans", params={"assetId": asset["id"]})
    assert listed.status_code == 200, listed.text
    assert (
        client.post(
            f"/api/v1/assets/{asset['id']}/purge", headers=auth, json={"confirm": True}
        ).status_code
        == 200
    )
    assert client.get(f"/api/v1/assets/{asset['id']}").status_code == 404
