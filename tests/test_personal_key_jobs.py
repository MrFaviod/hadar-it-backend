"""A queued job keeps the personal credential authority, not only its owner."""

import pytest
from tests.conftest import running_worker
from tests.test_phase6_job_authority import preview_and_queue, wait_task


@pytest.mark.parametrize("revoked", [False, True])
def test_personal_key_queued_executor_is_live(
    signed_in_client, settings_factory, tmp_path, revoked
):
    settings = settings_factory(
        attachment_storage_path=tmp_path / "attachments",
        extension_workspace_path=tmp_path / "extension-workspaces",
        extension_data_path=tmp_path / "extension-data",
    )
    client, auth = signed_in_client(settings)
    issued = client.post(
        "/api/v1/auth/api-keys",
        json={"label": "Queued executor", "permissions": ["assets.view", "assets.edit"]},
        headers=auth,
    )
    assert issued.status_code == 201
    key = issued.json()
    operation_id, job_id = preview_and_queue(
        client,
        auth,
        b"name,serial\nPersonal job,PERSONAL-JOB\n",
        queue_auth={"Authorization": "Bearer " + key["token"]},
    )
    if revoked:
        assert client.delete("/api/v1/auth/api-keys/" + key["id"], headers=auth).status_code == 200
    with running_worker(settings):
        wait_task(client, job_id, {"error" if revoked else "complete"})
    operation = client.get("/api/v1/operations/" + operation_id).json()
    assert operation["processed"] == (0 if revoked else 1)
    assert client.get("/api/v1/assets/search").json()["total"] == (0 if revoked else 1)
    if revoked:
        assert operation["summary"] == {"created": 0, "modified": 0, "omitted": 0, "failed": 0}
