"""Large approved imports must remain observable while a real worker applies rows."""

from __future__ import annotations

import time

from tests.conftest import running_worker
from tests.test_phase6_job_authority import preview_and_queue


def test_large_imports_keep_authenticated_progress_available(signed_in_client, settings_factory):
    settings = settings_factory()
    client, auth = signed_in_client(settings)
    operations = []
    for batch in range(2):
        data = "name,quickCode\n" + "".join(
            f"Concurrent import {batch}-{index},LOAD-{batch}-{index}-MANUAL\n"
            for index in range(500)
        )
        operation_id, _ = preview_and_queue(client, auth, data.encode())
        operations.append(operation_id)

    with running_worker(settings):
        deadline = time.monotonic() + 90
        pending = set(operations)
        while pending:
            for operation_id in tuple(pending):
                response = client.get(f"/api/v1/operations/{operation_id}")
                assert response.status_code == 200, response.text
                body = response.json()
                assert body["state"] != "error", body
                if body["state"] == "complete":
                    assert body["summary"] == {
                        "created": 500,
                        "modified": 0,
                        "omitted": 0,
                        "failed": 0,
                    }
                    pending.remove(operation_id)
            assert not pending or time.monotonic() < deadline
            time.sleep(0.1)

    assert client.get("/api/v1/assets", params={"limit": 1}).json()["total"] == 1000
    for operation_id in operations:
        retry = client.post(f"/api/v1/operations/{operation_id}/execute", headers=auth)
        assert retry.status_code == 200, retry.text
        assert retry.json()["summary"]["created"] == 500
    assert client.get("/api/v1/assets", params={"limit": 1}).json()["total"] == 1000
