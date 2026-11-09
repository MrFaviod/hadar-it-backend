"""Task queue access is permission-bound and owner-specific."""

from itsm.tasks import TaskState, TaskStatus
from tests.inventory_support import sign_in_as
from tests.test_identity_api_keys import api as _api
from tests.test_identity_api_keys import bearer, issue

api = _api


def test_demo_tasks_require_grants_and_cannot_be_read_by_another_owner(api, monkeypatch):
    catalog, client, headers = api
    empty = issue(client, headers, permissions=[])
    reader = issue(client, headers, permissions=["assets.view"])
    calls = []
    queue = client.app.state.task_queue
    original = queue.submit_demo

    def submit(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(queue, "submit_demo", submit)
    assert (
        client.post(
            "/api/v1/tasks/demo", json={"message": "Denied"}, headers=bearer(empty)
        ).status_code
        == 403
    )
    assert calls == []
    accepted = client.post(
        "/api/v1/tasks/demo", json={"message": "Owner only"}, headers=bearer(reader)
    )
    assert accepted.status_code == 202
    task_id = accepted.json()["task_id"]
    assert calls == [1]
    path = f"/api/v1/tasks/{task_id}"
    first = client.get(path, headers=bearer(reader))
    assert first.status_code == 200
    assert first.json()["state"] == "pending"
    assert client.get(path, headers=bearer(reader)).json() == first.json()
    assert client.get(path, headers=bearer(empty)).status_code == 403
    assert client.get(path).status_code == 200
    catalog.add_user("task.other", "Task Other", "user")
    sign_in_as(client, catalog.settings, "task.other")
    # A second owner may use their own queue but cannot inspect the first owner.
    assert client.get(path).status_code == 404
    assert calls == [1]
    assert client.get(path, headers=bearer(reader)).json() == first.json()


def test_task_owner_guard_runs_before_queue_lookup(api, monkeypatch):
    _, client, _ = api
    calls = []

    def unrelated(task_id):
        calls.append(task_id)
        return TaskStatus(task_id=task_id, state=TaskState.COMPLETE, result={"message": "Private"})

    monkeypatch.setattr(client.app.state.task_queue, "get_status", unrelated)
    response = client.get("/api/v1/tasks/0123456789abcdef0123456789abcdef")
    assert response.status_code == 404
    assert calls == []
