"""Workflow tools exercise the same fixed approvals without provider requests."""

import pydantic_ai.models
from itsm.tasks import TaskState, TaskStatus, TaskStorageUnavailable
from pydantic_ai.messages import TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from tests.test_agent_chat import scripted
from tests.test_inventory_api import create_asset
from tests.test_mcp_server import call_tool, catalog, mcp, operator  # noqa: F401 - pytest fixtures
from tests.test_phase6_workflows import analyze
from tests.test_redundancy_agents import chat, use_model


def test_agent_prepares_and_cannot_execute_unapproved_bulk(signed_in_client, monkeypatch):
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)
    client, auth = signed_in_client()
    asset = create_asset(client, auth)
    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "preview_bulk_operation",
                        {"asset_ids": [asset["id"]], "changes": {"brand": "Agent"}},
                        tool_call_id="preview",
                    )
                ],
                [TextPart("Vista preparada.")],
            )
        ),
    )
    reply = chat(client, auth, "Prepara el cambio")
    assert reply["actions"][0]["status"] == "completed"
    operation = reply["results"][0]
    assert operation["state"] == "preview" and not operation["approved"]
    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "apply_inventory_operation",
                        {"operation_id": operation["id"]},
                        tool_call_id="execute",
                    )
                ],
                [TextPart("Necesita aprobación.")],
            )
        ),
    )
    reply = chat(client, auth, "Ejecuta")
    assert reply["actions"][0]["status"] == "failed"
    assert client.get("/api/v1/assets/" + asset["id"]).json()["brand"] == asset["brand"]
    assert (
        client.post("/api/v1/operations/" + operation["id"] + "/approve", headers=auth).status_code
        == 200
    )
    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "apply_inventory_operation",
                        {"operation_id": operation["id"]},
                        tool_call_id="execute2",
                    )
                ],
                [TextPart("Aplicado.")],
            )
        ),
    )
    reply = chat(client, auth, "Ejecuta lo aprobado")
    assert reply["results"][0]["summary"]["modified"] == 1
    assert client.get("/api/v1/assets/" + asset["id"]).json()["brand"] == "Agent"


def rows(count: int) -> str:
    return "Nombre\n" + "".join(f"Equipo {index}\n" for index in range(count))


def test_agent_import_inspection_is_compact_but_keeps_total_and_locator(
    signed_in_client, monkeypatch
):
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)
    client, auth = signed_in_client()
    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "prepare_inventory_import",
                        {"csv_text": rows(30), "options": {"inspectOnly": True}},
                        tool_call_id="inspect",
                    )
                ],
                [TextPart("Hojas identificadas.")],
            )
        ),
    )

    reply = chat(client, auth, "Inspecciona las hojas")

    assert reply["actions"][0]["status"] == "completed"
    payload = reply["results"][0]
    assert payload["totalSheets"] == 1
    sheet = payload["sheets"][0]
    assert sheet["id"] == sheet["name"] == "CSV"
    assert sheet["columns"] == ["Nombre"]
    assert len(sheet["rows"]) == 20
    assert sheet["total"] == 30
    assert sheet["hasMore"] is True


def test_agent_import_preparation_is_compact_and_pages_the_rest(signed_in_client, monkeypatch):
    monkeypatch.setattr(pydantic_ai.models, "ALLOW_MODEL_REQUESTS", False)
    client, auth = signed_in_client()
    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "prepare_inventory_import",
                        {"csv_text": rows(25)},
                        tool_call_id="prepare",
                    )
                ],
                [TextPart("Vista preparada.")],
            )
        ),
    )

    reply = chat(client, auth, "Prepara la importación")

    payload = reply["results"][0]
    assert "sheets" not in payload
    assert len(payload["rows"]) == 20
    assert payload["total"] == 25
    assert payload["hasMore"] is True

    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "get_inventory_operation",
                        {"operation_id": payload["id"], "offset": 20, "limit": 20},
                        tool_call_id="page",
                    )
                ],
                [TextPart("Resto leído.")],
            )
        ),
    )

    page = chat(client, auth, "Lee el resto")["results"][0]
    assert len(page["rows"]) == 5
    assert page["total"] == 25
    assert page["hasMore"] is False


def test_mcp_import_inspection_returns_bounded_rows(mcp):  # noqa: F811 - fixture
    _, token = operator(mcp)

    result = call_tool(
        mcp,
        token,
        "prepare_inventory_import",
        {"csv_text": rows(25), "options": {"inspectOnly": True}},
    )

    payload = result.structured_content
    assert payload["totalSheets"] == 1
    sheet = payload["sheets"][0]
    assert sheet["id"] == "CSV"
    assert len(sheet["rows"]) == 20
    assert sheet["total"] == 25
    assert sheet["hasMore"] is True


def test_mcp_prepared_operation_is_compact_and_pages_the_rest(mcp):  # noqa: F811 - fixture
    _, token = operator(mcp)

    prepared = call_tool(
        mcp, token, "prepare_inventory_import", {"csv_text": "Nombre\n" + "Equipo\n" * 25}
    ).structured_content

    assert len(prepared["rows"]) == 20
    assert prepared["total"] == 25
    assert prepared["hasMore"] is True

    page = call_tool(
        mcp,
        token,
        "get_inventory_operation",
        {"operation_id": prepared["id"], "offset": 20, "limit": 20},
    ).structured_content

    assert len(page["rows"]) == 5
    assert page["total"] == 25
    assert page["hasMore"] is False


class StorageDouble:
    """Real task-queue boundary double: no queue storage is read or written."""

    def __init__(
        self,
        *,
        submit_error: Exception | None = None,
        status_error: Exception | None = None,
    ) -> None:
        self.submitted: list[tuple[str, str]] = []
        self._submit_error = submit_error
        self._status_error = status_error

    def submit_operation(self, operation_id: str, task_id: str) -> TaskStatus:
        if self._submit_error is not None:
            raise self._submit_error
        self.submitted.append((operation_id, task_id))
        return TaskStatus(task_id=task_id, state=TaskState.PENDING)

    def get_status(self, task_id: str) -> TaskStatus | None:
        if self._status_error is not None:
            raise self._status_error
        return None


def approved_preview(client, auth, data: bytes = b"name\nEquipo\n") -> str:
    preview = analyze(client, auth, data).json()
    approved = client.post(f"/api/v1/operations/{preview['id']}/approve", headers=auth)
    assert approved.status_code == 200, approved.text
    return preview["id"]


def test_queue_storage_failure_returns_503_and_keeps_the_operation_retryable(
    signed_in_client, monkeypatch
):
    client, auth = signed_in_client()
    operation_id = approved_preview(client, auth, b"id,name\n,Equipo\n")
    queue = StorageDouble(submit_error=TaskStorageUnavailable("queue storage is full"))
    monkeypatch.setattr(client.app.state, "task_queue", queue)

    response = client.post(f"/api/v1/operations/{operation_id}/enqueue", headers=auth)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "unavailable"
    assert queue.submitted == []
    state = client.get(f"/api/v1/operations/{operation_id}", headers=auth).json()["state"]
    assert state == "queue_error"


def test_recovery_read_failure_returns_503_without_a_second_dispatch(signed_in_client, monkeypatch):
    client, auth = signed_in_client()
    operation_id = approved_preview(client, auth)
    monkeypatch.setattr(client.app.state, "task_queue", StorageDouble())
    queued = client.post(f"/api/v1/operations/{operation_id}/enqueue", headers=auth)
    assert queued.status_code == 202, queued.text
    lost = StorageDouble(status_error=TaskStorageUnavailable("queue index is unavailable"))
    monkeypatch.setattr(client.app.state, "task_queue", lost)

    response = client.post(f"/api/v1/operations/{operation_id}/enqueue", headers=auth)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "unavailable"
    assert lost.submitted == []
    state = client.get(f"/api/v1/operations/{operation_id}", headers=auth).json()["state"]
    assert state == "queued"
