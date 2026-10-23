"""Real report jobs cross HTTP, Huey and tool authorization boundaries."""

from __future__ import annotations

import time
from io import BytesIO
from typing import Any

import pytest
from fastmcp.exceptions import ToolError
from itsm.agents.runtime import AgentRuntime, ChatRequest
from itsm.identity.hashing import hash_token
from itsm.reports.models import ReportDocument, ReportJob
from itsm.reports.service import build_report_service
from mcp.shared.exceptions import MCPError
from openpyxl import load_workbook
from pydantic_ai.messages import TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from sqlalchemy import select
from tests.conftest import running_worker
from tests.inventory_support import prepare
from tests.test_agent_chat import scripted
from tests.test_mcp_server import call_tool, operator
from tests.test_phase7_agents import (
    chat,
    create_asset,
    mcp,
    no_external_model_requests,
    use_model,
)

__all__ = ["catalog", "mcp", "no_external_model_requests"]


@pytest.fixture
def catalog(settings_factory, tmp_path):
    return prepare(
        lambda **overrides: settings_factory(
            attachment_storage_path=tmp_path / "mcp-blobs", **overrides
        )
    )


def completed(client, auth, job_id: str):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/reports/jobs/{job_id}", headers=auth)
        assert response.status_code == 200, response.text
        job = response.json()
        if job["status"] in {"completed", "failed"}:
            assert job["status"] == "completed", job
            return job
        time.sleep(0.1)
    raise AssertionError("real report worker did not finish before the smoke deadline")


def test_real_worker_generates_private_pdf_and_excel_with_same_selection(
    signed_in_client, settings_factory, tmp_path
):
    client, auth = signed_in_client(settings_factory(attachment_storage_path=tmp_path / "blobs"))
    selected = create_asset(client, auth, "Selected document asset")
    create_asset(client, auth, "Excluded document asset")
    with running_worker(client.app.state.settings, log_path=tmp_path / "reports-worker.log"):
        for output in ("pdf", "xlsx"):
            response = client.post(
                "/api/v1/reports/jobs",
                headers=auth,
                json={
                    "family": "inventory",
                    "assetIds": [selected["id"]],
                    "fields": ["id", "name"],
                    "output": output,
                },
            )
            assert response.status_code in {200, 201, 202}, response.text
            job = completed(client, auth, response.json()["id"])
            document = job["documents"][0]
            download = client.get(document["downloadUrl"], headers=auth)
            assert download.status_code == 200, download.text
            if output == "pdf":
                assert download.content.startswith(b"%PDF-")
            else:
                book = load_workbook(BytesIO(download.content), read_only=True)
                rows = list(book.active.values)
                book.close()
                assert any("Selected document asset" in row for row in rows)
                assert not any("Excluded document asset" in row for row in rows)
    client.post("/api/v1/auth/logout", headers=auth)
    assert client.get(document["downloadUrl"]).status_code == 401


def test_agent_prepares_report_using_canonical_inventory(signed_in_client):
    client, auth = signed_in_client()
    asset = create_asset(client, auth, "Agent report selection")
    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "prepare_report",
                        {
                            "request": {
                                "family": "inventory",
                                "assetIds": [asset["id"]],
                                "fields": ["name"],
                            }
                        },
                        tool_call_id="report",
                    )
                ],
                [TextPart("Reporte preparado.")],
            )
        ),
    )
    reply = chat(client, auth, "Prepara el reporte del activo indicado")
    assert reply["actions"] == [{"tool": "prepare_report", "status": "completed", "assetIds": []}]
    prepared = reply["results"][0]
    assert prepared["matched"] == 1
    assert prepared["assets"][0]["name"] == "Agent report selection"
    assert "html" not in prepared


def test_mcp_report_projection_and_revoked_identity(mcp):
    _, token = operator(mcp)
    asset = call_tool(
        mcp, token, "create_asset", {"name": "MCP report selection"}
    ).structured_content
    prepared = call_tool(
        mcp,
        token,
        "prepare_report",
        {"request": {"family": "inventory", "assetIds": [asset["id"]], "fields": ["name"]}},
    ).structured_content
    assert prepared["matched"] == 1
    assert prepared["assets"][0]["name"] == "MCP report selection"
    assert "html" not in prepared
    _, reader = mcp.catalog.add_machine("report-reader", "Report reader", "reader")
    with pytest.raises(ToolError):
        call_tool(
            mcp,
            reader,
            "prepare_report",
            {"request": {"family": "inventory", "fields": ["arbitrarySecret"]}},
        )
    mcp.catalog.revoke_machine("report-reader")
    with pytest.raises((MCPError, ToolError)):
        call_tool(mcp, reader, "list_report_templates", {})


def test_mcp_generates_owned_report_and_returns_protected_references(mcp, tmp_path):
    _, token = operator(mcp)
    created = call_tool(
        mcp, token, "create_asset", {"name": "MCP document asset", "category": "Red"}
    ).structured_content
    asset_id = created["id"]
    with running_worker(mcp.catalog.settings, log_path=tmp_path / "mcp-reports-worker.log"):
        job = call_tool(
            mcp,
            token,
            "generate_report",
            {"request": {"family": "inventory", "assetIds": [asset_id], "output": "csv"}},
        ).structured_content
        deadline = time.monotonic() + 40
        while job["status"] not in {"completed", "failed"} and time.monotonic() < deadline:
            time.sleep(0.1)
            job = call_tool(
                mcp, token, "report_job_status", {"job_id": job["id"]}
            ).structured_content
        assert job["status"] == "completed", job
        refs = call_tool(mcp, token, "report_documents", {"job_id": job["id"]}).structured_content
        assert refs["documents"][0]["id"] == job["documents"][0]["id"]
        assert refs["documents"][0]["downloadUrl"].startswith("/api/v1/reports/documents/")
        assert "storageKey" not in refs["documents"][0]

        labels = call_tool(
            mcp,
            token,
            "generate_labels",
            {
                "request": {
                    "family": "inventory",
                    "assetIds": [asset_id],
                    "labels": {"formatId": "roll-50x30", "fields": ["name", "code", "qr"]},
                }
            },
        ).structured_content
        deadline = time.monotonic() + 40
        while labels["status"] not in {"completed", "failed"} and time.monotonic() < deadline:
            time.sleep(0.1)
            labels = call_tool(
                mcp, token, "report_job_status", {"job_id": labels["id"]}
            ).structured_content
        assert labels["status"] == "completed", labels
        label_refs = call_tool(
            mcp, token, "report_documents", {"job_id": labels["id"]}
        ).structured_content
        assert label_refs["documents"][0]["mime"] == "application/pdf"
        assert "storageKey" not in label_refs["documents"][0]


def test_agent_generates_labels_and_reads_completed_document_references(
    signed_in_client, settings_factory, tmp_path
):
    client, auth = signed_in_client(settings_factory(attachment_storage_path=tmp_path / "blobs"))
    asset = create_asset(client, auth, "Agent printable label")
    request = {
        "family": "inventory",
        "assetIds": [asset["id"]],
        "labels": {"formatId": "roll-50x30", "fields": ["name", "code", "qr"]},
    }
    with running_worker(client.app.state.settings, log_path=tmp_path / "labels-worker.log"):
        use_model(
            client,
            FunctionModel(
                scripted(
                    [ToolCallPart("generate_labels", {"request": request}, tool_call_id="labels")],
                    [TextPart("Generación en cola.")],
                )
            ),
        )
        queued = chat(client, auth, "Genera la etiqueta del activo")
        assert queued["actions"][0]["status"] == "completed", queued
        job_id = queued["results"][0]["id"]
        job = completed(client, auth, job_id)
        use_model(
            client,
            FunctionModel(
                scripted(
                    [
                        ToolCallPart(
                            "report_documents", {"job_id": job_id}, tool_call_id="documents"
                        )
                    ],
                    [TextPart("Documento disponible.")],
                )
            ),
        )
        refs = chat(client, auth, "Consulta los documentos generados")["results"][0]
        assert refs["status"] == "completed"
        assert refs["documents"][0]["id"] == job["documents"][0]["id"]
        download = client.get(refs["documents"][0]["downloadUrl"])
        assert download.status_code == 200
        assert download.content.startswith(b"%PDF-")


def test_agent_cannot_generate_labels_without_structured_geometry(signed_in_client):
    client, auth = signed_in_client()
    use_model(
        client,
        FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "generate_labels",
                        {"request": {"family": "inventory"}},
                        tool_call_id="labels",
                    )
                ],
                [TextPart("Faltan las opciones de etiquetas.")],
            )
        ),
    )
    reply = chat(client, auth, "Genera etiquetas sin opciones")
    assert reply["actions"][0]["status"] == "failed"
    jobs = client.get("/api/v1/reports/jobs")
    assert jobs.status_code == 200
    assert jobs.json()["items"] == []


def _wait_for_job(catalog: Any, job_id: str, timeout: float = 40) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with catalog.session() as session:
            job = session.get(ReportJob, job_id)
            assert job is not None
            if job.status in {"completed", "failed"}:
                return {"status": job.status, "errors": list(job.errors or [])}
        time.sleep(0.1)
    raise AssertionError("report job did not finish before the deadline")


def test_mcp_credential_revoked_before_worker_denies_queued_report(mcp, tmp_path):
    _, token = operator(mcp)
    asset = call_tool(
        mcp, token, "create_asset", {"name": "MCP revoked asset", "category": "Red"}
    ).structured_content
    job = call_tool(
        mcp,
        token,
        "generate_report",
        {"request": {"family": "inventory", "assetIds": [asset["id"]], "output": "csv"}},
    ).structured_content
    mcp.catalog.revoke_machine("mcp-operator")

    with running_worker(mcp.catalog.settings, log_path=tmp_path / "mcp-revoked-worker.log"):
        finished = _wait_for_job(mcp.catalog, job["id"])
    assert finished["status"] == "failed", finished
    assert finished["errors"]
    with mcp.catalog.session() as session:
        assert session.execute(select(ReportDocument)).first() is None
    assert not (
        mcp.catalog.settings.attachment_storage_path.exists()
        and list(mcp.catalog.settings.attachment_storage_path.iterdir())
    )


def test_agent_runtime_propagates_machine_credential_to_report_job(mcp):
    principal, token = mcp.catalog.add_machine("report-agent", "Report agent", "operator")
    asset = call_tool(
        mcp, token, "create_asset", {"name": "Agent machine report", "category": "Red"}
    ).structured_content
    digest = hash_token(token)
    runtime = AgentRuntime(
        mcp.catalog.settings,
        mcp.catalog.factory(),
        model=FunctionModel(
            scripted(
                [
                    ToolCallPart(
                        "generate_report",
                        {
                            "request": {
                                "family": "inventory",
                                "assetIds": [asset["id"]],
                                "output": "csv",
                            }
                        },
                        tool_call_id="report",
                    )
                ],
                [TextPart("Reporte en cola.")],
            )
        ),
    )
    reply = runtime.chat(
        principal,
        ChatRequest(message="Genera el reporte del activo"),
        credential_digest=digest,
    )
    assert reply.actions[0].status == "completed", reply
    job = reply.results[0]
    with mcp.catalog.session() as session:
        stored = session.get(ReportJob, job["id"])
        assert stored is not None
        assert stored.executor["credentialDigest"] == digest

    service = build_report_service(mcp.catalog.settings, mcp.catalog.factory())
    finished = service.execute(job["id"])
    assert finished["status"] == "completed", finished
    assert len(finished["documents"]) == 1
