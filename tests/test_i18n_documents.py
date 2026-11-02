"""Documents in their own locale: labels, formats, exports, jobs and rejection.

A report document picks its language from the request (or the requester's own
preference) while the installation keeps the time zone and the currency. These
checks read the real composed HTML, the real CSV/XLSX bytes and the stored job.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from itsm.database import create_engine_from_settings
from itsm.identity.service import IdentityService
from itsm.inventory.service import InventoryService
from itsm.operations.tools import operational_summary
from itsm.reports.models import ReportDocument, ReportJob
from itsm.reports.schemas import ReportRequest
from itsm.reports.service import build_report_service
from openpyxl import load_workbook
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from tests.inventory_support import Catalog, asset_values, prepare

GENERATED_AT = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
SPANISH_MOMENT = "15 ene 2026, 9:00:00"
ENGLISH_MOMENT = "Jan 15, 2026, 9:00:00"


class RecordingQueue:
    """Minimal TaskQueue surface used by report jobs; no Huey types leak in."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def submit_report(self, job_id: str, task_id: str) -> None:
        self.calls.append((job_id, task_id))


@pytest.fixture
def catalog(settings_factory: Any, tmp_path: Path) -> Catalog:
    return prepare(
        settings_factory,
        attachment_storage_path=tmp_path / "blobs",
        report_base_url="https://itam.example.com",
    )


def reports(catalog: Catalog, queue: Any | None = None) -> Any:
    return build_report_service(catalog.settings, catalog.factory(), task_queue=queue)


def seed(catalog: Catalog, values: dict[str, Any]) -> str:
    with catalog.session() as session:
        inventory = InventoryService(
            session,
            catalog.settings,
            identity=IdentityService(session, catalog.settings),
            source="internal",
        )
        view = inventory.create(catalog.admin(), values)
        session.commit()
    return view.id


def preference(catalog: Catalog, locale: str | None) -> None:
    principal = catalog.admin()
    with catalog.session() as session:
        IdentityService(session, catalog.settings).update_preferences(principal, locale=locale)
        session.commit()


def document_rows(catalog: Catalog, service: Any, job_id: str) -> bytes:
    principal = catalog.admin()
    document = service.job(principal, job_id)["documents"][0]
    _, raw = service.download(principal, document["id"])
    return raw


def test_report_html_uses_the_document_locale_and_the_installation_formats(
    catalog: Catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("itsm.reports.service.utcnow", lambda: GENERATED_AT)
    seed(catalog, asset_values(quick_code="I18N-001", name="Impresora Fiscal", cost="1000.00"))
    service = reports(catalog)
    admin = catalog.admin()

    spanish = service.preview(admin, ReportRequest(family="inventory", locale="es"))
    english = service.preview(admin, ReportRequest(family="inventory", locale="en"))
    es_html, en_html = spanish["html"], english["html"]

    assert '<html lang="es">' in es_html
    assert '<html lang="en">' in en_html
    assert "Código rápido" in es_html and "Quick code" not in es_html
    assert "Quick code" in en_html and "Código rápido" not in en_html
    assert "Coste total:" in es_html and "Total cost:" in en_html
    assert "Generado:" in es_html and "Generated:" in en_html
    assert "Página " in es_html and "Page " in en_html
    # A formatted date in the document language, never the stored ISO instant.
    assert f"Generado: {SPANISH_MOMENT}" in es_html
    assert f"Generated: {ENGLISH_MOMENT}" in en_html
    assert "2026-01-15T12:00:00" not in es_html
    assert "2026-01-15T12:00:00" not in en_html
    # The installation currency never follows the document language.
    assert "1.000" in es_html and "PYG" in es_html
    assert "1,000" in en_html and "PYG" in en_html
    # Names and other free text are stored data, not translatable copy.
    assert "Impresora Fiscal" in es_html and "Impresora Fiscal" in en_html
    assert spanish["columns"][0]["label"] == "ID permanente"
    assert english["columns"][0]["label"] == "Permanent ID"


def test_labels_document_title_and_fields_are_localized(catalog: Catalog) -> None:
    asset_id = seed(catalog, asset_values(quick_code="LBL-I18N", name="Etiqueta"))
    service = reports(catalog)
    admin = catalog.admin()
    labels = {
        "formatId": "a4-24",
        "fields": ["name", "code", "site"],
        "offset": 0,
    }
    request = ReportRequest(
        family="inventory",
        assetIds=[asset_id],
        labels=labels,
        locale="en",
    )
    english = service.preview(admin, request)["html"]
    assert '<html lang="en">' in english
    assert "Labels ·" in english
    assert "LBL-I18N" in english
    assert "Site: Sede Norte" in english
    assert "Sitio:" not in english


def test_csv_and_xlsx_headers_follow_the_document_locale(catalog: Catalog) -> None:
    seed(catalog, asset_values(quick_code="EXP-001", name="Impresora Fiscal"))
    service = reports(catalog)
    principal = catalog.admin()

    for locale, expected in (
        ("es", ["ID", "Código rápido", "Nombre"]),
        ("en", ["ID", "Quick code", "Name"]),
    ):
        job = service.generate(
            principal,
            ReportRequest(
                family="inventory",
                output="csv",
                fields=["quickCode", "name"],
                locale=locale,
            ),
        )
        service.execute(job["id"])
        rows = list(
            csv.reader(io.StringIO(document_rows(catalog, service, job["id"]).decode("utf-8-sig")))
        )
        assert rows[0] == expected, locale
        assert rows[1][1] == "EXP-001"
        assert rows[1][2] == "Impresora Fiscal"

    workbook_job = service.generate(
        principal,
        ReportRequest(
            family="inventory",
            output="xlsx",
            fields=["quickCode", "name"],
            locale="en",
        ),
    )
    service.execute(workbook_job["id"])
    workbook = load_workbook(
        io.BytesIO(document_rows(catalog, service, workbook_job["id"])), read_only=True
    )
    assert workbook.active.title == "Report"
    values = list(workbook.active.iter_rows(values_only=True))
    workbook.close()
    assert values[0] == ("ID", "Quick code", "Name")


def test_english_pdf_job_renders_a_real_document(catalog: Catalog) -> None:
    seed(catalog, asset_values(quick_code="PDF-EN", name="English PDF"))
    service = reports(catalog)
    principal = catalog.admin()

    job = service.generate(
        principal,
        ReportRequest(family="inventory", output="pdf", locale="en"),
    )
    finished = service.execute(job["id"])

    assert finished["status"] == "completed", finished
    payload, data = service.download(principal, finished["documents"][0]["id"])
    assert payload["mime"] == "application/pdf"
    assert data.startswith(b"%PDF-") and b"%%EOF" in data[-2048:]


def test_job_stores_the_effective_locale_for_asynchronous_rendering(catalog: Catalog) -> None:
    seed(catalog, asset_values(quick_code="JOB-EN", name="Queued English"))
    service = reports(catalog)
    principal = catalog.admin()
    preference(catalog, "en")

    job = service.generate(
        principal,
        ReportRequest(family="inventory", output="csv", fields=["quickCode"]),
    )
    with catalog.session() as session:
        stored = session.get(ReportJob, job["id"])
        assert stored is not None and stored.request["locale"] == "en"

    # A preference changed after the request must not rewrite a queued language.
    preference(catalog, "es")
    service.execute(job["id"])

    header = document_rows(catalog, service, job["id"]).decode("utf-8-sig").splitlines()[0]
    assert header.split(",") == ["ID", "Quick code"]


def test_absent_document_locale_defaults_to_the_requester_preference(catalog: Catalog) -> None:
    service = reports(catalog)
    principal = catalog.admin()
    preference(catalog, "en")

    job = service.generate(principal, ReportRequest(family="inventory", output="csv"))

    with catalog.session() as session:
        stored = session.get(ReportJob, job["id"])
        assert stored is not None and stored.request["locale"] == "en"


def test_installed_subtag_is_accepted_as_the_document_locale(catalog: Catalog) -> None:
    service = reports(catalog)
    job = service.generate(
        catalog.admin(),
        ReportRequest(family="inventory", output="csv", locale="en-US"),
    )

    with catalog.session() as session:
        stored = session.get(ReportJob, job["id"])
        assert stored is not None and stored.request["locale"] == "en"


def test_invalid_document_locale_is_rejected_with_422_and_stores_nothing(
    signed_in_client: Any, settings_factory: Any, tmp_path: Path
) -> None:
    settings = settings_factory(attachment_storage_path=tmp_path / "http-blobs")
    client, auth = signed_in_client(settings)

    response = client.post(
        "/api/v1/reports/jobs",
        headers=auth,
        json={"family": "inventory", "locale": "fr"},
    )

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "validation_error"
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            assert session.execute(select(func.count()).select_from(ReportJob)).scalar_one() == 0
            assert (
                session.execute(select(func.count()).select_from(ReportDocument)).scalar_one() == 0
            )
    finally:
        engine.dispose()


def test_operational_result_message_follows_the_requester_locale(catalog: Catalog) -> None:
    principal = catalog.admin()
    with catalog.session() as session:
        identity = IdentityService(session, catalog.settings)
        identity.update_preferences(principal, locale="en")
        english = operational_summary(
            session, identity, catalog.settings, principal, source="agent"
        )
        identity.update_preferences(principal, locale=None)
        spanish = operational_summary(
            session, identity, catalog.settings, principal, source="agent"
        )

    assert english["message"]["key"] == "api.operations.summary_ready"
    assert english["message"]["locale"] == "en"
    assert english["message"]["message"] == (
        f"Operational summary for {english['period']} is ready."
    )
    assert spanish["message"]["locale"] == "es"
    assert spanish["message"]["message"] == f"Resumen operativo de {spanish['period']} listo."
