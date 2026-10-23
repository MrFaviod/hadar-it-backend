"""Phase 9 report families, templates, settings and real document output."""

from __future__ import annotations

import base64
import csv
import io
import shutil
import subprocess
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
from itsm.attachments.service import AttachmentService
from itsm.identity.service import IdentityService, PermissionDenied, ValidationFailed
from itsm.interventions.service import InterventionService
from itsm.inventory.service import InventoryService
from itsm.reports.models import ReportDocument, ReportSettings, ReportTemplate
from itsm.reports.schemas import ReportRequest, builtin_templates
from itsm.reports.service import ReportService, build_report_service
from itsm.workflows.warranties import WarrantyService
from openpyxl import load_workbook
from sqlalchemy import select
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import Catalog, asset_values, prepare

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


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
        report_retention_days=30,
    )


def reports(catalog: Catalog, queue: Any | None = None) -> ReportService:
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
    return view.id


def session_principal(catalog: Catalog) -> Any:
    with catalog.session() as session:
        return (
            IdentityService(session, catalog.settings)
            .login(ADMIN_USERNAME, ADMIN_PASSWORD)
            .principal
        )


def test_inventory_preview_uses_filters_and_real_summary(catalog: Catalog) -> None:
    red_a = seed(
        catalog,
        asset_values(
            quick_code="SW-RED-001",
            name="Switch rojo A",
            category="Red",
            site="Example Site",
            cost="1000.00",
        ),
    )
    red_b = seed(
        catalog,
        asset_values(
            quick_code="SW-RED-002",
            name="Switch rojo B",
            category="Red",
            site="Centro",
            cost="900.50",
        ),
    )
    seed(
        catalog,
        asset_values(quick_code="PC-BLU-001", name="PC azul", category="Azul", cost="50"),
    )
    service = reports(catalog)
    preview = service.preview(
        catalog.admin(),
        ReportRequest(
            family="inventory",
            filters={"category": "Red"},
            fields=["id", "quickCode", "name", "purchaseCost", "site"],
        ),
    )
    assert preview["matched"] == 2
    assert preview["truncated"] is False
    assert len(preview["rows"]) == 2
    assert {row["id"] for row in preview["rows"]} == {red_a, red_b}
    assert preview["summary"]["total"] == 2
    assert preview["summary"]["cost"] == "1900.50"
    assert preview["summary"]["byCategory"] == {"Red": 2}
    assert preview["summary"]["bySite"] == {"Example Site": 1, "Centro": 1}
    assert preview["template"]["id"] == "inventory-list"
    assert isinstance(preview["html"], str) and preview["html"]

    explicit = service.preview(
        catalog.admin(),
        ReportRequest(
            family="inventory",
            assetIds=[red_a],
            filters={"site": "Centro"},
            fields=["id", "name"],
        ),
    )
    assert explicit["matched"] == 0
    assert explicit["rows"] == []


def test_preview_rejects_oversized_selection(catalog: Catalog, settings_factory: Any) -> None:
    database = Path(str(catalog.settings.database_url).removeprefix("sqlite:///"))
    tight = prepare(
        settings_factory,
        database_url=f"sqlite:///{database}",
        attachment_storage_path=catalog.settings.attachment_storage_path,
        report_max_assets=1,
    )
    seed(tight, asset_values(quick_code="OVR-001", name="Uno"))
    seed(tight, asset_values(quick_code="OVR-002", name="Dos"))
    with pytest.raises(ValidationFailed, match=r"selection matches 2 assets"):
        reports(tight).preview(tight.admin(), ReportRequest(family="inventory"))


def test_history_family_lists_changes_and_intersects(catalog: Catalog) -> None:
    asset_id = seed(catalog, asset_values(quick_code="HIS-001", name="Equipo histórico"))
    with catalog.session() as session:
        inventory = InventoryService(
            session,
            catalog.settings,
            identity=IdentityService(session, catalog.settings),
            source="internal",
        )
        inventory.update(catalog.admin(), asset_id, {"status": "maintenance"})
    preview = reports(catalog).preview(
        catalog.admin(),
        ReportRequest(
            family="history",
            assetIds=[asset_id],
            filters={"event": "updated"},
            fields=["quickCode", "action", "statusNew"],
        ),
    )
    assert preview["matched"] == 1
    assert preview["summary"]["total"] == 1
    actions = [row["action"] for row in preview["rows"]]
    assert actions == ["updated"]
    assert preview["rows"][0]["quickCode"] == "HIS-001"
    assert preview["rows"][0]["statusNew"] == "maintenance"


def test_history_family_includes_interventions_and_incidents(catalog: Catalog) -> None:
    asset_id = seed(catalog, asset_values(quick_code="HIS-001", name="Con técnicos"))
    today = date.today().isoformat()
    with catalog.session() as session:
        identity = IdentityService(session, catalog.settings)
        interventions = InterventionService(
            session, catalog.settings, identity=identity, source="internal"
        )
        interventions.create(
            catalog.admin(),
            {
                "assetId": asset_id,
                "type": "corrective",
                "description": "Cambio de fuente",
                "occurredOn": today,
                "status": "completed",
            },
        )
        interventions.create_incident(
            catalog.admin(),
            {
                "primaryAssetId": asset_id,
                "description": "Sin red",
                "priority": "normal",
                "openedOn": today,
            },
        )
        session.commit()

    preview = reports(catalog).preview(
        catalog.admin(),
        ReportRequest(
            family="history",
            assetIds=[asset_id],
            filters={"actor": ADMIN_USERNAME, "from": today, "to": today},
        ),
    )
    technical = [
        row for row in preview["rows"] if row["entityType"] in {"intervention", "incident"}
    ]
    assert {row["entityType"] for row in technical} == {"intervention", "incident"}
    assert any(row["action"] == "intervention_logged" for row in technical)
    assert all(row["actor"] == ADMIN_USERNAME for row in technical)
    assert all(row["changes"] for row in technical)
    # Each technical entry is merged once, never double-counted from inventory history.
    assert len(technical) == 2
    assert preview["summary"]["total"] >= 2


def test_family_fields_and_stable_grouping(catalog: Catalog) -> None:
    seed(catalog, asset_values(quick_code="GRP-001", name="Uno", category="Blue"))
    seed(catalog, asset_values(quick_code="GRP-002", name="Dos", category="Red"))
    seed(catalog, asset_values(quick_code="GRP-003", name="Tres", category="Blue"))
    service = reports(catalog)
    grouped = service.preview(
        catalog.admin(),
        {
            "family": "inventory",
            "fields": ["quickCode"],
            "group": "category",
        },
    )
    plain = service.preview(
        catalog.admin(),
        {"family": "inventory", "fields": ["quickCode", "category"]},
    )
    base_order = {row["quickCode"]: index for index, row in enumerate(plain["rows"])}
    assert grouped["columns"] == [{"key": "quickCode", "label": "Código rápido"}]
    assert [row["group"] for row in grouped["rows"]] == ["Blue", "Blue", "Red"]
    grouped_codes = [row["quickCode"] for row in grouped["rows"]]
    assert grouped_codes == ["GRP-003", "GRP-001", "GRP-002"]
    assert base_order[grouped_codes[0]] < base_order[grouped_codes[1]]
    assert grouped["summary"]["groups"] == [
        {"key": "category", "label": "Blue", "count": 2},
        {"key": "category", "label": "Red", "count": 1},
    ]

    history = service.preview(
        catalog.admin(),
        {
            "family": "history",
            "fields": ["quickCode", "action"],
            "group": "status",
        },
    )
    assert history["columns"] == [
        {"key": "quickCode", "label": "Activo"},
        {"key": "action", "label": "Acción"},
    ]
    assert set(history["rows"][0]) == {"assetId", "quickCode", "action", "group"}

    warranty = service.preview(
        catalog.admin(),
        {
            "family": "warranty",
            "fields": ["quickCode", "coverage", "receiptId"],
        },
    )
    assert warranty["columns"] == [
        {"key": "quickCode", "label": "Activo"},
        {"key": "coverage", "label": "Cobertura"},
        {"key": "receiptId", "label": "Comprobante"},
    ]
    assert set(warranty["rows"][0]) == {"assetId", "quickCode", "coverage", "receiptId"}


def test_warranty_family_is_per_asset_and_filters_coverage(catalog: Catalog) -> None:
    covered = seed(catalog, asset_values(quick_code="WAR-001", name="Con garantía"))
    seed(catalog, asset_values(quick_code="WAR-002", name="Sin garantía"))
    expires = (date.today() + timedelta(days=200)).isoformat()
    with catalog.session() as session:
        identity = IdentityService(session, catalog.settings)
        attachments = AttachmentService(session, catalog.settings, identity=identity)
        receipt = attachments.upload(
            catalog.admin(),
            covered,
            filename="recibo.pdf",
            category="document",
            data=b"%PDF-1.4\n%%EOF",
        )
        warranty = WarrantyService(
            session,
            catalog.settings,
            identity=identity,
            source="internal",
        )
        warranty.put(
            catalog.admin(),
            covered,
            {
                "supplier": "Proveedor",
                "purchaseDate": date.today().isoformat(),
                "expiresOn": expires,
                "receiptId": receipt["id"],
            },
        )
        session.commit()
    service = reports(catalog)
    active = service.preview(
        catalog.admin(),
        ReportRequest(family="warranty", filters={"warrantyFilter": "active"}),
    )
    assert [row["quickCode"] for row in active["rows"]] == ["WAR-001"]
    assert active["rows"][0]["coverage"] == "active"
    assert active["rows"][0]["receiptId"] == receipt["id"]
    assert "data" not in active["rows"][0]
    assert "url" not in active["rows"][0]
    assert active["summary"]["byCoverage"] == {"active": 1}
    missing = service.preview(
        catalog.admin(),
        ReportRequest(family="warranty", filters={"warrantyFilter": "missing"}),
    )
    assert [row["quickCode"] for row in missing["rows"]] == ["WAR-002"]
    expired = service.preview(
        catalog.admin(),
        ReportRequest(family="warranty", filters={"warrantyFilter": "expired"}),
    )
    assert expired["rows"] == []


def test_custom_template_crud_and_reserved_builtins(catalog: Catalog) -> None:
    service = reports(catalog)
    admin = catalog.admin()
    definition = builtin_templates()[0]
    definition["id"] = "custom-inventario"
    definition["name"] = "Inventario propio"
    saved = service.save_template(admin, definition)
    assert saved["id"] == "custom-inventario"
    listed = {item["id"]: item for item in service.templates(admin)["items"]}
    assert {"inventory-list", "custom-inventario"} <= listed.keys()
    assert listed["inventory-list"]["builtin"] is True
    assert listed["custom-inventario"]["builtin"] is False
    preview = service.preview(
        admin, ReportRequest(family="inventory", templateId="custom-inventario")
    )
    assert preview["template"]["id"] == "custom-inventario"
    with pytest.raises(ValidationFailed, match="builtin templates are read-only"):
        service.delete_template(admin, "inventory-list")
    service.delete_template(admin, "custom-inventario")
    assert "custom-inventario" not in {item["id"] for item in service.templates(admin)["items"]}


def test_template_save_is_denied_without_assets_edit(catalog: Catalog) -> None:
    reader = catalog.add_user("reader-tpl", "Reader Tpl", "reader")
    service = reports(catalog)
    definition = builtin_templates()[0]
    definition["id"] = "reader-attempt"
    with pytest.raises(PermissionDenied):
        service.save_template(reader, definition)
    with catalog.session() as session:
        assert session.execute(select(ReportTemplate)).first() is None


def test_settings_defaults_save_and_logo_authorization(catalog: Catalog) -> None:
    service = reports(catalog)
    admin = catalog.admin()
    defaults = service.get_settings(admin)
    assert defaults["baseUrl"] == "https://itam.example.com"
    assert set(defaults["branding"]) >= {"name", "primary", "accent", "header", "footer"}
    assert defaults["labelDefaults"]["formatId"] == "a4-24"

    asset_id = seed(catalog, asset_values(quick_code="LOGO-001", name="Con logo"))
    with catalog.session() as session:
        attachments = AttachmentService(session, catalog.settings)
        logo = attachments.upload(
            admin,
            asset_id,
            filename="logo.png",
            category="photo",
            data=PNG,
        )
        text = attachments.upload(
            admin,
            asset_id,
            filename="notas.txt",
            category="document",
            data=b"plain text",
        )
    payload = {
        "baseUrl": "https://itam.example.com/",
        "branding": {
            "name": "example-org",
            "primary": "#123456",
            "accent": "#654321",
            "header": "Cabecera",
            "footer": "Pie",
            "logoAttachmentId": logo["id"],
        },
        "labelDefaults": {"formatId": "a4-21"},
    }
    saved = service.save_settings(admin, payload)
    assert saved["branding"]["name"] == "example-org"
    assert saved["labelDefaults"]["formatId"] == "a4-21"
    assert (
        "Cabecera"
        in service.preview(admin, ReportRequest(family="inventory", assetIds=[asset_id]))["html"]
    )

    with pytest.raises(ValidationFailed, match="raster"):
        service.save_settings(
            admin,
            {**payload, "branding": {**payload["branding"], "logoAttachmentId": text["id"]}},
        )
    with pytest.raises(ValidationFailed):
        service.save_settings(
            admin,
            {**payload, "branding": {**payload["branding"], "logoAttachmentId": "https://evil"}},
        )
    reader = catalog.add_user("reader-settings", "Reader Settings", "reader")
    with pytest.raises(PermissionDenied):
        service.save_settings(reader, payload)
    with catalog.session() as session:
        stored = session.get(ReportSettings, 1)
        assert stored is not None and stored.data["branding"]["name"] == "example-org"


def test_reports_deny_readers_without_assets_view(catalog: Catalog) -> None:
    service = reports(catalog)
    reader = catalog.add_user("reader-none", "Reader None", "reader")
    # A reader does hold assets.view in this product; removing the policy proves
    # the denial path and that nothing is stored.
    with catalog.session() as session:
        from itsm.identity.models import IdentityRolePolicy

        session.execute(
            IdentityRolePolicy.__table__.delete().where(
                IdentityRolePolicy.role_id == "reader",
                IdentityRolePolicy.resource == "assets",
                IdentityRolePolicy.operation == "view",
            )
        )
        session.commit()
    with pytest.raises(PermissionDenied):
        service.preview(reader, ReportRequest(family="inventory"))
    with pytest.raises(PermissionDenied):
        service.qr(reader, seed(catalog, asset_values(quick_code="DENY-001")))


def test_generated_pdf_csv_and_xlsx_are_real_and_consistent(catalog: Catalog) -> None:
    queue = RecordingQueue()
    service = reports(catalog, queue)
    seed(catalog, asset_values(quick_code="DOC-001", name="Impresora Fiscal Zeta"))
    seed(catalog, asset_values(quick_code="DOC-002", name="=CMD|calc", category="Red"))
    principal = session_principal(catalog)

    pdf_job = service.generate(
        principal,
        ReportRequest(family="inventory", mode="consolidated", output="pdf"),
        credential_digest=None,
    )
    assert pdf_job["status"] == "queued"
    assert queue.calls == [(pdf_job["id"], pdf_job["id"])]
    finished = service.execute(pdf_job["id"])
    assert finished["status"] == "completed", finished
    assert finished["processed"] == finished["total"] == 2
    assert len(finished["documents"]) == 1
    document = finished["documents"][0]
    payload, data = service.download(principal, document["id"])
    assert payload["mime"] == "application/pdf"
    assert data.startswith(b"%PDF-") and b"%%EOF" in data[-2048:]
    assert len(data) == document["size"]
    if shutil.which("pdftotext"):
        target = catalog.settings.attachment_storage_path / "sample.pdf"
        target.write_bytes(data)
        text = subprocess.run(
            ["pdftotext", str(target), "-"], capture_output=True, text=True, check=True
        ).stdout
        normalized_text = " ".join(text.split())
        assert "Impresora Fiscal Zeta" in normalized_text

    csv_job = service.generate(
        principal,
        ReportRequest(
            family="inventory",
            output="csv",
            fields=["quickCode", "name", "purchaseCost"],
        ),
    )
    service.execute(csv_job["id"])
    _, raw = service.download(
        principal, service.job(principal, csv_job["id"])["documents"][0]["id"]
    )
    assert raw.startswith(b"\xef\xbb\xbf")
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))
    assert rows[0] == ["ID", "Código rápido", "Nombre", "Coste de compra"]
    by_code = {row[1]: row for row in rows[1:]}
    assert by_code["DOC-001"][0]
    assert "'=CMD|calc" in by_code["DOC-002"][2]

    xlsx_job = service.generate(
        principal,
        ReportRequest(family="inventory", output="xlsx", fields=["quickCode", "name"]),
    )
    service.execute(xlsx_job["id"])
    _, workbook_raw = service.download(
        principal, service.job(principal, xlsx_job["id"])["documents"][0]["id"]
    )
    workbook = load_workbook(io.BytesIO(workbook_raw), read_only=True)
    values = list(workbook.active.iter_rows(values_only=True))
    assert values[0] == ("ID", "Código rápido", "Nombre")
    by_code = {row[1]: row for row in values[1:]}
    assert by_code["DOC-001"][0]
    assert by_code["DOC-001"][2] == "Impresora Fiscal Zeta"


def test_individual_labels_have_physical_a4_pages(catalog: Catalog) -> None:
    service = reports(catalog)
    asset_id = seed(catalog, asset_values(quick_code="LBL-001", name="Etiqueta Física"))
    principal = session_principal(catalog)
    job = service.generate(
        principal,
        ReportRequest(
            family="inventory",
            mode="individual",
            output="pdf",
            labels={"formatId": "a4-24", "logo": False, "fields": ["name", "code", "qr"]},
        ),
    )
    finished = service.execute(job["id"])
    assert finished["status"] == "completed", finished
    assert len(finished["documents"]) == 1
    document_id = finished["documents"][0]["id"]
    _, data = service.download(principal, document_id)
    assert finished["documents"][0]["assetId"] == asset_id
    if shutil.which("pdfinfo"):
        target = catalog.settings.attachment_storage_path / "labels.pdf"
        target.write_bytes(data)
        info = subprocess.run(
            ["pdfinfo", str(target)], capture_output=True, text=True, check=True
        ).stdout
        page = next(line for line in info.splitlines() if line.startswith("Page size:"))
        size = page.split(":", 1)[1].split("pts", 1)[0].strip()
        width, height = (float(part) for part in size.split(" x "))
        assert abs(width - 595.276) < 1 and abs(height - 841.89) < 1


def test_labels_only_allow_inventory_pdf(catalog: Catalog) -> None:
    with pytest.raises(ValueError):
        ReportRequest(family="history", labels={"formatId": "a4-24"})
    with pytest.raises(ValueError):
        ReportRequest(family="inventory", output="csv", labels={"formatId": "a4-24"})


def test_schema_rejects_unknown_template_and_request_keys(catalog: Catalog) -> None:
    service = reports(catalog)
    principal = session_principal(catalog)
    definition = builtin_templates()[0]
    with pytest.raises(ValueError):
        ReportRequest.model_validate(
            {"family": "inventory", "template": {**definition, "html": "<script>x</script>"}}
        )
    with pytest.raises(ValidationFailed, match="template"):
        service.generate(
            principal,
            ReportRequest.model_validate(
                {"family": "inventory", "template": {**definition, "id": "inventory-list"}}
            ),
        )
    with catalog.session() as session:
        assert session.execute(select(ReportTemplate)).first() is None
        assert session.execute(select(ReportDocument)).first() is None
