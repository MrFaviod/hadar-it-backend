"""Fictional installation in use, authored through the canonical services.

The dataset exists so a demonstration reads like an installation that has been
used: several related assets and people, organization history, redundancy,
incidents in every documented state, maintenance plans in every lifecycle state,
warranties with local receipts, synthetic monitoring alerts and their internal
inbox, one completed import with its own row receipts, and a saved workspace
view.

Everything is created through the same public service methods the API uses, with
the demonstration principal as author, so permissions, validation, history and
audit rows are the real ones. Two deliberate boundaries:

* nothing is delivered outside the installation. Alerts are ingested from a
  synthetic Alertmanager payload, notifications drain to the native internal
  inbox only, and no provider, task queue or remote channel is contacted;
* no rendered document is faked. Report jobs are not created here: the demo has
  no worker, so a queued job would be a lie. Reports, labels and QR codes stay
  on-demand reads over the seeded assets and the built-in templates.

Dates are relative to the demonstration clock (``utcnow``), so the hourly reset
regenerates overdue/upcoming/completed/postponed states that stay representative.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from itsm.attachments.service import AttachmentService
from itsm.attachments.storage import LocalBlobStorage
from itsm.config import Settings
from itsm.demo.telemetry import DemoRefused
from itsm.directory.service import DirectoryService
from itsm.identity.clock import utcnow
from itsm.identity.service import IdentityService, Principal
from itsm.interventions.service import InterventionService
from itsm.inventory.service import InventoryService
from itsm.maintenance.service import MaintenanceService
from itsm.monitoring.service import MonitoringService
from itsm.notifications.service import (
    NotificationService,
    process_notifications,
    record_alert_event,
)
from itsm.redundancy.service import RedundancyService
from itsm.relationships.service import RelationshipService
from itsm.workflows.service import WorkflowService
from itsm.workflows.warranties import WarrantyService
from itsm.workspace.service import WorkspaceService

SUPPLIER = "Proveedor ficticio de demostración"

# The container image default; the only outside path the seed may redirect.
IMAGE_ATTACHMENT_PATH = Path("/data/attachments")

# A 1x1 PNG: a real image for the photo category without any external asset.
PHOTO_BYTES = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d4944415478da63fcffff3f0300050001a5f645400000000049454e44ae426082"
)
RECEIPT_TEXT = (
    "Documento ficticio de demostración.\n"
    "Recibo de recepción del hipervisor ficticio del Campus Norte.\n"
    "No corresponde a una compra real y no tiene validez documental.\n"
)
DOCUMENT_TEXT = (
    "Informe ficticio de demostración.\n"
    "Revisión de la cámara de recepción y del cableado asociado.\n"
    "Datos inventados para mostrar adjuntos dentro de la instalación.\n"
)
IMPORT_CSV = (
    "quick_code,name,category,type,status,description\n"
    "DEMO-101,Punto de acceso recepción · DEMO,routers,Router,in_use,"
    "Importado por la demostración ficticia.\n"
    "DEMO-102,Repetidor pasillo · DEMO,routers,Router,in_storage,"
    "Importado por la demostración ficticia.\n"
)

# key, name, category, type, site index, room index, person index, status, extra
ASSET_DEFINITIONS: tuple[tuple[Any, ...], ...] = (
    (
        "hv-north",
        "Hipervisor Norte",
        "servidores",
        "Servidor",
        0,
        0,
        0,
        "in_use",
        {"ip": "192.0.2.10", "serial": "DEMO-SER-0001", "position": ("0.25", "0.30")},
    ),
    (
        "hv-south",
        "Hipervisor Sur",
        "servidores",
        "Servidor",
        1,
        2,
        1,
        "in_use",
        {"ip": "192.0.2.11", "serial": "DEMO-SER-0002", "position": ("0.60", "0.55")},
    ),
    (
        "sw-north",
        "Switch de núcleo Norte",
        "switches",
        "Switch",
        0,
        0,
        0,
        "in_use",
        {"ip": "192.0.2.12", "serial": "DEMO-SW-0001", "position": ("0.20", "0.60")},
    ),
    (
        "sw-south",
        "Switch de núcleo Sur",
        "switches",
        "Switch",
        1,
        2,
        1,
        "in_use",
        {"ip": "192.0.2.13", "serial": "DEMO-SW-0002"},
    ),
    (
        "fw-north",
        "Firewall perimetral",
        "routers",
        "Router",
        0,
        0,
        3,
        "in_use",
        {"ip": "192.0.2.1", "serial": "DEMO-RTR-0001"},
    ),
    (
        "cam-reception",
        "Cámara recepción",
        "camaras",
        "Cámara IP",
        0,
        1,
        0,
        "in_use",
        {"ip": "192.0.2.20", "position": ("0.75", "0.25")},
    ),
    (
        "cam-access",
        "Cámara acceso Sur",
        "camaras",
        "Cámara IP",
        1,
        2,
        None,
        "in_storage",
        {"ip": "192.0.2.21"},
    ),
    (
        "vm-helpdesk",
        "VM mesa de ayuda",
        "virtualizacion",
        "Máquina virtual",
        0,
        0,
        2,
        "in_use",
        {"technical": {"vmHost": "hv-north", "vmCpu": 4, "vmRam": 8}},
    ),
    (
        "vm-docs",
        "VM documentos",
        "virtualizacion",
        "Máquina virtual",
        0,
        0,
        1,
        "in_use",
        {"technical": {"vmHost": "hv-north", "vmCpu": 2, "vmRam": 4}},
    ),
    (
        "vm-erp",
        "VM ERP",
        "virtualizacion",
        "Máquina virtual",
        1,
        2,
        2,
        "in_use",
        {"technical": {"vmHost": "hv-south", "vmCpu": 8, "vmRam": 16}},
    ),
    (
        "db-north",
        "Base de datos Norte",
        "servidores",
        "Servidor",
        0,
        0,
        3,
        "in_use",
        {"ip": "192.0.2.14", "serial": "DEMO-SER-0003", "position": ("0.45", "0.20")},
    ),
    (
        "nb-support",
        "Notebook de soporte",
        "notebooks",
        "Notebook",
        1,
        3,
        None,
        "in_storage",
        {"serial": "DEMO-NB-0001"},
    ),
    (
        "printer-reception",
        "Impresora de recepción",
        "impresoras",
        "Impresora",
        0,
        1,
        None,
        "in_use",
        {"ip": "192.0.2.30"},
    ),
    (
        "monitor-room",
        "Monitor de sala técnica",
        "monitores",
        "Monitor",
        0,
        0,
        None,
        "in_storage",
        {},
    ),
)

RELATIONSHIP_EDGES: tuple[tuple[str, str, str], ...] = (
    ("vm-helpdesk", "hv-north", "hosted_in"),
    ("vm-docs", "hv-north", "hosted_in"),
    ("vm-erp", "hv-south", "hosted_in"),
    ("hv-north", "sw-north", "connected_to"),
    ("hv-south", "sw-south", "connected_to"),
    ("sw-north", "fw-north", "connected_to"),
    ("sw-south", "fw-north", "connected_to"),
    ("cam-reception", "sw-north", "connected_to"),
    ("cam-access", "sw-south", "connected_to"),
    ("hv-north", "fw-north", "protected_by"),
    ("sw-north", "fw-north", "protected_by"),
    ("vm-erp", "db-north", "depends_on"),
    ("vm-helpdesk", "db-north", "depends_on"),
)


def populate(
    session: Session,
    settings: Settings,
    identity: IdentityService,
    principal: Principal,
) -> dict[str, Any]:
    """Create the complete fictional dataset and return its public counts."""
    today = utcnow().date()
    directory = DirectoryService(session, settings, identity=identity)
    sites, rooms, people = _directory(directory, principal)
    inventory = InventoryService(session, settings, identity=identity, source="internal")
    assets = _assets(inventory, principal, sites, rooms, people)
    _relationships(session, settings, identity, inventory, principal, assets)
    _redundancy(session, settings, identity, principal, assets)
    _organization_history(inventory, principal, assets, sites, rooms, people)
    incidents = _incidents(session, settings, identity, principal, assets, people, today)
    _interventions(session, settings, identity, principal, assets, people, incidents, today)
    plans = _maintenance(session, settings, identity, principal, assets, people, today)
    attachments = _attachments(session, settings, identity, principal, assets)
    warranties = _warranties(session, settings, identity, principal, assets, attachments, today)
    alerts, notifications = _monitoring(session, settings, identity, principal, assets)
    operation = _import(session, settings, identity, principal)
    views = _workspace(session, identity, principal)
    return {
        "sites": len(sites),
        "people": len(people),
        "positions": sum(1 for asset in assets.values() if asset["position"]),
        "assets": len(assets),
        "relationships": len(RELATIONSHIP_EDGES),
        "redundancyGroups": 2,
        "incidents": len(incidents),
        "maintenancePlans": len(plans),
        "warranties": warranties,
        "attachments": attachments["count"],
        "alerts": alerts,
        "notifications": notifications,
        "importOperationId": operation["id"],
        "importSummary": operation["summary"],
        "workspaceViews": views,
    }


def _directory(
    directory: DirectoryService, principal: Principal
) -> tuple[list[Any], list[Any], list[Any]]:
    operations = directory.create_department(principal, {"name": "Operaciones de demostración"})
    support = directory.create_department(principal, {"name": "Soporte de demostración"})
    north = directory.create_location(
        principal,
        {
            "level": "site",
            "name": "Campus Norte · DEMO",
            "description": "Sede ficticia de demostración.",
            "latitude": -25.286,
            "longitude": -57.647,
        },
    )
    south = directory.create_location(
        principal,
        {
            "level": "site",
            "name": "Oficina Sur · DEMO",
            "description": "Sede ficticia de demostración.",
            "latitude": -25.301,
            "longitude": -57.612,
        },
    )
    sites = [north, south]
    rooms = []
    for site, building_name, floor_name, room_names in [
        (north, "Edificio principal", "Planta baja", ["Sala técnica", "Recepción"]),
        (south, "Edificio anexo", "Planta 1", ["Sala de servidores", "Depósito"]),
    ]:
        building = directory.create_location(
            principal, {"level": "building", "name": building_name, "parent_id": site.id}
        )
        floor = directory.create_location(
            principal, {"level": "floor", "name": floor_name, "parent_id": building.id}
        )
        for room_name in room_names:
            rooms.append(
                directory.create_location(
                    principal, {"level": "room_zone", "name": room_name, "parent_id": floor.id}
                )
            )
    # rooms: 0 Sala técnica, 1 Recepción, 2 Sala de servidores, 3 Depósito
    people = [
        directory.create_person(
            principal,
            {
                "name": "Alex Rivera",
                "job_title": "Técnico de infraestructura",
                "department_id": operations.id,
                "site_id": north.id,
                "contact_email": "alex.rivera@example.invalid",
            },
        ),
        directory.create_person(
            principal,
            {
                "name": "Sam Vega",
                "job_title": "Técnico de soporte",
                "department_id": support.id,
                "site_id": south.id,
                "contact_email": "sam.vega@example.invalid",
            },
        ),
        directory.create_person(
            principal,
            {
                "name": "María Benítez",
                "job_title": "Responsable de operaciones",
                "department_id": operations.id,
                "site_id": north.id,
                "contact_email": "maria.benitez@example.invalid",
            },
        ),
        directory.create_person(
            principal,
            {
                "name": "Diego Cáceres",
                "job_title": "Analista de seguridad",
                "department_id": operations.id,
                "site_id": north.id,
                "contact_email": "diego.caceres@example.invalid",
            },
        ),
        directory.create_person(
            principal,
            {
                "name": "Lucía Franco",
                "job_title": "Coordinadora de oficina",
                "department_id": support.id,
                "site_id": south.id,
                "contact_email": "lucia.franco@example.invalid",
            },
        ),
    ]
    return sites, rooms, people


def _assets(
    inventory: InventoryService,
    principal: Principal,
    sites: list[Any],
    rooms: list[Any],
    people: list[Any],
) -> dict[str, dict[str, Any]]:
    """Create the canonical assets; a few intentionally start unassigned."""
    assets: dict[str, dict[str, Any]] = {}
    for index, definition in enumerate(ASSET_DEFINITIONS):
        key, name, category, kind, site, room, person, status, extra = definition
        values: dict[str, Any] = {
            "name": f"{name} · DEMO",
            "category": category,
            "type": kind,
            "quick_code": f"DEMO-{index + 1:03d}",
            "site_id": sites[site].id,
            "location_id": rooms[room].id,
            "status": status,
            "description": "Activo ficticio de demostración. No corresponde a equipos reales.",
        }
        if person is not None:
            values["responsible_person_id"] = people[person].id
        details = dict(extra)
        position = details.pop("position", None)
        values.update(details)
        if position is not None:
            values["position_x"], values["position_y"] = position
        view = inventory.create(principal, values)
        assets[key] = {
            "id": view.id,
            "quick_code": view.quick_code,
            "position": position is not None,
        }
    return assets


def _relationships(
    session: Session,
    settings: Settings,
    identity: IdentityService,
    inventory: InventoryService,
    principal: Principal,
    assets: dict[str, dict[str, Any]],
) -> None:
    relationships = RelationshipService(session, settings, identity=identity, inventory=inventory)
    for child, host, type_key in RELATIONSHIP_EDGES:
        relationships.create(
            principal,
            source_id=assets[child]["id"],
            target_id=assets[host]["id"],
            type_key=type_key,
            notes="Relación ficticia de demostración",
        )


def _redundancy(
    session: Session,
    settings: Settings,
    identity: IdentityService,
    principal: Principal,
    assets: dict[str, dict[str, Any]],
) -> None:
    redundancy = RedundancyService(session, settings, identity=identity)
    redundancy.create(
        principal,
        name="Servidores de virtualización · DEMO",
        description="Par activo/pasivo ficticio entre las dos sedes de demostración.",
        mode="active_passive",
        members=[
            {"asset_id": assets["hv-north"]["id"], "role": "primary"},
            {"asset_id": assets["hv-south"]["id"], "role": "backup"},
        ],
    )
    redundancy.create(
        principal,
        name="Núcleo de red · DEMO",
        description="Agregación ficticia de los dos switches de demostración.",
        mode="active_active",
        members=[
            {"asset_id": assets["sw-north"]["id"], "share": "50.00"},
            {"asset_id": assets["sw-south"]["id"], "share": "50.00"},
        ],
    )


def _organization_history(
    inventory: InventoryService,
    principal: Principal,
    assets: dict[str, dict[str, Any]],
    sites: list[Any],
    rooms: list[Any],
    people: list[Any],
) -> None:
    """Leave assigned/returned/transferred entries in the structured history."""
    notebook = assets["nb-support"]["id"]
    inventory.assign_responsible(
        principal,
        notebook,
        people[4].id,
        reason="Entrega ficticia de equipo de demostración",
    )
    inventory.return_responsible(
        principal,
        notebook,
        reason="Devolución ficticia para reasignación",
        notes="El equipo vuelve al resguardo de demostración.",
    )
    inventory.assign_responsible(
        principal,
        notebook,
        people[1].id,
        reason="Reasignación ficticia al equipo de soporte",
    )
    inventory.assign_responsible(
        principal,
        assets["printer-reception"]["id"],
        people[4].id,
        reason="Asignación ficticia de la impresora de recepción",
    )
    inventory.transfer(
        principal,
        assets["vm-docs"]["id"],
        site_id=sites[1].id,
        location_id=rooms[2].id,
        reason="Traslado ficticio de la máquina virtual a la sede Sur",
    )


def _incidents(
    session: Session,
    settings: Settings,
    identity: IdentityService,
    principal: Principal,
    assets: dict[str, dict[str, Any]],
    people: list[Any],
    today: date,
) -> dict[str, str]:
    incidents = InterventionService(session, settings, identity=identity, source="internal")
    opened = incidents.create_incident(
        principal,
        {
            "primaryAssetId": assets["cam-reception"]["id"],
            "description": "DEMO: imagen intermitente en recepción",
            "priority": "high",
            "responsiblePersonId": people[0].id,
            "openedOn": (today - timedelta(days=1)).isoformat(),
        },
    )
    acknowledged = incidents.create_incident(
        principal,
        {
            "primaryAssetId": assets["hv-south"]["id"],
            "description": "DEMO: revisar capacidad del hipervisor Sur",
            "priority": "normal",
            "responsiblePersonId": people[1].id,
            "openedOn": (today - timedelta(days=2)).isoformat(),
            "affectedAssetIds": [assets["vm-erp"]["id"]],
        },
    )
    incidents.acknowledge_incident(
        principal, acknowledged.id, note="DEMO: en revisión por el equipo de soporte"
    )
    resolved = incidents.create_incident(
        principal,
        {
            "primaryAssetId": assets["sw-north"]["id"],
            "description": "DEMO: errores intermitentes en el puerto de agregación",
            "priority": "high",
            "responsiblePersonId": people[0].id,
            "openedOn": (today - timedelta(days=6)).isoformat(),
        },
    )
    incidents.acknowledge_incident(principal, resolved.id, note="DEMO: diagnóstico iniciado")
    incidents.resolve_incident(
        principal, resolved.id, note="DEMO: se reemplazó el cable de demostración"
    )
    closed = incidents.create_incident(
        principal,
        {
            "primaryAssetId": assets["vm-erp"]["id"],
            "description": "DEMO: disco virtual lleno en el servidor de aplicaciones",
            "priority": "critical",
            "responsiblePersonId": people[2].id,
            "openedOn": (today - timedelta(days=12)).isoformat(),
        },
    )
    incidents.acknowledge_incident(
        principal, closed.id, note="DEMO: ampliación de disco planificada"
    )
    incidents.resolve_incident(principal, closed.id, note="DEMO: disco ampliado en el laboratorio")
    incidents.close_incident(principal, closed.id, note="DEMO: verificado por operaciones")
    return {
        "open": opened.id,
        "acknowledged": acknowledged.id,
        "resolved": resolved.id,
        "closed": closed.id,
    }


def _interventions(
    session: Session,
    settings: Settings,
    identity: IdentityService,
    principal: Principal,
    assets: dict[str, dict[str, Any]],
    people: list[Any],
    incidents: dict[str, str],
    today: date,
) -> None:
    interventions = InterventionService(session, settings, identity=identity, source="internal")
    interventions.create(
        principal,
        {
            "assetId": assets["cam-reception"]["id"],
            "type": "corrective",
            "description": "DEMO: revisión de cableado y limpieza de lente",
            "technicianPersonId": people[0].id,
            "occurredOn": (today - timedelta(days=1)).isoformat(),
            "status": "in_progress",
            "laborCost": "35.50",
            "incidentId": incidents["open"],
        },
    )
    interventions.create(
        principal,
        {
            "assetId": assets["hv-north"]["id"],
            "type": "preventive",
            "description": "DEMO: mantenimiento preventivo del hipervisor Norte",
            "technicianPersonId": people[1].id,
            "occurredOn": (today - timedelta(days=20)).isoformat(),
            "status": "completed",
            "laborCost": "80.00",
            "notes": "Trabajo ficticio de demostración.",
        },
    )


def _maintenance(
    session: Session,
    settings: Settings,
    identity: IdentityService,
    principal: Principal,
    assets: dict[str, dict[str, Any]],
    people: list[Any],
    today: date,
) -> list[str]:
    maintenance = MaintenanceService(session, settings, identity=identity, source="internal")
    tasks = ["Revisar estado y registrar el resultado de demostración"]
    overdue = maintenance.create_plan(
        principal,
        asset_id=assets["hv-north"]["id"],
        interval_months=6,
        tasks=tasks,
        responsible_person_id=people[0].id,
        due_on=today - timedelta(days=6),
    )
    upcoming = maintenance.create_plan(
        principal,
        asset_id=assets["sw-north"]["id"],
        interval_months=6,
        tasks=tasks,
        responsible_person_id=people[0].id,
        due_on=today + timedelta(days=12),
    )
    completed = maintenance.create_plan(
        principal,
        asset_id=assets["hv-south"]["id"],
        interval_months=3,
        tasks=tasks,
        responsible_person_id=people[1].id,
        due_on=today - timedelta(days=30),
    )
    maintenance.complete_plan(
        principal,
        completed.id,
        completed_on=today - timedelta(days=4),
        notes="DEMO: mantenimiento preventivo realizado en el laboratorio",
    )
    postponed = maintenance.create_plan(
        principal,
        asset_id=assets["fw-north"]["id"],
        interval_months=6,
        tasks=tasks,
        responsible_person_id=people[3].id,
        due_on=today + timedelta(days=2),
    )
    maintenance.postpone_plan(
        principal,
        postponed.id,
        due_on=today + timedelta(days=25),
        notes="DEMO: reprogramado por la ventana de cambios ficticia",
    )
    return [overdue.id, upcoming.id, completed.id, postponed.id]


def _blob_storage(settings: Settings) -> LocalBlobStorage | None:
    """Blob storage at the configured attachment path, inside the demo directory.

    The configured path is authoritative so a non-default descendant (for example
    ``<demo>/storage/blobs``) is where the reset looks for and regenerates files.
    Only the container image default (``/data/attachments``) outside the demo
    directory falls back to the canonical ``<demo>/attachments``; any other
    outside path is refused instead of silently writing somewhere the demo does
    not own. A direct seed without an owned demo directory (tests, tooling) must
    not fail the dataset when the path is not writable; the payload reports the
    attachments actually created.
    """
    demo_directory = settings.demo_data_directory
    root = Path(settings.attachment_storage_path)
    if demo_directory is not None:
        demo_root = Path(demo_directory).resolve()
        resolved = root.resolve()
        if demo_root != resolved and demo_root not in resolved.parents:
            if root != IMAGE_ATTACHMENT_PATH:
                raise DemoRefused("demo attachment storage must be inside the demo directory")
            root = Path(demo_directory) / "attachments"
    storage = LocalBlobStorage(root)
    try:
        with storage.directory(create=True):
            pass
    except OSError:
        if demo_directory is not None:
            raise
        return None
    return storage


def _attachments(
    session: Session,
    settings: Settings,
    identity: IdentityService,
    principal: Principal,
    assets: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    storage = _blob_storage(settings)
    if storage is None:
        return {"count": 0, "receipt": None}
    attachments = AttachmentService(
        session, settings, identity=identity, source="internal", storage=storage
    )
    receipt = attachments.upload(
        principal,
        assets["hv-north"]["id"],
        filename="acta-recepcion-demo.txt",
        category="receipt",
        data=RECEIPT_TEXT.encode("utf-8"),
    )
    attachments.upload(
        principal,
        assets["cam-reception"]["id"],
        filename="informe-camara-demo.txt",
        category="document",
        data=DOCUMENT_TEXT.encode("utf-8"),
    )
    attachments.upload(
        principal,
        assets["hv-north"]["id"],
        filename="foto-rack-demo.png",
        category="photo",
        data=PHOTO_BYTES,
    )
    return {"count": 3, "receipt": receipt["id"]}


def _warranties(
    session: Session,
    settings: Settings,
    identity: IdentityService,
    principal: Principal,
    assets: dict[str, dict[str, Any]],
    attachments: dict[str, Any],
    today: date,
) -> int:
    warranties = WarrantyService(session, settings, identity=identity, source="internal")
    # Expiry is derived from purchase date plus duration so every state stays
    # consistent: current, expiring soon and already expired.
    for key, purchased_days_ago, months in [
        ("hv-north", 300, 36),
        ("sw-north", 360, 12),
        ("cam-reception", 800, 12),
        ("printer-reception", 200, 24),
    ]:
        warranties.put(
            principal,
            assets[key]["id"],
            {
                "supplier": SUPPLIER,
                "purchaseDate": (today - timedelta(days=purchased_days_ago)).isoformat(),
                "durationMonths": months,
                "status": "active",
                "notes": "Garantía ficticia de demostración, sin contrato real.",
            },
        )
    if attachments["receipt"]:
        warranties.put(
            principal,
            assets["hv-north"]["id"],
            {
                "supplier": SUPPLIER,
                "purchaseDate": (today - timedelta(days=300)).isoformat(),
                "durationMonths": 36,
                "status": "active",
                "receiptId": attachments["receipt"],
                "notes": "Garantía ficticia con recibo local de demostración.",
            },
        )
    warranties.put(
        principal,
        assets["monitor-room"]["id"],
        {
            "supplier": SUPPLIER,
            "status": "unknown",
            "notes": "Sin fecha de compra conocida en la demostración ficticia.",
        },
    )
    return 5


def _monitoring(
    session: Session,
    settings: Settings,
    identity: IdentityService,
    principal: Principal,
    assets: dict[str, dict[str, Any]],
) -> tuple[int, int]:
    """Ingest synthetic Alertmanager events and drain only the internal inbox."""
    monitoring = MonitoringService(
        session,
        settings,
        identity=identity,
        source="internal",
        notifier=record_alert_event,
    )
    now = utcnow()
    monitoring.ingest_alertmanager(
        {
            "version": "4",
            "status": "firing",
            "alerts": [
                _alert(
                    assets["hv-north"]["id"],
                    "DemoHighCpuUsage",
                    "critical",
                    (now - timedelta(minutes=45)).isoformat(),
                    "CPU ficticia por encima del umbral de demostración",
                    "demo-hvcpu0001",
                ),
                _alert(
                    assets["sw-south"]["id"],
                    "DemoInterfaceErrors",
                    "warning",
                    (now - timedelta(minutes=30)).isoformat(),
                    "Errores ficticios en el puerto de agregación",
                    "demo-swerr0001",
                ),
                _alert(
                    assets["cam-reception"]["id"],
                    "DemoCameraOffline",
                    "warning",
                    (now - timedelta(minutes=20)).isoformat(),
                    "La cámara ficticia dejó de responder",
                    "demo-camoff0001",
                ),
            ],
        },
        now=now,
    )
    notifications = NotificationService(session, settings)
    # The demo has no worker, so seeding drains the outbox through the same public
    # processing path the worker uses. Every configured channel is internal, and
    # the demo marker still suppresses external delivery at dispatch.
    _drain_outbox(session, settings, now)
    alerts = monitoring.list_alerts(principal, limit=100)["items"]
    for alert in alerts:
        if alert["alertName"] == "DemoHighCpuUsage":
            monitoring.acknowledge(principal, alert["id"], "DEMO: revisado por operaciones")
            session.commit()
    monitoring.ingest_alertmanager(
        {
            "version": "4",
            "status": "resolved",
            "alerts": [
                _alert(
                    assets["sw-south"]["id"],
                    "DemoInterfaceErrors",
                    "warning",
                    (now - timedelta(minutes=30)).isoformat(),
                    "Errores ficticios en el puerto de agregación",
                    "demo-swerr0001",
                    status="resolved",
                    ends_at=(now - timedelta(minutes=5)).isoformat(),
                )
            ],
        },
        now=now,
    )
    _drain_outbox(session, settings, now)
    inbox = notifications.list_inbox(principal, limit=200)
    return len(alerts), inbox["total"]


def _drain_outbox(session: Session, settings: Settings, now: datetime) -> None:
    """Deliver queued notification events with the supported processing path."""
    session.commit()
    process_notifications(settings, as_of=now)


def _alert(
    asset_id: str,
    name: str,
    severity: str,
    starts_at: str,
    summary: str,
    fingerprint: str,
    *,
    status: str = "firing",
    ends_at: str | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "status": status,
        "labels": {
            "alertname": name,
            "asset_id": asset_id,
            "severity": severity,
            "source": "demo",
        },
        "annotations": {"summary": summary},
        "startsAt": starts_at,
        "fingerprint": fingerprint,
    }
    if ends_at is not None:
        item["endsAt"] = ends_at
    return item


def _import(
    session: Session,
    settings: Settings,
    identity: IdentityService,
    principal: Principal,
) -> dict[str, Any]:
    """Run one small import through analyze, human approval and execution."""
    workflows = WorkflowService(session, settings, identity=identity, source="internal")
    preview = workflows.analyze(principal, IMPORT_CSV.encode("utf-8"), "demo-assets.csv")
    operation_id = preview["id"]
    workflows.approve(principal, operation_id)
    operation = workflows.execute(principal, operation_id)
    return {"id": operation_id, "summary": dict(operation["summary"])}


def _workspace(session: Session, identity: IdentityService, principal: Principal) -> int:
    workspace = WorkspaceService(session=session, identity=identity, source="internal")
    workspace.create_view(
        principal,
        {
            "name": "Servidores de demostración",
            "route": "inventory",
            "snapshot": {"search": "DEMO", "category": "servidores"},
        },
    )
    workspace.save_state(
        principal,
        {
            "widgets": ["availability", "alerts", "incidents", "maintenance", "warranties"],
            "lastViews": {"inventory": {}},
            "themeMode": "auto",
        },
    )
    return 1
