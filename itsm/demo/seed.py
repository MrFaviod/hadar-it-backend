"""Create a coherent fictional dataset using the same services as the API."""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.demo.state import DemoInstallation
from itsm.directory.service import DirectoryService
from itsm.identity.clock import utcnow
from itsm.identity.permissions import ROLE_OPERATOR
from itsm.identity.service import IdentityService
from itsm.interventions.service import InterventionService
from itsm.inventory.service import InventoryService
from itsm.maintenance.service import MaintenanceService
from itsm.relationships.service import RelationshipService
from itsm.workflows.warranties import WarrantyService


def seed(session: Session, settings: Settings, username: str, password: str) -> dict:
    session.add(DemoInstallation(id=1, dataset="fictional-infrastructure-v1", created_at=utcnow()))
    session.commit()  # Safety marker precedes every service commit, including partial failures.
    identity = IdentityService(session, settings)
    identity.bootstrap_superadmin(username, "Responsable de demostración", password)
    principal = identity.login(username, password).principal
    identity.create_user(
        principal,
        username="demo.operator",
        name="Operadora de demostración",
        role_id=ROLE_OPERATOR,
        password=password,
    )
    directory = DirectoryService(session, settings, identity=identity)
    department = directory.create_department(principal, {"name": "Operaciones de demostración"})
    sites, rooms, people = [], [], []
    for name, person_name in [
        ("Campus Norte · DEMO", "Alex Rivera"),
        ("Oficina Sur · DEMO", "Sam Vega"),
    ]:
        site = directory.create_location(principal, {"level": "site", "name": name})
        parent = site
        for level, label in [
            ("building", "Edificio principal"),
            ("floor", "Planta baja"),
            ("room_zone", "Sala técnica"),
        ]:
            parent = directory.create_location(
                principal,
                {
                    "level": level,
                    "name": label,
                    "parent_id": parent.id,
                },
            )
        person = directory.create_person(
            principal,
            {
                "name": person_name,
                "job_title": "Técnico de demostración",
                "department_id": department.id,
                "site_id": site.id,
                "contact_email": person_name.split()[0].lower() + "@example.invalid",
            },
        )
        sites.append(site)
        rooms.append(parent)
        people.append(person)
    inventory = InventoryService(session, settings, identity=identity)
    assets = []
    for index, (name, category, kind) in enumerate(
        [
            ("Hipervisor Norte", "servidores", "Servidor"),
            ("Hipervisor Sur", "servidores", "Servidor"),
            ("Switch Norte", "switches", "Switch"),
            ("Switch Sur", "switches", "Switch"),
            ("Cámara recepción", "camaras", "Cámara IP"),
            ("Cámara acceso", "camaras", "Cámara IP"),
            ("VM mesa de ayuda", "virtualizacion", "Máquina virtual"),
            ("VM documentos", "virtualizacion", "Máquina virtual"),
        ]
    ):
        location_index = index % 2
        values = {
            "name": name + " · DEMO",
            "category": category,
            "type": kind,
            "quick_code": f"DEMO-{index + 1:03d}",
            "site_id": sites[location_index].id,
            "location_id": rooms[location_index].id,
            "status": "in_storage" if index == 5 else "in_use",
            "description": (
                "Infraestructura ficticia de demostración. No corresponde a equipos reales."
            ),
            "ip": f"192.0.2.{index + 10}",
        }
        if index != 5:
            values["responsible_person_id"] = people[location_index].id
        assets.append(inventory.create(principal, values))
    relationships = RelationshipService(session, settings, identity=identity, inventory=inventory)
    for child, host in [(6, 0), (7, 1)]:
        relationships.create(
            principal,
            source_id=assets[child].id,
            target_id=assets[host].id,
            type_key="hosted_in",
            notes="Relación ficticia de demostración",
        )
    for child, switch in [(0, 2), (1, 3), (4, 2), (5, 3)]:
        relationships.create(
            principal,
            source_id=assets[child].id,
            target_id=assets[switch].id,
            type_key="connected_to",
        )
    incidents = InterventionService(session, settings, identity=identity)
    incidents.create_incident(
        principal,
        {
            "primaryAssetId": assets[4].id,
            "description": "DEMO: imagen intermitente en recepción",
            "priority": "high",
            "responsiblePersonId": people[0].id,
        },
    )
    incidents.create_incident(
        principal,
        {
            "primaryAssetId": assets[1].id,
            "description": "DEMO: revisar capacidad del hipervisor Sur",
            "priority": "normal",
            "responsiblePersonId": people[1].id,
            "affectedAssetIds": [assets[7].id],
        },
    )
    today = date.today()
    maintenance = MaintenanceService(session, settings, identity=identity)
    for index, days in [(0, 3), (2, -2)]:
        maintenance.create_plan(
            principal,
            asset_id=assets[index].id,
            interval_months=6,
            tasks=["Revisar estado y registrar resultado de demostración"],
            responsible_person_id=people[0].id,
            due_on=today + timedelta(days=days),
        )
    warranties = WarrantyService(session, settings, identity=identity)
    for index, days in [(0, 14), (1, 365), (4, -10)]:
        warranties.put(
            principal,
            assets[index].id,
            {
                "supplier": "Proveedor ficticio de demostración",
                "purchaseDate": (today - timedelta(days=365)).isoformat(),
                "expiresOn": (today + timedelta(days=days)).isoformat(),
                "notes": "Sin contrato real ni documento adjunto.",
            },
        )
    return {
        "mode": "demo",
        "dataset": "fictional-infrastructure-v1",
        "assets": len(assets),
        "sites": 2,
        "people": 2,
        "incidents": 2,
        "relationships": 6,
        "externalNotifications": "blocked",
    }
